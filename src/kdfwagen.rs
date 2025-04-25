use blake3::Hasher;
use rayon::prelude::*;
use secrecy::Secret;

fn hmac(key: &[u8], message: &[u8], block_size: usize, output_size: usize) -> Vec<u8> {
    let mut adjusted_key = if key.len() > block_size {
        let mut h = Hasher::new();
        h.update(key);
        let mut out = vec![0; output_size];
        h.finalize_xof().fill(&mut out);
        out
    } else {
        let mut out = vec![0; block_size];
        out[..key.len()].copy_from_slice(key);
        out
    };
    if adjusted_key.len() < block_size {
        adjusted_key.resize(block_size, 0);
    }
    let mut ipad = adjusted_key.clone();
    let mut opad = adjusted_key;
    for i in 0..block_size {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5C;
    }
    let mut inner = Hasher::new();
    inner.update(&ipad);
    inner.update(message);
    let mut inner_hash = vec![0; output_size];
    inner.finalize_xof().fill(&mut inner_hash);
    let mut outer = Hasher::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    let mut outer_hash = vec![0; output_size];
    outer.finalize_xof().fill(&mut outer_hash);
    outer_hash
}

pub(crate) fn kdfwagen(password: &[u8], salt: &[u8], iterations: usize) -> Secret<Vec<u8>> {
    const PRF_OUTPUT: usize = 64;
    const KEY_LEN: usize = 512;
    const BLOCK_SIZE: usize = 128;
    const OUT_SIZE: usize = 64;
    let mut result = Vec::with_capacity(KEY_LEN);
    let mut block = Vec::with_capacity(salt.len() + 8);
    let mut block_count = KEY_LEN.div_ceil(PRF_OUTPUT);
    if block_count > 255 { block_count = 255; }
    let mut u = vec![0; OUT_SIZE];
    for idx in 1..=block_count {
        block.clear();
        block.extend_from_slice(salt);
        block.extend_from_slice(&idx.to_be_bytes());
        u = hmac(password, &block, BLOCK_SIZE, OUT_SIZE);
        for _ in 2..=iterations {
            let x = hmac(password, &u, BLOCK_SIZE, OUT_SIZE);
            u.par_iter_mut().zip(x.par_iter()).for_each(|(a, &b)| *a ^= b);
        }
        let take = PRF_OUTPUT.min(KEY_LEN - result.len());
        result.extend_from_slice(&u[..take]);
    }
    result.resize(KEY_LEN, 0);
    Secret::new(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    #[test]
    fn test_hmac() {
        let key = b"key";
        let msg = b"The quick brown fox jumps over the lazy dog";
        let out = hmac(key, msg, 128, 64);
        assert_eq!(
            hex::encode(out),
            "7dd9b777e6a6a1ad1b6b7903dfd37f032310f4d10aada0057e84952e6a4bd5c2ceb935ebedaec8bfce881205d4856f9030af7ea005f73cb68a238b38f2e71f28"
        );
    }
    #[test]
    fn test_kdfwagen() {
        let pwd = b"password";
        let slt = b"salt";
        let res = kdfwagen(pwd, slt, 2);
        assert_eq!(
            hex::encode(res.expose_secret()),
            "413bd0ade22416e8e3d020ce630195a1344007b5ae5f7b80f4c8000954df962f0de0e577870cdb0b740cb40bbb3036e98d5a441cc9a23e6792c38d1c62d9e68ce44cb1b069bf2111c6f239260bc8a303ff27feec4712cf2eb6f77bbb2e57cde79367bb9db9b7deeaabef96bb26d7ad5958b4f29b26f7ed2bd80406aef4b0ebed6fee5f2ecf334ee5572028d563a42512bcc21be613aaf873c1b14b566c2747ca6fa9ef5542c2872fca20f71430f5a6db219ee5fb796fc991539763b3c2fe631ae1faa850ca7c184967bb4248fb2d8aaf633bf4b6c6ad76eeeb10ad1e42a104d7c2f07017e9812b01ee9c601cf4c45becac0d62bf33eaaed7ae92b5d93736cb66bfed9dbb2091334a883c6f4c65731bb1187bf186ca67c9e43954c4602d14efd3321c6e8cb4501bb81256def8f63ff5f0ebdbbec62e41be0e849be79f3caeac391f4aec954c9dda8a30a41b56e062a601dc9c3dbf6b0e4958b6a8528f673082fd5072caadf970cfc1cba9aa789b2c5f3e57cc12cd43284275d4e8bccc1a001d8e8f3c052589d2c9441c0df8c9fc4d3ef4a3a9f8cd523d5e1b2c96425bb3b415b5bb22070c9349421c9746f65e31331aab58950b4722c98d422cc88c1ab4601011c1d29db969edca4000e130ea788bef2de34e6856088f6a61df8545f55b174234702b22564710e99dea7cd55d01ce24f10f612424b0ea1bdc77c1cceb6774af4b"
        );
    }
}
