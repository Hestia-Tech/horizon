use blake3::Hasher;
use rayon::iter::IntoParallelRefMutIterator;
use rayon::iter::IndexedParallelIterator;
use rayon::prelude::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use secrecy::Secret;

/// Computes the Hash-based Message Authentication Code (HMAC) using the SHA3-512 hashing algorithm.
///
/// # Parameters
///
/// - `key`: A slice of unsigned 8-bit integers representing the secret key for HMAC.
/// - `message`: A slice of unsigned 8-bit integers representing the message to be authenticated.
///
/// # Returns
///
/// Returns the HMAC as a vector of unsigned 8-bit integers.
///
/// # Examples
///
/// ```rust
/// let key = vec![/* vector of u8 representing key */];
/// let message = vec![/* vector of u8 representing message */];
/// let hmac_result = hmac(&key, &message);
/// println!("{:?}", hmac_result);
/// ```
fn hmac(key: &[u8], message: &[u8], block_size: usize, output_size: usize) -> Vec<u8> {
    let mut adjusted_key = if key.len() > block_size {
        let mut hasher = Hasher::new();
        hasher.update(key);
        let mut output = vec![0; output_size];
        hasher.finalize_xof().fill(&mut output);
        output
    } else {
        let mut output = vec![0; output_size];
        output[..key.len()].copy_from_slice(key);
        output
    };

    if adjusted_key.len() < block_size {
        adjusted_key.resize(block_size, 0);
    }

    let mut ipad = adjusted_key.clone();
    let mut opad = adjusted_key;

    for (i, b) in ipad.iter_mut().enumerate() {
        *b ^= 0x36;
        opad[i] ^= 0x5C;
    }

    let inner_input: Vec<u8> = ipad.into_iter().chain(message.iter().cloned()).collect();

    let mut inner_hasher = Hasher::new();
    inner_hasher.update(&inner_input);
    let mut inner_hash = vec![0; output_size];
    inner_hasher.finalize_xof().fill(&mut inner_hash);

    let outer_input: Vec<u8> = opad.into_iter().chain(inner_hash.iter().cloned()).collect();
    let mut outer_hasher = Hasher::new();
    outer_hasher.update(&outer_input);
    let mut outer_hash = vec![0; output_size];
    outer_hasher.finalize_xof().fill(&mut outer_hash);

    outer_hash
}

/// Performs the Key Derivation Function (KDF) based on the HMAC-SHA3-512 algorithm.
///
/// # Parameters
///
/// - `password`: A slice of unsigned 8-bit integers representing the password.
/// - `salt`: A slice of unsigned 8-bit integers representing the salt.
/// - `iterations`: The number of iterations for the KDF.
///
/// # Returns
///
/// Returns the derived key as a vector of unsigned 8-bit integers.
///
/// # Examples
///
/// ```rust
/// let password = vec![/* vector of u8 representing password */];
/// let salt = vec![/* vector of u8 representing salt */];
/// let iterations = 1000;
/// let derived_key = kdfwagen(&password, &salt, iterations);
/// println!("{:?}", derived_key);
/// ```
pub(crate) fn kdfwagen(password: &[u8], salt: &[u8], iterations: usize) -> Secret<Vec<u8>> {
    const PRF_OUTPUT_SIZE: usize = 64;
    const KEY_LENGTH: usize = 512;
    const BLOCK_SIZE: usize = 128;
    const OUTPUT_SIZE: usize = 64;

    let mut result = Vec::new();
    let mut block_count = KEY_LENGTH.div_ceil(PRF_OUTPUT_SIZE);

    if block_count > 255 {
        block_count = 255;
    }

    for block_index in 1..=block_count {
        let mut block = salt.to_vec();
        block.extend_from_slice(&block_index.to_be_bytes());

        let mut u = hmac(password, &block, BLOCK_SIZE, OUTPUT_SIZE);

        for _ in 2..=iterations {
            let x = hmac(password, &u, BLOCK_SIZE, OUTPUT_SIZE);
            u.par_iter_mut().zip(x.par_iter()).for_each(|(a, b)| *a ^= b);
        }

        result.extend_from_slice(&u[..std::cmp::min(PRF_OUTPUT_SIZE, KEY_LENGTH)]);
    }

    result.resize(KEY_LENGTH, 0);
    Secret::new(result)
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;
    use super::*;
    

    #[test]
    fn test_hmac() {
        let key = b"key";
        let message = b"The quick brown fox jumps over the lazy dog";
        let expected = "7dd9b777e6a6a1ad1b6b7903dfd37f032310f4d10aada0057e84952e6a4bd5c2ceb935ebedaec8bfce881205d4856f9030af7ea005f73cb68a238b38f2e71f28";
        let result = hmac(key, message, 128,64);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_kdfwagen() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 2;
        let expected = "413bd0ade22416e8e3d020ce630195a1344007b5ae5f7b80f4c8000954df962f0de0e577870cdb0b740cb40bbb3036e98d5a441cc9a23e6792c38d1c62d9e68ce44cb1b069bf2111c6f239260bc8a303ff27feec4712cf2eb6f77bbb2e57cde79367bb9db9b7deeaabef96bb26d7ad5958b4f29b26f7ed2bd80406aef4b0ebed6fee5f2ecf334ee5572028d563a42512bcc21be613aaf873c1b14b566c2747ca6fa9ef5542c2872fca20f71430f5a6db219ee5fb796fc991539763b3c2fe631ae1faa850ca7c184967bb4248fb2d8aaf633bf4b6c6ad76eeeb10ad1e42a104d7c2f07017e9812b01ee9c601cf4c45becac0d62bf33eaaed7ae92b5d93736cb66bfed9dbb2091334a883c6f4c65731bb1187bf186ca67c9e43954c4602d14efd3321c6e8cb4501bb81256def8f63ff5f0ebdbbec62e41be0e849be79f3caeac391f4aec954c9dda8a30a41b56e062a601dc9c3dbf6b0e4958b6a8528f673082fd5072caadf970cfc1cba9aa789b2c5f3e57cc12cd43284275d4e8bccc1a001d8e8f3c052589d2c9441c0df8c9fc4d3ef4a3a9f8cd523d5e1b2c96425bb3b415b5bb22070c9349421c9746f65e31331aab58950b4722c98d422cc88c1ab4601011c1d29db969edca4000e130ea788bef2de34e6856088f6a61df8545f55b174234702b22564710e99dea7cd55d01ce24f10f612424b0ea1bdc77c1cceb6774af4b";
        let result = kdfwagen(password, salt, iterations);
        assert_eq!(hex::encode(result.expose_secret()), expected);
    }
}
