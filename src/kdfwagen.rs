use sha3::{Digest, Sha3_512};
use rayon::iter::IntoParallelRefMutIterator;
use rayon::iter::IndexedParallelIterator;
use rayon::prelude::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;

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
fn hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 128;

    let mut adjusted_key = if key.len() > BLOCK_SIZE {
        let mut hasher = Sha3_512::new();
        hasher.update(key);
        hasher.finalize().to_vec()
    } else {
        key.to_vec()
    };

    if adjusted_key.len() < BLOCK_SIZE {
        adjusted_key.resize(BLOCK_SIZE, 0);
    }

    let ipad: Vec<u8> = adjusted_key.iter().map(|&b| b ^ 0x36).collect();
    let opad: Vec<u8> = adjusted_key.iter().map(|&b| b ^ 0x5C).collect();

    let inner_input: Vec<u8> = ipad.into_iter().chain(message.into_iter().cloned()).collect();

    let inner_hash = Sha3_512::digest(inner_input);

    let outer_input: Vec<u8> = opad.into_iter().chain(inner_hash.iter().cloned()).collect();

    Sha3_512::digest(outer_input).to_vec()
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
pub(crate) fn kdfwagen(password: &[u8], salt: &[u8], iterations: usize) -> Vec<u8> {
    const PRF_OUTPUT_SIZE: usize = 64;
    const KEY_LENGTH: usize = 512;

    let mut result = Vec::new();
    let mut block_count = (KEY_LENGTH + PRF_OUTPUT_SIZE - 1) / PRF_OUTPUT_SIZE;

    if block_count > 255 {
        block_count = 255;
    }

    for block_index in 1..=block_count {
        let mut block = salt.to_vec();
        block.extend_from_slice(&block_index.to_be_bytes());

        let mut u = hmac(password, &block);

        for _ in 2..=iterations {
            let x = hmac(password, &u);
            u.par_iter_mut().zip(x.par_iter()).for_each(|(a, b)| *a ^= b);
        }

        result.extend_from_slice(&u[..std::cmp::min(PRF_OUTPUT_SIZE, KEY_LENGTH)]);
    }

    result.resize(KEY_LENGTH, 0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_hmac() {
        let key = b"key";
        let message = b"The quick brown fox jumps over the lazy dog";
        let expected = "2a18de870613ad3cb1d3ed660320c8508c1107915ab7d9eadc06723237e97de491e8ba87b3a2e2f4c61775e24e11f77bdd9e7406d5dca68e9c692c67fc3307b1";
        let result = hmac(key, message);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_kdfwagen() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 2;
        let expected = "4714bcc31299ffafd9bef3315f28596a77fc51e5dca321e485dbf67e203f7c5c08a01f65090539ff9a0ae2d610373729ed3e7f54201d581a7e9a2d023b6900407c9aa051f645cb7254772d3f538aa1714ec81b10204e2b70c1b9c7f118e4713cd2e17ce7d6f450fadfdd40727001e16554a58ac16c589feaba2f7c58827b517d00416e457e494721b5f3d150fd76d91ca5a0034da249b23d9cc07cfc5916ce568c24ac15bc936b6f26c3f75625146e9927113adefc35eb8a4ee5f4c18ccc2cba7efef4510307f8ccd0f8d523cbf3efbb26da6cd7aaf31eb541b603d6e1ab07e2eb8d440690e9fb8ba48a470257c95b76047af1b696d87ca78d8b91743e6a3ed0e335285f248729b644fe1eeb07487daedc04581b244e149eeb0bc4c98f7a323ac805141741992b88b7d6586cce599e508f6a7581f6589739f68079f0f158519039f2cb05e302b953b324ff7d52993d5cb8b8ddc5793f9bfaa27cfae49465e9f0ef8938aefb94a96cb48697f3db737a96d9a0c8c1b2bc3975f0aea3e3fe0582bb1456cbadab03466c9fa5d91c796db5304258350f3bc1be5cea14dff983b48c12bac1f20327b55a3215b91506db3c6fdad0a58253405a033b0d68a3145f5e91b2f54f9ca7dfe864e680b5af70545aed4553a9f180025fc98d713e5d4408bf2e65dcbc94e1acd9a5d154e04f26fcc2617ee0acb5cc164280c6e504b291635fcd5b";
        let result = kdfwagen(password, salt, iterations);
        assert_eq!(hex::encode(result), expected);
    }
}
