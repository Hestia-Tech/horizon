use std::error::Error;
use std::sync::Arc;
use std::convert::TryInto;

use argon2::{Argon2, Params};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use rand::RngCore;
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;
use zeroize::Zeroize;

use dashmap::DashMap;
use rayon::prelude::*;
use once_cell::sync::Lazy;
use std::collections::HashSet;

const KEY_LENGTH: usize = 512;
const SALT_LEN: usize = 32;
type HmacSha256 = Hmac<Sha256>;

static ROW_CACHE: Lazy<DashMap<u128, Arc<[u8; 256]>>> = Lazy::new(|| DashMap::new());

#[inline(always)]
fn table_row_cache_key(seed: u64, i: u32, j: u32) -> u128 {
    ((seed as u128) << 64) | ((i as u128) << 32) | (j as u128)
}

fn derive_subkeys_with_salt_and_seed(
    key1: &Secret<Vec<u8>>,
    key2: &Secret<Vec<u8>>,
    salt: &[u8],
    seed_bytes: &[u8; 8],
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let k1 = key1.expose_secret();
    let k2 = key2.expose_secret();
    let mut ikm = Vec::with_capacity(k1.len() + k2.len() + seed_bytes.len());
    ikm.extend_from_slice(k1);
    ikm.extend_from_slice(k2);
    ikm.extend_from_slice(seed_bytes);
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut xor_key = vec![0u8; KEY_LENGTH];
    hk.expand(b"xor_key", &mut xor_key).expect("hkdf xor");
    let mut rot_key = vec![0u8; KEY_LENGTH];
    hk.expand(b"rot_key", &mut rot_key).expect("hkdf rot");
    let mut hmac_key = vec![0u8; 32];
    hk.expand(b"hmac_key_seeded", &mut hmac_key).expect("hkdf hmac seeded");
    ikm.zeroize();
    (xor_key, rot_key, hmac_key)
}

fn derive_hmac_key_no_seed(
    key1: &Secret<Vec<u8>>,
    key2: &Secret<Vec<u8>>,
    salt: &[u8],
) -> Vec<u8> {
    let k1 = key1.expose_secret();
    let k2 = key2.expose_secret();
    let mut ikm = Vec::with_capacity(k1.len() + k2.len());
    ikm.extend_from_slice(k1);
    ikm.extend_from_slice(k2);
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut hmac_key = vec![0u8; 32];
    hk.expand(b"hmac_key", &mut hmac_key).expect("hkdf hmac");
    ikm.zeroize();
    hmac_key
}

fn gene3_with_salt(seed: &[u8], salt: &[u8]) -> Secret<Vec<u8>> {
    let params = Params::new(65536, 3, 1, None).expect("params");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = vec![0u8; 64];
    argon2.hash_password_into(seed, salt, &mut out).expect("argon2");
    let hk = Hkdf::<Sha256>::new(Some(salt), &out);
    let mut okm = vec![0u8; KEY_LENGTH];
    hk.expand(b"key_expand", &mut okm).expect("hkdf expand");
    out.zeroize();
    Secret::new(okm)
}

fn escape_zero_bytes(input: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 2);
    for b in input {
        if b == 0 {
            out.push(0u8);
            out.push(0xFFu8);
        } else {
            out.push(b);
        }
    }
    out
}

fn unescape_and_remove_stars(v: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len());
    let mut i = 0usize;
    while i < v.len() {
        if v[i] == 0 {
            if i + 1 < v.len() {
                let nxt = v[i + 1];
                if nxt == 0 {
                    i += 2;
                    continue;
                } else if nxt == 0xFF {
                    out.push(0u8);
                    i += 2;
                    continue;
                } else {
                    out.push(v[i]);
                    i += 1;
                    continue;
                }
            } else {
                i += 1;
                continue;
            }
        } else {
            out.push(v[i]);
            i += 1;
        }
    }
    out
}

fn insert_random_stars_escaped(word: Vec<u8>) -> Vec<u8> {
    if word.is_empty() {
        return word;
    }
    let mut escaped = escape_zero_bytes(word);
    let min = (escaped.len() / 2) as u64;
    let max = escaped.len() as u64;
    let mut rng = rand::rng();
    let range = if max > min { max - min + 1 } else { 1 };
    let offset = if range == 0 { 0 } else { rng.next_u64() % range };
    let num_stars = (min + offset) as usize;
    let mut indices: Vec<usize> = (0..num_stars)
        .into_par_iter()
        .map(|_| {
            let mut local = [0u8; 8];
            let mut r = rand::rng();
            r.fill_bytes(&mut local);
            (u64::from_le_bytes(local) as usize) % (escaped.len() + 1)
        })
        .collect();
    indices.par_sort_unstable_by(|a, b| b.cmp(a));
    for idx in indices {
        let pos = if idx <= escaped.len() { idx } else { escaped.len() };
        escaped.insert(pos, 0u8);
        escaped.insert(pos + 1, 0u8);
    }
    escaped
}

fn hkdf_ctr_expand(key: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(None, key);
    let mut generated = 0usize;
    let mut counter: u32 = 0;
    while generated < out.len() {
        let mut info = [0u8; 6];
        info[..4].copy_from_slice(&counter.to_le_bytes());
        info[4..].copy_from_slice(b"ks");
        let mut block = [0u8; 32];
        hk.expand(&info, &mut block).expect("hkdf expand ctr");
        let take = std::cmp::min(block.len(), out.len() - generated);
        out[generated..generated + take].copy_from_slice(&block[..take]);
        generated += take;
        counter = counter.wrapping_add(1);
    }
}

fn generate_row_direct(salt: &[u8], seed: u64, table_2d: usize, row: usize) -> [u8; 256] {
    let mut ikm = Vec::with_capacity(24);
    ikm.extend_from_slice(&seed.to_le_bytes());
    ikm.extend_from_slice(&(table_2d as u64).to_le_bytes());
    ikm.extend_from_slice(&(row as u64).to_le_bytes());
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut randbuf = vec![0u8; 8 * 256];
    hk.expand(b"perm_row", &mut randbuf).expect("hkdf perm");
    let mut perm_vec: Vec<u8> = (0u8..=255u8).collect();
    for k_idx in (1usize..=255usize).rev() {
        let base = k_idx * 8;
        let mut w = [0u8; 8];
        w.copy_from_slice(&randbuf[base..base + 8]);
        let r = u64::from_le_bytes(w);
        let jrand = (r as usize) % (k_idx + 1);
        perm_vec.swap(k_idx, jrand);
    }
    let perm: [u8; 256] = perm_vec.try_into().expect("perm length");
    ikm.zeroize();
    randbuf.zeroize();
    perm
}

fn get_table_row(salt: &[u8], seed: u64, table_2d: usize, row: usize) -> Arc<[u8; 256]> {
    let key = table_row_cache_key(seed, table_2d as u32, row as u32);
    if let Some(v) = ROW_CACHE.get(&key) {
        return v.clone();
    }
    let perm = generate_row_direct(salt, seed, table_2d, row);
    let arc = Arc::new(perm);
    ROW_CACHE.insert(key, arc.clone());
    arc
}

fn shift_bits_with_rot_key_par(mut buf: Vec<u8>, rot_key: &[u8]) -> Vec<u8> {
    const CHUNK_SIZE: usize = 1024;
    buf.par_chunks_mut(CHUNK_SIZE)
        .enumerate()
        .for_each(|(chunk_idx, chunk)| {
            let base_idx = chunk_idx * CHUNK_SIZE;
            chunk.iter_mut().enumerate().for_each(|(i, byte)| {
                let idx = base_idx + i;
                let amount = (rot_key[idx % rot_key.len()] & 0x07) as u32;
                *byte = byte.rotate_left(amount);
            });
        });
    buf
}

fn unshift_bits_with_rot_key_par(mut buf: Vec<u8>, rot_key: &[u8]) -> Vec<u8> {
    const CHUNK_SIZE: usize = 1024;
    buf.par_chunks_mut(CHUNK_SIZE)
        .enumerate()
        .for_each(|(chunk_idx, chunk)| {
            let base_idx = chunk_idx * CHUNK_SIZE;
            chunk.iter_mut().enumerate().for_each(|(i, byte)| {
                let idx = base_idx + i;
                let amount = (rot_key[idx % rot_key.len()] & 0x07) as u32;
                *byte = byte.rotate_right(amount);
            });
        });
    buf
}

fn compute_hmac(hmac_key: &[u8], header: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(hmac_key).expect("hmac key");
    mac.update(header);
    mac.update(ciphertext);
    mac.finalize().into_bytes().to_vec()
}

fn verify_hmac(hmac_key: &[u8], header: &[u8], ciphertext: &[u8], tag: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(hmac_key).expect("hmac key");
    mac.update(header);
    mac.update(ciphertext);
    mac.verify_slice(tag).is_ok()
}

pub(crate) fn encrypt3(
    plain_text: Vec<u8>,
    key1: &Secret<Vec<u8>>,
    key2: &Secret<Vec<u8>>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if plain_text.is_empty() {
        return Ok(Vec::new());
    }
    let mut salt = [0u8; SALT_LEN];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut salt);
    let mut seed_bytes = [0u8; 8];
    rng.fill_bytes(&mut seed_bytes);
    let (xor_key, rot_key, _hmac_key_seeded) =
        derive_subkeys_with_salt_and_seed(key1, key2, &salt, &seed_bytes);
    let hmac_key = derive_hmac_key_no_seed(key1, key2, &salt);
    let escaped = plain_text;
    let (characters, key_chars) = rayon::join(
        || {
            let mut characters: Vec<u8> = (0u16..=255u16).map(|x| x as u8).collect();
            let hk = Hkdf::<Sha256>::new(Some(&salt), &seed_bytes);
            let mut randbuf = vec![0u8; 8 * 256];
            hk.expand(b"chars_perm", &mut randbuf).expect("chars perm");
            for k_idx in (1usize..=255usize).rev() {
                let base = k_idx * 8;
                let mut w = [0u8; 8];
                w.copy_from_slice(&randbuf[base..base + 8]);
                let r = u64::from_le_bytes(w);
                let jrand = (r as usize) % (k_idx + 1);
                characters.swap(k_idx, jrand);
            }
            randbuf.zeroize();
            characters
        },
        || {
            let key1_bytes = key1.expose_secret();
            let key2_bytes = key2.expose_secret();
            rayon::join(
                || key1_bytes.par_iter().map(|&c| c as usize % 256).collect::<Vec<_>>(),
                || key2_bytes.par_iter().map(|&c| c as usize % 256).collect::<Vec<_>>(),
            )
        },
    );
    let mut char_positions = [0usize; 256];
    for (i, &c) in characters.iter().enumerate() {
        char_positions[c as usize] = i;
    }
    let (key1_chars, key2_chars) = key_chars;
    let pairs: Vec<_> = escaped
        .par_iter()
        .enumerate()
        .map(|(i, &_c)| {
            let table_2d = key1_chars[i % key1_chars.len()] % 256;
            let row = key2_chars[i % key2_chars.len()] % 256;
            (table_2d, row)
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    prefetch_table_rows(&salt, u64::from_le_bytes(seed_bytes), &pairs);
    let mut keystream = vec![0u8; escaped.len()];
    hkdf_ctr_expand(&xor_key, &mut keystream);
    let cipher_text: Vec<u8> = escaped
        .par_chunks(256)
        .enumerate()
        .flat_map(|(chunk_idx, chunk)| {
            let base_idx = chunk_idx * 256;
            chunk
                .par_iter()
                .enumerate()
                .map(|(i, &c)| {
                    let global_idx = base_idx + i;
                    let table_2d = key1_chars[global_idx % key1_chars.len()] % 256;
                    let row = key2_chars[global_idx % key2_chars.len()] % 256;
                    let row_vec = get_table_row(&salt, u64::from_le_bytes(seed_bytes), table_2d, row);
                    let col = char_positions[c as usize];
                    let mut val = row_vec[col];
                    val ^= keystream[global_idx % keystream.len()];
                    val
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let cipher_text = shift_bits_with_rot_key_par(cipher_text, &rot_key);
    let mut header = Vec::with_capacity(SALT_LEN + 8);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&seed_bytes);
    let tag = compute_hmac(&hmac_key, &header, &cipher_text);
    let mut package = header;
    package.extend_from_slice(&cipher_text);
    package.extend_from_slice(&tag);
    let mut xor_key = xor_key;
    let mut rot_key = rot_key;
    let mut hmac_key_mut = hmac_key;
    xor_key.zeroize();
    rot_key.zeroize();
    hmac_key_mut.zeroize();
    Ok(package)
}

pub(crate) fn decrypt3(
    package: Vec<u8>,
    key1: &Secret<Vec<u8>>,
    key2: &Secret<Vec<u8>>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if package.len() < SALT_LEN + 8 + 32 {
        return Err("ciphertext too short".into());
    }
    let salt = &package[..SALT_LEN];
    let seed_bytes_slice = &package[SALT_LEN..SALT_LEN + 8];
    let seed_bytes: [u8; 8] = seed_bytes_slice.try_into().unwrap();
    let cipher_and_tag = &package[SALT_LEN + 8..];
    if cipher_and_tag.len() < 32 {
        return Err("ciphertext too short (no tag)".into());
    }
    let tag_pos = cipher_and_tag.len() - 32;
    let cipher_text = &cipher_and_tag[..tag_pos];
    let tag = &cipher_and_tag[tag_pos..];
    let (xor_key, rot_key, _hmac_key_seeded) =
        derive_subkeys_with_salt_and_seed(key1, key2, salt, &seed_bytes);
    let hmac_key = derive_hmac_key_no_seed(key1, key2, salt);
    let header = &package[..SALT_LEN + 8];
    if !verify_hmac(&hmac_key, header, cipher_text, tag) {
        return Err("HMAC verification failed".into());
    }
    let (characters, key_chars_and_keystream) = rayon::join(
        || {
            let mut characters: Vec<u8> = (0u8..=255u8).collect();
            let hk = Hkdf::<Sha256>::new(Some(salt), &seed_bytes);
            let mut randbuf = vec![0u8; 8 * 256];
            hk.expand(b"chars_perm", &mut randbuf).expect("chars perm");
            for k_idx in (1usize..=255usize).rev() {
                let base = k_idx * 8;
                let mut w = [0u8; 8];
                w.copy_from_slice(&randbuf[base..base + 8]);
                let r = u64::from_le_bytes(w);
                let jrand = (r as usize) % (k_idx + 1);
                characters.swap(k_idx, jrand);
            }
            randbuf.zeroize();
            characters
        },
        || {
            let (key_chars, keystream) = rayon::join(
                || {
                    let key1_bytes = key1.expose_secret();
                    let key2_bytes = key2.expose_secret();
                    rayon::join(
                        || key1_bytes.par_iter().map(|&c| c as usize % 256).collect::<Vec<_>>(),
                        || key2_bytes.par_iter().map(|&c| c as usize % 256).collect::<Vec<_>>(),
                    )
                },
                || {
                    let mut keystream = vec![0u8; cipher_text.len()];
                    hkdf_ctr_expand(&xor_key, &mut keystream);
                    keystream
                },
            );
            (key_chars, keystream)
        },
    );
    let (key_chars, keystream) = key_chars_and_keystream;
    let (key1_chars, key2_chars) = key_chars;
    let pairset: HashSet<(usize, usize)> = (0..cipher_text.len())
        .into_par_iter()
        .map(|i| {
            let table_2d = key1_chars[i % key1_chars.len()] % 256;
            let row = key2_chars[i % key2_chars.len()] % 256;
            (table_2d, row)
        })
        .collect();
    let pairs: Vec<_> = pairset.into_iter().collect();
    prefetch_table_rows(salt, u64::from_le_bytes(seed_bytes), &pairs);
    let mut middle = unshift_bits_with_rot_key_par(cipher_text.to_vec(), &rot_key);
    middle
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, byte)| *byte ^= keystream[i % keystream.len()]);
    const CHUNK: usize = 256;
    let plain_with_stars: Vec<u8> = middle
        .par_chunks(CHUNK)
        .enumerate()
        .flat_map(|(chunk_idx, chunk)| {
            let base_idx = chunk_idx * CHUNK;
            chunk
                .par_iter()
                .enumerate()
                .map(|(i, &c)| {
                    let global_idx = base_idx + i;
                    let table_2d = key1_chars[global_idx % key1_chars.len()] % 256;
                    let row = key2_chars[global_idx % key2_chars.len()] % 256;
                    let row_vec = get_table_row(salt, u64::from_le_bytes(seed_bytes), table_2d, row);
                    if let Some(col) = row_vec.iter().position(|x| *x == c) {
                        if col < characters.len() {
                            characters[col]
                        } else {
                            c
                        }
                    } else {
                        c
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let mut xor_k = xor_key;
    let mut rot_k = rot_key;
    let mut hmac_k = hmac_key;
    xor_k.zeroize();
    rot_k.zeroize();
    hmac_k.zeroize();
    Ok(plain_with_stars)
}

fn prefetch_table_rows(salt: &[u8], seed: u64, pairs: &[(usize, usize)]) {
    if pairs.is_empty() {
        return;
    }
    let mut needed_keys = std::collections::HashSet::with_capacity(pairs.len());
    for &(i, j) in pairs {
        needed_keys.insert(table_row_cache_key(seed, i as u32, j as u32));
    }
    needed_keys.retain(|k| !ROW_CACHE.contains_key(k));
    if needed_keys.is_empty() {
        return;
    }
    let to_generate: Vec<(u128, usize, usize)> = needed_keys
        .into_iter()
        .map(|k| {
            let i = ((k >> 32) & 0xffffffff) as u32 as usize;
            let j = (k & 0xffffffff) as u32 as usize;
            (k, i, j)
        })
        .collect();
    let generated: Vec<(u128, Arc<[u8; 256]>)> = to_generate
        .into_par_iter()
        .map(|(k, i, j)| {
            let perm = generate_row_direct(salt, seed, i, j);
            (k, Arc::new(perm))
        })
        .collect();
    for (k, arc) in generated {
        ROW_CACHE.insert(k, arc);
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let original_data = b"ce soir je sors ne t'inquiete pas je rentre bientot".to_vec();
    let pass = b"LeMOTdePAsse34!";
    const ROUND: usize = 3;
    let mut run_salt = [0u8; SALT_LEN];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut run_salt);
    let key1 = gene3_with_salt(pass, &run_salt);
    let liste: Vec<String> = (0..ROUND)
        .into_par_iter()
        .map(|_| {
            let mut rnum = [0u8; 8];
            let mut r = rand::rng();
            r.fill_bytes(&mut rnum);
            u64::from_le_bytes(rnum).to_string()
        })
        .collect();
    let mut chif = insert_random_stars_escaped(original_data.clone());
    let start = std::time::Instant::now();
    for element in liste.iter() {
        let key2 = gene3_with_salt(element.as_bytes(), &run_salt);
        chif = encrypt3(chif, &key1, &key2)?;
    }
    println!("enc time: {:?}", start.elapsed());
    let start = std::time::Instant::now();
    for element in liste.iter().rev() {
        let key2 = gene3_with_salt(element.as_bytes(), &run_salt);
        chif = decrypt3(chif, &key1, &key2)?;
    }
    println!("dec time: {:?}", start.elapsed());
    let chif_stripped = unescape_and_remove_stars(chif);
    println!("{}", String::from_utf8_lossy(&chif_stripped));
    assert_eq!(original_data, chif_stripped);
    Ok(())
}
