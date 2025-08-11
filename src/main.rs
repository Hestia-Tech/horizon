use std::error::Error;
use std::sync::Arc;

use argon2::{Argon2, Params};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use rand::{rng, RngCore};
use hashbrown::HashMap;
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;
use zeroize::Zeroize;

use std::collections::HashSet;
use rayon::prelude::*;
use std::sync::RwLock;

const KEY_LENGTH: usize = 512;
const SALT_LEN: usize = 16;
type HmacSha256 = Hmac<Sha256>;


static TABLE3_ROW_CACHE: once_cell::sync::Lazy<RwLock<HashMap<u128, Arc<Vec<u8>>>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(HashMap::new()));

#[inline(always)]
fn table_row_cache_key(seed: u64, i: u32, j: u32) -> u128 {
    ((seed as u128) << 64) | ((i as u128) << 32) | (j as u128)
}

fn derive_subkeys_with_salt(
    key1: &Secret<Vec<u8>>,
    key2: &Secret<Vec<u8>>,
    salt: &[u8],
) -> (u64, Vec<u8>, Vec<u8>, Vec<u8>) {
    let k1 = key1.expose_secret();
    let k2 = key2.expose_secret();


    let mut ikm = Vec::with_capacity(k1.len() + k2.len());
    ikm.extend_from_slice(k1);
    ikm.extend_from_slice(k2);

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);

    let (seed_bytes, keys) = rayon::join(
        || {
            let mut seed_bytes = [0u8; 8];
            hk.expand(b"seed", &mut seed_bytes).expect("HKDF expand seed");
            seed_bytes
        },
        || {
            let (xor_key, rest) = rayon::join(
                || {
                    let mut xor_key = vec![0u8; KEY_LENGTH];
                    hk.expand(b"xor_key", &mut xor_key).expect("HKDF expand xor");
                    xor_key
                },
                || {
                    let (rot_key, hmac_key) = rayon::join(
                        || {
                            let mut rot_key = vec![0u8; KEY_LENGTH];
                            hk.expand(b"rot_key", &mut rot_key).expect("HKDF expand rot");
                            rot_key
                        },
                        || {
                            let mut hmac_key = vec![0u8; 32];
                            hk.expand(b"hmac_key", &mut hmac_key).expect("HKDF expand hmac");
                            hmac_key
                        }
                    );
                    (rot_key, hmac_key)
                }
            );
            (xor_key, rest.0, rest.1)
        }
    );

    let seed_u64 = u64::from_le_bytes(seed_bytes);

    ikm.zeroize();

    (seed_u64, keys.0, keys.1, keys.2)
}


thread_local! {
    static ARGON2_INSTANCE: Argon2<'static> = {
        let params = Params::new(65536, 3, 1, None).expect("valid params");
        Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
    };
}

fn gene3_with_salt(seed: &[u8], salt: &[u8]) -> Secret<Vec<u8>> {
    ARGON2_INSTANCE.with(|argon2| {
        let mut out = vec![0u8; 64];
        argon2
            .hash_password_into(seed, salt, &mut out)
            .expect("Argon2 hashing failed");

        let hk = Hkdf::<Sha256>::new(Some(salt), &out);
        let mut okm = vec![0u8; KEY_LENGTH];
        hk.expand(b"key_expand", &mut okm).expect("HKDF expand failed");

        out.zeroize();
        Secret::new(okm)
    })
}

fn insert_random_stars(word: Vec<u8>) -> Vec<u8> {
    if word.is_empty() {
        return word;
    }

    let min = (word.len() / 2) as u64;
    let max = word.len() as u64;
    let mut rng = rng();
    let range = if max > min { max - min + 1 } else { 1 };
    let offset = if range == 0 { 0 } else { rng.next_u64() % range };
    let num_stars = (min + offset) as usize;

    let mut indices: Vec<usize> = (0..num_stars)
        .into_par_iter()
        .map(|_| {
            let mut local_rng = rand::rng();
            (local_rng.next_u64() as usize) % (word.len() + 1)
        })
        .collect();

    indices.par_sort_unstable_by(|a, b| b.cmp(a));

    let mut result = word;
    for idx in indices {
        let pos = if idx <= result.len() { idx } else { result.len() };
        result.insert(pos, 0u8);
    }

    result
}

fn generate_row_direct(salt: &[u8], seed: u64, table_2d: usize, row: usize) -> Vec<u8> {
    let mut ikm = Vec::with_capacity(24);
    ikm.extend_from_slice(&seed.to_le_bytes());
    ikm.extend_from_slice(&(table_2d as u64).to_le_bytes());
    ikm.extend_from_slice(&(row as u64).to_le_bytes());

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);

    let mut randbuf = vec![0u64; 256]; // Directement en u64 pour éviter les conversions
    let randbuf_u8 = unsafe {
        std::slice::from_raw_parts_mut(randbuf.as_mut_ptr() as *mut u8, randbuf.len() * 8)
    };
    hk.expand(b"perm_row", randbuf_u8).expect("HKDF expand perm_row");

    let mut perm: Vec<u8> = (0u8..=255u8).collect();

    for (k_idx, &r) in randbuf.iter().enumerate().take(255).rev() {
        let jrand = (r as usize) % (k_idx + 1);
        perm.swap(k_idx, jrand);
    }

    ikm.zeroize();
    perm
}

fn get_table_row(salt: &[u8], seed: u64, table_2d: usize, row: usize) -> Arc<Vec<u8>> {
    let key = table_row_cache_key(seed, table_2d as u32, row as u32);

    {
        let cache = TABLE3_ROW_CACHE.read().unwrap();
        if let Some(v) = cache.get(&key) {
            return Arc::clone(v);
        }
    }

    // Génération et insertion atomique
    let perm = generate_row_direct(salt, seed, table_2d, row);
    let arc = Arc::new(perm);

    {
        let mut cache = TABLE3_ROW_CACHE.write().unwrap();
        cache.entry(key).or_insert_with(|| Arc::clone(&arc));
    }

    arc
}

fn prefetch_table_rows(salt: &[u8], seed: u64, pairs: &[(usize, usize)]) {
    if pairs.is_empty() {
        return;
    }

    let mut needed_keys = HashSet::with_capacity(pairs.len());
    for &(i, j) in pairs {
        needed_keys.insert(table_row_cache_key(seed, i as u32, j as u32));
    }

    {
        let cache = TABLE3_ROW_CACHE.read().unwrap();
        needed_keys.retain(|k| !cache.contains_key(k));
    }

    if needed_keys.is_empty() {
        return;
    }

    let to_generate: Vec<_> = needed_keys
        .into_iter()
        .map(|k| {
            let i = ((k >> 32) & 0xffffffff) as u32 as usize;
            let j = (k & 0xffffffff) as u32 as usize;
            (k, i, j)
        })
        .collect();


    const CHUNK_SIZE: usize = 32;
    let generated: Vec<_> = to_generate
        .par_chunks(CHUNK_SIZE)
        .flat_map(|chunk| {
            chunk.iter().map(|(k, i, j)| {
                let perm = generate_row_direct(salt, seed, *i, *j);
                (*k, Arc::new(perm))
            }).collect::<Vec<_>>()
        })
        .collect();

    {
        let mut cache = TABLE3_ROW_CACHE.write().unwrap();
        cache.reserve(generated.len()); // Pré-allocation
        for (k, arc) in generated {
            cache.entry(k).or_insert(arc);
        }
    }
}

#[inline(always)]
fn shift_bits_with_rot_key_par(mut buf: Vec<u8>, rot_key: &[u8]) -> Vec<u8> {
    // Traitement par chunks pour améliorer la localité des données
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

#[inline(always)]
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

#[inline(always)]
fn compute_hmac(hmac_key: &[u8], header: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC key size");
    mac.update(header);
    mac.update(ciphertext);
    mac.finalize().into_bytes().to_vec()
}

#[inline(always)]
fn verify_hmac(hmac_key: &[u8], header: &[u8], ciphertext: &[u8], tag: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC key size");
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

    let mut salt = vec![0u8; SALT_LEN];
    rng().fill_bytes(&mut salt);
    let (seed_u64, mut xor_key, mut rot_key, mut hmac_key) = derive_subkeys_with_salt(key1, key2, &salt);

    let (characters, key_chars) = rayon::join(
        || {
            let mut characters: Vec<u8> = (0u8..=255u8).collect();
            let seed_bytes = seed_u64.to_le_bytes();
            let hk = Hkdf::<Sha256>::new(Some(&salt), &seed_bytes);
            let mut randbuf = vec![0u64; 256];
            let randbuf_u8 = unsafe {
                std::slice::from_raw_parts_mut(randbuf.as_mut_ptr() as *mut u8, randbuf.len() * 8)
            };
            hk.expand(b"chars_perm", randbuf_u8).unwrap();
            for (k_idx, &r) in randbuf.iter().enumerate().take(255).rev() {
                let jrand = (r as usize) % (k_idx + 1);
                characters.swap(k_idx, jrand);
            }
            characters
        },
        || {
            let key1_bytes = key1.expose_secret();
            let key2_bytes = key2.expose_secret();
            rayon::join(
                || key1_bytes.iter().map(|&c| c as usize % 256).collect::<Vec<_>>(),
                || key2_bytes.iter().map(|&c| c as usize % 256).collect::<Vec<_>>()
            )
        },
    );

    let char_positions: HashMap<_, _> = characters.iter()
        .enumerate()
        .map(|(i, &c)| (c, i))
        .collect();

    let (key1_chars, key2_chars) = key_chars;

    let pairs: Vec<_> = plain_text
        .par_iter()
        .enumerate()
        .map(|(i, _)| {
            let table_2d = key1_chars[i % key1_chars.len()] % 256;
            let row = key2_chars[i % key2_chars.len()] % 256;
            (table_2d, row)
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    prefetch_table_rows(&salt, seed_u64, &pairs);

    let mut keystream = vec![0u8; plain_text.len()];
    {
        let hk = Hkdf::<Sha256>::new(None, &xor_key);
        hk.expand(b"ks", &mut keystream).unwrap();
    }

    let cipher_text: Vec<u8> = plain_text
        .par_chunks(256) // Réduction de la taille des blocs pour une meilleure utilisation du cache
        .enumerate()
        .flat_map(|(chunk_idx, chunk)| {
            let base_idx = chunk_idx * 256;
            chunk.par_iter().enumerate().map(|(i, &c)| {
                let global_idx = base_idx + i;
                let table_2d = key1_chars[global_idx % key1_chars.len()] % 256;
                let row = key2_chars[global_idx % key2_chars.len()] % 256;

                let row_vec = get_table_row(&salt, seed_u64, table_2d, row);

                let mut val = if let Some(&col) = char_positions.get(&c) {
                    if col < row_vec.len() {
                        row_vec[col]
                    } else {
                        characters[col]
                    }
                } else {
                    c
                };
                val ^= keystream[global_idx % keystream.len()];
                val
            }).collect::<Vec<_>>()
        })
        .collect();

    let cipher_text = shift_bits_with_rot_key_par(cipher_text, &rot_key);

    let mut header = Vec::with_capacity(SALT_LEN + 8);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&seed_u64.to_le_bytes());
    let tag = compute_hmac(&hmac_key, &header, &cipher_text);

    let mut package = header;
    package.extend_from_slice(&cipher_text);
    package.extend_from_slice(&tag);

    xor_key.zeroize();
    rot_key.zeroize();
    hmac_key.zeroize();

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
    let seed_bytes = &package[SALT_LEN..SALT_LEN + 8];
    let cipher_and_tag = &package[SALT_LEN + 8..];

    if cipher_and_tag.len() < 32 {
        return Err("ciphertext too short (no tag)".into());
    }

    let tag_pos = cipher_and_tag.len() - 32;
    let cipher_text = &cipher_and_tag[..tag_pos];
    let tag = &cipher_and_tag[tag_pos..];

    let (seed_u64_from_keys, mut xor_key, mut rot_key, mut hmac_key) =
        derive_subkeys_with_salt(key1, key2, salt);
    let seed_from_header = u64::from_le_bytes(seed_bytes.try_into().unwrap());

    if seed_from_header != seed_u64_from_keys {
        return Err("seed mismatch (keys/salt)".into());
    }

    let seed_u64 = seed_from_header;

    let header = &package[..SALT_LEN + 8];
    if !verify_hmac(&hmac_key, header, cipher_text, tag) {
        return Err("HMAC verification failed".into());
    }

    let (characters, key_chars_and_keystream) = rayon::join(
        || {
            let mut characters: Vec<u8> = (0u8..=255u8).collect();
            let seed_b = seed_u64.to_le_bytes();
            let hk = Hkdf::<Sha256>::new(Some(salt), &seed_b);
            let mut randbuf = vec![0u64; 256];
            let randbuf_u8 = unsafe {
                std::slice::from_raw_parts_mut(randbuf.as_mut_ptr() as *mut u8, randbuf.len() * 8)
            };
            hk.expand(b"chars_perm", randbuf_u8).unwrap();
            for (k_idx, &r) in randbuf.iter().enumerate().take(255).rev() {
                let jrand = (r as usize) % (k_idx + 1);
                characters.swap(k_idx, jrand);
            }
            characters
        },
        || {
            let (key_chars, keystream) = rayon::join(
                || {
                    let key1_bytes = key1.expose_secret();
                    let key2_bytes = key2.expose_secret();
                    rayon::join(
                        || key1_bytes.iter().map(|&c| c as usize % 256).collect::<Vec<_>>(),
                        || key2_bytes.iter().map(|&c| c as usize % 256).collect::<Vec<_>>()
                    )
                },
                || {
                    let mut keystream = vec![0u8; cipher_text.len()];
                    let hk = Hkdf::<Sha256>::new(None, &xor_key);
                    hk.expand(b"ks", &mut keystream).unwrap();
                    keystream
                }
            );
            (key_chars, keystream)
        }
    );

    let ((key1_chars, key2_chars), keystream) = key_chars_and_keystream;

    let pairset: HashSet<(usize, usize)> = (0..cipher_text.len())
        .into_par_iter()
        .map(|i| {
            let table_2d = key1_chars[i % key1_chars.len()] % 256;
            let row = key2_chars[i % key2_chars.len()] % 256;
            (table_2d, row)
        })
        .collect();

    let pairs: Vec<_> = pairset.into_iter().collect();
    prefetch_table_rows(salt, seed_u64, &pairs);

    let mut middle = unshift_bits_with_rot_key_par(cipher_text.to_vec(), &rot_key);

    middle.par_iter_mut()
        .enumerate()
        .for_each(|(i, byte)| *byte ^= keystream[i % keystream.len()]);

    const DECRYPT_CHUNK_SIZE: usize = 256;
    let plain_with_stars: Vec<u8> = middle
        .par_chunks(DECRYPT_CHUNK_SIZE)
        .enumerate()
        .flat_map(|(chunk_idx, chunk)| {
            let base_idx = chunk_idx * DECRYPT_CHUNK_SIZE;
            chunk.par_iter().enumerate().map(|(i, &c)| {
                let global_idx = base_idx + i;
                let table_2d = key1_chars[global_idx % key1_chars.len()] % 256;
                let row = key2_chars[global_idx % key2_chars.len()] % 256;

                let row_vec = get_table_row(salt, seed_u64, table_2d, row);

                if let Some(col) = row_vec.iter().position(|x| *x == c) {
                    if col < characters.len() {
                        characters[col]
                    } else {
                        c
                    }
                } else {
                    c
                }
            }).collect::<Vec<_>>()
        })
        .collect();

    xor_key.zeroize();
    rot_key.zeroize();
    hmac_key.zeroize();

    Ok(plain_with_stars)
}

fn main() -> Result<(), Box<dyn Error>> {
    let original_data = b"ce soir je sors ne t'inquiete pas je rentre bientot".to_vec();
    let pass = b"LeMOTdePAsse34!";

    const ROUND: usize = 6;

    // Salt de run avec meilleure entropie
    let mut run_salt = vec![0u8; SALT_LEN];
    rng().fill_bytes(&mut run_salt);
    let key1 = gene3_with_salt(pass, &run_salt);

    // Génération parallèle des clés
    let liste: Vec<String> = (0..ROUND)
        .into_par_iter()
        .map(|_| {
            let mut rng = rand::rng();
            let mut rnum = [0u8; 8];
            rng.fill_bytes(&mut rnum);
            u64::from_le_bytes(rnum).to_string()
        })
        .collect();

    // Insertion des étoiles une seule fois
    let mut chif = insert_random_stars(original_data.clone());

    // Chiffrement séquentiel (nécessaire pour préserver la chaîne)
    let start = std::time::Instant::now();
    for (index, element) in liste.iter().enumerate() {
        let key2 = gene3_with_salt(element.as_bytes(), &run_salt);
        chif = encrypt3(chif, &key1, &key2)?;
        println!("{} Chiffré (len={})", index, chif.len());
    }
    println!("Chiffrement total: {:?}", start.elapsed());

    println!("-----------------------------------------");

    // Déchiffrement en ordre inverse
    let start = std::time::Instant::now();
    for element in liste.iter().rev() {
        let key2 = gene3_with_salt(element.as_bytes(), &run_salt);
        chif = decrypt3(chif, &key1, &key2)?;
        println!("Déchiffré étape (len={})", chif.len());
    }
    println!("Déchiffrement total: {:?}", start.elapsed());

    // Suppression des zéros insérés
    let chif_stripped: Vec<u8> = chif.into_par_iter().filter(|&b| b != 0u8).collect();
    println!("Après suppression des 0 : len={}", chif_stripped.len());
    println!(
        "Texte final (utf8 lossy): {}",
        String::from_utf8_lossy(&chif_stripped)
    );

    assert_eq!(original_data, chif_stripped);
    println!("Roundtrip OK.");

    Ok(())
}
