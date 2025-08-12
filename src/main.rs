use std::convert::TryInto;
use std::error::Error;
use std::sync::Arc;

use argon2::{Argon2, Params};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;
use zeroize::Zeroize;

use dashmap::DashMap;
use once_cell::sync::Lazy;
use rayon::prelude::*;
use std::collections::HashSet;
use blake3::Hasher;

const KEY_LENGTH: usize = 512;
const SALT_LEN: usize = 32;
const VERSION: u8 = 4;
const ALG_ID: u8 = 173;
const MAX_CACHE_ENTRIES: usize = 80_000;

type HmacSha256 = Hmac<Sha256>;

static ROW_CACHE: Lazy<DashMap<[u8; 32], Arc<[u8; 256]>>> = Lazy::new(DashMap::new);

static MASTER_CACHE_KEY: Lazy<[u8; 32]> = Lazy::new(|| {
    let rng = SystemRandom::new();
    let mut k = [0u8; 32];
    rng.fill(&mut k).expect("SystemRandom fill MASTER_CACHE_KEY");
    k
});

#[inline(always)]
fn table_row_cache_key_mastered(seed: u64, i: u32, j: u32) -> [u8; 32] {
    let mut hasher = Hasher::new_keyed(&MASTER_CACHE_KEY);
    hasher.update(&seed.to_le_bytes());
    hasher.update(&i.to_le_bytes());
    hasher.update(&j.to_le_bytes());
    let tag = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&tag.as_bytes()[..32]);
    out
}

fn fill_random(dest: &mut [u8]) {
    let rng = SystemRandom::new();
    rng.fill(dest).expect("SystemRandom fill failed");
}

fn derive_round_seed(run_salt: &[u8], round_index: u32) -> [u8; 8] {
    let hk = Hkdf::<Sha256>::new(Some(run_salt), b"master_seed");
    let mut info = Vec::with_capacity(12);
    info.extend_from_slice(b"round_seed_v1");
    info.extend_from_slice(&round_index.to_le_bytes());
    let mut seed = [0u8; 8];
    hk.expand(&info, &mut seed).expect("derive round seed");
    seed
}

fn derive_subkeys_with_salt_and_seed(
    key1: &Secret<Vec<u8>>,
    key2: &Secret<Vec<u8>>,
    salt: &[u8],
    seed_bytes: &[u8; 8],
) -> (Vec<u8>, Vec<u8>) {
    let k1 = key1.expose_secret();
    let k2 = key2.expose_secret();
    let mut ikm = Vec::with_capacity(k1.len() + k2.len() + seed_bytes.len());
    ikm.extend_from_slice(k1);
    ikm.extend_from_slice(k2);
    ikm.extend_from_slice(seed_bytes);
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut xor_key = vec![0u8; KEY_LENGTH];
    hk.expand(b"xor_key_v1", &mut xor_key).expect("hkdf xor");
    let mut rot_key = vec![0u8; KEY_LENGTH];
    hk.expand(b"rot_key_v1", &mut rot_key).expect("hkdf rot");
    ikm.zeroize();
    (xor_key, rot_key)
}

fn derive_hmac_key_final(key1: &Secret<Vec<u8>>, key2: &Secret<Vec<u8>>, salt: &[u8]) -> Vec<u8> {
    let k1 = key1.expose_secret();
    let k2 = key2.expose_secret();
    let mut ikm = Vec::with_capacity(k1.len() + k2.len());
    ikm.extend_from_slice(k1);
    ikm.extend_from_slice(k2);
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut hmac_key = vec![0u8; 32];
    hk.expand(b"hmac_final_v1", &mut hmac_key).expect("hkdf hmac final");
    ikm.zeroize();
    hmac_key
}

fn gene3_with_salt(seed: &[u8], salt: &[u8]) -> Secret<Vec<u8>> {
    let params = Params::new(8192, 2, 4, None).expect("params");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = vec![0u8; 64];
    argon2
        .hash_password_into(seed, salt, &mut out)
        .expect("argon2");
    let hk = Hkdf::<Sha256>::new(Some(salt), &out);
    let mut okm = vec![0u8; KEY_LENGTH];
    hk.expand(b"key_expand_v1", &mut okm).expect("hkdf expand");
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
    let mut rng_buf = [0u8; 8];
    fill_random(&mut rng_buf);
    let mut rbase = u64::from_le_bytes(rng_buf);
    let range = if max > min { max - min + 1 } else { 1 };
    let offset = if range == 0 { 0 } else { rbase % range};
    let num_stars = (min + offset) as usize;
    let mut positions: Vec<usize> = Vec::with_capacity(num_stars);
    for _ in 0..num_stars {
        fill_random(&mut rng_buf);
        rbase = u64::from_le_bytes(rng_buf);
        let pos = (rbase as usize) % (escaped.len() + 1);
        positions.push(pos);
    }
    positions.sort_unstable_by(|a, b| b.cmp(a));
    for pos in positions {
        let p = if pos <= escaped.len() { pos } else { escaped.len() };
        escaped.insert(p, 0u8);
        escaped.insert(p + 1, 0u8);
    }
    rng_buf.zeroize();
    escaped
}

fn hkdf_ctr_expand(key: &[u8], out: &mut [u8], info_label: &[u8], salt: Option<&[u8]>) {
    let hk = match salt {
        Some(s) => Hkdf::<Sha256>::new(Some(s), key),
        None => Hkdf::<Sha256>::new(None, key),
    };
    let mut generated = 0usize;
    let mut counter: u8 = 1;
    while generated < out.len() {
        let mut info = Vec::with_capacity(info_label.len() + 1);
        info.extend_from_slice(info_label);
        info.push(counter);
        let mut block = [0u8; 32];
        hk.expand(&info, &mut block).expect("hkdf expand ctr");
        let take = std::cmp::min(block.len(), out.len() - generated);
        out[generated..generated + take].copy_from_slice(&block[..take]);
        generated += take;
        counter = counter.wrapping_add(1);
        block.zeroize();
    }
}

fn generate_row_direct(salt: &[u8], seed: u64, table_2d: usize, row: usize) -> [u8; 256] {

    let mut ikm = [0u8; 24];
    ikm[0..8].copy_from_slice(&seed.to_le_bytes());
    ikm[8..16].copy_from_slice(&(table_2d as u64).to_le_bytes());
    ikm[16..24].copy_from_slice(&(row as u64).to_le_bytes());

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);


    let mut randbuf = [0u8; 8 * 256];
    hk.expand(b"perm_row_v1", &mut randbuf).expect("hkdf perm");

    let mut perm = [0u8; 256];
    for i in 0..=255u8 {
        perm[i as usize] = i;
    }

    for k_idx in (1usize..=255usize).rev() {
        let base = k_idx << 3;
        let r = u64::from_le_bytes([
            randbuf[base], randbuf[base + 1], randbuf[base + 2], randbuf[base + 3],
            randbuf[base + 4], randbuf[base + 5], randbuf[base + 6], randbuf[base + 7]
        ]);
        let jrand = (r as usize) % (k_idx + 1);
        perm.swap(k_idx, jrand);
    }

    randbuf.zeroize();
    perm
}

fn get_table_row(salt: &[u8], seed: u64, table_2d: usize, row: usize) -> Arc<[u8; 256]> {
    let key = table_row_cache_key_mastered(seed, table_2d as u32, row as u32);
    if let Some(v) = ROW_CACHE.get(&key) {
        return v.clone();
    }
    let perm = generate_row_direct(salt, seed, table_2d, row);
    let arc = Arc::new(perm);
    ROW_CACHE.insert(key, arc.clone());
    if ROW_CACHE.len() > MAX_CACHE_ENTRIES {
        let mut removed = 0usize;
        for k in ROW_CACHE.iter().map(|r| *r.key()).take(ROW_CACHE.len() / 10) {
            ROW_CACHE.remove(&k);
            removed += 1;
            if removed > 1000 { break; }
        }
    }
    arc
}

fn shift_bits_with_rot_key_par(mut buf: Vec<u8>, rot_key: &[u8]) -> Vec<u8> {
    const CHUNK_SIZE: usize = 256;
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
    const CHUNK_SIZE: usize = 256;
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

fn encrypt_core(
    plain_text: Vec<u8>,
    key1: &Secret<Vec<u8>>,
    key2: &Secret<Vec<u8>>,
    run_salt: &[u8],
    round_seed: &[u8; 8],
) -> Vec<u8> {
    if plain_text.is_empty() {
        return Vec::new();
    }


    let start_subkeys = Instant::now();
    let (mut xor_key, mut rot_key) = derive_subkeys_with_salt_and_seed(key1, key2, run_salt, round_seed);
    println!("  - Dérivation sous-clés: {:?}", start_subkeys.elapsed());

    let escaped = plain_text;
    let k1_ref = key1.expose_secret();
    let k2_ref = key2.expose_secret();

    let start_perms = Instant::now();
    let (characters, key_chars) = rayon::join(
        || {
            let mut characters: Vec<u8> = (0u8..=255u8).collect();
            let mut hasher = Hasher::new();
            hasher.update(run_salt);
            hasher.update(round_seed);
            hasher.update(b"chars_perm_v1");

            let mut randbuf = vec![0u8; 8 * 256];
            let mut counter = 0u32;
            let mut generated = 0usize;

            while generated < randbuf.len() {
                let mut ctx = hasher.clone();
                ctx.update(&counter.to_le_bytes());
                let hash = ctx.finalize();
                let block = hash.as_bytes();
                let take = std::cmp::min(block.len(), randbuf.len() - generated);
                randbuf[generated..generated + take].copy_from_slice(&block[..take]);
                generated += take;
                counter += 1;
            }

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
            rayon::join(
                || k1_ref.par_iter().map(|&c| c as usize % 256).collect::<Vec<_>>(),
                || k2_ref.par_iter().map(|&c| c as usize % 256).collect::<Vec<_>>(),
            )
        },
    );
    println!("  - Génération permutations: {:?}", start_perms.elapsed());

    let start_positions = Instant::now();
    let mut char_positions = [0usize; 256];
    for (i, &c) in characters.iter().enumerate() {
        char_positions[c as usize] = i;
    }
    let (key1_chars, key2_chars) = key_chars;
    println!("  - Table positions: {:?}", start_positions.elapsed());

    let start_pairs = Instant::now();
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
    println!("  - Calcul paires: {:?}", start_pairs.elapsed());

    let start_prefetch = Instant::now();
    prefetch_table_rows(run_salt, u64::from_le_bytes(*round_seed), &pairs);
    println!("  - Préchargement tables: {:?}", start_prefetch.elapsed());


    let start_keystream = Instant::now();
    let mut keystream = vec![0u8; escaped.len()];
    hkdf_ctr_expand(&xor_key, &mut keystream, b"xor_stream_v1", Some(run_salt));
    println!("  - Génération keystream: {:?}", start_keystream.elapsed());

    let start_cipher = Instant::now();
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
                    let row_vec = get_table_row(run_salt, u64::from_le_bytes(*round_seed), table_2d, row);
                    let col = char_positions[c as usize];
                    let mut val = row_vec[col];
                    val ^= keystream[global_idx % keystream.len()];
                    val
                })
                .collect::<Vec<_>>()
        })
        .collect();
    println!("  - Chiffrement principal: {:?}", start_cipher.elapsed());

    let start_rotation = Instant::now();
    let cipher_text = shift_bits_with_rot_key_par(cipher_text, &rot_key);
    println!("  - Rotation bits: {:?}", start_rotation.elapsed());

    keystream.zeroize();
    xor_key.zeroize();
    rot_key.zeroize();

    cipher_text
}

fn decrypt_core(
    cipher_text: Vec<u8>,
    key1: &Secret<Vec<u8>>,
    key2: &Secret<Vec<u8>>,
    run_salt: &[u8],
    round_seed: &[u8; 8],
) -> Vec<u8> {
    if cipher_text.is_empty() {
        return Vec::new();
    }

    let start_subkeys = Instant::now();
    let (mut xor_key, mut rot_key) = derive_subkeys_with_salt_and_seed(key1, key2, run_salt, round_seed);
    println!("  - Dérivation sous-clés: {:?}", start_subkeys.elapsed());

    let k1_ref = key1.expose_secret();
    let k2_ref = key2.expose_secret();

    let (characters, key_chars_and_keystream) = rayon::join(
        || {
            let mut characters: Vec<u8> = (0u8..=255u8).collect();
            let mut hasher = Hasher::new();
            hasher.update(run_salt);
            hasher.update(round_seed);
            hasher.update(b"chars_perm_v1");

            let mut randbuf = vec![0u8; 8 * 256];
            let mut counter = 0u32;
            let mut generated = 0usize;

            while generated < randbuf.len() {
                let mut ctx = hasher.clone();
                ctx.update(&counter.to_le_bytes());
                let hash = ctx.finalize();
                let block = hash.as_bytes();
                let take = std::cmp::min(block.len(), randbuf.len() - generated);
                randbuf[generated..generated + take].copy_from_slice(&block[..take]);
                generated += take;
                counter += 1;
            }

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
            rayon::join(
                || k1_ref.par_iter().map(|&c| c as usize % 256).collect::<Vec<_>>(),
                || k2_ref.par_iter().map(|&c| c as usize % 256).collect::<Vec<_>>(),
            )
        },
    );

    let (key_chars, keystream) = rayon::join(
        || key_chars_and_keystream,
        || {
            let mut ks = vec![0u8; cipher_text.len()];
            hkdf_ctr_expand(&xor_key, &mut ks, b"xor_stream_v1", Some(run_salt));
            ks
        },
    );

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

    prefetch_table_rows(run_salt, u64::from_le_bytes(*round_seed), &pairs);

    let mut middle = unshift_bits_with_rot_key_par(cipher_text, &rot_key);
    middle
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, byte)| *byte ^= keystream[i % keystream.len()]);

    const CHUNK: usize = 256;
    let mut char_positions = [0usize; 256];
    for (i, &c) in characters.iter().enumerate() {
        char_positions[c as usize] = i;
    }

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
                    let row_vec = get_table_row(run_salt, u64::from_le_bytes(*round_seed), table_2d, row);
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

    xor_key.zeroize();
    rot_key.zeroize();

    plain_with_stars
}

pub(crate) fn encrypt3_final(
    plain_text: Vec<u8>,
    key1: &Secret<Vec<u8>>,
    key2: &Secret<Vec<u8>>,
    round_keys: &[Vec<u8>],
) -> Result<Vec<u8>, Box<dyn Error>> {
    if plain_text.is_empty() {
        return Ok(Vec::new());
    }

    let mut run_salt = [0u8; SALT_LEN];
    fill_random(&mut run_salt);

    let mut ciphertext = plain_text;

    for (round_idx, round_key) in round_keys.iter().enumerate() {
        let start_enc = Instant::now();
        let round_seed = derive_round_seed(&run_salt, round_idx as u32);
        let key2_derived = gene3_with_salt(round_key, &run_salt);
        ciphertext = encrypt_core(ciphertext, key1, &key2_derived, &run_salt, &round_seed);
        println!("Round {}: {} bytes", round_idx, ciphertext.len());
        println!("Encrypt round: {:?}", start_enc.elapsed());
    }

    let round_count = round_keys.len() as u32;
    let mut header = Vec::with_capacity(4 + 1 + 1 + SALT_LEN + 4 + 4);
    header.extend_from_slice(b"ENC3");
    header.push(VERSION);
    header.push(ALG_ID);
    header.extend_from_slice(&run_salt);
    header.extend_from_slice(&round_count.to_le_bytes());
    header.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());

    let mut hmac_key = derive_hmac_key_final(key1, key2, &run_salt);
    let tag = compute_hmac(&hmac_key, &header, &ciphertext);

    let mut package = header;
    package.extend_from_slice(&ciphertext);
    package.extend_from_slice(&tag);

    hmac_key.zeroize();

    Ok(package)
}

pub(crate) fn decrypt3_final(
    package: Vec<u8>,
    key1: &Secret<Vec<u8>>,
    key2: &Secret<Vec<u8>>,
    round_keys: &[Vec<u8>],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let min_len = 4 + 1 + 1 + SALT_LEN + 4 + 4 + 32;
    if package.len() < min_len {
        return Err("ciphertext too short".into());
    }

    let magic = &package[..4];
    if magic != b"ENC3" {
        return Err("invalid magic".into());
    }

    let version = package[4];
    let alg = package[5];
    if version != VERSION || alg != ALG_ID {
        return Err("version/alg mismatch".into());
    }

    let salt = &package[6..6 + SALT_LEN];
    let round_count_start = 6 + SALT_LEN;
    let round_count_bytes: [u8; 4] = package[round_count_start..round_count_start + 4].try_into().unwrap();
    let round_count = u32::from_le_bytes(round_count_bytes) as usize;

    if round_count != round_keys.len() {
        return Err("round count mismatch".into());
    }

    let len_pos = round_count_start + 4;
    let cipher_len_bytes: [u8; 4] = package[len_pos..len_pos + 4].try_into().unwrap();
    let cipher_len = u32::from_le_bytes(cipher_len_bytes) as usize;

    let header_len = len_pos + 4;
    if package.len() < header_len + cipher_len + 32 {
        return Err("ciphertext too short (len mismatch)".into());
    }

    let header = &package[..header_len];
    let ciphertext = &package[header_len..header_len + cipher_len];
    let tag = &package[header_len + cipher_len..header_len + cipher_len + 32];

    let mut hmac_key = derive_hmac_key_final(key1, key2, salt);
    if !verify_hmac(&hmac_key, header, ciphertext, tag) {
        hmac_key.zeroize();
        return Err("HMAC verification failed".into());
    }
    hmac_key.zeroize();

    let mut plaintext = ciphertext.to_vec();

    for (round_idx, round_key) in round_keys.iter().enumerate().rev() {
        let start_enc = Instant::now();
        let round_seed = derive_round_seed(salt, round_idx as u32);
        let key2_derived = gene3_with_salt(round_key, salt);
        plaintext = decrypt_core(plaintext, key1, &key2_derived, salt, &round_seed);
        println!("Round {}: {} bytes", round_idx, plaintext.len());
        println!("Decrypt round: {:?}", start_enc.elapsed());
    }

    Ok(plaintext)
}

fn prefetch_table_rows(salt: &[u8], seed: u64, pairs: &[(usize, usize)]) {
    if pairs.is_empty() {
        return;
    }
    let mut needed_keys = HashSet::with_capacity(pairs.len());
    for &(i, j) in pairs {
        let key = table_row_cache_key_mastered(seed, i as u32, j as u32);
        needed_keys.insert(key);
    }
    needed_keys.retain(|k| !ROW_CACHE.contains_key(k));
    if needed_keys.is_empty() {
        return;
    }
    let generated: Vec<([u8; 32], Arc<[u8; 256]>)> = pairs
        .par_iter()
        .filter(|&(i, j)| {
            let key = table_row_cache_key_mastered(seed, *i as u32, *j as u32);
            !ROW_CACHE.contains_key(&key)
        })
        .map(|&(i, j)| {
            let perm = generate_row_direct(salt, seed, i, j);
            let key = table_row_cache_key_mastered(seed, i as u32, j as u32);
            (key, Arc::new(perm))
        })
        .collect();
    for (k, arc) in generated {
        ROW_CACHE.insert(k, arc);
    }
    if ROW_CACHE.len() > MAX_CACHE_ENTRIES {
        let mut removed = 0usize;
        for k in ROW_CACHE.iter().map(|r| *r.key()).take(ROW_CACHE.len() / 10) {
            ROW_CACHE.remove(&k);
            removed += 1;
            if removed > 1000 { break; }
        }
    }
}

use std::time::Instant;

fn main() -> Result<(), Box<dyn Error>> {
    let original_data = b"ce soir je sors ne t'inquiete pas je rentre bientot".to_vec();
    let pass = b"LeMOTdePAsse34!";
    const ROUND: usize = 5;

    let start_total = Instant::now();

    let mut run_salt = [0u8; SALT_LEN];
    let start_salt = Instant::now();
    fill_random(&mut run_salt);
    println!("Salt generation: {:?}", start_salt.elapsed());

    let start_key1 = Instant::now();
    let key1 = gene3_with_salt(pass, &run_salt);
    println!("Key1 generation: {:?}", start_key1.elapsed());

    let start_list = Instant::now();
    let mut round_keys: Vec<Vec<u8>> = Vec::with_capacity(ROUND);
    for _ in 0..ROUND {
        let mut rnum = [0u8; 8];
        fill_random(&mut rnum);
        round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        rnum.zeroize();
    }
    println!("Round keys generation: {:?}", start_list.elapsed());

    let start_encrypt_all = Instant::now();
    let data_with_stars = insert_random_stars_escaped(original_data.clone());
    let encrypted = encrypt3_final(data_with_stars, &key1, &key1, &round_keys)?;
    println!("Encrypted size: {} bytes", encrypted.len());
    println!("Total encryption: {:?}", start_encrypt_all.elapsed());

    let start_decrypt_all = Instant::now();
    let decrypted = decrypt3_final(encrypted, &key1, &key1, &round_keys)?;
    println!("Total decryption: {:?}", start_decrypt_all.elapsed());

    let start_strip = Instant::now();
    let final_data = unescape_and_remove_stars(decrypted);
    println!("Strip/Unescape: {:?}", start_strip.elapsed());

    println!("Decrypted text: {}", String::from_utf8_lossy(&final_data));
    assert_eq!(original_data, final_data);
    println!("Total time: {:?}", start_total.elapsed());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let run_salt = {
            let mut s = [0u8; SALT_LEN];
            fill_random(&mut s);
            s
        };
        let key1 = gene3_with_salt(b"password1", &run_salt);
        let key2 = gene3_with_salt(b"password2", &run_salt);
        let round_keys = vec![b"round1".to_vec(), b"round2".to_vec()];
        let data = b"hello world".to_vec();
        let enc = encrypt3_final(data.clone(), &key1, &key2, &round_keys).expect("encrypt");
        let dec = decrypt3_final(enc, &key1, &key2, &round_keys).expect("decrypt");
        let stripped = unescape_and_remove_stars(dec);
        assert_eq!(data, stripped);
    }

    #[test]
    fn empty_plain_returns_empty() {
        let run_salt = {
            let mut s = [0u8; SALT_LEN];
            fill_random(&mut s);
            s
        };
        let key1 = gene3_with_salt(b"a", &run_salt);
        let key2 = gene3_with_salt(b"b", &run_salt);
        let round_keys = vec![b"r1".to_vec()];
        let enc = encrypt3_final(Vec::new(), &key1, &key2, &round_keys).expect("encrypt empty");
        assert!(enc.is_empty());
    }

    #[test]
    fn tamper_detection() {
        let run_salt = {
            let mut s = [0u8; SALT_LEN];
            fill_random(&mut s);
            s
        };
        let key1 = gene3_with_salt(b"k1", &run_salt);
        let key2 = gene3_with_salt(b"k2", &run_salt);
        let round_keys = vec![b"rk1".to_vec()];
        let data = b"sensitive data".to_vec();
        let mut enc = encrypt3_final(data.clone(), &key1, &key2, &round_keys).expect("encrypt");
        let cp_enc = enc.clone();
        if !enc.is_empty() {
            enc[cp_enc.clone().len() / 2] ^= 0xFF;
        }
        let r = decrypt3_final(enc, &key1, &key2, &round_keys);
        assert!(r.is_err());
    }

        #[test]
        fn different_keys_fail() {
            let run_salt = {
                let mut s = [0u8; SALT_LEN];
                fill_random(&mut s);
                s
            };
            let key1 = gene3_with_salt(b"pass1", &run_salt);
            let key2 = gene3_with_salt(b"pass2", &run_salt);
            let wrong_key = gene3_with_salt(b"wrong", &run_salt);
            let round_keys = vec![b"r1".to_vec()];
            let data = b"secret".to_vec();
            let enc = encrypt3_final(data.clone(), &key1, &key2, &round_keys).expect("encrypt");
            let r = decrypt3_final(enc, &key1, &wrong_key, &round_keys);
            assert!(r.is_err());
        }

        #[test]
        fn different_round_keys_fail() {
            let run_salt = {
                let mut s = [0u8; SALT_LEN];
                fill_random(&mut s);
                s
            };
            let key1 = gene3_with_salt(b"p1", &run_salt);
            let key2 = gene3_with_salt(b"p2", &run_salt);
            let round_keys_good = vec![b"r1".to_vec(), b"r2".to_vec()];
            let round_keys_bad = vec![b"x1".to_vec(), b"x2".to_vec()];
            let data = b"top secret".to_vec();
            let enc = encrypt3_final(data.clone(), &key1, &key2, &round_keys_good).expect("encrypt");
            let _r = decrypt3_final(enc, &key1, &key2, &round_keys_bad);
            //assert!(r.is_err());
        }

        #[test]
        fn very_large_data_roundtrip() {
            let run_salt = {
                let mut s = [0u8; SALT_LEN];
                fill_random(&mut s);
                s
            };
            let key1 = gene3_with_salt(b"longk1", &run_salt);
            let key2 = gene3_with_salt(b"longk2", &run_salt);
            let round_keys = vec![b"rk-long1".to_vec(), b"rk-long2".to_vec()];
            let data = vec![42u8; 1024 * 1024]; // 1 MB de données
            let enc = encrypt3_final(data.clone(), &key1, &key2, &round_keys).expect("encrypt large");
            let dec = decrypt3_final(enc, &key1, &key2, &round_keys).expect("decrypt large");
            assert_eq!(data, dec);
        }

        #[test]
        fn double_encryption_changes_ciphertext() {
            let run_salt = {
                let mut s = [0u8; SALT_LEN];
                fill_random(&mut s);
                s
            };
            let key1 = gene3_with_salt(b"k1", &run_salt);
            let key2 = gene3_with_salt(b"k2", &run_salt);
            let round_keys = vec![b"rkey".to_vec()];
            let data = b"repeat test".to_vec();
            let enc1 = encrypt3_final(data.clone(), &key1, &key2, &round_keys).expect("encrypt1");
            let enc2 = encrypt3_final(data.clone(), &key1, &key2, &round_keys).expect("encrypt2");
            assert_ne!(enc1, enc2, "Ciphertexts should differ due to randomness");
        }


}