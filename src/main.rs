use std::convert::TryInto;
use std::error::Error;

use argon2::{Argon2, Params};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;
use zeroize::Zeroize;

use rayon::prelude::*;
use blake3::Hasher;
use std::time::Instant;

type HmacSha256 = Hmac<Sha256>;

static AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

static AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];

const KEY_LENGTH: usize = 512;
const SALT_LEN: usize = 32;
const VERSION: u8 = 4;
const ALG_ID: u8 = 173;

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
    argon2.hash_password_into(seed, salt, &mut out).expect("argon2");
    let hk = Hkdf::<Sha256>::new(Some(salt), &out);
    let mut okm = vec![0u8; KEY_LENGTH];
    hk.expand(b"key_expand_v1", &mut okm).expect("hkdf expand");
    out.zeroize();
    Secret::new(okm)
}

fn escape_zero_bytes(input: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 2);
    let mut i = 0usize;
    while i < input.len() {
        let b = input[i];
        if b == 0 {
            out.push(0u8);
            out.push(0xFFu8);
        } else {
            out.push(b);
        }
        i += 1;
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
    let offset = if range == 0 { 0 } else { rbase % range };
    let num_stars = (min + offset) as usize;
    let mut positions: Vec<usize> = Vec::with_capacity(num_stars);
    let mut t = 0usize;
    while t < num_stars {
        fill_random(&mut rng_buf);
        rbase = u64::from_le_bytes(rng_buf);
        let pos = (rbase as usize) % (escaped.len() + 1);
        positions.push(pos);
        t += 1;
    }
    positions.sort_unstable_by(|a, b| b.cmp(a));
    let mut pidx = 0usize;
    while pidx < positions.len() {
        let pos = positions[pidx];
        let p = if pos <= escaped.len() { pos } else { escaped.len() };
        escaped.insert(p, 0u8);
        escaped.insert(p + 1, 0u8);
        pidx += 1;
    }
    rng_buf.zeroize();
    escaped
}

fn hkdf_block(key: &[u8], info_label: &[u8], counter: u8, salt: Option<&[u8]>, out32: &mut [u8; 32]) {
    let hk = match salt {
        Some(s) => Hkdf::<Sha256>::new(Some(s), key),
        None => Hkdf::<Sha256>::new(None, key),
    };
    let mut info = Vec::with_capacity(info_label.len() + 1);
    info.extend_from_slice(info_label);
    info.push(counter);
    hk.expand(&info, out32).expect("hkdf expand block");
}

fn hkdf_ctr_expand_par(key: &[u8], out: &mut [u8], info_label: &[u8], salt: Option<&[u8]>) {
    if out.is_empty() {
        return;
    }

    let blocks = (out.len() + 31) / 32;
    let mut tmp = vec![[0u8; 32]; blocks];

    // Itération parallèle sur références mutables directes
    tmp.par_iter_mut()
        .enumerate()
        .for_each(|(b, block)| {
            hkdf_block(key, info_label, (b as u8).wrapping_add(1), salt, block);
        });

    let mut written = 0usize;
    for block in tmp.iter() {
        let take = std::cmp::min(32, out.len() - written);
        out[written..written + take].copy_from_slice(&block[..take]);
        written += take;
    }

    tmp.par_iter_mut().for_each(|t| t.zeroize());
}

fn perm256_from_key(key: &[u8; 32]) -> [u8; 256] {
    let add1 = key[0];
    let x1 = key[1];
    let mul = key[2] | 1;
    let x2 = key[3];
    let add2 = key[4];
    let rot = (key[5] as usize) & 0xFF;
    let mut out = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        let j = (i + rot) & 0xFF;
        let mut x = i as u8;
        x = x.wrapping_add(add1);
        x ^= x1;
        x = AES_SBOX[x as usize];
        x = x.wrapping_mul(mul);
        x = AES_INV_SBOX[x as usize];
        x ^= x2;
        x = x.wrapping_add(add2);
        out[j] = x;
        i += 1;
    }
    out
}

fn generate_row_direct(salt: &[u8], seed: u64, table_2d: usize, row: usize) -> [u8; 256] {
    let mut ikm = [0u8; 24];
    ikm[0..8].copy_from_slice(&seed.to_le_bytes());
    ikm[8..16].copy_from_slice(&(table_2d as u64).to_le_bytes());
    ikm[16..24].copy_from_slice(&(row as u64).to_le_bytes());
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut transform_key = [0u8; 32];
    hk.expand(b"sbox_key_v1", &mut transform_key).expect("hkdf sbox key");
    let sbox = perm256_from_key(&transform_key);
    transform_key.zeroize();
    sbox
}

fn shift_bits_with_rot_key_par(mut buf: Vec<u8>, rot_key: &[u8]) -> Vec<u8> {
    const CHUNK_SIZE: usize = 256;
    buf.par_chunks_mut(CHUNK_SIZE)
        .enumerate()
        .for_each(|(chunk_idx, chunk)| {
            let base_idx = chunk_idx * CHUNK_SIZE;
            let mut i = 0usize;
            while i < chunk.len() {
                let idx = base_idx + i;
                let amount = (rot_key[idx % rot_key.len()] & 0x07) as u32;
                chunk[i] = chunk[i].rotate_left(amount);
                i += 1;
            }
        });
    buf
}

fn unshift_bits_with_rot_key_par(mut buf: Vec<u8>, rot_key: &[u8]) -> Vec<u8> {
    const CHUNK_SIZE: usize = 256;
    buf.par_chunks_mut(CHUNK_SIZE)
        .enumerate()
        .for_each(|(chunk_idx, chunk)| {
            let base_idx = chunk_idx * CHUNK_SIZE;
            let mut i = 0usize;
            while i < chunk.len() {
                let idx = base_idx + i;
                let amount = (rot_key[idx % rot_key.len()] & 0x07) as u32;
                chunk[i] = chunk[i].rotate_right(amount);
                i += 1;
            }
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

fn build_characters(run_salt: &[u8], round_seed: &[u8; 8]) -> [u8; 256] {
    let mut hasher = Hasher::new();
    hasher.update(run_salt);
    hasher.update(round_seed);
    hasher.update(b"chars_sbox_v1");
    let mut sbox_key = [0u8; 32];
    let hash = hasher.finalize();
    sbox_key.copy_from_slice(&hash.as_bytes()[..32]);
    let out = perm256_from_key(&sbox_key);
    sbox_key.zeroize();
    out
}

#[inline]
fn build_pairs(key1_chars: &[usize], key2_chars: &[usize], len: usize) -> Vec<(u16, u16)> {
    let mut v = Vec::with_capacity(len.min(65536));
    let mut i = 0usize;
    while i < len {
        let table_2d = (key1_chars[i % key1_chars.len()] & 0xFF) as u16;
        let row = (key2_chars[i % key2_chars.len()] & 0xFF) as u16;
        v.push((table_2d, row));
        i += 1;
    }
    v.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    v.dedup();
    v
}

#[inline]
fn build_row_cache_local(salt: &[u8], seed: u64, pairs: &[(u16, u16)]) -> (Vec<[u8; 256]>, Vec<usize>) {
    let mut rows: Vec<[u8; 256]> = vec![[0u8; 256]; pairs.len()];
    rows.par_iter_mut()
        .zip(pairs.par_iter().cloned())
        .for_each(|(slot, (i, j))| {
            *slot = generate_row_direct(salt, seed, i as usize, j as usize);
        });
    let mut map = vec![usize::MAX; 256 * 256];
    let mut idx = 0usize;
    while idx < pairs.len() {
        let (i, j) = pairs[idx];
        map[((i as usize) << 8) | (j as usize)] = idx;
        idx += 1;
    }
    (rows, map)
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
    let (characters, (key1_chars, key2_chars)) = rayon::join(
        || build_characters(run_salt, round_seed),
        || {
            rayon::join(
                || k1_ref.par_iter().map(|&c| (c as usize) & 0xFF).collect::<Vec<_>>(),
                || k2_ref.par_iter().map(|&c| (c as usize) & 0xFF).collect::<Vec<_>>(),
            )
        },
    );
    println!("  - Génération permutations: {:?}", start_perms.elapsed());

    let start_positions = Instant::now();
    let mut char_positions = [0usize; 256];
    let mut i = 0usize;
    while i < 256 {
        char_positions[characters[i] as usize] = i;
        i += 1;
    }
    println!("  - Table positions: {:?}", start_positions.elapsed());

    let start_pairs = Instant::now();
    let pairs = build_pairs(&key1_chars, &key2_chars, escaped.len());
    println!("  - Calcul paires: {:?}", start_pairs.elapsed());

    let start_prefetch = Instant::now();
    let (rows, index_map) = build_row_cache_local(run_salt, u64::from_le_bytes(*round_seed), &pairs);
    println!("  - Préchargement tables: {:?}", start_prefetch.elapsed());

    let start_keystream = Instant::now();
    let mut keystream = vec![0u8; escaped.len()];
    hkdf_ctr_expand_par(&xor_key, &mut keystream, b"xor_stream_v1", Some(run_salt));
    println!("  - Génération keystream: {:?}", start_keystream.elapsed());

    let start_cipher = Instant::now();
    let cipher_text: Vec<u8> = escaped
        .par_chunks(256)
        .enumerate()
        .flat_map(|(chunk_idx, chunk)| {
            let base_idx = chunk_idx * 256;
            let mut out = vec![0u8; chunk.len()];
            let mut j = 0usize;
            while j < chunk.len() {
                let gi = base_idx + j;
                let t = (key1_chars[gi % key1_chars.len()] & 0xFF) as u16;
                let r = (key2_chars[gi % key2_chars.len()] & 0xFF) as u16;
                let idx = index_map[((t as usize) << 8) | (r as usize)];
                let col = char_positions[chunk[j] as usize];
                let mut v = rows[idx][col];
                v ^= keystream[gi];
                out[j] = v;
                j += 1;
            }
            out
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

    let (characters, (key1_chars, key2_chars)) = rayon::join(
        || build_characters(run_salt, round_seed),
        || {
            rayon::join(
                || k1_ref.par_iter().map(|&c| (c as usize) & 0xFF).collect::<Vec<_>>(),
                || k2_ref.par_iter().map(|&c| (c as usize) & 0xFF).collect::<Vec<_>>(),
            )
        },
    );

    let pairs = build_pairs(&key1_chars, &key2_chars, cipher_text.len());
    let (rows, index_map) = build_row_cache_local(run_salt, u64::from_le_bytes(*round_seed), &pairs);

    let mut keystream = vec![0u8; cipher_text.len()];
    hkdf_ctr_expand_par(&xor_key, &mut keystream, b"xor_stream_v1", Some(run_salt));

    let mut middle = unshift_bits_with_rot_key_par(cipher_text, &rot_key);
    middle
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, byte)| *byte ^= keystream[i]);

    const CHUNK: usize = 256;

    let plain_with_stars: Vec<u8> = middle
        .par_chunks(CHUNK)
        .enumerate()
        .flat_map(|(chunk_idx, chunk)| {
            let base_idx = chunk_idx * CHUNK;
            let mut out = vec![0u8; chunk.len()];
            let mut j = 0usize;
            while j < chunk.len() {
                let gi = base_idx + j;
                let t = (key1_chars[gi % key1_chars.len()] & 0xFF) as u16;
                let r = (key2_chars[gi % key2_chars.len()] & 0xFF) as u16;
                let idx = index_map[((t as usize) << 8) | (r as usize)];
                let c = chunk[j];
                let row_vec = &rows[idx];
                let col = {
                    let mut k = 0usize;
                    let mut pos = None;
                    while k < 256 {
                        if row_vec[k] == c {
                            pos = Some(k);
                            break;
                        }
                        k += 1;
                    }
                    pos
                };
                out[j] = match col {
                    Some(cc) => characters[cc],
                    None => c,
                };
                j += 1;
            }
            out
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

fn main() -> Result<(), Box<dyn Error>> {
    let original_data: Vec<u8> = vec![b'A'; 1 * 256 * 256];

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
    let mut r = 0usize;
    while r < ROUND {
        let mut rnum = [0u8; 8];
        fill_random(&mut rnum);
        round_keys.push(u64::from_le_bytes(rnum).to_string().into_bytes());
        rnum.zeroize();
        r += 1;
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

    //println!("Decrypted text: {}", String::from_utf8_lossy(&final_data));
    assert_eq!(original_data, final_data);
    println!("Total time: {:?}", start_total.elapsed());
    Ok(())
}
