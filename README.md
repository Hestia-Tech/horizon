# Horizon-Cryptography

> **Horizon** — a research/experimental Rust implementation of a custom multi-round symmetric encryption pipeline. **Important:** this project implements a custom cryptographic construction. It has **not** been audited. Do **not** use it to protect high-value or production secrets without a professional security review.

---

## Table of contents

* [Overview](#overview)
* [Highlights & design summary](#highlights--design-summary)
* [Security notes & disclaimers](#security-notes--disclaimers)
* [Project structure & key modules](#project-structure--key-modules)
* [Public API / functions](#public-api--functions)
* [On-disk/over-the-wire format (`ENC3`)](#on-diskover-the-wire-format-enc3)
* [Dependencies & build](#dependencies--build)
* [Usage examples](#usage-examples)
* [Testing & benchmarking](#testing--benchmarking)
* [Contributing](#contributing)
* [License](#license)

---

## Overview

Horizon is an experimental Rust library and CLI demonstrating a custom, multi-round encryption flow that combines modern KDFs and HKDF expansion with table-based byte permutations, per-round derived subkeys, and parallelized operations for performance. The code uses well-known primitives (Argon2id, HKDF-SHA256, HMAC-SHA256, BLAKE3 for permutation material, and `ring` for system randomness) but composes them into a bespoke construction.

This README documents the current implementation and how to use the library and the example `main()` program.

---

## Highlights & design summary

* **Multi-round pipeline:** ciphertext is produced after applying several rounds. Each round derives a per-round `key2` using Argon2id + HKDF and then runs a core encrypt operation.
* **Subkey derivation:** master keys are combined and expanded via HKDF-SHA256 to produce very large `xor_key` and `rot_key` material (constant `KEY_LENGTH = 512`).
* **Permutation tables:** 2D table rows (256-byte permutations) are generated deterministically using BLAKE3 keyed hashing and cached in a thread-safe `DashMap` with an LRU-like trimming strategy.
* **Parallelism:** heavy-lifting operations (permutations, keystream expansion, chunk processing, rotation/unrotation) are parallelized with `rayon` for multi-core performance.
* **Memory hygiene:** secret material is held in `secrecy::Secret` and zeroized where practical via the `zeroize` trait.
* **HMAC authentication:** final package includes an HMAC-SHA256 (32 bytes) computed over the header and ciphertext.

---

## Security notes & disclaimers

* **This is experimental, not audited.** The construction is custom. Custom cryptography risks subtle weaknesses. Do not rely on this for production or critical secrecy without a formal audit.
* **Authentication included.** A 32-byte HMAC-SHA256 tag protects header + ciphertext. HMAC key is HKDF-derived from key material.
* **Non-standard format.** The wire/header format is specific to this project (see below). It should be considered application-level and not interchangeable with standard protocols.
* **Randomness:** `ring::rand::SystemRandom` is used. The implementation also generates salts and per-round randomness.
* **Key management:** caller is responsible for secure key storage/rotation. Keys are passed as `Secret<Vec<u8>>` in the library API.

---

## Project structure & key modules (implementation notes)

* **Core primitives used**

   * `argon2::Argon2` (Argon2id) for per-round key stretching (`gene3_with_salt`).
   * `hkdf::Hkdf<Sha256>` for subkey and keystream expansion.
   * `hmac::Hmac<Sha256>` for authentication.
   * `blake3::Hasher` to produce permutation randomness.
   * `ring::rand::SystemRandom` for salt and other nonces.
   * `secrecy::Secret` + `zeroize` to minimize leak risk.
   * `rayon` for parallel operations.
   * `dashmap::DashMap` + `once_cell::sync::Lazy` for cached table rows.

* **Important constants**

   * `KEY_LENGTH = 512` — length (bytes) for expanded xor/rot subkeys.
   * `SALT_LEN = 32` — per-encryption run salt size.
   * `VERSION = 4`, `ALG_ID = 173` — header/version identifiers used in the package.
   * `MAX_CACHE_ENTRIES = 80_000` — in-memory row cache trimming threshold.

* **Cache**

   * The permutation row cache (`ROW_CACHE`) maps a derived 32-byte cache key to a `Arc<[u8; 256]>` permutation. Rows are generated deterministically and cached; the cache is periodically trimmed when it grows beyond `MAX_CACHE_ENTRIES`.

* **Permutation generation**

   * `generate_row_direct(salt, seed, table_2d, row)` deterministically generates a 256-byte permutation using keyed BLAKE3 output and a Fisher–Yates-like shuffle.

* **Keystream & rotation**

   * `hkdf_ctr_expand` expands large pseudorandom streams (used for XOR keystream) via repeated HKDF-SHA256 expands with a counter.
   * `rot_key` material is used to rotate bytes (left during encryption, right during decryption) in 256-byte chunks. Rotation amounts are taken from `rot_key[i % rot_key.len()] & 0x07`.

---

## Public API / functions

(These names reflect the current codebase and can be used from library/CLI code.)

* `pub(crate) fn encrypt3_final(plain_text: Vec<u8>, key1: &Secret<Vec<u8>>, key2: &Secret<Vec<u8>>, round_keys: &[Vec<u8>]) -> Result<Vec<u8>, Box<dyn Error>>`

   * Produces a packaged `ENC3` blob. The caller supplies `key1` and `key2` (both wrapped in `Secret<Vec<u8>>`) and a slice of per-round `round_keys` (each `Vec<u8>`). Each round uses `gene3_with_salt` to derive the per-round `key2` material from `round_key` and the run salt.

* `pub(crate) fn decrypt3_final(package: Vec<u8>, key1: &Secret<Vec<u8>>, key2: &Secret<Vec<u8>>, round_keys: &[Vec<u8>]) -> Result<Vec<u8>, Box<dyn Error>>`

   * Verifies header & HMAC, then reverses the rounds to return plaintext bytes.

* `fn gene3_with_salt(seed: &[u8], salt: &[u8]) -> Secret<Vec<u8>>`

   * Argon2id + HKDF-based expansion used to turn a per-round input into a `KEY_LENGTH`-sized key material.

* `fn encrypt_core(...)` / `fn decrypt_core(...)`

   * Internal round primitives that perform permutation lookup, keystream XOR, and bit rotations in parallel.

* `fn insert_random_stars_escaped(...)` / `fn unescape_and_remove_stars(...)`

   * Utility to insert and remove marker bytes (the example CLI uses these to embed random padding markers).

* `fn prefetch_table_rows(salt, seed, pairs)`

   * Hinting routine that generates permutation rows in parallel and populates `ROW_CACHE` before heavy encryption loops.

---

## On-disk / over-the-wire format (`ENC3`)

The library packages output into a single `Vec<u8>` structured as:

```
[ "ENC3" (4 bytes) ]
[ version (1 byte) = 4 ]
[ alg id (1 byte) = 173 ]
[ run_salt (32 bytes) ]
[ round_count (4 bytes, little-endian) ]
[ cipher_len (4 bytes, little-endian) ]
[ ciphertext (cipher_len bytes) ]
[ hmac_tag (32 bytes) ]
```

* HMAC-SHA256 tag is computed over the header (everything before ciphertext) and the ciphertext. The HMAC key is derived with `derive_hmac_key_final` using `key1`, `key2`, and `run_salt`.

---

## Dependencies & build

* Rust (2021 edition or later recommended)

Minimum `Cargo.toml` dependencies used by the code (representative):

```toml
[dependencies]
argon2 = "0.4"
hkdf = "0.12"
hmac = "0.12"
sha2 = "0.10"
ring = "0.16"
secrecy = "0.8"
zeroize = "1.5"
dashmap = "5.4"
once_cell = "1.18"
rayon = "1.8"
blake3 = "1.4"
```

Build:

```bash
cargo build --release
```

---

## Usage examples

This repository includes an example `main()` that demonstrates:

* generating a run salt (`SALT_LEN = 32`),
* deriving `key1` with `gene3_with_salt(pass, &run_salt)`,
* creating a `round_keys` list (each entry is arbitrary bytes; the implementation uses random 8-byte nonces serialized to bytes in the example),
* optionally inserting random marker bytes (`insert_random_stars_escaped`) prior to encryption,
* calling `encrypt3_final(...)` to produce the package,
* calling `decrypt3_final(...)` to recover plaintext and finally stripping markers with `unescape_and_remove_stars(...)`.

Short example (conceptual):

```rust
let pass = b"my-password";
let key1 = gene3_with_salt(pass, &run_salt); // Secret<Vec<u8>>
let round_keys: Vec<Vec<u8>> = vec![b"r1".to_vec(), b"r2".to_vec()];
let package = encrypt3_final(plaintext, &key1, &key1, &round_keys)?;
let recovered = decrypt3_final(package, &key1, &key1, &round_keys)?;
```

Notes:

* `round_keys` must match between encryption and decryption in content and order.
* The example program in `main()` demonstrates the full flow including timing prints.

---

## Testing & benchmarking

* Unit tests: run `cargo test` to execute existing tests (if present).
* Benchmarks: time the `main()` example or add criterion-based benchmarks to measure performance across different data sizes and round counts.
* Profiling: `perf` / flamegraph can help identify CPU or allocation hotspots — useful because the implementation uses heavy parallel workloads and large HKDF expansions.

---

## Contribution

Contributions and issues are welcome. Please:

1. Open an issue describing the feature or bug.
2. Submit a PR with focused changes and tests where applicable.

Before submitting cryptography-related changes, explain the intended security model and rationale so reviewers can evaluate it.

---

## License

This project is distributed under the **AGPLv3** license (see `LICENSE`).
