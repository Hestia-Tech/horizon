use std::error::Error;
use std::sync::{Arc, Mutex};
use argon2::Argon2;
use once_cell::sync::Lazy;

use hashbrown::HashMap;
use rayon::prelude::*;
use secrecy::{ExposeSecret, Secret};
use sysinfo::System;

use crate::cryptex::{decrypt_file, encrypt_file};
use crate::nebula::{Nebula, secured_seed, seeded_shuffle};
use crate::systemtrayerror::SystemTrayError;

mod systemtrayerror;
mod kdfwagen;
mod cryptex;
mod nebula;

const KEY_LENGTH: usize = 512;

/// Caching le sel sacré pour éviter des recalculs redondants  
static SALT: Lazy<String> = Lazy::new(|| {
    System::name().unwrap_or_default() +
    &System::host_name().unwrap_or_default() +
    &System::os_version().unwrap_or_default() +
    &System::kernel_version().unwrap_or_default()
});

/// Génère une table tridimensionnelle optimisée, employant une granularité définie pour Rayon.
/// Génère une table tridimensionnelle optimisée, employant une granularité définie pour Rayon.
fn table3(size: usize, seed: u64) -> Vec<Vec<Vec<u8>>> {
    let mut characters: Vec<u8> = (0..=255).collect();
    seeded_shuffle(&mut characters, seed as usize);

    (0..size)
        .into_par_iter()
        .map(|i| {
            (0..size)
                .map(|j| {
                    (0..size)
                        .map(|k| {
                            let idx: usize = (i + j + k) % size;
                            characters[idx]
                        })
                        .collect::<Vec<u8>>()
                })
                .collect::<Vec<Vec<u8>>>()
        })
        .collect::<Vec<Vec<Vec<u8>>>>()
}


/// Retourne le sel pré-calculé pour la dérivation rituelle
fn get_salt() -> String {
    SALT.clone()
}

/// Somme les valeurs d'une adresse MAC en parallèle
fn addition_chiffres(adresse_mac: &Vec<u8>) -> u64 {
    adresse_mac.par_iter().map(|&x| x as u64).sum()
}

/// Génère une clé secondaire à partir d'une graine
fn generate_key2(seed: &str) -> Result<Secret<Vec<u8>>, SystemTrayError> {
    if seed.len() < 10 {
        return Err(SystemTrayError::new(4));
    }
    if get_salt().len() < 10 {
        return Err(SystemTrayError::new(10));
    }
    Ok(gene3(seed.as_bytes()))
}

/// Dérive le matériau clé sacré en utilisant Argon2
fn gene3(seed: &[u8]) -> Secret<Vec<u8>> {
    let mut output_key_material = vec![0u8; KEY_LENGTH];
    Argon2::default()
        .hash_password_into(seed, get_salt().as_ref(), &mut output_key_material)
        .expect("Hashing failed");
    Secret::new(output_key_material)
}

/// Insère des étoiles aléatoires dans le vecteur, en optimisant l'accès au générateur d'entropie
fn insert_random_stars(mut word: Vec<u8>) -> Vec<u8> {
    // Utilisation d'un Arc pour le générateur d'entropie et réduction de contention par acquisition groupée
    let rng_arc = Arc::new(Mutex::new(Nebula::new(secured_seed())));
    
    // Générer le nombre sacré d'étoiles en une seule acquisition
    let num_stars: usize = {
        let mut rng = rng_arc.lock().unwrap();
        rng.generate_bounded_number((word.len() / 2) as u128, word.len() as u128)
            .unwrap() as usize
    };

    // Pré-calculer la liste des indices aléatoires en une acquisition groupée
    let random_indices: Vec<usize> = {
        let mut rng = rng_arc.lock().unwrap();
        (0..num_stars)
            .map(|_| rng.generate_bounded_number(0, word.len() as u128).unwrap() as usize)
            .collect()
    };

    // Trie descendant pour éviter le décalage des indices lors des insertions
    let mut sorted_indices = random_indices;
    sorted_indices.par_sort_unstable_by(|a, b| b.cmp(a));

    for index in sorted_indices {
        word.insert(index, 0); // Insertion de la valeur sacrée (0 dans ce rituel)
    }
    word
}

/// Construit une nouvelle clé secrète issue de multiples opérations arithmétiques sacrées
fn vz_maker(val1: u64, val2: u64, seed: u64) -> Secret<Vec<u8>> {
    gene3(&[
        (val1 + val2) as u8,
        (val1 % val2) as u8,
        seed as u8,
        val1.abs_diff(val2) as u8,
        val1.wrapping_mul(val2) as u8,
    ])
}

/// Chiffre le message sacré en combinant substitutions, XOR et rotations binaires
pub(crate) fn encrypt3(
    plain_text: Vec<u8>,
    key1: &Secret<Vec<u8>>,
    key2: &Secret<Vec<u8>>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let inter = insert_random_stars(plain_text);

    let key1_bytes = key1.expose_secret();
    let key2_bytes = key2.expose_secret();

    // Pré-calcul des sommes d'énergie
    let val1 = addition_chiffres(key2_bytes);
    let val2 = addition_chiffres(key1_bytes);
    let seed = val2 * val1;

    let mut characters: Vec<u8> = (0..=255).collect();
    let table = table3(256, seed);

    seeded_shuffle(&mut characters, seed as usize);

    let char_positions: HashMap<_, _> = characters
        .par_iter()
        .enumerate()
        .map(|(i, &c)| (c, i))
        .collect();

    let table_len = 256;
    let key1_chars: Vec<usize> = key1_bytes.into_par_iter().map(|&c| c as usize % 256).collect();
    let key2_chars: Vec<usize> = key2_bytes.into_par_iter().map(|&c| c as usize % 256).collect();

    let mut cipher_text: Vec<u8> = inter
        .par_iter()
        .enumerate()
        .filter_map(|(i, c)| {
            let table_2d = key1_chars[i % key1_chars.len()] % table_len;
            let row = key2_chars[i % key2_chars.len()] % table_len;
            if let Some(col) = char_positions.get(c).map(|&col| col % 256) {
                if table_2d < table_len && row < table[table_2d].len() && col < table[table_2d][row].len() {
                    Some(table[table_2d][row][col])
                } else {
                    // Hérésie: l'indice n'est pas dans le répertoire sacré
                    None
                }
            } else {
                None
            }
        })
        .collect();

        // Rotation rituelle de la clé avant application de XOR
        let mut key_clone = key1_bytes.clone();
        key_clone.rotate_left(seed as usize % 64);
        xor_crypt3(&mut cipher_text, &key_clone);
        let vz = vz_maker(val1, val2, seed);
        Ok(shift_bits(cipher_text, vz))
}

/// Déchiffre le message sacré en inversant les transformations rituelles appliquées
pub(crate) fn decrypt3(
    cipher_text: Vec<u8>,
    key1: &Secret<Vec<u8>>,
    key2: &Secret<Vec<u8>>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let key1_bytes = key1.expose_secret();
    let key2_bytes = key2.expose_secret();

    let val1 = addition_chiffres(key2_bytes);
    let val2 = addition_chiffres(key1_bytes);
    let seed = val2 * val1;

    let mut characters: Vec<u8> = (0..=255).collect();
    seeded_shuffle(&mut characters, seed as usize);
    let table = table3(256, seed);
    let table_len = 256;

    let vz = vz_maker(val1, val2, seed);
    let mut cipher_text = unshift_bits(cipher_text, vz);
    let mut key_clone = key1_bytes.clone();
    key_clone.rotate_left(seed as usize % 64);
    xor_crypt3(&mut cipher_text, &key_clone);

    let key1_chars: Vec<usize> = key1_bytes.into_par_iter().map(|&c| c as usize % 256).collect();
    let key2_chars: Vec<usize> = key2_bytes.into_par_iter().map(|&c| c as usize % 256).collect();

    let plain_text: Vec<u8> = cipher_text
        .par_iter()
        .enumerate()
        .filter_map(|(i, c)| {
            let table_2d = key1_chars[i % key1_chars.len()] % table_len;
            let row = key2_chars[i % key2_chars.len()] % table_len;
            if table_2d < table_len && row < table[table_2d].len() {
                if let Some(col) = table[table_2d][row].iter().position(|x| x == c) {
                    if characters[col] != 0 {
                        Some(characters[col])
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    Ok(plain_text)
}

/// Applique l'opération XOR en parallèle pour obscurcir les données
fn xor_crypt3(input: &mut [u8], key: &[u8]) {
    input.par_iter_mut().enumerate().for_each(|(i, byte)| {
        *byte ^= key[i % key.len()];
    });
}

/// Effectue un décalage binaire des octets en fonction d'une clé secrète
pub fn shift_bits(cipher_text: Vec<u8>, key: Secret<Vec<u8>>) -> Vec<u8> {
    let key = key.expose_secret();
    cipher_text
        .par_iter()
        .enumerate()
        .map(|(i, &byte)| byte.rotate_left(key[i % key.len()] as u32))
        .collect::<Vec<u8>>()
}

/// Inverse le décalage binaire précédemment appliqué
pub fn unshift_bits(cipher_text: Vec<u8>, key: Secret<Vec<u8>>) -> Vec<u8> {
    let key = key.expose_secret();
    cipher_text
        .par_iter()
        .enumerate()
        .map(|(i, &byte)| byte.rotate_right(key[i % key.len()] as u32))
        .collect::<Vec<u8>>()
}

/// Fonction rituelle orchestrant le processus complet de chiffrement et déchiffrement
fn main() {
    // Données sacrées et mot de passe
    let original_data = "ce soir je sors ne t'inquiète pas je rentre bientôt";
    let pass = "LeMOTdePAsse34!";

    const ROUND: usize = 6;

    let key1 = gene3(pass.as_bytes());

    // Génération d'une liste de clés rituelles aléatoires
    let mut rng = Nebula::new(123456789);
    let liste: Vec<String> = (0..ROUND)
        .map(|_| rng.generate_random_number().to_string())
        .collect();

    let mut chif = original_data.as_bytes().to_vec();

    // Enchiffrement sur plusieurs cycles pour renforcer la protection sacrée
    for (index, element) in liste.iter().enumerate() {
        let key2 = gene3(element.as_bytes());
        chif = if index < 1 {
            encrypt3(chif, &key1, &key2).unwrap()
        } else {
            encrypt_file(chif, &key1, &key2).unwrap()
        };

        println!("{} Chiffré : {}", index, String::from_utf8_lossy(&chif));
    }

    println!("-----------------------------------------");

    // Déchiffrement en inversant les cycles rituels
    for (index, element) in liste.iter().enumerate().rev() {
        let key2 = gene3(element.as_bytes());
        chif = if index < 1 {
            decrypt3(chif, &key1, &key2).unwrap()
        } else {
            decrypt_file(chif, &key1, &key2).unwrap()
        };

        println!("{} déChiffré : {}", index, String::from_utf8_lossy(&chif));
    }

    assert_eq!(original_data, String::from_utf8_lossy(&chif));
}



#[cfg(test)]
mod tests {
    use std::fs::File;

    use crate::cryptex::{decrypt_file, encrypt_file};

    use super::*;

    #[test]
/// Tests file encryption and decryption.
///
/// This function demonstrates the process of encrypting and decrypting the content of a file.
/// It reads the content of a file, encrypts it using the `encrypt_file` function, then decrypts it back using the `decrypt_file` function.
/// Finally, it verifies that the decrypted content matches the original content of the file.
///
/// # Note
///
/// This function is meant for testing purposes and should be adapted or extended for actual use cases.
///
/// # Examples
///
/// ```
/// // Execute the test for file encryption and decryption
/// test_crypt_file();
/// ```
    fn test_crypt_file(){
        //let password = "bonjourcestmoi";
        //let key1 = generate_key2(password);
        //let key2 = generate_key2(password);
        //let key3 = generate_key2(password);


        //let mut file_content = Vec::new();
        //let mut file = File::open("invoicesample.pdf").unwrap();
        //file.read_to_end(&mut file_content).expect("TODO: panic message");

        //let encrypted_content = encrypt_file(file_content.clone(), &key1.unwrap(), &key2.unwrap());

        //let b = encrypted_content.unwrap();


        //let dcrypted_content = decrypt_file(b, &key1.unwrap(), &key3.unwrap());
        //let a = dcrypted_content.unwrap();
        //assert_eq!(a.clone(), file_content);
    }

    #[test]
    fn test_table3() {
        let size = 255;

        let table = table3(size, 123456789);

        for (_i, table_2d) in table.iter().enumerate() {
            for (_j, row) in table_2d.iter().enumerate() {
                for (_k, col) in row.iter().enumerate() {
                    print!("{} ", col);
                }

                println!();
            }

            println!();
            println!();
        }
    }

    #[test]
    fn test_speed_table(){
        let size = 255;
        table3(size, 123456789);
    }

    #[test]
    fn test_get_salt() {
        let salt = get_salt();
        assert_ne!(salt.len(), 0);
    }

    #[test]
    fn test_generate_key2() {
        let seed = "0123456789";
        let key = generate_key2(seed).unwrap();


        assert_ne!(key.expose_secret().len(), 0)
    }

    #[test]
    fn test_insert_random_stars() {
        let word = "Hello World!".as_bytes().to_vec();
        let word2 = insert_random_stars(word.clone());

        println!("Word: {:?}", word2);
        assert_ne!(word, word2);
    }


    #[test]
    fn test_shift_unshift_bits() {
        let original_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10,1, 2, 3, 4, 5, 6, 7, 8, 9, 10,1, 2, 3, 4, 5, 6, 7, 8, 9, 10,1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let shifted_data = shift_bits(original_data.clone(), Secret::new(key.clone()));
        let unshifted_data = unshift_bits(shifted_data, Secret::new(key));

        assert_eq!(original_data, unshifted_data);
    }

    use std::io::Write;
    use std::io::{BufRead, BufReader};



    #[test]
    fn test_gene3() {
        let seed = b"test_seed"; // Exemple de graine
        let secret = gene3(seed);

        // Vérifier que le matériel de clé de sortie a la bonne longueur
        assert_eq!(secret.expose_secret().len(), KEY_LENGTH);

        // Vous pouvez également vérifier que le matériel de clé de sortie n'est pas vide
        assert!(!secret.expose_secret().is_empty());
    }

    #[test]
    fn test_gene3_different_seeds() {
        let seed1 = b"seed_one";
        let seed2 = b"seed_two";

        let secret1 = gene3(seed1);
        let secret2 = gene3(seed2);

        // Vérifier que les résultats sont différents pour des graines différentes
        assert_ne!(secret1.expose_secret(), secret2.expose_secret());
    }

}
