use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use blake3::Hasher;
use rayon::iter::ParallelIterator;
use rayon::prelude::{IntoParallelIterator, IntoParallelRefIterator};
use secrecy::ExposeSecret;
use sysinfo::{Networks, Pid, ProcessesToUpdate, System};

use crate::kdfwagen::kdfwagen;
use crate::systemtrayerror::SystemTrayError;

const MAX_RESEED_INTERVAL: u128 = 60;
const MAX_POOL_SIZE: usize = 1024;
const RESEED_THRESHOLD: usize = 512;

pub struct Nebula {
    seed: u128,
    pool: Mutex<VecDeque<u8>>,
    last_reseed_time: u128,
    bytes_since_reseed: Mutex<usize>,
}

impl Nebula {
/// Creates a new instance of the `Nebula` struct with the specified seed.
///
/// This function creates a new instance of the `Nebula` struct with the specified seed and initializes its internal state.
///
/// # Arguments
///
/// * `seed` - A 128-bit seed value to initialize the pseudo-random number generator.
///
/// # Returns
///
/// A new instance of the `Nebula` struct with the specified seed and initialized internal state.
///
/// # Examples
///
/// ```
/// use your_crate::Nebula;
///
/// // Create a new Nebula instance with a seed value of 123456789
/// let nebula = Nebula::new(123456789);
/// ```
    pub fn new(seed: u128) -> Self {
        Nebula {
            seed,
            pool: Mutex::new(VecDeque::new()),
            last_reseed_time: 0,
            bytes_since_reseed: Mutex::new(0),
        }
    }

    
/// Adds entropy to the internal pool of the `Nebula` struct.
///
/// This method adds entropy to the internal pool of the `Nebula` struct by hashing and incorporating entropy sources.
///
/// # Errors
///
/// This method returns an error if there's an issue with gathering entropy sources or hashing.
///
/// # Examples
///
/// ```
/// use your_crate::{Nebula, SystemTrayError};
///
/// # fn main() -> Result<(), SystemTrayError> {
/// let nebula = Nebula::new(123456789);
///
/// // Add entropy to the Nebula instance's pool
/// nebula.add_entropy()?;
/// # Ok(())
/// # }
/// ```
    pub fn add_entropy(&self) -> Result<(), SystemTrayError> {


        let mut pool = self.pool.lock().unwrap();
        if pool.len() >= MAX_POOL_SIZE {
            pool.pop_front();
        }

        let mut entropy_sources = data_computer()?;
        self.shuffle_array(&mut entropy_sources);
        for source in &entropy_sources {
            let entropy_bytes = source.to_be_bytes();
            let mut hasher = Hasher::new();
            hasher.update(&entropy_bytes);
            let mut hash = [0; 64];
            hasher.finalize_xof().fill(&mut hash);
            pool.extend(hash.iter());
        }
        Ok(())
    }

    
/// Shuffles elements of an array using a cryptographic pseudorandom number generator.
///
/// This method shuffles elements of a generic array using the cryptographic pseudorandom number generator of the `Nebula` struct.
///
/// # Arguments
///
/// * `array` - A mutable reference to a generic array whose elements need to be shuffled.
///
/// # Example
///
/// ```
/// use your_crate::Nebula;
///
/// let mut array = [1, 2, 3, 4, 5];
/// let nebula = Nebula::new(123456789);
///
/// // Shuffle the elements of the array using the Nebula instance
/// nebula.shuffle_array(&mut array);
/// ```
    fn shuffle_array<T>(&self, array: &mut [T]) {
        let mut rng = Nebula::new(secured_seed());
        rng.combine_entropy();
        let len = array.len();
        for i in (1..len).rev() {
            match rng.generate_bounded_number(0, i as u128) {
                Ok(random_number) => {
                    let j = random_number as usize;
                    array.swap(i, j);
                }
                Err(err) => {
                    eprintln!("SystemTrayError: {:?}", err);
                }
            }
        }
    }

/// Reseeds the internal state of the `Nebula` struct.
///
/// This method reseeds the internal state of the `Nebula` struct with a new seed and additional entropy.
/// It performs reseeding based on adaptive conditions and periodically based on time.
///
/// # Arguments
///
/// * `new_seed` - A new seed value to reseed the `Nebula` instance.
///
/// # Example
///
/// ```
/// use your_crate::Nebula;
///
/// let mut nebula = Nebula::new(123456789);
///
/// // Reseed the Nebula instance with a new seed value
/// nebula.reseed(987654321);
/// ```
fn reseed(&mut self, new_seed: u128) {
    {
        let mut bytes_since_reseed = self.bytes_since_reseed.lock().unwrap();

        if *bytes_since_reseed < RESEED_THRESHOLD {
            return;
        }

        *bytes_since_reseed = 0;
    }

    // Gather additional entropy
    let _ = self.add_entropy();
    let combined_entropy = self.combine_entropy();

    // Create a new seed using the BLAKE3 hash function
    let mut hasher = Hasher::new();
    hasher.update(&self.seed.to_be_bytes());
    hasher.update(&new_seed.to_be_bytes());
    hasher.update(&combined_entropy.to_be_bytes());
    hasher.update(&self.last_reseed_time.to_be_bytes());

    // Finalize the hash and use the first 16 bytes as the new seed
    let hash_result = hasher.finalize();
    self.seed = u128::from_be_bytes(hash_result.as_bytes()[0..16].try_into().unwrap());

    // Update the last reseed time
    self.last_reseed_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();

    // Clear the pool to prevent leakage of old entropy
    let mut pool = self.pool.lock().unwrap();
    pool.clear();
}


    /// Combines entropy in the `Nebula` struct to produce a new seed value.
///
/// This method combines the entropy present in the internal pool of the `Nebula` struct with other factors, such as the current seed and last reseed time, to produce a new seed value.
///
/// # Returns
///
/// A new seed value resulting from the combination of entropy present in the internal pool, the current seed, and the last reseed time.
///
/// # Example
///
/// ```
/// use your_crate::Nebula;
///
/// let nebula = Nebula::new(123456789);
///
/// // Combine entropy and obtain a new seed value
/// let new_seed = nebula.combine_entropy();
/// ```
    fn combine_entropy(&self) -> u128 {
        let mut hasher = Hasher::new();

        // Add the current seed
        hasher.update(&self.seed.to_be_bytes());

        // Lock the pool and add its bytes
        let mut pool = self.pool.lock().unwrap();
        hasher.update(pool.make_contiguous()); // Efficiently add all bytes in the pool

        // Add additional entropy sources
        hasher.update(&self.last_reseed_time.to_be_bytes());
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        hasher.update(&current_time.to_be_bytes());

        // Finalize the hash and convert the first 16 bytes to u128
        let hash_result = hasher.finalize();
        u128::from_be_bytes(hash_result.as_bytes()[0..16].try_into().unwrap())
    }

/// Mixes entropy in the `Nebula` struct to enhance randomness.
///
/// This method mixes the given entropy value with the existing internal pool of the `Nebula` struct to enhance randomness.
///
/// # Arguments
///
/// * `entropy` - A 128-bit entropy value to be mixed with the internal pool.
///
/// # Example
///
/// ```
/// use your_crate::Nebula;
///
/// let mut nebula = Nebula::new(123456789);
///
/// // Mix the given entropy with the internal pool
/// let entropy = 987654321;
/// nebula.mix_entropy(entropy);
/// ```
    fn mix_entropy(&mut self, entropy: u128) {
        let entropy_bytes = entropy.to_be_bytes();

        let mut hasher = Hasher::new();
        hasher.update(self.pool.lock().unwrap().make_contiguous());
        hasher.update(&entropy_bytes);

        let mut hash = [0; 64];
        hasher.finalize_xof().fill(&mut hash);
        self.pool = Mutex::new(VecDeque::from(hash.to_vec()));
    }

/// Generates a sequence of random bytes using the `Nebula` struct's internal state.
///
/// This method generates a sequence of random bytes using the `Nebula` struct's internal state.
///
/// # Arguments
///
/// * `count` - The number of random bytes to generate.
///
/// # Returns
///
/// A vector containing the generated random bytes.
///
/// # Example
///
/// ```
/// use your_crate::Nebula;
///
/// let mut nebula = Nebula::new(123456789);
///
/// // Generate 10 random bytes
/// let random_bytes = nebula.generate_random_bytes(10);
/// ```
pub(crate) fn generate_random_bytes(&mut self, count: usize) -> Vec<u8> {
    let mut random_bytes = Vec::with_capacity(count);
    let mut hasher = Hasher::new(); // Utilisez un algorithme de hachage sécurisé

    for _ in 0..count {
        // Combinez l'entropie à chaque itération
        let entropy = self.combine_entropy();
        self.mix_entropy(entropy);

        // Ajoutez l'entropie au hachage
        hasher.update(&entropy.to_be_bytes());

        // Finalisez le hachage pour obtenir un nouvel octet aléatoire
        let hash_result = hasher.finalize();
        let random_byte = hash_result.as_bytes()[0]; // Prenez le premier octet du hachage
        random_bytes.push(random_byte);

        // Réinitialisez le hachage pour la prochaine itération
        hasher = Hasher::new();
    }

    // Reseed avec le dernier octet généré
    let last_byte = random_bytes.last().copied().unwrap_or(0);
    self.reseed(last_byte as u128);

    random_bytes
}

/// Generates a 128-bit random number using the `Nebula` struct's internal state.
///
/// This method generates a 128-bit random number using the `Nebula` struct's internal state.
///
/// # Returns
///
/// A 128-bit random number.
///
/// # Example
///
/// ```
/// use your_crate::Nebula;
///
/// let mut nebula = Nebula::new(123456789);
///
/// // Generate a random number
/// let random_number = nebula.generate_random_number();
/// ```
pub(crate) fn generate_random_number(&mut self) -> u128 {
        let random_bytes = self.generate_random_bytes(8);

        let mut random_number: u128 = 0;

        for &byte in &random_bytes {
            random_number = (random_number << 8) | u128::from(byte);
        }

        random_number
    }

/// Generates a bounded random number using the `Nebula` struct's internal state.
///
/// This method generates a random number within a specified range using the `Nebula` struct's internal state.
///
/// # Arguments
///
/// * `min` - The minimum value (inclusive) of the range.
/// * `max` - The maximum value (inclusive) of the range.
///
/// # Returns
///
/// A random number within the specified range.
///
/// # Errors
///
/// An error is returned if `min` is greater than `max`.
///
/// # Example
///
/// ```
/// use your_crate::{Nebula, SystemTrayError};
///
/// let mut nebula = Nebula::new(123456789);
///
/// // Generate a random number within the range [10, 20]
/// match nebula.generate_bounded_number(10, 20) {
///     Ok(random_number) => {
///         println!("Random number within the range: {}", random_number);
///     },
///     Err(err) => {
///         eprintln!("Error: {}", err);
///     },
/// }
/// ```
    pub fn generate_bounded_number(&mut self, min: u128, max: u128) -> Result<u128, SystemTrayError> {
        if min > max {
            return Err(SystemTrayError::new(9));
        }
        let random_number = self.generate_random_number();

        Ok(min + (random_number % (max - min + 1)))
    }
}

/// Gathers system data for entropy generation.
///
/// This function gathers various system-related data to be used for entropy generation in cryptographic operations.
///
/// # Returns
///
/// An array containing system-related data for entropy generation. The array has a fixed length of 10 and includes the following elements:
/// - Current system time in nanoseconds since the UNIX epoch.
/// - Process ID of the current process.
/// - Total system memory.
/// - Used system memory.
/// - Total swap space.
/// - Number of CPUs.
/// - Total disk read bytes of all processes.
/// - System uptime in seconds.
/// - System boot time in seconds since the UNIX epoch.
/// - Total network data transfer across all network interfaces.
///
/// # Errors
///
/// An error is returned if the total disk usage by all processes is zero, indicating a failure to retrieve disk usage data.
///
/// # Example
///
/// ```
/// use your_crate::{data_computer, SystemTrayError};
///
/// // Gather system-related data for entropy generation
/// match data_computer() {
///     Ok(system_data) => {
///         println!("System data: {:?}", system_data);
///     },
///     Err(err) => {
///         eprintln!("Error: {}", err);
///     },
/// }
/// ```
fn data_computer() -> Result<[u128; 10], SystemTrayError> {
    let mut sys = System::new();
    sys.refresh_memory();

    let mut s = System::new();
    s.refresh_processes(ProcessesToUpdate::All);

    let total_memory = sys.total_memory();
    let used_memory = sys.used_memory();
    let total_swap = sys.total_swap();
    let cpu = s.cpus().len() as u128;
    let uptime = System::uptime() as u128;
    let boot_time= System::boot_time() as u128;

    let networks = Networks::new_with_refreshed_list();
    let network_data: u128 = calculate_network_data(&networks);

    let pid_set: HashSet<&Pid> = s.processes().keys().collect();
    let pid_disk_usage: u128 = pid_set.into_par_iter()
        .map(|&pid| calculate_disk_usage(&s, pid))
        .sum();

    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos();

    let pid = std::process::id();

    Ok([time, pid.into(), total_memory as u128, used_memory as u128, total_swap as u128, pid_disk_usage, uptime, boot_time, network_data, cpu])
}

fn calculate_network_data(network: &Networks) -> u128 {
    network.par_iter()
        .map(|(_, network)| {
            network.received() as u128
                + network.total_received() as u128
                + network.transmitted() as u128
                + network.total_transmitted() as u128
                + network.packets_received() as u128
                + network.total_packets_received() as u128
                + network.packets_transmitted() as u128
                + network.total_packets_transmitted() as u128
                + network.errors_on_received() as u128
                + network.total_errors_on_received() as u128
                + network.errors_on_transmitted() as u128
        })
        .sum()
}

fn calculate_disk_usage(sys: &System, pid: Pid) -> u128 {
    sys.process(pid)
        .map_or(0, |process| process.disk_usage().total_read_bytes as u128)
}

/// Generates a secured seed for cryptographic operations.
///
/// This function generates a secured seed by combining system-related data and current system time.
///
/// # Returns
///
/// A secured seed for cryptographic operations.
///
/// # Panics
///
/// Panics if the current system time goes backwards.
///
/// # Example
///
/// ```
/// use your_crate::secured_seed;
///
/// // Generate a secured seed for cryptographic operations
/// let seed = secured_seed();
/// ```
pub fn secured_seed() -> u128 {
    let actual_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos();

    let context_bytes: Vec<u8> = data_computer()
        .unwrap()
        .par_iter()
        .flat_map(|&x| x.to_be_bytes())
        .collect();

    let key = kdfwagen(&context_bytes, &actual_time.to_be_bytes(), 10);
    let key = key.expose_secret();

    let (part1, part2): (&[u8], &[u8]) = key.split_at(256);

    let sum1: u128 = part1.par_iter().map(|&x| x as u128).sum();
    let sum2: u128 = part2.par_iter().map(|&x| x as u128).sum();

    sum1.wrapping_mul(sum2)
}

/// Shuffles the elements of a slice.
///
/// This function shuffles the elements of a slice using a secured seed for randomness.
///
/// # Arguments
///
/// * `items` - A mutable reference to a slice of elements that need to be shuffled.
///
/// # Example
///
/// ```
/// use your_crate::shuffle;
///
/// // Create a vector of integers
/// let mut numbers = vec![1, 2, 3, 4, 5];
///
/// // Shuffle the vector
/// shuffle(&mut numbers);
///
/// // Now `numbers` contains shuffled elements
/// ```
pub fn shuffle<T>(items: &mut [T]) {
    let len = items.len();
    for i in (1..len).rev() {
        let j = (secured_seed() as usize) % (i + 1);
        items.swap(i, j);
    }
}

/// Shuffles the elements of a slice with a specified seed.
///
/// This function shuffles the elements of a slice using a specified seed for randomness.
///
/// # Arguments
///
/// * `items` - A mutable reference to a slice of elements that need to be shuffled.
/// * `seed` - The seed used for shuffling. It determines the randomness of the shuffle.
///
/// # Example
///
/// ```
/// use your_crate::seeded_shuffle;
///
/// // Create a vector of integers
/// let mut numbers = vec![1, 2, 3, 4, 5];
///
/// // Shuffle the vector with a specified seed
/// seeded_shuffle(&mut numbers, 123);
///
/// // Now `numbers` contains shuffled elements based on the seed
/// ```
pub fn seeded_shuffle<T>(items: &mut [T], seed: usize) {
    let len = items.len();
    for i in (1..len).rev() {
        let j = (seed) % (i + 1);
        items.swap(i, j);
    }
}

////////// function test
fn monobit_test(sequence: &[u8]) -> bool {
    let total_bits = sequence.len() * 8;
    let mut one_bits: i32 = 0;

    for &byte in sequence {
        for i in 0..8 {
            one_bits = match one_bits.checked_add(((byte >> i) & 1) as i32) {
                Some(v) => v,
                None => return false, // or handle overflow in another way
            };
        }
    }

    let zero_bits = total_bits - one_bits as usize;
    let difference = (one_bits as isize - zero_bits as isize).abs();
    println!("{difference} sur {}", (total_bits as f64).sqrt());
    // The difference should be less than the square root of the total number of bits
    difference < (total_bits as f64).sqrt() as isize
}


#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn test_add_entropy() {
        let rng = Nebula::new(12345);
        let initial_state = rng.pool.lock().unwrap().clone();
        let _ = rng.add_entropy();
        println!("{:?} {:?}", initial_state, rng.pool.lock().unwrap());
        assert_ne!(*rng.pool.lock().unwrap(), initial_state, "L'ajout d'entropie n'a pas modifié l'état du générateur");
    }

    #[test]
    fn test_reseed() {
        let mut rng = Nebula::new(12345);
        let initial_state = rng.pool.lock().unwrap().clone();
        // Generate enough random bytes to meet the reseed threshold
        for _ in 0..(RESEED_THRESHOLD / 8) {
            rng.generate_random_bytes(8);
        }
        rng.reseed(67890);
        assert_ne!(*rng.pool.lock().unwrap(), initial_state, "La méthode reseed n'a pas modifié l'état du générateur");
    }

    #[test]
    fn test_generate_random_bytes() {
        let mut rng = Nebula::new(12345);
        let first = rng.generate_random_bytes(10);
        let second = rng.generate_random_bytes(10);
        assert_ne!(first, second, "Les deux appels à generate_random_bytes ont produit les mêmes résultats");
    }

    #[test]
    fn test_printer(){
        let mut rng = Nebula::new(12345);
        for _ in 0..10 {
            rng.reseed(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
            let random_bytes = rng.generate_random_number();
            println!("{:?}", random_bytes);
        }
    }
    #[test]
    fn test_generate_bounded_number() {
        let mut rng = Nebula::new(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
        let mut distribution_counts = HashMap::new();

        for _ in 0..100 {
            let number = rng.generate_bounded_number(10, 20).unwrap();

            // Mettez à jour le compteur de distribution
            let count = distribution_counts.entry(number).or_insert(0);
            *count += 1;

            assert!((10..=20).contains(&number), "Le nombre généré est hors de la plage spécifiée");
        }

        // Afficher la répartition des valeurs
        println!("Répartition des valeurs générées :");
        for (value, count) in &distribution_counts {
            println!("Valeur {}: {} fois", value, count);
        }
    }

    #[test]
    fn test_shuffle_string() {
        let mut s = "1234567890".chars().collect::<Vec<_>>();
        let original = s.clone().into_iter().collect::<String>();
        shuffle(&mut s);
        let shuffled = s.into_iter().collect::<String>();
        println!("shuffled: {}", shuffled);
        assert_ne!(shuffled, original, "The string was not shuffled");
    }

    #[test]
    fn test_seeded_shuffle() {
        let mut items = "1234567890".chars().collect::<Vec<_>>();
        let original = items.clone();
        seeded_shuffle(&mut items, 12345);
        assert_ne!(items, original, "The string was not shuffled");
        let shuffled = items.clone().into_iter().collect::<String>();
        println!("shuffled: {}", shuffled);
    }

    #[test]
    fn test_generate_bounded_number_distribution() {
        let mut rng = Nebula::new(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
        let mut distribution_counts = HashMap::new();

        for _ in 0..100000 {
            let number = rng.generate_bounded_number(10, 20).unwrap();

            // Update the distribution counter
            let count = distribution_counts.entry(number).or_insert(0);
            *count += 1;

            assert!((10..=20).contains(&number), "Generated number is outside the specified range");
        }

        // Check if the distribution is uniform
        let expected_count = 100000 / 11; // 11 because numbers from 10 to 20 inclusive
        let tolerance = (expected_count as f64 * 0.1).round() as usize; // 10% tolerance

        for count in distribution_counts.values() {
            println!("count: {}", count);
            assert!(*count >= expected_count - tolerance && *count <= expected_count + tolerance, "Distribution is not uniform");
        }
    }

    #[test]
    fn test_monobit() {
        let mut rng = Nebula::new(12345);
        let sequence = rng.generate_random_bytes(1000000);
        assert!(monobit_test(&sequence), "monobit test has not been passed");
    }

    #[test]
    fn test_secureseed() {
        let a = secured_seed();
        println!("{a}");
        let mut rng = Nebula::new(a);

        for _ in 0..10 {
            let random_bytes = rng.generate_random_number();
            println!("{:?}", random_bytes);
        }

    }

    #[test]
    fn monte_carlo_test() {
        const SAMPLE_SIZE: usize = 10000;

        let mut nebula = Nebula::new(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
        let mut ones_count:i64 = 0;
        let mut zeros_count:i64 = 0;

        for _ in 0..SAMPLE_SIZE {
            let random_bit = nebula.generate_bounded_number(0, 1).unwrap();

            match random_bit {
                0 => zeros_count += 1,
                1 => ones_count += 1,
                _ => panic!("Unexpected value from PRNG"),
            }
        }

        // Calculate the proportion of ones and zerosdo
        let ones_proportion = ones_count as f64 / SAMPLE_SIZE as f64;
        let zeros_proportion = zeros_count as f64 / SAMPLE_SIZE as f64;
        println!("{} || {}", ones_proportion, zeros_proportion);

        // Check if the proportions are roughly equal (within some tolerance)
        // Adjust the tolerance based on your requirements
        assert!((ones_proportion - zeros_proportion).abs() < 0.02);
    }

    #[test]
    fn test_global(){
        //println!("{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
        println!("{}",secured_seed());
    }

    #[test]
    fn test_speed(){
        println!("{:?}", data_computer().unwrap());
    }
}
