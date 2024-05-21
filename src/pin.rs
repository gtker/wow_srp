//! Module for calculating the PIN hash used by [CMD_AUTH_LOGON_CHALLENGE_Server](https://wowdev.wiki/CMD_AUTH_LOGON_CHALLENGE_Server)
//! and [CMD_AUTH_LOGON_PROOF_Client](https://wowdev.wiki/CMD_AUTH_LOGON_PROOF_Client).
//!
//! Use [`get_pin_grid_seed`] and [`get_pin_salt`] on the server to generate values, and then
//! [`calculate_hash`] on the server/client to get the PIN hash.
use rand::{random, thread_rng, Rng, RngCore};
use sha1::digest::FixedOutput;
use sha1::{Digest, Sha1};

const PIN_SALT_SIZE: u8 = 16;
const PIN_HASH_SIZE: u8 = 20;

const MIN_PIN_LENGTH: u8 = 4;
const MAX_PIN_LENGTH: u8 = 10;

const MIN_PIN_VALUE: u64 = 1000;
const MAX_PIN_VALUE: u64 = 9999999999;

/// Represents a PIN code.
///
/// This type upholds the invariants that the PIN must have at least 4 digits, but no more than 10.
#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct PinCode {
    inner: [u8; MAX_PIN_LENGTH as usize],
    length: u8,
}

impl PinCode {
    /// Creates a new [`PinCode`] with random digits and a length of between 4 and 10 digits.
    pub fn new() -> Self {
        let length: u8 = thread_rng().gen_range(4..10);

        let mut inner = [0_u8; MAX_PIN_LENGTH as usize];
        for i in inner.iter_mut().take(length as usize) {
            *i = thread_rng().gen_range(0..10);
        }

        Self { inner, length }
    }

    /// Creates a new [`PinCode`] with random digits and a specific length.
    pub fn random_of_length(length: u8) -> Option<Self> {
        if !(MIN_PIN_LENGTH..MAX_PIN_LENGTH).contains(&length) {
            return None;
        }

        let mut inner = [0_u8; MAX_PIN_LENGTH as usize];
        for i in inner.iter_mut().take(length as usize) {
            *i = thread_rng().gen_range(0..10);
        }

        Some(Self { inner, length })
    }

    /// Create [`PinCode`] from a compressed format of the keypresses.
    ///
    /// Every decimal digit in the number represents a single keypress.
    ///
    /// So `1234` represents the keypresses `1`, `2`, `3`, and `4`.
    ///
    /// The `pin` must be at least `1000` and no higher than `9999999999`.
    pub fn from_u64(pin: u64) -> Option<Self> {
        let mut pin_array = [0_u8; MAX_PIN_LENGTH as usize];
        if !(MIN_PIN_VALUE..=MAX_PIN_VALUE).contains(&pin) {
            return None;
        }

        let length = {
            let bytes = pin_to_bytes(pin, &mut pin_array);
            if bytes.len() < MIN_PIN_LENGTH as usize || bytes.len() > MAX_PIN_LENGTH as usize {
                return None;
            }
            bytes.len() as u8
        };

        Some(Self {
            inner: pin_array,
            length,
        })
    }

    /// Create [`PinCode`] from a slice of separate keypresses between 0 and 9.
    ///
    /// The slice must be at least 4 bytes long, and at most 10.
    pub fn from_slice(pin: &[u8]) -> Option<Self> {
        let valid_length =
            pin.len() >= (MIN_PIN_LENGTH as usize) && pin.len() <= (MAX_PIN_LENGTH as usize);
        let valid_digits = pin.iter().all(|&a| a < 10);

        if valid_length && valid_digits {
            let mut pin_array = [0_u8; MAX_PIN_LENGTH as usize];
            pin_array[..pin.len()].copy_from_slice(pin);
            Some(Self {
                inner: pin_array,
                length: pin.len() as u8,
            })
        } else {
            None
        }
    }

    /// Gets the digits of the PIN as a slice.
    ///
    /// Every byte is in the range `[0;9]` and the length is always between 4 and 10.
    pub fn digits(&self) -> &[u8] {
        &self.inner[..self.length as usize]
    }

    fn digits_mut(&mut self) -> &mut [u8] {
        &mut self.inner[..self.length as usize]
    }

    /// Converts the PIN into the hash required by the implementation.
    pub fn into_hash(
        self,
        pin_grid_seed: u32,
        server_salt: &[u8; 16],
        client_salt: &[u8; 16],
    ) -> [u8; PIN_HASH_SIZE as usize] {
        calculate_hash(self, pin_grid_seed, server_salt, client_salt)
    }
}

impl Default for PinCode {
    fn default() -> Self {
        Self::new()
    }
}

/// Randomized value to be sent in [`CMD_AUTH_LOGON_CHALLENGE_Server`](https://wowdev.wiki/CMD_AUTH_LOGON_CHALLENGE).
///
/// Just a convenience function for generating a random `u32`.
pub fn get_pin_grid_seed() -> u32 {
    random::<u32>()
}

/// Randomized value to be sent in [`CMD_AUTH_LOGON_CHALLENGE_Server`](https://wowdev.wiki/CMD_AUTH_LOGON_CHALLENGE).
///
/// Just a convenience function for generating a 16 byte array.
pub fn get_pin_salt() -> [u8; PIN_SALT_SIZE as usize] {
    let mut buf = [0_u8; PIN_SALT_SIZE as usize];
    thread_rng().fill_bytes(&mut buf);
    buf
}

/// Verify client hash PIN.
///
/// This is just a convenience wrapper around [`calculate_hash`].
///
/// This will also return [`false`] if the `pin` is invalid.
pub fn verify_client_pin_hash(
    pin: PinCode,
    pin_grid_seed: u32,
    server_salt: &[u8; 16],
    client_salt: &[u8; 16],
    client_pin_hash: &[u8; 20],
) -> bool {
    *client_pin_hash == calculate_hash(pin, pin_grid_seed, server_salt, client_salt)
}

/// Calculate the hash of a pin.
#[allow(clippy::missing_panics_doc)] // Can't actually panic
pub fn calculate_hash(
    mut pin: PinCode,
    pin_grid_seed: u32,
    server_salt: &[u8; 16],
    client_salt: &[u8; 16],
) -> [u8; PIN_HASH_SIZE as usize] {
    let bytes = pin.digits_mut();

    let remapped_pin_grid = remap_pin_grid(pin_grid_seed);

    convert_pin_grid(bytes, remapped_pin_grid);

    // Convert to ASCII
    for b in &mut *bytes {
        *b += 0x30;
    }

    let sha1: [u8; 20] = Sha1::new()
        .chain_update(server_salt)
        .chain_update(bytes)
        .finalize_fixed()
        .into();

    Sha1::new()
        .chain_update(client_salt)
        .chain_update(sha1)
        .finalize_fixed()
        .into()
}

fn pin_to_bytes(mut pin: u64, out_pin_array: &mut [u8; MAX_PIN_LENGTH as usize]) -> &mut [u8] {
    let mut i = 0;
    while pin != 0 {
        out_pin_array[i] = (pin % 10) as u8;
        pin /= 10;
        i += 1;
    }

    // Make little endian
    out_pin_array[0..i].reverse();

    &mut out_pin_array[0..i]
}

fn remap_pin_grid(mut pin_grid_seed: u32) -> [u8; MAX_PIN_LENGTH as usize] {
    let mut grid = [0_u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let mut remapped_grid = grid;

    for (remapped_index, i) in (1..=MAX_PIN_LENGTH as u32).rev().enumerate() {
        let remainder = pin_grid_seed % i;
        pin_grid_seed /= i;
        remapped_grid[remapped_index] = grid[remainder as usize];

        let copy_size = i - remainder - 1;

        for i in 0..copy_size as usize {
            grid[remainder as usize + i] = grid[remainder as usize + i + 1];
        }
    }

    remapped_grid
}

fn convert_pin_grid(bytes: &mut [u8], remapped_pin_grid: [u8; MAX_PIN_LENGTH as usize]) {
    for b in &mut *bytes {
        let (i, _) = remapped_pin_grid
            .iter()
            .enumerate()
            .find(|(_, a)| **a == *b)
            .unwrap();
        *b = i as u8;
    }
}

#[cfg(test)]
mod test {
    use crate::hex::hex_decode_be;
    use crate::pin::{
        calculate_hash, convert_pin_grid, pin_to_bytes, remap_pin_grid, PinCode, MAX_PIN_LENGTH,
    };
    use std::convert::TryInto;

    #[test]
    fn test_convert() {
        let content = include_str!("../tests/pin/convert_regression.txt");
        for line in content.lines() {
            let mut line = line.split_whitespace();
            let mut bytes: Vec<u8> = hex_decode_be(line.next().unwrap()).try_into().unwrap();
            let remapped_pin_grid: [u8; 10] =
                hex_decode_be(line.next().unwrap()).try_into().unwrap();
            let expected: Vec<u8> = hex_decode_be(line.next().unwrap()).try_into().unwrap();

            convert_pin_grid(&mut bytes, remapped_pin_grid);
            assert_eq!(bytes, expected);
        }
    }

    #[test]
    fn test_pin_to_bytes() {
        const MINIMUM_PIN: u64 = 1000;

        let _ = PinCode::from_u64(MINIMUM_PIN).unwrap();
        assert!(PinCode::from_u64(MINIMUM_PIN - 1).is_none());
        assert!(PinCode::from_u64(u64::MAX).is_none());

        let mut buf = [0_u8; 10];
        assert_eq!(pin_to_bytes(9999999999, &mut buf).len(), 10);
    }

    #[test]
    fn no_remapping() {
        // Numbers 1, 2, 3, 4
        let pin = PinCode::from_u64(1234).unwrap();
        // No switching
        const PIN_GRID_SEED: u32 = 0;

        const CLIENT_SALT: [u8; 16] = [
            121, 62, 76, 125, 207, 0, 130, 51, 128, 244, 161, 24, 110, 245, 114, 57,
        ];
        const SERVER_SALT: [u8; 16] = [0_u8; 16];
        const EXPECTED: [u8; 20] = [
            13, 132, 14, 117, 154, 168, 208, 143, 51, 176, 230, 6, 61, 161, 46, 249, 51, 210, 44,
            204,
        ];

        let actual = calculate_hash(pin, PIN_GRID_SEED, &SERVER_SALT, &CLIENT_SALT);
        assert_eq!(actual, EXPECTED);

        // Numbers 1, 2, 3, 4
        let pin = PinCode::from_slice(&[1, 2, 3, 4]).unwrap();
        let actual = calculate_hash(pin, PIN_GRID_SEED, &SERVER_SALT, &CLIENT_SALT);
        assert_eq!(actual, EXPECTED);
    }

    #[test]
    fn remap_regression() {
        let content = include_str!("../tests/pin/remap_regression.txt");
        for line in content.lines() {
            let mut line = line.split_whitespace();
            let pin_grid_seed: u32 = line.next().unwrap().parse().unwrap();
            let expected: [u8; 10] = hex_decode_be(line.next().unwrap()).try_into().unwrap();

            let actual = remap_pin_grid(pin_grid_seed);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn remap_1() {
        // Numbers 1, 2, 3, 4
        let pin = PinCode::from_u64(1234).unwrap();

        // No switching
        const PIN_GRID_SEED: u32 = 1;

        const CLIENT_SALT: [u8; 16] = [
            3, 40, 23, 66, 122, 100, 117, 88, 223, 183, 228, 64, 77, 34, 48, 200,
        ];
        const SERVER_SALT: [u8; 16] = [
            60, 173, 61, 234, 37, 169, 6, 63, 59, 213, 23, 47, 63, 221, 103, 43,
        ];
        const EXPECTED: [u8; 20] = [
            136, 112, 171, 81, 112, 16, 230, 239, 233, 104, 224, 107, 29, 5, 59, 117, 227, 167, 18,
            188,
        ];

        let actual = calculate_hash(pin, PIN_GRID_SEED, &SERVER_SALT, &CLIENT_SALT);
        assert_eq!(actual, EXPECTED);
    }

    #[test]
    fn regression() {
        let content = include_str!("../tests/pin/regression.txt");
        for line in content.lines() {
            let mut line = line.split_whitespace();
            let pin = PinCode::from_slice(&hex_decode_be(line.next().unwrap())).unwrap();
            let pin_grid_seed: u32 = line.next().unwrap().parse().unwrap();
            let server_salt: [u8; 16] = hex_decode_be(line.next().unwrap()).try_into().unwrap();
            let client_salt: [u8; 16] = hex_decode_be(line.next().unwrap()).try_into().unwrap();
            let expected: [u8; 20] = hex_decode_be(line.next().unwrap()).try_into().unwrap();

            let actual = calculate_hash(pin, pin_grid_seed, &server_salt, &client_salt);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn remap_pin_grid_1() {
        const EXPECTED: [u8; MAX_PIN_LENGTH as usize] = [1, 0, 2, 3, 4, 5, 6, 7, 8, 9];
        let actual = remap_pin_grid(1);

        assert_eq!(actual, EXPECTED);
    }
}
