//! Module for calculating the PIN hash used by [CMD_AUTH_LOGON_CHALLENGE_Server](https://wowdev.wiki/CMD_AUTH_LOGON_CHALLENGE_Server)
//! and [CMD_AUTH_LOGON_PROOF_Client](https://wowdev.wiki/CMD_AUTH_LOGON_PROOF_Client).
//!
//! Use [`get_pin_grid_seed`] and [`get_pin_salt`] on the server to generate values, and then
//! [`calculate_hash`] on the server/client to get the PIN hash.
use rand::{random, thread_rng, RngCore};
use sha1::digest::FixedOutput;
use sha1::{Digest, Sha1};

const PIN_SALT_SIZE: u8 = 16;
const PIN_HASH_SIZE: u8 = 20;

const MIN_PIN_LENGTH: u8 = 4;
const MAX_PIN_LENGTH: u8 = 10;

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
    pin: u32,
    pin_grid_seed: u32,
    server_salt: &[u8; 16],
    client_salt: &[u8; 16],
    client_pin_hash: &[u8; 20],
) -> bool {
    if let Some(server_pin_hash) = calculate_hash(pin, pin_grid_seed, server_salt, client_salt) {
        server_pin_hash == *client_pin_hash
    } else {
        false
    }
}

/// Calculate the hash of a pin.
///
/// The pin is stored as a `u32` where every base 10 digit is a
/// separate button press.
/// So `1234` would be the button presses `1, 2, 3, 4` in the client.
///
/// Will return [`None`](Option::None) if `pin` is less than `1000`.
#[allow(clippy::missing_panics_doc)] // Can't actually panic
pub fn calculate_hash(
    pin: u32,
    pin_grid_seed: u32,
    server_salt: &[u8; 16],
    client_salt: &[u8; 16],
) -> Option<[u8; PIN_HASH_SIZE as usize]> {
    let mut pin_array = [0_u8; MAX_PIN_LENGTH as usize];
    let remapped_pin_grid = remap_pin_grid(pin_grid_seed);
    let bytes = pin_to_bytes(pin, &mut pin_array);
    if bytes.len() < MIN_PIN_LENGTH as usize || bytes.len() > MAX_PIN_LENGTH as usize {
        return None;
    }

    for b in &mut *bytes {
        let (i, _) = remapped_pin_grid
            .iter()
            .enumerate()
            .find(|(_, a)| **a == *b)
            .unwrap();
        *b = i as u8;
    }

    // Convert to ASCII
    for b in &mut *bytes {
        *b += 0x30;
    }

    let sha1: [u8; 20] = Sha1::new()
        .chain_update(server_salt)
        .chain_update(bytes)
        .finalize_fixed()
        .into();

    Some(
        Sha1::new()
            .chain_update(client_salt)
            .chain_update(sha1)
            .finalize_fixed()
            .into(),
    )
}

fn pin_to_bytes(mut pin: u32, out_pin_array: &mut [u8; MAX_PIN_LENGTH as usize]) -> &mut [u8] {
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

#[cfg(test)]
mod test {
    use crate::hex::hex_decode;
    use crate::pin::{calculate_hash, remap_pin_grid, MAX_PIN_LENGTH};
    use std::convert::TryInto;

    #[test]
    fn no_remapping() {
        // Numbers 1, 2, 3, 4
        const PIN: u32 = 1234;
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

        let actual = calculate_hash(PIN, PIN_GRID_SEED, &SERVER_SALT, &CLIENT_SALT);
        assert_eq!(actual, Some(EXPECTED));
    }

    #[test]
    fn remap_1() {
        // Numbers 1, 2, 3, 4
        const PIN: u32 = 1234;
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

        let actual = calculate_hash(PIN, PIN_GRID_SEED, &SERVER_SALT, &CLIENT_SALT);
        assert_eq!(actual, Some(EXPECTED));
    }

    #[test]
    fn regression() {
        let content = include_str!("../tests/pin/regression.txt");
        for line in content.lines() {
            let mut line = line.split_whitespace();
            let pin: u32 = line.next().unwrap().parse().unwrap();
            let pin_grid_seed: u32 = line.next().unwrap().parse().unwrap();
            let server_salt: [u8; 16] = hex_decode(line.next().unwrap()).try_into().unwrap();
            let client_salt: [u8; 16] = hex_decode(line.next().unwrap()).try_into().unwrap();
            let expected: [u8; 20] = hex_decode(line.next().unwrap()).try_into().unwrap();

            let actual = calculate_hash(pin, pin_grid_seed, &server_salt, &client_salt);
            assert_eq!(actual, Some(expected));
        }
    }

    #[test]
    fn remap_pin_grid_1() {
        const EXPECTED: [u8; MAX_PIN_LENGTH as usize] = [1, 0, 2, 3, 4, 5, 6, 7, 8, 9];
        let actual = remap_pin_grid(1);

        assert_eq!(actual, EXPECTED);
    }
}
