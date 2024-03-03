//! Functionality for the Matrix Card system.
//!
//! Matrix Cards are essentially pre shared keys where the client is tested on
//! a randomized part of the key on every login.
//! This means that you will need to send the data from [`MatrixCard`] through a different
//! channel such as e-mail or website login.
//!
//! The general workflow for servers is:
//!
//! 1. Create the randomized data for the card with a [`MatrixCard`].
//! 2. Send the [`MatrixCard`] data to the client, possibly printing it using [`MatrixCard::to_printer`].
//! 3. Saving the [`MatrixCard`] to the database using [`MatrixCard::data`], and all non-hardcoded parameters.
//! 4. Upon login, retrieve the data and regenerate a [`MatrixCard`].
//! 5. Retrieve the proof from the client and use [`verify_matrix_card_hash`] to verify that the hashes match.
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use wow_srp::matrix_card::{get_matrix_card_seed, MatrixCard, MatrixCardVerifier, verify_matrix_card_hash};
//! use wow_srp::{PROOF_LENGTH, SESSION_KEY_LENGTH};
//!
//! const DIGIT_COUNT: u8 = 2;
//! const HEIGHT: u8 = 8;
//! const WIDTH: u8 = 10;
//!
//! const CHALLENGE_COUNT: u8 = 1;
//! let seed = get_matrix_card_seed();
//! const SESSION_KEY: &[u8; SESSION_KEY_LENGTH as usize] = &[
//!     102, 94, 221, 27, 188, 90, 39, 16, 200, 68, 41, 48, 224, 105, 1, 102, 18, 212, 59, 119,
//!     207, 76, 237, 37, 240, 225, 148, 192, 63, 31, 65, 98, 142, 197, 217, 88, 34, 85, 72, 158,
//! ];
//!
//! const CLIENT_PROOF: &[u8; PROOF_LENGTH as usize] = &[
//!     193, 75, 79, 43, 182, 117, 141, 123, 100, 155, 172, 137, 139, 67, 215, 195, 187, 55, 30,
//!     231,
//! ];
//!
//! let matrix_card = MatrixCard::new(DIGIT_COUNT, HEIGHT, WIDTH);
//!
//! if !verify_matrix_card_hash(&matrix_card, CHALLENGE_COUNT, seed, SESSION_KEY, CLIENT_PROOF) {
//!     println!("Do not let this client log in.");
//! }
//!
//! # Ok(())
//! # }
//! ```
//!
//! For clients the workflow is:
//!
//! 1. Receive the randomized data somehow and either enter it into a [`MatrixCard`], or just use the [`MatrixCardVerifier`] directly
//! 2. Create a [`MatrixCardVerifier`] and use the methods to enter digits provided by the user.
//! 3. Send the proof to the server.
//!
//! ```rust
//! # fn t() -> Option<()> {
//! use wow_srp::matrix_card::{get_matrix_card_seed, MatrixCard, MatrixCardVerifier, verify_matrix_card_hash};
//! use wow_srp::{PROOF_LENGTH, SESSION_KEY_LENGTH};
//!
//! const DIGIT_COUNT: u8 = 2;
//! const HEIGHT: u8 = 8;
//! const WIDTH: u8 = 10;
//!
//! const CHALLENGE_COUNT: u8 = 1;
//! let seed = get_matrix_card_seed();
//! const SESSION_KEY: &[u8; SESSION_KEY_LENGTH as usize] = &[
//!     102, 94, 221, 27, 188, 90, 39, 16, 200, 68, 41, 48, 224, 105, 1, 102, 18, 212, 59, 119,
//!     207, 76, 237, 37, 240, 225, 148, 192, 63, 31, 65, 98, 142, 197, 217, 88, 34, 85, 72, 158,
//! ];
//!
//! const CLIENT_PROOF: &[u8; PROOF_LENGTH as usize] = &[
//!     193, 75, 79, 43, 182, 117, 141, 123, 100, 155, 172, 137, 139, 67, 215, 195, 187, 55, 30,
//!     231,
//! ];
//!
//! let matrix_card = MatrixCard::new(DIGIT_COUNT, HEIGHT, WIDTH);
//!
//! let mut verifier = MatrixCardVerifier::new(CHALLENGE_COUNT, HEIGHT, seed, WIDTH, SESSION_KEY);
//!
//! let (x, y) = verifier.get_matrix_coordinates(0)?;
//! let digits = matrix_card.get_number_at_coordinates(x, y);
//!
//! for digit in digits {
//!     verifier.enter_value(*digit);
//! }
//!
//! if !verify_matrix_card_hash(&matrix_card, CHALLENGE_COUNT, seed, SESSION_KEY, CLIENT_PROOF) {
//!     println!("Do not let this client log in.");
//! }
//!
//! # Some(())
//! # }
//! ```
//!
use crate::key::SHA1_HASH_LENGTH;
use crate::rc4::Rc4;
use crate::SESSION_KEY_LENGTH;
use hmac::digest::FixedOutput;
use hmac::{Hmac, Mac};
use md5::Context;
use rand::distributions::Uniform;
use rand::prelude::Distribution;
use rand::thread_rng;
use sha1::Sha1;
use std::slice::Chunks;

const MIN_MATRIX_CARD_VALUE: u8 = 0;
const MAX_MATRIX_CARD_VALUE: u8 = 9;

/// Randomized value to be sent in [`CMD_AUTH_LOGON_CHALLENGE_Server`](https://wowdev.wiki/CMD_AUTH_LOGON_CHALLENGE).
///
/// Just a convenience function for generating an 8 byte array.
pub fn get_matrix_card_seed() -> u64 {
    rand::random::<u64>()
}

/// Verify client matrix card entries.
pub fn verify_matrix_card_hash(
    matrix_card: &MatrixCard,
    challenge_count: u8,
    seed: u64,
    session_key: &[u8; SESSION_KEY_LENGTH as usize],
    client_proof: &[u8; SHA1_HASH_LENGTH as usize],
) -> bool {
    let mut v = MatrixCardVerifier::new(
        challenge_count,
        matrix_card.height(),
        seed,
        matrix_card.width(),
        session_key,
    );

    for round in 0..challenge_count {
        let (x, y) = v.get_matrix_coordinates(round).unwrap();

        for digit in matrix_card.get_number_at_coordinates(x, y) {
            v.enter_value(*digit);
        }
    }

    let server_proof = v.into_proof();
    server_proof == *client_proof
}

/// Represents the physical card that would be given to clients.
///
/// Use [`Self::to_printer`] in order to have human-readable output.
pub struct MatrixCard {
    digit_count: u8,
    width: u8,
    height: u8,
    data: Vec<u8>,
}

impl MatrixCard {
    /// Creates a new randomized Matrix Card.
    pub fn new(digit_count: u8, height: u8, width: u8) -> Self {
        let mut data = vec![0_u8; Self::get_matrix_card_size(digit_count, height, width)];

        fill_matrix_card_values(&mut data);

        Self {
            digit_count,
            width,
            height,
            data,
        }
    }

    /// Returns the digits at the specified position.
    ///
    /// Amount of bytes returned will depend on the `digit_count` the struct
    /// was instantiated with.
    pub fn get_number_at_coordinates(&self, x: u8, y: u8) -> &[u8] {
        let start = x as usize * y as usize;
        let end = start + self.digit_count as usize;

        &self.data[start..end]
    }

    /// The amount of bytes required to store the data for the matrix card.
    pub fn get_matrix_card_size(digit_count: u8, height: u8, width: u8) -> usize {
        let digit_count: usize = digit_count.into();
        let height: usize = height.into();
        let width: usize = width.into();

        digit_count * height * width
    }

    /// The randomized matrix card data itself.
    ///
    /// Store this in the database and use [`Self::from_data`] to recreate it.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Recreate the Matrix Card from database values.
    pub fn from_data(digit_count: u8, height: u8, width: u8, data: Vec<u8>) -> Option<Self> {
        let expected_size = Self::get_matrix_card_size(digit_count, height, width);
        if data.len() != expected_size {
            return None;
        }

        Some(Self {
            digit_count,
            width,
            height,
            data,
        })
    }

    /// Creates an iterator of strings over the individual fields in the card.
    pub fn to_printer(&self) -> MatrixCardPrinter {
        MatrixCardPrinter {
            chunks: self.data.chunks(self.digit_count.into()),
        }
    }

    /// The width of the card (x).
    pub fn width(&self) -> u8 {
        self.width
    }

    /// The height of the card (y).
    pub fn height(&self) -> u8 {
        self.height
    }

    /// Amount of digits per cell.
    pub fn digit_count(&self) -> u8 {
        self.digit_count
    }
}

/// Iterator over the cells as strings.
pub struct MatrixCardPrinter<'a> {
    chunks: Chunks<'a, u8>,
}

impl Iterator for MatrixCardPrinter<'_> {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(bytes) = self.chunks.next() {
            let mut s = String::with_capacity(8);

            for b in bytes {
                s += &*b.to_string();
            }

            Some(s)
        } else {
            None
        }
    }
}

fn fill_matrix_card_values(buf: &mut [u8]) {
    let mut rng = thread_rng();
    let die = Uniform::from(MIN_MATRIX_CARD_VALUE..=MAX_MATRIX_CARD_VALUE);

    for b in buf {
        *b = die.sample(&mut rng);
    }
}

/// Struct to enter digits and create a final proof.
///
/// Use this for clients and [`verify_matrix_card_hash`] for servers.
pub struct MatrixCardVerifier {
    challenge_count: u8,
    height: u8,
    width: u8,
    coordinates: Vec<u8>,
    hmac: Hmac<Sha1>,
    rc4: Rc4,
}

impl MatrixCardVerifier {
    /// Create a new verifier.
    pub fn new(
        challenge_count: u8,
        height: u8,
        seed: u64,
        width: u8,
        session_key: &[u8; SESSION_KEY_LENGTH as usize],
    ) -> Self {
        let coordinates = generate_coordinates(width, height, challenge_count, seed);

        let mut md5 = Context::new();
        md5.consume(&seed.to_le_bytes());
        md5.consume(&session_key);
        let md5 = md5.compute().0;

        let rc4 = Rc4::new(&md5);

        let hmac = Hmac::<Sha1>::new_from_slice(&md5).unwrap();

        Self {
            challenge_count,
            height,
            width,
            coordinates,
            hmac,
            rc4,
        }
    }

    /// Returns the coordinates required for a specific round.
    ///
    /// This is in the for of `(x, y)`.
    pub fn get_matrix_coordinates(&mut self, round: u8) -> Option<(u8, u8)> {
        if round > self.challenge_count {
            return None;
        }

        let coord = self.coordinates[round as usize];
        let x = coord % self.width;
        let y = coord % self.width;

        if y >= self.height {
            return None;
        }

        return Some((x, y));
    }

    /// Enter a single digit of a code.
    ///
    /// Note that if the cell says `934`, you should first enter `9_u8`, then `3_u8`, and then `4_u8`.
    /// You do not need to do anything in between cells.
    pub fn enter_value(&mut self, value: u8) {
        let value = &mut [value];
        self.rc4.apply_keystream(value.as_mut_slice());
        self.hmac.update(value);
    }

    /// Turns the verifier into the proof that is either sent to the server, or compared
    /// to the client proof.
    pub fn into_proof(self) -> [u8; SHA1_HASH_LENGTH as usize] {
        self.hmac.finalize_fixed().into()
    }
}

fn generate_coordinates(width: u8, height: u8, challenge_count: u8, mut seed: u64) -> Vec<u8> {
    let mut coordinates = vec![0_u8; challenge_count.into()];

    let matrix_size = width * height;
    let mut matrix_indices = vec![0_u8; matrix_size.into()];

    for i in 1..matrix_size {
        matrix_indices[i as usize] = i;
    }

    for i in 0..challenge_count {
        let count = matrix_size - i;
        let index = seed % count as u64;

        coordinates[i as usize] = matrix_indices[index as usize];

        for j in index..(count as u64 - 1) {
            matrix_indices[j as usize] = matrix_indices[j as usize + 1];
        }

        seed /= count as u64;
    }

    coordinates
}

#[test]
fn real_3_3_5_client() {
    const SESSION_KEY: [u8; 40] = [
        46, 167, 52, 11, 179, 156, 220, 26, 87, 175, 253, 222, 115, 66, 233, 19, 167, 238, 19, 84,
        138, 175, 136, 247, 241, 239, 119, 140, 15, 202, 125, 85, 137, 178, 159, 127, 134, 58, 46,
        126,
    ];

    const CHALLENGE_COUNT: u8 = 1;
    const HEIGHT: u8 = 10;
    const SEED: u64 = 0;
    const WIDTH: u8 = 8;
    let mut card = MatrixCardVerifier::new(CHALLENGE_COUNT, HEIGHT, SEED, WIDTH, &SESSION_KEY);
    card.enter_value(0);
    card.enter_value(0);

    assert_eq!(card.get_matrix_coordinates(0), Some((0, 0)));

    let actual = card.into_proof();

    const EXPECTED: [u8; 20] = [
        241, 196, 101, 128, 135, 11, 160, 192, 252, 108, 209, 242, 49, 157, 119, 131, 135, 191,
        181, 153,
    ];
    assert_eq!(actual, EXPECTED);
}

#[test]
fn real_3_3_5_client_multiple_challenges() {
    const SESSION_KEY: [u8; 40] = [
        102, 94, 221, 27, 188, 90, 39, 16, 200, 68, 41, 48, 224, 105, 1, 102, 18, 212, 59, 119,
        207, 76, 237, 37, 240, 225, 148, 192, 63, 31, 65, 98, 142, 197, 217, 88, 34, 85, 72, 158,
    ];

    const CHALLENGE_COUNT: u8 = 3;
    const HEIGHT: u8 = 10;
    const SEED: u64 = 14574472801782155463;
    const WIDTH: u8 = 8;
    let mut card = MatrixCardVerifier::new(CHALLENGE_COUNT, HEIGHT, SEED, WIDTH, &SESSION_KEY);
    card.enter_value(0);
    card.enter_value(0);

    card.enter_value(0);
    card.enter_value(0);

    card.enter_value(0);
    card.enter_value(0);

    assert_eq!(card.get_matrix_coordinates(0), Some((7, 7)));
    assert_eq!(card.get_matrix_coordinates(1), Some((0, 0)));
    assert_eq!(card.get_matrix_coordinates(2), Some((4, 4)));

    let actual = card.into_proof();

    const EXPECTED: [u8; 20] = [
        193, 75, 79, 43, 182, 117, 141, 123, 100, 155, 172, 137, 139, 67, 215, 195, 187, 55, 30,
        231,
    ];
    assert_eq!(actual, EXPECTED);
}
