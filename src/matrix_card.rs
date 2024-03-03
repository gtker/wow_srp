use crate::key::SHA1_HASH_LENGTH;
use crate::rc4::Rc4;
use crate::SESSION_KEY_LENGTH;
use hmac::digest::FixedOutput;
use hmac::{Hmac, Mac};
use md5::Context;
use sha1::Sha1;

pub fn get_seed_value() -> u64 {
    rand::random::<u64>()
}

pub struct MatrixCard {
    challenge_count: u8,
    height: u8,
    width: u8,
    coordinates: Vec<u8>,
    hmac: Hmac<Sha1>,
    rc4: Rc4,
}

impl MatrixCard {
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

    pub fn enter_matrix(&mut self, value: u8) {
        let value = &mut [value];
        self.rc4.apply_keystream(value.as_mut_slice());
        self.hmac.update(value);
    }

    pub fn finalize(self) -> [u8; SHA1_HASH_LENGTH as usize] {
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
    let mut card = MatrixCard::new(CHALLENGE_COUNT, HEIGHT, SEED, WIDTH, &SESSION_KEY);
    card.enter_matrix(0);
    card.enter_matrix(0);

    assert_eq!(card.get_matrix_coordinates(0), Some((0, 0)));

    let actual = card.finalize();

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
    let mut card = MatrixCard::new(CHALLENGE_COUNT, HEIGHT, SEED, WIDTH, &SESSION_KEY);
    card.enter_matrix(0);
    card.enter_matrix(0);

    card.enter_matrix(0);
    card.enter_matrix(0);

    card.enter_matrix(0);
    card.enter_matrix(0);

    assert_eq!(card.get_matrix_coordinates(0), Some((7, 7)));
    assert_eq!(card.get_matrix_coordinates(1), Some((0, 0)));
    assert_eq!(card.get_matrix_coordinates(2), Some((4, 4)));

    let actual = card.finalize();

    const EXPECTED: [u8; 20] = [
        193, 75, 79, 43, 182, 117, 141, 123, 100, 155, 172, 137, 139, 67, 215, 195, 187, 55, 30,
        231,
    ];
    assert_eq!(actual, EXPECTED);
}
