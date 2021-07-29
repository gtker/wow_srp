//! Functionality for encrypting/decrypting [World Packet] headers.
//! For unknown reasons the session key obtained during the SRP6
//! exchange is used to "encrypt" packet headers.
//! Be aware that [Login Packets] are not encrypted in this way.
//!
//! The packet headers are different length depending on if they are
//! [client](traits::CLIENT_HEADER_LENGTH) or [server](traits::SERVER_HEADER_LENGTH) headers.
//!
//! The sending party will encrypt the packets they send using an [Encrypter] and the receiving
//! party will decrypt with a [Decrypter].
//! The [`HeaderCrypto`] struct contains both.
//!
//! [World Packet]: https://wowdev.wiki/World_Packet
//! [Login Packets]: https://wowdev.wiki/Login_Packet

use sha1::{Digest, Sha1};

pub use traits::Decrypter;
pub use traits::Encrypter;
pub use traits::CLIENT_HEADER_LENGTH;
pub use traits::SERVER_HEADER_LENGTH;

pub use decrypt::DecrypterHalf;
pub use encrypt::EncrypterHalf;

use crate::normalized_string::NormalizedString;
use crate::{PROOF_LENGTH, SESSION_KEY_LENGTH};

pub(crate) mod decrypt;
pub(crate) mod encrypt;
pub(crate) mod traits;

#[derive(Debug)]
pub struct ServerHeader {
    pub size: u16,
    pub opcode: u16,
}

#[derive(Debug)]
pub struct ClientHeader {
    pub size: u16,
    pub opcode: u32,
}

#[derive(Debug)]
pub struct HeaderCrypto {
    session_key: [u8; SESSION_KEY_LENGTH as usize],
    username: NormalizedString,
    encrypt_index: u8,
    encrypt_previous_value: u8,
    decrypt_index: u8,
    decrypt_previous_value: u8,
}

impl Encrypter for HeaderCrypto {
    fn encrypt(&mut self, data: &mut [u8]) {
        encrypt::encrypt(
            data,
            self.session_key,
            &mut self.encrypt_index,
            &mut self.encrypt_previous_value,
        );
    }
}

impl Decrypter for HeaderCrypto {
    fn decrypt(&mut self, data: &mut [u8]) {
        decrypt::decrypt(
            data,
            &self.session_key,
            &mut self.decrypt_index,
            &mut self.decrypt_previous_value,
        );
    }
}

impl HeaderCrypto {
    pub const fn new(
        username: NormalizedString,
        session_key: [u8; SESSION_KEY_LENGTH as usize],
    ) -> Self {
        Self {
            session_key,
            username,
            encrypt_index: 0,
            encrypt_previous_value: 0,
            decrypt_index: 0,
            decrypt_previous_value: 0,
        }
    }

    pub fn client_proof_is_correct(
        &self,
        server_seed: u32,
        client_proof: [u8; PROOF_LENGTH as usize],
        client_seed: u32,
    ) -> bool {
        let server_proof: [u8; PROOF_LENGTH as usize] = Sha1::new()
            .chain(&self.username.as_ref())
            .chain(0_u32.to_le_bytes())
            .chain(client_seed.to_le_bytes())
            .chain(server_seed.to_le_bytes())
            .chain(&self.session_key)
            .finalize()
            .into();

        server_proof == client_proof
    }

    #[allow(clippy::missing_const_for_fn)] // Clippy does not consider `self` arg
    pub fn split(self) -> (EncrypterHalf, DecrypterHalf) {
        let encrypt = EncrypterHalf {
            username: self.username,
            session_key: self.session_key,
            index: self.encrypt_index,
            previous_value: self.encrypt_previous_value,
        };

        let decrypt = DecrypterHalf {
            session_key: self.session_key,
            index: self.decrypt_index,
            previous_value: self.decrypt_previous_value,
        };

        (encrypt, decrypt)
    }
}

#[cfg(test)]
mod test {
    use std::fs::read_to_string;

    use crate::header_crypto::traits::{Decrypter, Encrypter};
    use crate::header_crypto::HeaderCrypto;
    use crate::key::SessionKey;
    use crate::normalized_string::NormalizedString;
    use crate::SESSION_KEY_LENGTH;
    use std::convert::TryInto;

    #[test]
    fn verify_server_header() {
        // Real capture with 1.12 client

        let session_key = [
            239, 107, 150, 237, 174, 220, 162, 4, 138, 56, 166, 166, 138, 152, 188, 146, 96, 151,
            1, 201, 202, 137, 231, 87, 203, 23, 62, 17, 7, 169, 178, 1, 51, 208, 202, 223, 26, 216,
            250, 9,
        ];
        let mut encryption = HeaderCrypto::new(NormalizedString::new("A").unwrap(), session_key);

        let header = encryption.encrypt_server_header(12, 494);
        let expected_header = [239, 86, 206, 186];
        assert_eq!(header, expected_header);

        let header = encryption.encrypt_server_header(170, 59);
        let expected_header = [104, 222, 119, 123];
        assert_eq!(header, expected_header);

        let header = encryption.encrypt_server_header(6, 477);
        let expected_header = [5, 67, 190, 101];
        assert_eq!(header, expected_header);

        let header = encryption.encrypt_server_header(6, 477);
        let expected_header = [239, 141, 238, 129];
        assert_eq!(header, expected_header);
    }

    #[test]
    fn verify_client_header() {
        // Real capture with 1.12 client

        let session_key = [
            9, 83, 75, 103, 5, 182, 16, 162, 170, 134, 230, 117, 11, 100, 136, 74, 88, 145, 175,
            126, 216, 48, 38, 40, 234, 116, 174, 149, 133, 20, 193, 51, 103, 223, 194, 141, 4, 191,
            161, 96,
        ];
        let mut encryption = HeaderCrypto::new(NormalizedString::new("A").unwrap(), session_key);

        let header = [9, 96, 220, 67, 72, 254];
        let c = encryption.decrypt_client_header(header);
        let expected_size = 4;
        let expected_opcode = 55; // CMSG_CHAR_ENUM
        assert_eq!(c.opcode, expected_opcode);
        assert_eq!(c.size, expected_size);

        let expected_size = 12;
        let expected_opcode = 476; // CMSG_PING

        // Must be run through in order because the session key index is changed
        let headers = [
            [14, 188, 50, 185, 159, 20],
            [31, 135, 219, 38, 126, 15],
            [190, 48, 52, 101, 139, 179],
        ];
        for header in headers.iter() {
            let c = encryption.decrypt_client_header(*header);
            assert_eq!(c.opcode, expected_opcode);
            assert_eq!(c.size, expected_size);
        }
    }

    #[test]
    fn verify_login() {
        let session_key = [
            115, 0, 100, 222, 18, 15, 156, 194, 27, 1, 216, 229, 165, 207, 78, 233, 183, 241, 248,
            73, 190, 142, 14, 89, 44, 235, 153, 190, 103, 206, 34, 88, 45, 199, 104, 175, 79, 108,
            93, 48,
        ];
        let username = NormalizedString::new("A").unwrap();
        let server_seed = 0xDEADBEEF;
        let client_seed = 1266519981;
        let client_proof = [
            202, 54, 102, 180, 90, 87, 9, 107, 217, 97, 235, 56, 221, 203, 108, 19, 109, 141, 137,
            7,
        ];

        let encryption = HeaderCrypto::new(username, session_key);
        assert!(encryption.client_proof_is_correct(server_seed, client_proof, client_seed));
    }

    #[test]
    fn verify_encrypt() {
        let contents = read_to_string("tests/encryption/calculate_encrypt_values.txt").unwrap();

        for line in contents.lines() {
            let mut line = line.split_whitespace();
            let session_key = SessionKey::from_le_hex_str(line.next().unwrap());
            let mut data = hex::decode(line.next().unwrap()).unwrap();
            let mut split_data = data.clone();
            let original_data = data.clone();
            let expected = hex::decode(line.next().unwrap()).unwrap();

            let mut encryption =
                HeaderCrypto::new(NormalizedString::new("A").unwrap(), *session_key.as_le());

            encryption.encrypt(&mut data);

            assert_eq!(
                hex::encode(&expected),
                hex::encode(&data),
                "Session Key: {},
                 data: {},
                 Got data: {}",
                hex::encode(session_key.as_le()),
                hex::encode(&original_data),
                hex::encode(&data)
            );

            let full = HeaderCrypto::new(NormalizedString::new("A").unwrap(), *session_key.as_le());
            let (mut enc, _dec) = full.split();

            enc.encrypt(&mut split_data);

            assert_eq!(
                hex::encode(&expected),
                hex::encode(&split_data),
                "Session Key: {},
                 data: {},
                 Got data: {}",
                hex::encode(session_key.as_le()),
                hex::encode(&original_data),
                hex::encode(&split_data)
            );
        }
    }

    #[test]
    fn verify_mixed_used() {
        // Verify that mixed use does not interfere with each other

        let session_key = hex::decode(
            "2EFEE7B0C177EBBDFF6676C56EFC2339BE9CAD14BF8B54BB5A86FBF81F6D424AA23CC9A3149FB175",
        )
        .unwrap();
        let session_key: [u8; SESSION_KEY_LENGTH as usize] = session_key.try_into().unwrap();

        let original_data = hex::decode("3d9ae196ef4f5be4df9ea8b9f4dd95fe68fe58b653cf1c2dbeaa0be167db9b27df32fd230f2eab9bd7e9b2f3fbf335d381ca").unwrap();
        let mut encrypt_data = original_data.clone();
        let mut decrypt_data = original_data.clone();

        let mut encryption = HeaderCrypto::new(NormalizedString::new("A").unwrap(), session_key);
        const STEP: usize = 10;
        for (i, _d) in original_data.iter().enumerate().step_by(STEP) {
            encryption.encrypt(&mut encrypt_data[i..(i) + STEP]);
            encryption.decrypt(&mut decrypt_data[i..(i) + STEP]);
        }

        let expected_decrypt = hex::decode("13a3a0059817e73404d97cd455159b50d40af74a22f719aacb6a9a2e991982c61a6f0285f880cc8512ec2ef1c98fa923512f").unwrap();
        let expected_encrypt = hex::decode("13777da3d109b912322a08841e3ff5bc92f4e98b77bb03997da999b22ae0b926a3b1e56580314b3932499ee11b9f7deb6915").unwrap();
        assert_eq!(
            expected_decrypt, decrypt_data,
            "Original data: {:?}, expected: {:?}, got: {:?}",
            original_data, expected_decrypt, decrypt_data
        );
        assert_eq!(
            expected_encrypt, encrypt_data,
            "Original data: {:?}, expected: {:?}, got: {:?}",
            original_data, expected_encrypt, encrypt_data
        );
    }

    #[test]
    fn verify_decrypt() {
        let contents = read_to_string("tests/encryption/calculate_decrypt_values.txt").unwrap();

        for line in contents.lines() {
            let mut line = line.split_whitespace();
            let session_key = SessionKey::from_le_hex_str(line.next().unwrap());
            let mut data = hex::decode(line.next().unwrap()).unwrap();
            let mut split_data = data.clone();
            let original_data = data.clone();
            let expected = hex::decode(line.next().unwrap()).unwrap();

            let mut encryption =
                HeaderCrypto::new(NormalizedString::new("A").unwrap(), *session_key.as_le());

            encryption.decrypt(&mut data);

            assert_eq!(
                hex::encode(&expected),
                hex::encode(&data),
                "Session Key: {},
                 data: {},
                 Got data: {}",
                hex::encode(session_key.as_le()),
                hex::encode(&original_data),
                hex::encode(&data)
            );

            let full = HeaderCrypto::new(NormalizedString::new("A").unwrap(), *session_key.as_le());
            let (_enc, mut dec) = full.split();

            dec.decrypt(&mut split_data);

            assert_eq!(
                hex::encode(&expected),
                hex::encode(&split_data),
                "Session Key: {},
                 data: {},
                 Got data: {}",
                hex::encode(session_key.as_le()),
                hex::encode(&original_data),
                hex::encode(&split_data),
            );
        }
    }
}
