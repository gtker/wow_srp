//! Functionality for encrypting/decrypting [World Packet] headers.
//!
//! For unknown reasons the session key obtained during the SRP6
//! exchange is used to "encrypt" packet headers.
//! Be aware that [Login Packets] are not encrypted in this way.
//!
//! The packet headers are different length depending on if they are
//! [client](traits::CLIENT_HEADER_LENGTH) or [server](traits::SERVER_HEADER_LENGTH) headers.
//!
//! The sending party will encrypt the packets they send using an [Encrypter] and the receiving
//! party will decrypt with a [Decrypter].
//! The [`HeaderCrypto`] struct contains both and can be split with [`HeaderCrypto::split`].
//!
//! The [Typestate](https://yoric.github.io/post/rust-typestate/) pattern is used
//! in order to prevent incorrect use.
//! This means that whenever the next step of computation takes place, you call a function
//! taking `self`, consuming the old object, and returning the new object.
//!
//! When a player connects to the world server, the server will need to send a seed value
//! in the [SMSG_AUTH_CHALLENGE] message before the username has been received in the
//! [CMSG_AUTH_SESSION] message.
//!
//! This means the following workflow has to be done:
//!
//! 1. Create a [`ServerSeed`] struct containing a randomly generated `u32` seed.
//! 2. Send the seed to the client in a [SMSG_AUTH_CHALLENGE] message.
//! 3. Receive the username in the [CMSG_AUTH_SESSION] message.
//! 4. Retrieve the session key from the login server.
//! 5. Create the [`HeaderCrypto`] struct through [`ServerSeed::into_header_crypto`].
//! 6. Optionally, split the [`HeaderCrypto`] into [`EncrypterHalf`] and [`DecrypterHalf`] through
//! [`HeaderCrypto::split`].
//! 7. Optionally, unsplit them through [`EncrypterHalf::unsplit`].
//!
//! In a diagram this would look like:
//! ```text
//!                         Optional
//!                            |
//!                            |   |-> EncrypterHalf -|
//! ServerSeed -> HeaderCrypto | --|                  |--> HeaderCrypto
//!                            |   |-> DecrypterHalf -|
//!                            |
//! ```
//!
//! # Example
//!
//! After establishing a successful connection to the world server individual headers can be
//! encrypted or decrypted through a few different means:
//!
//! ```
//! use std::io::{Read, Error, Write};
//! use wow_srp::header_crypto::{HeaderCrypto, Decrypter, ServerHeader, Encrypter, ServerSeed};
//! use std::convert::TryInto;
//! use wow_srp::{SESSION_KEY_LENGTH, PROOF_LENGTH};
//! use wow_srp::normalized_string::NormalizedString;
//!
//! fn establish_connection(username: NormalizedString,
//!                         session_key: [u8; SESSION_KEY_LENGTH as _],
//!                         client_proof: [u8; PROOF_LENGTH as _],
//!                         client_seed: u32) {
//!     let seed = ServerSeed::new();
//!     // Send seed to client
//!     // Get username from client, fetch session key from login server
//!     let encryption = seed.into_header_crypto(username, session_key, client_proof, client_seed);
//!
//!     // Send the first server message
//! }
//!
//! fn decrypt_header<R: Read>(r: &mut R, raw_data: &mut [u8], encryption: &mut HeaderCrypto) {
//!     let client_header = encryption.read_and_decrypt_server_header(r);
//!     match client_header {
//!         Ok(c) => {}
//!         Err(_) => {
//!             panic!("Reader error")
//!         }
//!     }
//!
//!     // OR
//!
//!     let header = raw_data[0..6].try_into().unwrap();
//!     let client_header = encryption.decrypt_server_header(header);
//!
//!     // OR
//!
//!     encryption.decrypt(raw_data);
//! }
//!
//! fn encrypt<W: Write>(w: &mut W, raw_data: &mut [u8], encryption: &mut HeaderCrypto) {
//!     let result = encryption.write_encrypted_server_header(w, 4, 0xFF);
//!     match result {
//!         Ok(_) => {}
//!         Err(_) => {
//!             panic!("Reader error")
//!         }
//!     }
//!
//!     // OR
//!
//!     let server_header = encryption.encrypt_server_header(4, 0xFF);
//!     // Send server_header
//!
//!     // OR
//!
//!     encryption.encrypt(raw_data);
//! }
//!
//! ```
//!
//! [World Packet]: https://wowdev.wiki/World_Packet
//! [Login Packets]: https://wowdev.wiki/Login_Packet
//! [SMSG_AUTH_CHALLENGE]: https://wowdev.wiki/SMSG_AUTH_CHALLENGE
//! [CMSG_AUTH_SESSION]: https://wowdev.wiki/SMSG_AUTH_SESSION

pub use traits::Decrypter;
pub use traits::Encrypter;
pub use traits::CLIENT_HEADER_LENGTH;
pub use traits::SERVER_HEADER_LENGTH;

pub use decrypt::DecrypterHalf;
pub use encrypt::EncrypterHalf;

use crate::error::MatchProofsError;
use crate::key::{Proof, SessionKey};
use crate::normalized_string::NormalizedString;
use crate::srp_internal::calculate_world_server_proof;
use crate::{PROOF_LENGTH, SESSION_KEY_LENGTH};
use rand::{thread_rng, RngCore};

pub(crate) mod decrypt;
pub(crate) mod encrypt;
pub(crate) mod traits;

/// Decrypted values from a server.
///
/// Gotten from either
/// [`decrypt_server_header`](traits::Decrypter::decrypt_server_header) or
/// [`read_and_decrypt_server_header`](traits::Decrypter::read_and_decrypt_server_header).
#[derive(Debug, Clone, Copy)]
pub struct ServerHeader {
    /// Size of the message in bytes.
    /// Includes the opcode field but not the size field
    pub size: u16,
    /// Opcode of the message. Note that the size is not the same as the [`ClientHeader`].
    pub opcode: u16,
}

/// Decrypted values from a client.
///
/// Gotten from either
/// [`decrypt_client_header`](traits::Decrypter::decrypt_client_header) or
/// [`read_and_decrypt_server_header`](traits::Decrypter::read_and_decrypt_server_header).
#[derive(Debug, Clone, Copy)]
pub struct ClientHeader {
    /// Size of the message in bytes.
    /// Includes the opcode field but not the size field
    pub size: u16,
    /// Opcode of the message. Note that the size is not the same as the [`ServerHeader`].
    pub opcode: u32,
}

/// Main struct for encryption or decryption.
///
/// Created from [`ServerSeed::into_header_crypto`].
///
/// Handles both encryption and decryption of headers through the
/// [`Encrypter`] and [`Decrypter`] traits.
///
/// Can be split into a [`EncrypterHalf`] and [`DecrypterHalf`] through
/// the [`HeaderCrypto::split`] method. This is useful if you have this struct behind a
/// mutex and don't want to lock both reading and writing at the same time.
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

pub struct ServerSeed {
    server_seed: u32,
}

impl ServerSeed {
    pub fn new() -> Self {
        Self {
            server_seed: thread_rng().next_u32(),
        }
    }

    #[cfg(test)]
    fn from_specific_seed(server_seed: u32) -> Self {
        Self { server_seed }
    }

    pub const fn seed(&self) -> u32 {
        self.server_seed
    }

    pub fn into_header_crypto(
        self,
        username: NormalizedString,
        session_key: [u8; SESSION_KEY_LENGTH as _],
        client_proof: [u8; PROOF_LENGTH as _],
        client_seed: u32,
    ) -> Result<HeaderCrypto, MatchProofsError> {
        let server_proof = calculate_world_server_proof(
            &username,
            &SessionKey::from_le_bytes(session_key),
            self.server_seed,
            client_seed,
        );

        if server_proof != Proof::from_le_bytes(client_proof) {
            return Err(MatchProofsError {
                client_proof,
                server_proof: *server_proof.as_le(),
            });
        }

        Ok(HeaderCrypto {
            session_key,
            username,
            encrypt_index: 0,
            encrypt_previous_value: 0,
            decrypt_index: 0,
            decrypt_previous_value: 0,
        })
    }
}

#[cfg(test)]
mod test {
    use std::fs::read_to_string;

    use crate::header_crypto::traits::{Decrypter, Encrypter};
    use crate::header_crypto::{HeaderCrypto, ServerSeed};
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
        let client_seed = 12589856;
        let client_proof = [
            26, 97, 90, 187, 176, 134, 53, 49, 75, 160, 129, 47, 67, 207, 231, 42, 234, 184, 227,
            124,
        ];
        let mut encryption = ServerSeed::from_specific_seed(0xDEADBEEF)
            .into_header_crypto(
                NormalizedString::new("A").unwrap(),
                session_key,
                client_proof,
                client_seed,
            )
            .unwrap();

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
        let client_proof = [
            102, 178, 126, 54, 19, 161, 151, 190, 103, 77, 100, 97, 155, 55, 161, 248, 99, 146,
            229, 128,
        ];
        let client_seed = 12589856;
        let mut encryption = ServerSeed::from_specific_seed(0xDEADBEEF)
            .into_header_crypto(
                NormalizedString::new("A").unwrap(),
                session_key,
                client_proof,
                client_seed,
            )
            .unwrap();

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

        let seed = ServerSeed::from_specific_seed(server_seed);
        let encryption = seed.into_header_crypto(username, session_key, client_proof, client_seed);
        assert!(encryption.is_ok());
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

            // Bypass checking seeds and proofs because they aren't there
            let mut encryption = HeaderCrypto {
                session_key: *session_key.as_le(),
                username: NormalizedString::new("A").unwrap(),
                encrypt_index: 0,
                encrypt_previous_value: 0,
                decrypt_index: 0,
                decrypt_previous_value: 0,
            };

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

            // Bypass checking seeds and proofs because they aren't there
            let full = HeaderCrypto {
                session_key: *session_key.as_le(),
                username: NormalizedString::new("A").unwrap(),
                encrypt_index: 0,
                encrypt_previous_value: 0,
                decrypt_index: 0,
                decrypt_previous_value: 0,
            };
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

        let client_proof = [
            171, 16, 181, 52, 139, 193, 19, 213, 173, 100, 0, 37, 65, 184, 70, 148, 36, 169, 17,
            228,
        ];

        let mut encryption = ServerSeed::from_specific_seed(0xDEADBEEF)
            .into_header_crypto(
                NormalizedString::new("A").unwrap(),
                session_key,
                client_proof,
                0,
            )
            .unwrap();
        const STEP: usize = 10;
        for (i, _d) in original_data.iter().enumerate().step_by(STEP) {
            // Ensure that encrypting, then decrypting doesn't change how encryption works
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
    fn verify_splitting() {
        // Verify that splitting and combining again works
        let session_key = hex::decode(
            "2EFEE7B0C177EBBDFF6676C56EFC2339BE9CAD14BF8B54BB5A86FBF81F6D424AA23CC9A3149FB175",
        )
        .unwrap();
        let session_key: [u8; SESSION_KEY_LENGTH as usize] = session_key.try_into().unwrap();

        let original_data = hex::decode("3d9ae196ef4f5be4df9ea8b9f4dd95fe68fe58b653cf1c2dbeaa0be167db9b27df32fd230f2eab9bd7e9b2f3fbf335d381ca").unwrap();
        let mut encrypt_data = original_data.clone();
        let mut decrypt_data = original_data.clone();

        let client_proof = [
            171, 16, 181, 52, 139, 193, 19, 213, 173, 100, 0, 37, 65, 184, 70, 148, 36, 169, 17,
            228,
        ];

        let mut encryption = ServerSeed::from_specific_seed(0xDEADBEEF)
            .into_header_crypto(
                NormalizedString::new("A").unwrap(),
                session_key,
                client_proof,
                0,
            )
            .unwrap();

        const STEP: usize = 20;
        encryption.encrypt(&mut encrypt_data[0..STEP]);
        encryption.decrypt(&mut decrypt_data[0..STEP]);

        let (mut e, mut d) = encryption.split();
        e.encrypt(&mut encrypt_data[STEP..STEP * 2]);
        d.decrypt(&mut decrypt_data[STEP..STEP * 2]);

        let mut encryption = e.unsplit(d);

        encryption.encrypt(&mut encrypt_data[STEP * 2..]);
        encryption.decrypt(&mut decrypt_data[STEP * 2..]);

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
    fn verify_trait_helpers() {
        // Verify that the trait helpers do the same thing as manually encrypting/decrypting
        let session_key = hex::decode(
            "2EFEE7B0C177EBBDFF6676C56EFC2339BE9CAD14BF8B54BB5A86FBF81F6D424AA23CC9A3149FB175",
        )
        .unwrap();
        let session_key: [u8; SESSION_KEY_LENGTH as usize] = session_key.try_into().unwrap();

        let original_data = [
            0x3d, 0x9a, 0xe1, 0x96, 0xef, 0x4f, 0x3d, 0x9a, 0xe1, 0x96, 0x3d, 0x9a, 0xe1, 0x96,
            0xef, 0x4f, 0x3d, 0x9a, 0xe1, 0x96,
        ];
        let mut encrypt_data = original_data.clone();
        let mut encrypted_data = Vec::new();
        let mut decrypt_data = original_data.clone();
        let decrypted_data = original_data.clone().to_vec();

        let client_proof = [
            171, 16, 181, 52, 139, 193, 19, 213, 173, 100, 0, 37, 65, 184, 70, 148, 36, 169, 17,
            228,
        ];

        let mut encryption = ServerSeed::from_specific_seed(0xDEADBEEF)
            .into_header_crypto(
                NormalizedString::new("A").unwrap(),
                session_key,
                client_proof,
                0,
            )
            .unwrap();
        let mut helper_encryption = ServerSeed::from_specific_seed(0xDEADBEEF)
            .into_header_crypto(
                NormalizedString::new("A").unwrap(),
                session_key,
                client_proof,
                0,
            )
            .unwrap();

        encryption
            .write_encrypted_client_header(&mut encrypted_data, 0x3d9a, 0x4fef96e1)
            .unwrap();
        encryption
            .write_encrypted_server_header(&mut encrypted_data, 0x3d9a, 0x96e1)
            .unwrap();
        encrypted_data.append(
            &mut encryption
                .encrypt_client_header(0x3d9a, 0x4fef96e1)
                .to_vec(),
        );
        encrypted_data.append(&mut encryption.encrypt_server_header(0x3d9a, 0x96e1).to_vec());
        helper_encryption.encrypt(&mut encrypt_data);
        assert_eq!(encrypted_data, encrypt_data);

        encryption.decrypt(&mut decrypt_data);
        let c = helper_encryption
            .read_and_decrypt_client_header(&mut decrypted_data[0..6].to_vec().as_slice())
            .unwrap();
        assert_eq!(
            c.size,
            u16::from_be_bytes(decrypt_data[0..2].try_into().unwrap())
        );
        assert_eq!(
            c.opcode,
            u32::from_le_bytes(decrypt_data[2..6].try_into().unwrap())
        );
        let s = helper_encryption
            .read_and_decrypt_server_header(&mut decrypted_data[6..10].to_vec().as_slice())
            .unwrap();
        assert_eq!(
            s.size,
            u16::from_be_bytes(decrypt_data[6..8].try_into().unwrap())
        );
        assert_eq!(
            s.opcode,
            u16::from_le_bytes(decrypt_data[8..10].try_into().unwrap())
        );
        let c = helper_encryption.decrypt_client_header(decrypted_data[10..16].try_into().unwrap());
        assert_eq!(
            c.size,
            u16::from_be_bytes(decrypt_data[10..12].try_into().unwrap())
        );
        assert_eq!(
            c.opcode,
            u32::from_le_bytes(decrypt_data[12..16].try_into().unwrap())
        );
        let s = helper_encryption.decrypt_server_header(decrypted_data[16..20].try_into().unwrap());
        assert_eq!(
            s.size,
            u16::from_be_bytes(decrypt_data[16..18].try_into().unwrap())
        );
        assert_eq!(
            s.opcode,
            u16::from_le_bytes(decrypt_data[18..20].try_into().unwrap())
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

            let mut encryption = HeaderCrypto {
                session_key: *session_key.as_le(),
                username: NormalizedString::new("A").unwrap(),
                encrypt_index: 0,
                encrypt_previous_value: 0,
                decrypt_index: 0,
                decrypt_previous_value: 0,
            };

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

            let full = HeaderCrypto {
                session_key: *session_key.as_le(),
                username: NormalizedString::new("A").unwrap(),
                encrypt_index: 0,
                encrypt_previous_value: 0,
                decrypt_index: 0,
                decrypt_previous_value: 0,
            };
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
