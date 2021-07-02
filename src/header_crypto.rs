//! Functionality for encrypting/decrypting [World Packet] headers.
//!
//! [World Packet]: https://wowdev.wiki/World_Packet

use crate::normalized_string::NormalizedString;
use crate::{PROOF_LENGTH, SESSION_KEY_LENGTH};
use sha1::{Digest, Sha1};
use std::io::Write;

pub const CLIENT_HEADER_LENGTH: u8 =
    (std::mem::size_of::<u32>() + std::mem::size_of::<u16>()) as u8;
pub const SERVER_HEADER_LENGTH: u8 =
    (std::mem::size_of::<u16>() + std::mem::size_of::<u16>()) as u8;

pub trait Encryptor {
    fn write_encrypted_server_header<W: Write>(
        &mut self,
        write: &mut W,
        size: u16,
        opcode: u16,
    ) -> std::io::Result<()>;

    fn write_encrypted_client_header<W: Write>(
        &mut self,
        write: &mut W,
        size: u16,
        opcode: u32,
    ) -> std::io::Result<()>;

    fn encrypt_server_header(
        &mut self,
        size: u16,
        opcode: u16,
    ) -> [u8; SERVER_HEADER_LENGTH as usize];

    fn encrypt_client_header(
        &mut self,
        size: u16,
        opcode: u32,
    ) -> [u8; CLIENT_HEADER_LENGTH as usize];

    fn encrypt(&mut self, data: &mut [u8]);
}

#[derive(Debug)]
pub struct ClientHeader {
    size: u16,
    opcode: u32,
}

impl ClientHeader {
    pub fn new(size: u16, opcode: u32) -> Self {
        Self { size, opcode }
    }

    pub fn size(&self) -> u16 {
        self.size
    }

    pub fn opcode(&self) -> u32 {
        self.opcode
    }
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

impl Encryptor for HeaderCrypto {
    fn write_encrypted_server_header<W: Write>(
        &mut self,
        write: &mut W,
        size: u16,
        opcode: u16,
    ) -> std::io::Result<()> {
        let buf = self.encrypt_server_header(size, opcode);

        write.write_all(&buf)?;

        Ok(())
    }

    fn write_encrypted_client_header<W: Write>(
        &mut self,
        write: &mut W,
        size: u16,
        opcode: u32,
    ) -> std::io::Result<()> {
        let buf = self.encrypt_client_header(size, opcode);

        write.write_all(&buf)?;

        Ok(())
    }

    fn encrypt_server_header(
        &mut self,
        size: u16,
        opcode: u16,
    ) -> [u8; SERVER_HEADER_LENGTH as usize] {
        let size = size.to_be_bytes();
        let opcode = opcode.to_le_bytes();

        let mut header = [size[0], size[1], opcode[0], opcode[1]];

        self.encrypt(&mut header);

        header
    }

    fn encrypt_client_header(
        &mut self,
        size: u16,
        opcode: u32,
    ) -> [u8; CLIENT_HEADER_LENGTH as usize] {
        let size = size.to_be_bytes();
        let opcode = opcode.to_le_bytes();

        let mut header = [size[0], size[1], opcode[0], opcode[1], opcode[2], opcode[3]];
        self.encrypt(&mut header);

        header
    }

    fn encrypt(&mut self, data: &mut [u8]) {
        for unencrypted in data {
            // x = (d ^ session_key[index]) + previous_value
            let encrypted = (*unencrypted ^ self.session_key[self.encrypt_index as usize])
                .wrapping_add(self.encrypt_previous_value);

            // Use the session key as a circular buffer
            self.encrypt_index = (self.encrypt_index + 1) % SESSION_KEY_LENGTH as u8;

            *unencrypted = encrypted;
            self.encrypt_previous_value = encrypted;
        }
    }
}

impl HeaderCrypto {
    pub fn new(username: NormalizedString, session_key: [u8; SESSION_KEY_LENGTH as usize]) -> Self {
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

    pub fn decrypt_client_header(
        &mut self,
        mut header: [u8; CLIENT_HEADER_LENGTH as usize],
    ) -> ClientHeader {
        self.decrypt(&mut header);
        let size: u16 = u16::from_be_bytes([header[0], header[1]]);
        let opcode: u32 = u32::from_le_bytes([header[2], header[3], header[4], header[5]]);

        ClientHeader::new(size, opcode)
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        for encrypted in data {
            // unencrypted = (encrypted - previous_value) ^ session_key[index]
            let unencrypted = encrypted.wrapping_sub(self.decrypt_previous_value)
                ^ self.session_key[self.decrypt_index as usize];

            // Use session key as circular buffer
            self.decrypt_index = (self.decrypt_index + 1) % SESSION_KEY_LENGTH as u8;

            self.decrypt_previous_value = *encrypted;
            *encrypted = unencrypted;
        }
    }
}

#[cfg(test)]
mod test {
    use crate::header_crypto::{Encryptor, HeaderCrypto};
    use crate::key::SessionKey;
    use crate::normalized_string::NormalizedString;
    use std::fs::read_to_string;

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
        assert_eq!(c.opcode(), expected_opcode);
        assert_eq!(c.size(), expected_size);

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
            assert_eq!(c.opcode(), expected_opcode);
            assert_eq!(c.size(), expected_size);
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
            let original_data = data.clone();
            let expected = hex::decode(line.next().unwrap()).unwrap();

            let mut encryption =
                HeaderCrypto::new(NormalizedString::new("A").unwrap(), *session_key.as_le());
            encryption.encrypt(&mut data);
            assert_eq!(
                hex::encode(&expected),
                hex::encode(&data),
                "Session Key: {},
                 data: {}",
                hex::encode(session_key.as_le()),
                hex::encode(&original_data)
            );
        }
    }

    #[test]
    fn verify_decrypt() {
        let contents = read_to_string("tests/encryption/calculate_decrypt_values.txt").unwrap();

        for line in contents.lines() {
            let mut line = line.split_whitespace();
            let session_key = SessionKey::from_le_hex_str(line.next().unwrap());
            let mut data = hex::decode(line.next().unwrap()).unwrap();
            let original_data = data.clone();
            let expected = hex::decode(line.next().unwrap()).unwrap();

            let mut encryption =
                HeaderCrypto::new(NormalizedString::new("A").unwrap(), *session_key.as_le());
            encryption.decrypt(&mut data);

            assert_eq!(
                hex::encode(&expected),
                hex::encode(&data),
                "Session Key: {},
                 data: {}",
                hex::encode(session_key.as_le()),
                hex::encode(&original_data)
            );
        }
    }
}
