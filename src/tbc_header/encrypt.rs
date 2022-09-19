use crate::tbc_header::{CLIENT_HEADER_LENGTH, SERVER_HEADER_LENGTH};
use crate::{PROOF_LENGTH, SESSION_KEY_LENGTH};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::convert::TryInto;
use std::io::Write;

/// Encryption part of a [`HeaderCrypto`].
///
/// Intended to be kept with the writer half of a connection.
///
/// Use the [`EncrypterHalf`] functions to encrypt.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct EncrypterHalf {
    pub(crate) key: [u8; PROOF_LENGTH as usize],
    pub(crate) index: u8,
    pub(crate) previous_value: u8,
}

impl EncrypterHalf {
    /// Use either [the client](EncrypterHalf::write_encrypted_client_header)
    /// or [the server](EncrypterHalf::write_encrypted_server_header)
    /// [`Write`](std::io::Write) functions, or
    /// [the client](EncrypterHalf::encrypt_client_header)
    /// or [the server](EncrypterHalf::encrypt_server_header) array functions.
    pub fn encrypt(&mut self, data: &mut [u8]) {
        encrypt(data, self.key, &mut self.index, &mut self.previous_value);
    }

    /// [`Write`](std::io::Write) wrapper for [`EncrypterHalf::encrypt_server_header`].
    ///
    /// # Errors
    ///
    /// Has the same errors as [`std::io::Write::write_all`].
    pub fn write_encrypted_server_header<W: Write>(
        &mut self,
        write: &mut W,
        size: u16,
        opcode: u16,
    ) -> std::io::Result<()> {
        let buf = self.encrypt_server_header(size, opcode);

        write.write_all(&buf)?;

        Ok(())
    }

    /// [`Write`](std::io::Write) wrapper for [`EncrypterHalf::encrypt_server_header`].
    ///
    /// # Errors
    ///
    /// Has the same errors as [`std::io::Write::write_all`].
    pub fn write_encrypted_client_header<W: Write>(
        &mut self,
        write: &mut W,
        size: u16,
        opcode: u32,
    ) -> std::io::Result<()> {
        let buf = self.encrypt_client_header(size, opcode);

        write.write_all(&buf)?;

        Ok(())
    }

    /// Convenience function for encrypting client headers.
    ///
    /// Prefer this over directly using [`EncrypterHalf::encrypt`].
    pub fn encrypt_server_header(
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

    /// Convenience function for encrypting client headers.
    ///
    /// Prefer this over directly using [`EncrypterHalf::encrypt`].
    pub fn encrypt_client_header(
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

    pub(crate) fn new(session_key: [u8; SESSION_KEY_LENGTH as usize]) -> Self {
        const SEED_KEY_SIZE: usize = 16;
        let s: [u8; SEED_KEY_SIZE] = [
            0x38, 0xA7, 0x83, 0x15, 0xF8, 0x92, 0x25, 0x30, 0x71, 0x98, 0x67, 0xB1, 0x8C, 0x4,
            0xE2, 0xAA,
        ];
        let mut key: Hmac<Sha1> = Hmac::new_from_slice(s.as_slice()).unwrap();
        key.update(&session_key);
        let key = key.finalize().into_bytes().as_slice().try_into().unwrap();

        Self {
            key,
            index: 0,
            previous_value: 0,
        }
    }
}

pub(crate) fn encrypt(
    data: &mut [u8],
    session_key: [u8; PROOF_LENGTH as usize],
    index: &mut u8,
    previous_value: &mut u8,
) {
    for unencrypted in data {
        // x = (d ^ session_key[index]) + previous_value
        let encrypted = (*unencrypted ^ session_key[*index as usize]).wrapping_add(*previous_value);

        // Use the session key as a circular buffer
        *index = (*index + 1) % PROOF_LENGTH as u8;

        *unencrypted = encrypted;
        *previous_value = encrypted;
    }
}
