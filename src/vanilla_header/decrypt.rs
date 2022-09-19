use crate::vanilla_header::encrypt::EncrypterHalf;
use crate::vanilla_header::{
    ClientHeader, ServerHeader, CLIENT_HEADER_LENGTH, SERVER_HEADER_LENGTH,
};
use crate::SESSION_KEY_LENGTH;
use std::io::Read;

/// Decryption part of a [`HeaderCrypto`](crate::vanilla_header::HeaderCrypto).
///
/// Intended to be kept with the reader half of a connection.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct DecrypterHalf {
    pub(crate) session_key: [u8; SESSION_KEY_LENGTH as usize],
    pub(crate) index: u8,
    pub(crate) previous_value: u8,
}

impl DecrypterHalf {
    /// Use either [the client](DecrypterHalf::read_and_decrypt_client_header)
    /// or [the server](DecrypterHalf::read_and_decrypt_server_header)
    /// [`Read`](std::io::Read) functions, or
    /// [the client](DecrypterHalf::decrypt_client_header)
    /// or [the server](DecrypterHalf::decrypt_server_header) array functions.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        decrypt(
            data,
            &self.session_key,
            &mut self.index,
            &mut self.previous_value,
        );
    }

    /// [`Read`](std::io::Read) wrapper for [`DecrypterHalf::decrypt_server_header`].
    ///
    /// # Errors
    ///
    /// Has the same errors as [`std::io::Read::read_exact`].
    pub fn read_and_decrypt_server_header<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> std::io::Result<ServerHeader> {
        let mut buf = [0_u8; SERVER_HEADER_LENGTH as usize];
        reader.read_exact(&mut buf)?;

        Ok(self.decrypt_server_header(buf))
    }

    /// [`Read`](std::io::Read) wrapper for [`DecrypterHalf::decrypt_client_header`].
    ///
    /// # Errors
    ///
    /// Has the same errors as [`std::io::Read::read_exact`].
    pub fn read_and_decrypt_client_header<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> std::io::Result<ClientHeader> {
        let mut buf = [0_u8; CLIENT_HEADER_LENGTH as usize];
        reader.read_exact(&mut buf)?;

        Ok(self.decrypt_client_header(buf))
    }

    /// Convenience function for decrypting server headers.
    ///
    /// Prefer this over directly using [`DecrypterHalf::decrypt`].
    pub fn decrypt_server_header(
        &mut self,
        mut data: [u8; SERVER_HEADER_LENGTH as usize],
    ) -> ServerHeader {
        self.decrypt(&mut data);

        let size = u16::from_be_bytes([data[0], data[1]]);
        let opcode = u16::from_le_bytes([data[2], data[3]]);

        ServerHeader { size, opcode }
    }

    /// Convenience function for decrypting client headers.
    ///
    /// Prefer this over directly using [`DecrypterHalf::decrypt`].
    pub fn decrypt_client_header(
        &mut self,
        mut data: [u8; CLIENT_HEADER_LENGTH as usize],
    ) -> ClientHeader {
        self.decrypt(&mut data);

        let size: u16 = u16::from_be_bytes([data[0], data[1]]);
        let opcode: u32 = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);

        ClientHeader { size, opcode }
    }

    /// Tests whether both halves originate from the same
    /// [`HeaderCrypto`](crate::vanilla_header::HeaderCrypto)
    /// and can be [`EncrypterHalf::unsplit`].
    ///
    /// Same as [`EncrypterHalf::is_pair_of`], provided for convenience/readability.
    pub fn is_pair_of(&self, other: &EncrypterHalf) -> bool {
        other.is_pair_of(self)
    }

    pub(crate) const fn new(session_key: [u8; SESSION_KEY_LENGTH as usize]) -> Self {
        Self {
            session_key,
            index: 0,
            previous_value: 0,
        }
    }
}

pub(crate) fn decrypt(
    data: &mut [u8],
    session_key: &[u8; SESSION_KEY_LENGTH as usize],
    index: &mut u8,
    previous_value: &mut u8,
) {
    for encrypted in data {
        // unencrypted = (encrypted - previous_value) ^ session_key[index]
        let unencrypted = encrypted.wrapping_sub(*previous_value) ^ session_key[*index as usize];

        // Use session key as circular buffer
        *index = (*index + 1) % SESSION_KEY_LENGTH as u8;

        *previous_value = *encrypted;
        *encrypted = unencrypted;
    }
}
