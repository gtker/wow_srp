use crate::tbc_header::{
    create_tbc_key, ClientHeader, ServerHeader, CLIENT_HEADER_LENGTH, SERVER_HEADER_LENGTH,
};
use crate::vanilla_header::decrypt::decrypt;
use crate::{PROOF_LENGTH, SESSION_KEY_LENGTH};
use std::io::Read;

/// Decryption part of a [`HeaderCrypto`](crate::tbc_header::HeaderCrypto).
///
/// Intended to be kept with the reader half of a connection.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct DecrypterHalf {
    pub(crate) key: [u8; PROOF_LENGTH as usize],
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
        decrypt(data, &self.key, &mut self.index, &mut self.previous_value);
    }

    /// [`Read`](std::io::Read) wrapper for [`DecrypterHalf::decrypt_server_header`].
    ///
    /// # Errors
    ///
    /// Has the same errors as [`std::io::Read::read_exact`].
    pub fn read_and_decrypt_server_header<R: Read>(
        &mut self,
        mut reader: R,
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
        mut reader: R,
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

        ServerHeader::from_array(data)
    }

    /// Convenience function for decrypting client headers.
    ///
    /// Prefer this over directly using [`DecrypterHalf::decrypt`].
    pub fn decrypt_client_header(
        &mut self,
        mut data: [u8; CLIENT_HEADER_LENGTH as usize],
    ) -> ClientHeader {
        self.decrypt(&mut data);

        ClientHeader::from_array(data)
    }

    pub(crate) fn new(session_key: [u8; SESSION_KEY_LENGTH as usize]) -> Self {
        Self {
            key: create_tbc_key(session_key),
            index: 0,
            previous_value: 0,
        }
    }
}
