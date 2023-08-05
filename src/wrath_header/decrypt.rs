use crate::wrath_header::{
    ClientHeader, ServerHeader, CLIENT_HEADER_LENGTH, R, S, SERVER_HEADER_MAXIMUM_LENGTH,
    SERVER_HEADER_MINIMUM_LENGTH,
};
use crate::SESSION_KEY_LENGTH;

use crate::wrath_header::inner_crypto::InnerCrypto;
use std::io::Read;

/// Decryption part of a [`ServerCrypto`](crate::wrath_header::ServerCrypto).
///
/// Intended to be kept with the reader half of a connection.
#[derive(Debug)]
pub struct ServerDecrypterHalf {
    decrypt: InnerCrypto,
}

impl ServerDecrypterHalf {
    /// Raw access to decryption.
    ///
    /// Use either [the server](Self::read_and_decrypt_client_header)
    /// [`Read`](std::io::Read) function, or
    /// [the server](Self::decrypt_client_header) array functions.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.decrypt.apply(data);
    }

    /// Convenience wrapper for [`ServerDecrypterHalf::read_and_decrypt_client_header`].
    ///
    /// # Errors
    ///
    /// Has the same errors as [`ServerDecrypterHalf::read_and_decrypt_client_header`].
    pub fn read_and_decrypt_client_header<R: Read>(
        &mut self,
        mut reader: R,
    ) -> std::io::Result<ClientHeader> {
        let mut buf = [0_u8; CLIENT_HEADER_LENGTH as usize];
        reader.read_exact(&mut buf)?;

        Ok(self.decrypt_client_header(buf))
    }

    /// Convenience wrapper for [`ServerDecrypterHalf::decrypt_client_header`].
    ///
    /// Prefer this over directly using [`Self::decrypt`].
    #[must_use]
    pub fn decrypt_client_header(
        &mut self,
        mut data: [u8; CLIENT_HEADER_LENGTH as usize],
    ) -> ClientHeader {
        self.decrypt(&mut data);

        let size: u16 = u16::from_be_bytes([data[0], data[1]]);
        let opcode: u32 = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);

        ClientHeader { size, opcode }
    }

    pub(crate) fn new(session_key: [u8; SESSION_KEY_LENGTH as usize]) -> Self {
        Self {
            decrypt: InnerCrypto::new(session_key, &S),
        }
    }
}

/// Decryption part of a [`ClientCrypto`](crate::wrath_header::ClientCrypto).
///
/// Intended to be kept with the reader half of a connection.
#[derive(Debug)]
pub struct ClientDecrypterHalf {
    decrypt: InnerCrypto,
}

impl ClientDecrypterHalf {
    /// Raw access to decryption.
    ///
    /// Use
    /// [the server](Self::decrypt_server_header) array function instead of this.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.decrypt.apply(data);
    }

    /// Convenience wrapper for [`ServerDecrypterHalf::decrypt_client_header`].
    ///
    /// This handles situations where the size field is 3 bytes instead of 2.
    ///
    /// Prefer this over directly using [`Self::decrypt`].
    #[must_use]
    pub fn decrypt_server_header(
        &mut self,
        mut data: [u8; SERVER_HEADER_MAXIMUM_LENGTH as usize],
    ) -> ServerHeader {
        self.decrypt.apply(&mut data[0..1]);

        if data[0] & 0x80 != 0 {
            self.decrypt(&mut data[1..]);

            // The most significant bit of the most significant byte is set
            // in order to indicate that this is a 3-byte size.
            // The 0x80 indicator must be cleared, otherwise the size is off
            let most_significant_byte = data[0] & 0x7F;
            let size = u32::from_be_bytes([0, most_significant_byte, data[1], data[2]]);
            let opcode = u16::from_le_bytes([data[3], data[4]]);

            ServerHeader { size, opcode }
        } else {
            self.decrypt(&mut data[1..SERVER_HEADER_MINIMUM_LENGTH as usize]);
            let size = u16::from_be_bytes([data[0], data[1]]);
            let opcode = u16::from_le_bytes([data[2], data[3]]);

            ServerHeader {
                size: size.into(),
                opcode,
            }
        }
    }

    pub(crate) fn new(session_key: [u8; SESSION_KEY_LENGTH as usize]) -> Self {
        Self {
            decrypt: InnerCrypto::new(session_key, &R),
        }
    }
}
