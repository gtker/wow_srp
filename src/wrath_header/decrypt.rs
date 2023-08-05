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
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
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

    /// Convenience function for [Read]ing header directly.
    /// Prefer this over directly using [`Self::decrypt`].
    ///
    /// # Errors
    ///
    /// Has the same errors as [`Read::read_exact`].
    pub fn read_and_decrypt_client_header<R: Read>(
        &mut self,
        mut reader: R,
    ) -> std::io::Result<ClientHeader> {
        let mut buf = [0_u8; CLIENT_HEADER_LENGTH as usize];
        reader.read_exact(&mut buf)?;

        Ok(self.decrypt_client_header(buf))
    }

    /// Convenience function for decrypting the header from a statically known header array.
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
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct ClientDecrypterHalf {
    decrypt: InnerCrypto,
    header: [u8; SERVER_HEADER_MAXIMUM_LENGTH as usize],
}

impl ClientDecrypterHalf {
    /// Raw access to decryption.
    ///
    /// Use
    /// [the server](Self::decrypt_internal_server_header) array function instead of this.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.decrypt.apply(data);
    }

    /// Provides an internal buffer for reading headers into that is decrypted using [`Self::decrypt_internal_server_header`].
    ///
    /// This function does not progress the internal state of the encryption, and it **MUST** be
    /// followed by a call to [`Self::decrypt_internal_server_header`].
    ///
    /// See [`Self::decrypt_internal_server_header`] for more.
    #[must_use]
    pub fn get_header_buffer(&mut self, byte: u8) -> &mut [u8] {
        self.header[0] = byte;

        if large_header(self.decrypt.peek(byte)) {
            &mut self.header[1..]
        } else {
            &mut self.header[1..SERVER_HEADER_MINIMUM_LENGTH as usize]
        }
    }

    /// Decrypts the internal buffer provided by [`Self::get_header_buffer`].
    ///
    /// This function and [`Self::get_header_buffer`] is for streams that don't support [Read] like various
    /// async frameworks.
    /// If your stream supports [Read] use [`Self::read_and_decrypt_server_header`] instead.
    ///
    /// [`Self::get_header_buffer`] **MUST** be called before this, otherwise
    /// the decrypter will enter an invalid state and the connection will have to be terminated.
    ///
    /// Unlike other versinos, Wrath messages from the server (`SMSG`) can have a dynamic size field
    /// of either 2 **or** 3 bytes.
    /// This means that reading the first 4 bytes of a message and passing it as an array won't work.
    ///
    /// To properly use this API, read a single byte from your stream and pass it to [`Self::get_header_buffer`].
    /// This will return a buffer where you can `read_exact` or similar into.
    /// The buffer is automatically sized correctly, so do not bother matching on the length, just fill it up.
    /// Then call this function to decrypt.
    #[must_use]
    pub fn decrypt_internal_server_header(&mut self) -> ServerHeader {
        self.decrypt.apply(&mut self.header[0..1]);

        let large_header = large_header(self.header[0]);

        let header = if large_header {
            &mut self.header[1..]
        } else {
            &mut self.header[1..SERVER_HEADER_MINIMUM_LENGTH as usize]
        };

        self.decrypt.apply(header);

        let (size, opcode) = if large_header {
            let most_significant_byte = clear_large_header(self.header[0]);
            let size =
                u32::from_be_bytes([0, most_significant_byte, self.header[1], self.header[2]]);
            let opcode = u16::from_le_bytes([self.header[3], self.header[4]]);

            (size, opcode)
        } else {
            let size = u16::from_be_bytes([self.header[0], self.header[1]]);
            let opcode = u16::from_le_bytes([self.header[2], self.header[3]]);

            (size.into(), opcode)
        };

        ServerHeader { size, opcode }
    }

    /// Convenience function for [Read]ing header directly.
    /// Prefer this over directly using [`Self::decrypt`].
    ///
    /// # Errors
    ///
    /// Has the same errors as [`Read::read_exact`].
    pub fn read_and_decrypt_server_header<R: Read>(
        &mut self,
        mut reader: R,
    ) -> std::io::Result<ServerHeader> {
        let msb = [0_u8; 1];
        let mut header = self.get_header_buffer(msb[0]);

        reader.read_exact(&mut header)?;

        Ok(self.decrypt_internal_server_header())
    }

    pub(crate) fn new(session_key: [u8; SESSION_KEY_LENGTH as usize]) -> Self {
        Self {
            decrypt: InnerCrypto::new(session_key, &R),
            header: [0_u8; SERVER_HEADER_MAXIMUM_LENGTH as usize],
        }
    }
}

const fn clear_large_header(v: u8) -> u8 {
    v & 0x7F
}

const fn large_header(v: u8) -> bool {
    // The most significant bit of the most significant byte is set
    // in order to indicate that this is a 3-byte size.
    // The 0x80 indicator must be cleared, otherwise the size is off
    v & 0x80 != 0
}
