use crate::wrath_header::{
    CLIENT_HEADER_LENGTH, R, S, SERVER_HEADER_MAXIMUM_LENGTH, SERVER_HEADER_MINIMUM_LENGTH,
};
use crate::SESSION_KEY_LENGTH;

use crate::wrath_header::inner_crypto::InnerCrypto;
use std::io::Write;

/// Encryption part of a [`ServerCrypto`](crate::wrath_header::ServerCrypto).
///
/// Intended to be kept with the writer half of a connection.
#[derive(Debug)]
pub struct ServerEncrypterHalf {
    encrypt: InnerCrypto,
    server_header: [u8; SERVER_HEADER_MAXIMUM_LENGTH as usize],
}

impl ServerEncrypterHalf {
    /// Use either
    /// [the server](Self::write_encrypted_server_header)
    /// [`Write`](std::io::Write) function, or
    /// or [the server](Self::encrypt_server_header) array function.
    pub fn encrypt(&mut self, data: &mut [u8]) {
        self.encrypt.apply(data);
    }

    /// [`Write`](std::io::Write) wrapper for [`Self::encrypt_server_header`].
    ///
    /// # Errors
    ///
    /// Has the same errors as [`std::io::Write::write_all`].
    pub fn write_encrypted_server_header<W: Write>(
        &mut self,
        write: &mut W,
        size: u32,
        opcode: u16,
    ) -> std::io::Result<()> {
        let buf = self.encrypt_server_header(size, opcode);

        write.write_all(buf)?;

        Ok(())
    }

    /// Convenience function for encrypting client headers.
    ///
    /// Prefer this over directly using [`Self::encrypt`].
    pub fn encrypt_server_header(&mut self, size: u32, opcode: u16) -> &[u8] {
        if size > 0x7FFF {
            let size = size.to_be_bytes();
            let opcode = opcode.to_le_bytes();

            // The most significant bit of the 3rd byte must be set in order to indicate
            // that this is a 3-byte size. This must be cleared on decryption in order to
            // not report the wrong size.
            let most_significant_byte = size[1] | 0x80;
            let mut header = [
                most_significant_byte,
                size[2],
                size[3],
                opcode[0],
                opcode[1],
            ];

            self.encrypt(&mut header);

            self.server_header[0] = header[0];
            self.server_header[1] = header[1];
            self.server_header[2] = header[2];
            self.server_header[3] = header[3];
            self.server_header[4] = header[4];

            &self.server_header
        } else {
            let size = size.to_be_bytes();
            let opcode = opcode.to_le_bytes();

            let mut header = [size[2], size[3], opcode[0], opcode[1]];

            self.encrypt(&mut header);

            self.server_header[0] = header[0];
            self.server_header[1] = header[1];
            self.server_header[2] = header[2];
            self.server_header[3] = header[3];

            &self.server_header[0..SERVER_HEADER_MINIMUM_LENGTH as usize]
        }
    }

    pub(crate) fn new(session_key: [u8; SESSION_KEY_LENGTH as usize]) -> Self {
        Self {
            encrypt: InnerCrypto::new(session_key, &R),
            server_header: [0_u8; SERVER_HEADER_MAXIMUM_LENGTH as usize],
        }
    }
}

/// Encryption part of a [`ClientCrypto`](crate::wrath_header::ClientCrypto).
///
/// Intended to be kept with the writer half of a connection.
#[derive(Debug)]
pub struct ClientEncrypterHalf {
    encrypt: InnerCrypto,
}

impl ClientEncrypterHalf {
    /// Use either
    /// [the client](Self::write_encrypted_client_header)
    /// [`Write`](std::io::Write) function, or
    /// or [the client](Self::encrypt_client_header) array function.
    pub fn encrypt(&mut self, data: &mut [u8]) {
        self.encrypt.apply(data);
    }

    /// [`Write`](std::io::Write) wrapper for [`Self::encrypt_client_header`].
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
    /// Prefer this over directly using [`Self::encrypt`].
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
        Self {
            encrypt: InnerCrypto::new(session_key, &S),
        }
    }
}
