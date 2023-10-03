use crate::wrath_header::{
    ClientHeader, ServerHeader, CLIENT_HEADER_LENGTH, R, S, SERVER_HEADER_MINIMUM_LENGTH,
};
use crate::SESSION_KEY_LENGTH;

use crate::wrath_header::inner_crypto::InnerCrypto;
use std::io::Read;

/// Decryption part of a [`ServerCrypto`](crate::wrath_header::ServerCrypto).
///
/// Intended to be kept with the reader half of a connection.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
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

        ClientHeader::from_array(data)
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
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct ClientDecrypterHalf {
    decrypt: InnerCrypto,
    header: [u8; SERVER_HEADER_MINIMUM_LENGTH as usize],
}

impl ClientDecrypterHalf {
    /// Raw access to decryption.
    ///
    /// Use
    /// [the server](Self::attempt_decrypt_server_header) array function instead of this.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.decrypt.apply(data);
    }

    /// Attempts to decrypt the provided `buf`, returning either a header or a request for an additional byte
    /// provided to [`Self::decrypt_large_server_header`].
    ///
    /// This function and [`Self::decrypt_large_server_header`] is for streams that don't support [Read] like various
    /// async frameworks.
    /// If your stream supports [Read] use [`Self::read_and_decrypt_server_header`] instead.
    ///
    /// This **MUST** be called before [`Self::decrypt_large_server_header`] otherwise
    /// the decrypter will enter an invalid state and the connection will have to be terminated.
    ///
    /// Unlike other versions, Wrath messages from the server (`SMSG`) can have a dynamic size field
    /// of either 2 **or** 3 bytes.
    /// This means that reading the first 4 bytes of a message and passing it as an array won't work.
    ///
    /// To properly use this API, read 4 bytes from your stream and pass it to this function.
    /// This will either return a well formed header, or a [`WrathServerAttempt::AdditionalByteRequired`].
    /// When you get [`WrathServerAttempt::AdditionalByteRequired`], read an aditional byte and pass it to
    /// [`Self::decrypt_large_server_header`].
    pub fn attempt_decrypt_server_header(
        &mut self,
        mut buf: [u8; SERVER_HEADER_MINIMUM_LENGTH as usize],
    ) -> WrathServerAttempt {
        self.decrypt.apply(&mut buf);

        if large_header(buf[0]) {
            self.header[0] = buf[0];
            self.header[1] = buf[1];
            self.header[2] = buf[2];
            self.header[3] = buf[3];
            WrathServerAttempt::AdditionalByteRequired
        } else {
            WrathServerAttempt::Header(ServerHeader::from_small_array(buf))
        }
    }

    /// Finalizes the header decryption provided in [`Self::attempt_decrypt_server_header`].
    ///
    /// See [`Self::attempt_decrypt_server_header`] for more.
    pub fn decrypt_large_server_header(&mut self, byte: u8) -> ServerHeader {
        let mut buf = [byte];
        self.decrypt.apply(&mut buf);

        let buf = [
            self.header[0],
            self.header[1],
            self.header[2],
            self.header[3],
            buf[0],
        ];
        ServerHeader::from_large_array(buf)
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
        let mut buf = [0_u8; 4];
        reader.read_exact(&mut buf)?;

        Ok(match self.attempt_decrypt_server_header(buf) {
            WrathServerAttempt::Header(h) => h,
            WrathServerAttempt::AdditionalByteRequired => {
                let mut buf = [0_u8; 1];
                reader.read_exact(&mut buf)?;

                self.decrypt_large_server_header(buf[0])
            }
        })
    }

    pub(crate) fn new(session_key: [u8; SESSION_KEY_LENGTH as usize]) -> Self {
        Self {
            decrypt: InnerCrypto::new(session_key, &R),
            header: [0_u8; SERVER_HEADER_MINIMUM_LENGTH as usize],
        }
    }
}
/// Used in [`ClientDecrypterHalf::attempt_decrypt_server_header`] to notify when an additional
/// byte is required.
pub enum WrathServerAttempt {
    /// The message header has been fully decrypted and you should do nothing until the next message.
    Header(ServerHeader),
    /// Call [`ClientDecrypterHalf::decrypt_large_server_header`]
    AdditionalByteRequired,
}

pub(crate) const fn clear_large_header(v: u8) -> u8 {
    v & 0x7F
}

const fn large_header(v: u8) -> bool {
    // The most significant bit of the most significant byte is set
    // in order to indicate that this is a 3-byte size.
    // The 0x80 indicator must be cleared, otherwise the size is off
    v & 0x80 != 0
}
