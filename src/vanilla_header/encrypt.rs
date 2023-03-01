use crate::error::UnsplitCryptoError;
use crate::vanilla_header::decrypt::DecrypterHalf;
use crate::vanilla_header::{HeaderCrypto, CLIENT_HEADER_LENGTH, SERVER_HEADER_LENGTH};
use crate::SESSION_KEY_LENGTH;
use std::io::Write;

/// Encryption part of a [`HeaderCrypto`].
///
/// Intended to be kept with the writer half of a connection.
///
/// Use the [`EncrypterHalf`] functions to encrypt.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct EncrypterHalf {
    pub(crate) session_key: [u8; SESSION_KEY_LENGTH as usize],
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
        encrypt(
            data,
            self.session_key,
            &mut self.index,
            &mut self.previous_value,
        );
    }

    /// [`Write`](std::io::Write) wrapper for [`EncrypterHalf::encrypt_server_header`].
    ///
    /// # Errors
    ///
    /// Has the same errors as [`std::io::Write::write_all`].
    pub fn write_encrypted_server_header<W: Write>(
        &mut self,
        mut write: W,
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
        mut write: W,
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
    #[must_use]
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
    #[must_use]
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

    /// Tests whether both halves originate from the same [`HeaderCrypto`]
    /// and can be [`EncrypterHalf::unsplit`].
    #[must_use]
    pub fn is_pair_of(&self, other: &DecrypterHalf) -> bool {
        self.session_key == other.session_key
    }

    pub(crate) const fn new(session_key: [u8; SESSION_KEY_LENGTH as usize]) -> Self {
        Self {
            session_key,
            index: 0,
            previous_value: 0,
        }
    }

    /// Unsplits the two halves.
    ///
    /// # Errors
    ///
    /// This will error if the two halfs do not originate from the same
    /// [`HeaderCrypto::split`].
    /// This is a logic bug and should either lead
    /// to panic or some other highly visible event.
    /// If [`EncrypterHalf::is_pair_of`] returns [`true`] this will not
    /// error.
    pub fn unsplit(self, decrypter: DecrypterHalf) -> Result<HeaderCrypto, UnsplitCryptoError> {
        if !self.is_pair_of(&decrypter) {
            return Err(UnsplitCryptoError {});
        }

        Ok(HeaderCrypto {
            decrypt: decrypter,
            encrypt: self,
        })
    }
}

pub(crate) fn encrypt(
    data: &mut [u8],
    session_key: [u8; SESSION_KEY_LENGTH as usize],
    index: &mut u8,
    previous_value: &mut u8,
) {
    for unencrypted in data {
        // x = (d ^ session_key[index]) + previous_value
        let encrypted = (*unencrypted ^ session_key[*index as usize]).wrapping_add(*previous_value);

        // Use the session key as a circular buffer
        *index = (*index + 1) % SESSION_KEY_LENGTH;

        *unencrypted = encrypted;
        *previous_value = encrypted;
    }
}
