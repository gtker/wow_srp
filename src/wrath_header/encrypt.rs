use crate::error::UnsplitCryptoError;
use crate::wrath_header::decrypt::DecrypterHalf;
use crate::wrath_header::{HeaderCrypto, CLIENT_HEADER_LENGTH, SERVER_HEADER_LENGTH};
use crate::SESSION_KEY_LENGTH;
use rc4::consts::U20;
use rc4::{Rc4, StreamCipher};

use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::io::Write;

/// Encryption part of a [`HeaderCrypto`].
///
/// Intended to be kept with the writer half of a connection.
///
/// Use the [`EncrypterHalf`] functions to encrypt.
pub struct EncrypterHalf {
    encrypt: Rc4<U20>,
}

impl EncrypterHalf {
    /// Use either [the client](EncrypterHalf::write_encrypted_client_header)
    /// or [the server](EncrypterHalf::write_encrypted_server_header)
    /// [`Write`](std::io::Write) functions, or
    /// [the client](EncrypterHalf::encrypt_client_header)
    /// or [the server](EncrypterHalf::encrypt_server_header) array functions.
    pub fn encrypt(&mut self, data: &mut [u8]) {
        self.encrypt.apply_keystream(data);
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

    /// Tests whether both halves originate from the same [`HeaderCrypto`]
    /// and can be [`EncrypterHalf::unsplit`].
    pub fn is_pair_of(&self, other: &DecrypterHalf) -> bool {
        unimplemented!()
    }

    const R: [u8; 16] = [
        0xCC, 0x98, 0xAE, 0x04, 0xE8, 0x97, 0xEA, 0xCA, 0x12, 0xDD, 0xC0, 0x93, 0x42, 0x91, 0x53,
        0x57,
    ];

    pub(crate) fn new(session_key: [u8; SESSION_KEY_LENGTH as usize]) -> Self {
        const S: [u8; 16] = [
            0xC2, 0xB3, 0x72, 0x3C, 0xC6, 0xAE, 0xD9, 0xB5, 0x34, 0x3C, 0x53, 0xEE, 0x2F, 0x43,
            0x67, 0xCE,
        ];

        let mut hmac: Hmac<Sha1> = Hmac::<Sha1>::new_from_slice(&S).unwrap();
        hmac.update(&session_key);
        let hmac = hmac.finalize();

        let mut encrypt = {
            use rc4::KeyInit;
            Rc4::new_from_slice(&hmac.into_bytes()).unwrap()
        };

        let mut pad_data = [0_u8; 1024];

        encrypt.apply_keystream(&mut pad_data);

        Self { encrypt }
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
