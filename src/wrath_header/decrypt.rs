use crate::wrath_header::encrypt::EncrypterHalf;
use crate::wrath_header::{ClientHeader, ServerHeader, CLIENT_HEADER_LENGTH, SERVER_HEADER_LENGTH};
use crate::SESSION_KEY_LENGTH;
use rc4::consts::U20;
use rc4::{Rc4, StreamCipher};

use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::io::Read;

/// Decryption part of a [`HeaderCrypto`](crate::wrath_header::HeaderCrypto).
///
/// Intended to be kept with the reader half of a connection.
///
/// Use the [`DecrypterHalf`] functions to decrypt.
pub struct DecrypterHalf {
    decrypt: Rc4<U20>,
}

impl DecrypterHalf {
    /// Use either [the client](DecrypterHalf::read_and_decrypt_client_header)
    /// or [the server](DecrypterHalf::read_and_decrypt_server_header)
    /// [`Read`](std::io::Read) functions, or
    /// [the client](DecrypterHalf::decrypt_client_header)
    /// or [the server](DecrypterHalf::decrypt_server_header) array functions.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.decrypt.apply_keystream(data);
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
    /// [`HeaderCrypto`](crate::wrath_header::HeaderCrypto)
    /// and can be [`EncrypterHalf::unsplit`].
    ///
    /// Same as [`EncrypterHalf::is_pair_of`], provided for convenience/readability.
    pub fn is_pair_of(&self, other: &EncrypterHalf) -> bool {
        other.is_pair_of(self)
    }

    pub(crate) fn new(session_key: [u8; SESSION_KEY_LENGTH as usize]) -> Self {
        const S: [u8; 16] = [
            0xC2, 0xB3, 0x72, 0x3C, 0xC6, 0xAE, 0xD9, 0xB5, 0x34, 0x3C, 0x53, 0xEE, 0x2F, 0x43,
            0x67, 0xCE,
        ];

        let mut hmac: Hmac<Sha1> = Hmac::<Sha1>::new_from_slice(&S).unwrap();
        hmac.update(&session_key);
        let hmac = hmac.finalize();

        let mut decrypt = {
            use rc4::KeyInit;
            Rc4::new_from_slice(&hmac.into_bytes()).unwrap()
        };

        let mut pad_data = [0_u8; 1024];

        decrypt.apply_keystream(&mut pad_data);

        Self { decrypt }
    }
}
