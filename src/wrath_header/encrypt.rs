use crate::error::UnsplitCryptoError;
use crate::wrath_header::decrypt::DecrypterHalf;
use crate::wrath_header::{HeaderCrypto, CLIENT_HEADER_LENGTH, SERVER_HEADER_LENGTH};
use crate::SESSION_KEY_LENGTH;

use crate::wrath_header::inner_crypto::{InnerCrypto, KEY_LENGTH};
use std::io::Write;

pub struct EncrypterHalf {
    encrypt: InnerCrypto,
}

impl EncrypterHalf {
    pub fn encrypt(&mut self, data: &mut [u8]) {
        self.encrypt.apply(data);
    }

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

    pub fn is_pair_of(&self, other: &DecrypterHalf) -> bool {
        unimplemented!()
    }

    pub(crate) fn new(
        session_key: [u8; SESSION_KEY_LENGTH as usize],
        key: &[u8; KEY_LENGTH as usize],
    ) -> Self {
        Self {
            encrypt: InnerCrypto::new(session_key, key),
        }
    }

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
