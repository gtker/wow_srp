use crate::wrath_header::{ClientHeader, ServerHeader, CLIENT_HEADER_LENGTH, SERVER_HEADER_LENGTH};
use crate::SESSION_KEY_LENGTH;

use crate::wrath_header::inner_crypto::{InnerCrypto, KEY_LENGTH};
use std::io::Read;

pub struct ServerDecrypterHalf {
    decrypt: InnerCrypto,
}

impl ServerDecrypterHalf {
    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.decrypt.apply(data);
    }

    pub fn read_and_decrypt_client_header<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> std::io::Result<ClientHeader> {
        let mut buf = [0_u8; CLIENT_HEADER_LENGTH as usize];
        reader.read_exact(&mut buf)?;

        Ok(self.decrypt_client_header(buf))
    }

    pub fn decrypt_client_header(
        &mut self,
        mut data: [u8; CLIENT_HEADER_LENGTH as usize],
    ) -> ClientHeader {
        self.decrypt(&mut data);

        let size: u16 = u16::from_be_bytes([data[0], data[1]]);
        let opcode: u32 = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);

        ClientHeader { size, opcode }
    }

    pub(crate) fn new(
        session_key: [u8; SESSION_KEY_LENGTH as usize],
        key: &[u8; KEY_LENGTH as usize],
    ) -> Self {
        Self {
            decrypt: InnerCrypto::new(session_key, &key),
        }
    }
}

pub struct ClientDecrypterHalf {
    decrypt: InnerCrypto,
}

impl ClientDecrypterHalf {
    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.decrypt.apply(data);
    }

    pub fn read_and_decrypt_server_header<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> std::io::Result<ServerHeader> {
        let mut buf = [0_u8; SERVER_HEADER_LENGTH as usize];
        reader.read_exact(&mut buf)?;

        Ok(self.decrypt_server_header(buf))
    }

    pub fn decrypt_server_header(
        &mut self,
        mut data: [u8; SERVER_HEADER_LENGTH as usize],
    ) -> ServerHeader {
        self.decrypt(&mut data);

        let size = u16::from_be_bytes([data[0], data[1]]);
        let opcode = u16::from_le_bytes([data[2], data[3]]);

        ServerHeader { size, opcode }
    }

    pub(crate) fn new(
        session_key: [u8; SESSION_KEY_LENGTH as usize],
        key: &[u8; KEY_LENGTH as usize],
    ) -> Self {
        Self {
            decrypt: InnerCrypto::new(session_key, &key),
        }
    }
}
