use std::io::{Read, Write};

use crate::header_crypto::{ClientHeader, ServerHeader};

pub const CLIENT_HEADER_LENGTH: u8 =
    (std::mem::size_of::<u32>() + std::mem::size_of::<u16>()) as u8;
pub const SERVER_HEADER_LENGTH: u8 =
    (std::mem::size_of::<u16>() + std::mem::size_of::<u16>()) as u8;

pub trait Encryptor {
    fn write_encrypted_server_header<W: Write>(
        &mut self,
        write: &mut W,
        size: u16,
        opcode: u16,
    ) -> std::io::Result<()>;

    fn write_encrypted_client_header<W: Write>(
        &mut self,
        write: &mut W,
        size: u16,
        opcode: u32,
    ) -> std::io::Result<()>;

    fn encrypt_server_header(
        &mut self,
        size: u16,
        opcode: u16,
    ) -> [u8; SERVER_HEADER_LENGTH as usize];

    fn encrypt_client_header(
        &mut self,
        size: u16,
        opcode: u32,
    ) -> [u8; CLIENT_HEADER_LENGTH as usize];

    fn encrypt(&mut self, data: &mut [u8]);
}

pub trait Decryptor {
    fn read_decrypted_server_header<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> std::io::Result<ServerHeader>;

    fn read_decrypted_client_header<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> std::io::Result<ClientHeader>;

    fn decrypt_server_header(&mut self, data: [u8; SERVER_HEADER_LENGTH as usize]) -> ServerHeader;

    fn decrypt_client_header(&mut self, data: [u8; CLIENT_HEADER_LENGTH as usize]) -> ClientHeader;

    fn decrypt(&mut self, data: &mut [u8]);
}
