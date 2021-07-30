use std::io::{Read, Write};

use crate::header_crypto::{ClientHeader, ServerHeader};

/// Size in bytes of the client [world packet] header.
///
/// Always 6 bytes because the size is 2 bytes and the opcode is 4 bytes.
///
/// [world packet]: https://wowdev.wiki/World_Packet
pub const CLIENT_HEADER_LENGTH: u8 =
    (std::mem::size_of::<u16>() + std::mem::size_of::<u32>()) as u8;

/// Size in bytes of the server [world packet] header.
///
/// Always 4 bytes because the size is 2 bytes and the opcode is 2 bytes.
///
/// [world packet]: https://wowdev.wiki/World_Packet
pub const SERVER_HEADER_LENGTH: u8 =
    (std::mem::size_of::<u16>() + std::mem::size_of::<u16>()) as u8;

/// The `Encrypter` trait allows for decrypting world packet headers.
///
/// Only the [`Encrypter::encrypt`] method is required to be implemented, the rest
/// are provided as convenience wrappers around it.
///
/// The are no `async` convenience methods because it can be trivially implemented by
/// the user, and it would be tedious to support all the different runtimes.
/// If in doubt look at the source for the [`Write`](std::io::Write) versions.
pub trait Encrypter {
    /// [`Write`](std::io::Write) wrapper for [`Encrypter::encrypt_server_header`].
    ///
    /// # Errors
    ///
    /// Has the same errors as [`std::io::Write::write_all`].
    fn write_encrypted_server_header<W: Write>(
        &mut self,
        write: &mut W,
        size: u16,
        opcode: u16,
    ) -> std::io::Result<()> {
        let buf = self.encrypt_server_header(size, opcode);

        write.write_all(&buf)?;

        Ok(())
    }

    /// [`Write`](std::io::Write) wrapper for [`Encrypter::encrypt_server_header`].
    ///
    /// # Errors
    ///
    /// Has the same errors as [`std::io::Write::write_all`].
    fn write_encrypted_client_header<W: Write>(
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
    /// Prefer this over directly using [`Encrypter::encrypt`].
    fn encrypt_server_header(
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
    /// Prefer this over directly using [`Encrypter::encrypt`].
    fn encrypt_client_header(
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

    /// Directly encrypt the unencrypted `data` and leave the encrypted values.
    fn encrypt(&mut self, data: &mut [u8]);
}

/// The `Decrypter` trait allows for decrypting world packet headers.
///
/// Only the [`Decrypter::decrypt`] method is required to be implemented, the rest
/// are provided as convenience wrappers around it.
///
/// The are no `async` convenience methods because it can be trivially implemented by
/// the user, and it would be tedious to support all the different runtimes.
/// If in doubt look at the source for the [`Read`](std::io::Read) versions.
pub trait Decrypter {
    /// [`Read`](std::io::Read) wrapper for [`Decrypter::decrypt_server_header`].
    ///
    /// # Errors
    ///
    /// Has the same errors as [`std::io::Read::read_exact`].
    fn read_and_decrypt_server_header<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> std::io::Result<ServerHeader> {
        let mut buf = [0_u8; SERVER_HEADER_LENGTH as usize];
        reader.read_exact(&mut buf)?;

        Ok(self.decrypt_server_header(buf))
    }

    /// [`Read`](std::io::Read) wrapper for [`Decrypter::decrypt_client_header`].
    ///
    /// # Errors
    ///
    /// Has the same errors as [`std::io::Read::read_exact`].
    fn read_and_decrypt_client_header<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> std::io::Result<ClientHeader> {
        let mut buf = [0_u8; CLIENT_HEADER_LENGTH as usize];
        reader.read_exact(&mut buf)?;

        Ok(self.decrypt_client_header(buf))
    }

    /// Convenience function for decrypting server headers.
    ///
    /// Prefer this over directly using [`Decrypter::decrypt`].
    fn decrypt_server_header(
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
    /// Prefer this over directly using [`Decrypter::decrypt`].
    fn decrypt_client_header(
        &mut self,
        mut data: [u8; CLIENT_HEADER_LENGTH as usize],
    ) -> ClientHeader {
        self.decrypt(&mut data);

        let size: u16 = u16::from_be_bytes([data[0], data[1]]);
        let opcode: u32 = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);

        ClientHeader { size, opcode }
    }

    /// Directly the encrypted `data` and leave the unencrypted values.
    fn decrypt(&mut self, data: &mut [u8]);
}
