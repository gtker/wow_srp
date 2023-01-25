//! Functionality for encrypting/decrypting [World Packet] headers.
//!
//! For unknown reasons the session key obtained during the SRP6
//! exchange is used to "encrypt" packet headers.
//! Be aware that [Login Packets] are not encrypted in this way.
//!
//! The packet headers are different length depending on if they are
//! [client](CLIENT_HEADER_LENGTH) or server headers.
//! Unlike [vanilla](crate::vanilla_header) the server header length is variable
//! in order to support a longer size field. This means that the server headers
//! have a [minimum](SERVER_HEADER_MINIMUM_LENGTH) and a [maximum](SERVER_HEADER_MAXIMUM_LENGTH) length.
//!
//! Because the keys used to encrypt and decrypt for client and server differ slightly, clients will
//! have to use [`ClientCrypto`] and servers will have to use [`ServerCrypto`].
//!
//! The [Typestate](https://yoric.github.io/post/rust-typestate/) pattern is used
//! in order to prevent incorrect use.
//! This means that whenever the next step of computation takes place, you call a function
//! taking `self`, consuming the old object, and returning the new object.
//!
//! When a player connects to the world server, the server will need to send a seed value
//! in the [`SMSG_AUTH_CHALLENGE`] message before the username has been received in the
//! [`CMSG_AUTH_SESSION`] message.
//!
//! This means the following workflow has to be done for servers:
//!
//! 1. Create a [`ProofSeed`] struct containing a randomly generated `u32` seed.
//! 2. Send the seed to the client in a [`SMSG_AUTH_CHALLENGE`] message.
//! 3. Receive the username, proof and seed in the [`CMSG_AUTH_SESSION`] message.
//! 4. Retrieve the session key from the login server.
//! 5. Create the [`ServerCrypto`] struct through [`ProofSeed::into_header_crypto`].
//! 6. Optionally, split the [`ServerCrypto`] into [`ServerEncrypterHalf`] and [`ServerDecrypterHalf`] through
//! [`ServerCrypto::split`].
//!
//! and for clients:
//!
//! 1. Create a [`ProofSeed`] struct containing a randomly generated `u32` seed.
//! 2. Receive the server seed from [`SMSG_AUTH_CHALLENGE`].
//! 3. Create the [`ClientCrypto`] struct through [`ProofSeed::into_proof_and_header_crypto`].
//! 4. Send the proof and seed through [`CMSG_AUTH_SESSION`].
//! 5. Optionally, split the [`ClientCrypto`] into [`ClientEncrypterHalf`] and [`ClientDecrypterHalf`] through
//! [`ClientCrypto::split`].
//!
//! Unlike the [vanilla](crate::vanilla_header) version, the Wrath version does not support unsplitting.
//! This is because there is no easy way to ensure that the structs being unsplit actually came from the same original struct.
//!
//! For servers this would look like this in a diagram:
//! ```text
//!                         Optional
//!                            |
//!                            |   |-> ServerEncrypterHalf
//! ProofSeed -> ServerCrypto -|---|                
//!                            |   |-> ServerDecrypterHalf
//!                            |
//! ```
//!
//! And for clients:
//! ```text
//!                         Optional
//!                            |
//!                            |   |-> ClientEncrypterHalf
//! ProofSeed -> ClientCrypto -|---|                
//!                            |   |-> ClientDecrypterHalf
//!                            |
//! ```
//!
//! [World Packet]: https://wowdev.wiki/World_Packet
//! [Login Packets]: https://wowdev.wiki/Login_Packet
//! [`SMSG_AUTH_CHALLENGE`]: https://wowdev.wiki/SMSG_AUTH_CHALLENGE
//! [`CMSG_AUTH_SESSION`]: https://wowdev.wiki/SMSG_AUTH_SESSION
use std::io::{Read, Write};

pub use decrypt::ClientDecrypterHalf;
pub use decrypt::ServerDecrypterHalf;
pub use encrypt::ClientEncrypterHalf;
pub use encrypt::ServerEncrypterHalf;

use crate::error::MatchProofsError;
use crate::key::{Proof, SessionKey};
use crate::normalized_string::NormalizedString;
use crate::vanilla_header::calculate_world_server_proof;
use crate::{PROOF_LENGTH, SESSION_KEY_LENGTH};
use rand::{thread_rng, RngCore};

pub(crate) mod decrypt;
pub(crate) mod encrypt;
mod inner_crypto;

/// Size in bytes of the client [world packet] header.
///
/// Always 6 bytes because the size is 2 bytes and the opcode is 4 bytes.
///
/// [world packet]: https://wowdev.wiki/World_Packet
pub const CLIENT_HEADER_LENGTH: u8 =
    (std::mem::size_of::<u16>() + std::mem::size_of::<u32>()) as u8;

/// Minimum size in bytes of the server [world packet] header.
///
/// The minimum is always 4 bytes because because the size is 2 bytes
/// and the opcode is 2 bytes.
///
/// The [maximum](SERVER_HEADER_MAXIMUM_LENGTH) is always 5 bytes.
///
/// [world packet]: https://wowdev.wiki/World_Packet
pub const SERVER_HEADER_MINIMUM_LENGTH: u8 =
    (std::mem::size_of::<u16>() + std::mem::size_of::<u16>()) as u8;

/// Maximum size in bytes of the server [world packet] header.
///
/// The minimum is always 5 bytes because because the size is 3 bytes
/// and the opcode is 2 bytes.
///
/// The [minimum](SERVER_HEADER_MAXIMUM_LENGTH) is always 4 bytes.
///
/// The size field is 3 bytes if the first unencrypted byte has the eighth bit set (0x80).
///
/// [world packet]: https://wowdev.wiki/World_Packet
pub const SERVER_HEADER_MAXIMUM_LENGTH: u8 =
    (std::mem::size_of::<u16>() + std::mem::size_of::<u16>() + std::mem::size_of::<u8>()) as u8;

// Used for Client (Encryption) to Server (Decryption)
const S: [u8; 16] = [
    0xC2, 0xB3, 0x72, 0x3C, 0xC6, 0xAE, 0xD9, 0xB5, 0x34, 0x3C, 0x53, 0xEE, 0x2F, 0x43, 0x67, 0xCE,
];

// Used for Server (Encryption) to Client (Decryption) messages
const R: [u8; 16] = [
    0xCC, 0x98, 0xAE, 0x04, 0xE8, 0x97, 0xEA, 0xCA, 0x12, 0xDD, 0xC0, 0x93, 0x42, 0x91, 0x53, 0x57,
];

/// Decrypted values from a server.
///
/// Gotten from [`ClientDecrypterHalf`].
///
/// Different from the [vanilla version](crate::vanilla_header::ServerHeader) because the Wrath
/// version needs to support 3-byte size values.
#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct ServerHeader {
    /// Size of the message in bytes.
    /// Includes the size of the opcode field but not the size of the size field.
    ///
    /// This is a [u32] to ensure that 3-byte size values fit into it.
    pub size: u32,
    /// Opcode of the message. Note that the size is not the same as the [`ClientHeader`].
    pub opcode: u16,
}

pub use crate::vanilla_header::ClientHeader;

/// Main struct for enccryption and decryption for clients.
///
/// Created from [`ProofSeed::into_proof_and_header_crypto`].
///
/// Handles both encryption and decryption of headers through the
/// [`ClientEncrypterHalf`] and [`ClientDecrypterHalf`] structs.
///
/// Can be split into a [`ClientEncrypterHalf`] and [`ClientDecrypterHalf`] through
/// the [`ClientCrypto::split`] method. This is useful if you have this struct behind a
/// mutex and don't want to lock both reading and writing at the same time.
pub struct ClientCrypto {
    decrypt: ClientDecrypterHalf,
    encrypt: ClientEncrypterHalf,
}

impl ClientCrypto {
    /// Direct access to the internal [`ClientDecrypterHalf`].
    #[must_use]
    pub fn decrypter(&mut self) -> &mut ClientDecrypterHalf {
        &mut self.decrypt
    }

    /// Direct access to the internal [`ClientEncrypterHalf`].
    #[must_use]
    pub fn encrypter(&mut self) -> &mut ClientEncrypterHalf {
        &mut self.encrypt
    }

    /// Raw access to the encryption.
    ///
    /// Use either [the client](Self::write_encrypted_client_header)
    /// [`Write`](std::io::Write) function, or
    /// [the client](Self::encrypt_client_header)  array function.
    pub fn encrypt(&mut self, data: &mut [u8]) {
        self.encrypt.encrypt(data);
    }

    /// Convenience wrapper for [`ClientEncrypterHalf::write_encrypted_client_header`].
    ///
    /// # Errors
    ///
    /// Has the same errors as [`ClientEncrypterHalf::write_encrypted_client_header`].
    pub fn write_encrypted_client_header<W: Write>(
        &mut self,
        write: &mut W,
        size: u16,
        opcode: u32,
    ) -> std::io::Result<()> {
        self.encrypt
            .write_encrypted_client_header(write, size, opcode)
    }

    /// Convenience wrapper for [`ClientEncrypterHalf::encrypt_client_header`].
    #[must_use]
    pub fn encrypt_client_header(
        &mut self,
        size: u16,
        opcode: u32,
    ) -> [u8; CLIENT_HEADER_LENGTH as usize] {
        self.encrypt.encrypt_client_header(size, opcode)
    }

    /// Raw access to decryption.
    ///
    /// Use the
    /// [the client](Self::decrypt_server_header) array function.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.decrypt.decrypt(data);
    }

    /// Convenience wrapper for [`ClientDecrypterHalf::decrypt_server_header`].
    ///
    /// Prefer this over directly using [`Self::decrypt`].
    #[must_use]
    pub fn decrypt_server_header(
        &mut self,
        data: &[u8; SERVER_HEADER_MAXIMUM_LENGTH as usize],
    ) -> ServerHeader {
        self.decrypt.decrypt_server_header(data)
    }

    pub(crate) fn new(session_key: [u8; SESSION_KEY_LENGTH as usize]) -> Self {
        Self {
            decrypt: ClientDecrypterHalf::new(session_key),
            encrypt: ClientEncrypterHalf::new(session_key),
        }
    }

    /// Split the [`ClientCrypto`] into two parts for use with split connections.
    ///
    /// It is intended for the [`ClientEncrypterHalf`] to be stored with the write half of
    /// the connection and for the [`ClientDecrypterHalf`] to be stored with the read half
    /// of the connection.
    ///
    /// This is not necessary to do unless you actually can split your connections into
    /// read and write halves, and you have some reason for not just keeping the crypto together
    /// like if you don't want locking encryption to also lock decryption in a mutex.
    #[allow(clippy::missing_const_for_fn)] // Clippy does not consider `self` arg
    #[must_use]
    pub fn split(self) -> (ClientEncrypterHalf, ClientDecrypterHalf) {
        (self.encrypt, self.decrypt)
    }
}

/// Main struct for encryption or decryption.
///
/// Created from [`ProofSeed::into_header_crypto`].
///
/// Handles both encryption and decryption of headers through the
/// [`ServerEncrypterHalf`] and [`ServerDecrypterHalf`] structs.
///
/// Can be split into a [`ServerEncrypterHalf`] and [`ServerDecrypterHalf`] through
/// the [`ServerCrypto::split`] method. This is useful if you have this struct behind a
/// mutex and don't want to lock both reading and writing at the same time.
pub struct ServerCrypto {
    decrypt: ServerDecrypterHalf,
    encrypt: ServerEncrypterHalf,
}

impl ServerCrypto {
    /// Direct access to the internal [`ServerDecrypterHalf`].
    #[must_use]
    pub fn decrypter(&mut self) -> &mut ServerDecrypterHalf {
        &mut self.decrypt
    }

    /// Direct access to the internal [`ServerEncrypterHalf`].
    #[must_use]
    pub fn encrypter(&mut self) -> &mut ServerEncrypterHalf {
        &mut self.encrypt
    }

    /// Raw access to the encryption.
    ///
    /// Use either [the server](Self::write_encrypted_server_header)
    /// [`Write`](std::io::Write) function, or
    /// [the server](Self::encrypt_server_header)  array function.
    pub fn encrypt(&mut self, data: &mut [u8]) {
        self.encrypt.encrypt(data);
    }

    /// Convenience wrapper for [`ServerEncrypterHalf::write_encrypted_server_header`].
    ///
    /// # Errors
    ///
    /// Has the same errors as [`ServerEncrypterHalf::write_encrypted_server_header`].
    pub fn write_encrypted_server_header<W: Write>(
        &mut self,
        write: &mut W,
        size: u32,
        opcode: u16,
    ) -> std::io::Result<()> {
        self.encrypt
            .write_encrypted_server_header(write, size, opcode)
    }

    /// Convenience wrapper for [`ServerEncrypterHalf::encrypt_server_header`].
    #[must_use]
    pub fn encrypt_server_header(&mut self, size: u32, opcode: u16) -> &[u8] {
        self.encrypt.encrypt_server_header(size, opcode)
    }

    /// Raw access to decryption.
    ///
    /// Use either [the server](Self::read_and_decrypt_client_header)
    /// [`Read`](std::io::Read) function, or
    /// [the server](Self::decrypt_client_header) array functions.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.decrypt.decrypt(data);
    }

    /// Convenience wrapper for [`ServerDecrypterHalf::read_and_decrypt_client_header`].
    ///
    /// # Errors
    ///
    /// Has the same errors as [`ServerDecrypterHalf::read_and_decrypt_client_header`].
    pub fn read_and_decrypt_client_header<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> std::io::Result<ClientHeader> {
        self.decrypt.read_and_decrypt_client_header(reader)
    }

    /// Convenience wrapper for [`ServerDecrypterHalf::decrypt_client_header`].
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
            decrypt: ServerDecrypterHalf::new(session_key),
            encrypt: ServerEncrypterHalf::new(session_key),
        }
    }

    /// Split the [`ServerCrypto`] into two parts for use with split connections.
    ///
    /// It is intended for the [`ServerEncrypterHalf`] to be stored with the write half of
    /// the connection and for the [`ServerDecrypterHalf`] to be stored with the read half
    /// of the connection.
    ///
    /// This is not necessary to do unless you actually can split your connections into
    /// read and write halves, and you have some reason for not just keeping the crypto together
    /// like if you don't want locking encryption to also lock decryption in a mutex.
    #[allow(clippy::missing_const_for_fn)] // Clippy does not consider `self` arg
    #[must_use]
    pub fn split(self) -> (ServerEncrypterHalf, ServerDecrypterHalf) {
        (self.encrypt, self.decrypt)
    }
}

/// Random Seed part of the calculation needed to verify
/// that a client knows the session key.
///
/// The [`ProofSeed::into_header_crypto`] function is used by the server to verify
/// that a client knows the session key.
///
/// The [`ProofSeed::into_proof_and_header_crypto`] function is used by the client to
/// prove to the server that the client knows the session key.
#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct ProofSeed {
    seed: u32,
}

impl ProofSeed {
    /// Creates a new, random, seed.
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn from_specific_seed(server_seed: u32) -> Self {
        Self { seed: server_seed }
    }

    /// Either the server seed used in [`SMSG_AUTH_CHALLENGE`] or the client
    /// seed used in [`CMSG_AUTH_SESSION`].
    ///
    /// [`SMSG_AUTH_CHALLENGE`]: https://wowdev.wiki/SMSG_AUTH_CHALLENGE
    /// [`CMSG_AUTH_SESSION`]: https://wowdev.wiki/CMSG_AUTH_SESSION
    #[must_use]
    pub const fn seed(&self) -> u32 {
        self.seed
    }

    /// Generates world server proof and [`ClientCrypto`].
    ///
    /// This is not valid until the server has responded with a successful [`SMSG_AUTH_RESPONSE`].
    ///
    /// [`SMSG_AUTH_RESPONSE`]: https://wowdev.wiki/SMSG_AUTH_RESPONSE
    #[must_use]
    pub fn into_proof_and_header_crypto(
        self,
        username: &NormalizedString,
        session_key: [u8; SESSION_KEY_LENGTH as _],
        server_seed: u32,
    ) -> ([u8; PROOF_LENGTH as _], ClientCrypto) {
        let client_proof = calculate_world_server_proof(
            username,
            &SessionKey::from_le_bytes(session_key),
            server_seed,
            self.seed,
        );

        let crypto = ClientCrypto::new(session_key);

        (*client_proof.as_le(), crypto)
    }

    /// Asserts that the client knows the session key.
    ///
    /// # Errors
    ///
    /// If the `client_proof` does not match the server generated proof.
    /// This should only happen if:
    ///
    /// * There's an error with the provided parameters.
    /// * The session key might be out of date.
    /// * The client is not well behaved and deliberately trying to get past the login server.
    ///
    pub fn into_header_crypto(
        self,
        username: &NormalizedString,
        session_key: [u8; SESSION_KEY_LENGTH as _],
        client_proof: [u8; PROOF_LENGTH as _],
        client_seed: u32,
    ) -> Result<ServerCrypto, MatchProofsError> {
        let server_proof = calculate_world_server_proof(
            username,
            &SessionKey::from_le_bytes(session_key),
            self.seed,
            client_seed,
        );

        if server_proof != Proof::from_le_bytes(client_proof) {
            return Err(MatchProofsError {
                client_proof,
                server_proof: *server_proof.as_le(),
            });
        }

        Ok(ServerCrypto::new(session_key))
    }
}

impl Default for ProofSeed {
    fn default() -> Self {
        Self {
            seed: thread_rng().next_u32(),
        }
    }
}

#[cfg(test)]
mod test {
    use std::fs::read_to_string;

    use crate::hex::*;
    use crate::key::SessionKey;
    use crate::normalized_string::NormalizedString;
    use crate::wrath_header::{
        ClientCrypto, ProofSeed, ServerCrypto, SERVER_HEADER_MAXIMUM_LENGTH,
        SERVER_HEADER_MINIMUM_LENGTH,
    };
    use std::convert::TryInto;

    #[test]
    fn verify_seed_proof() {
        const FILE: &str = "tests/encryption/calculate_world_server_proof.txt";
        let contents = read_to_string(FILE).unwrap();
        for line in contents.lines() {
            let mut line = line.split_whitespace();

            let username = line.next().unwrap();
            let session_key = SessionKey::from_be_hex_str(line.next().unwrap());
            let server_seed =
                u32::from_le_bytes(hex_decode(line.next().unwrap()).try_into().unwrap());
            let client_seed = ProofSeed::from_specific_seed(u32::from_le_bytes(
                hex_decode(line.next().unwrap()).try_into().unwrap(),
            ));
            let expected: [u8; 20] = hex_decode(line.next().unwrap()).try_into().unwrap();

            let (proof, _) = client_seed.into_proof_and_header_crypto(
                &username.try_into().unwrap(),
                *session_key.as_le(),
                server_seed,
            );

            assert_eq!(expected, proof);
        }
    }

    #[test]
    fn verify_client_and_server_agree() {
        let session_key = [
            239, 107, 150, 237, 174, 220, 162, 4, 138, 56, 166, 166, 138, 152, 188, 146, 96, 151,
            1, 201, 202, 137, 231, 87, 203, 23, 62, 17, 7, 169, 178, 1, 51, 208, 202, 223, 26, 216,
            250, 9,
        ];

        let username = NormalizedString::new("A").unwrap();

        let client_seed = ProofSeed::new();
        let client_seed_value = client_seed.seed();
        let server_seed = ProofSeed::new();

        let (client_proof, mut client_crypto) =
            client_seed.into_proof_and_header_crypto(&username, session_key, server_seed.seed());

        let mut server_crypto = server_seed
            .into_header_crypto(&username, session_key, client_proof, client_seed_value)
            .unwrap();

        let original_data = hex_decode("3d9ae196ef4f5be4df9ea8b9f4dd95fe68fe58b653cf1c2dbeaa0be167db9b27df32fd230f2eab9bd7e9b2f3fbf335d381ca");
        let mut data = original_data.clone();

        client_crypto.encrypt(&mut data);
        server_crypto.decrypt(&mut data);

        assert_eq!(original_data, data);

        server_crypto.encrypt(&mut data);
        client_crypto.decrypt(&mut data);

        assert_eq!(original_data, data);
    }

    #[test]
    fn verify_headers() {
        // Real capture with 3.3.5 client
        let session_key = [
            1, 51, 81, 113, 146, 209, 181, 133, 131, 129, 50, 206, 122, 228, 208, 115, 52, 15, 132,
            54, 189, 17, 178, 157, 178, 3, 35, 186, 202, 151, 226, 58, 162, 188, 65, 174, 60, 18,
            152, 7,
        ];

        let client_proof = [
            145, 164, 79, 1, 159, 98, 226, 16, 5, 12, 237, 65, 135, 95, 214, 190, 65, 92, 15, 77,
        ];
        let client_seed = 3567746900;

        let mut encryption = ProofSeed::from_specific_seed(3818341363)
            .into_header_crypto(
                &NormalizedString::new("A").unwrap(),
                session_key,
                client_proof,
                client_seed,
            )
            .unwrap();

        let header = encryption.encrypt_server_header(13, 0x1ee);
        let expected_header = [0x17, 0xaa, 0xd4, 0x4c];
        assert_eq!(header, expected_header);

        let header = encryption.decrypt_client_header([0x85, 0x0f, 0x6e, 0x91, 0x55, 0xf9]);
        assert_eq!(header.size, 4);
        assert_eq!(header.opcode, 0x4ff);

        let header = encryption.encrypt_server_header(277, 0x3b);
        let expected_header = [0x1a, 0x9c, 0x7c, 0x10];
        assert_eq!(header, expected_header);

        let header = encryption.decrypt_client_header([0x56, 0x8e, 0x8c, 0x9a, 0xed, 0x42]);
        assert_eq!(header.size, 4);
        assert_eq!(header.opcode, 0x37);

        let header = encryption.encrypt_server_header(19, 0x38B);
        let expected_header = [0x10, 0xfb, 0x6e, 0xa8];
        assert_eq!(header, expected_header);

        let header = encryption.decrypt_client_header([0xc2, 0xf3, 0xb7, 0xc5, 0x17, 0xbc]);
        assert_eq!(header.size, 8);
        assert_eq!(header.opcode, 0x38c);

        let header = encryption.decrypt_client_header([0x30, 0xf7, 0xa6, 0xee, 0x74, 0xbe]);
        assert_eq!(header.size, 12);
        assert_eq!(header.opcode, 0x1DC);
    }

    #[test]
    fn verify_login() {
        let session_key = [
            115, 0, 100, 222, 18, 15, 156, 194, 27, 1, 216, 229, 165, 207, 78, 233, 183, 241, 248,
            73, 190, 142, 14, 89, 44, 235, 153, 190, 103, 206, 34, 88, 45, 199, 104, 175, 79, 108,
            93, 48,
        ];
        let username = NormalizedString::new("A").unwrap();
        let server_seed = 0xDEADBEEF;
        let client_seed = 1266519981;
        let client_proof = [
            202, 54, 102, 180, 90, 87, 9, 107, 217, 97, 235, 56, 221, 203, 108, 19, 109, 141, 137,
            7,
        ];

        let seed = ProofSeed::from_specific_seed(server_seed);
        let encryption = seed.into_header_crypto(&username, session_key, client_proof, client_seed);
        assert!(encryption.is_ok());
    }

    #[test]
    fn verify_encrypt_and_decrypt() {
        let contents =
            read_to_string("tests/encryption/calculate_wrath_encrypt_values.txt").unwrap();

        for line in contents.lines() {
            let mut line = line.split_whitespace();

            let session_key = SessionKey::from_le_hex_str(line.next().unwrap());
            let mut data = hex_decode(line.next().unwrap());
            let expected_client = hex_decode(line.next().unwrap());
            let expected_server = hex_decode(line.next().unwrap());

            let original_data = data.clone();

            let mut client = ClientCrypto::new(*session_key.as_le());
            client.encrypt(&mut data);
            assert_eq!(data, expected_client);

            let mut server = ServerCrypto::new(*session_key.as_le());
            server.decrypt(&mut data);
            assert_eq!(data, original_data);

            server.encrypt(&mut data);
            assert_eq!(data, expected_server);

            client.decrypt(&mut data);
            assert_eq!(data, original_data);
        }
    }

    #[test]
    fn verify_splitting() {
        // Same as verify_encrypt_and_decrypt but with split
        let contents =
            read_to_string("tests/encryption/calculate_wrath_encrypt_values.txt").unwrap();

        for line in contents.lines() {
            let mut line = line.split_whitespace();

            let session_key = SessionKey::from_le_hex_str(line.next().unwrap());
            let mut data = hex_decode(line.next().unwrap());
            let expected_client = hex_decode(line.next().unwrap());
            let expected_server = hex_decode(line.next().unwrap());

            let original_data = data.clone();

            let (mut client_enc, mut client_dec) = ClientCrypto::new(*session_key.as_le()).split();
            client_enc.encrypt(&mut data);
            assert_eq!(data, expected_client);

            let (mut server_enc, mut server_dec) = ServerCrypto::new(*session_key.as_le()).split();
            server_dec.decrypt(&mut data);
            assert_eq!(data, original_data);

            server_enc.encrypt(&mut data);
            assert_eq!(data, expected_server);

            client_dec.decrypt(&mut data);
            assert_eq!(data, original_data);
        }
    }

    #[test]
    fn verify_server_header() {
        let session_key = [
            1, 51, 81, 113, 146, 209, 181, 133, 131, 129, 50, 206, 122, 228, 208, 115, 52, 15, 132,
            54, 189, 17, 178, 157, 178, 3, 35, 186, 202, 151, 226, 58, 162, 188, 65, 174, 60, 18,
            152, 7,
        ];

        let mut server = ServerCrypto::new(session_key);
        let mut client = ClientCrypto::new(session_key);

        let header = server.encrypt_server_header(0x8008, 0x1ee);
        let expected_header = [0x97, 0x27, 0x32, 0xa3, 0x1a];
        assert_eq!(header, expected_header);

        let header = client.decrypt_server_header(&header.try_into().unwrap());
        assert_eq!(header.opcode, 0x1ee);
        assert_eq!(header.size, 0x8008);

        let header = server.encrypt_server_header(0x08, 0x1ee);
        let expected_header = [0x89, 0x4F, 0xFE, 0x11];
        assert_eq!(header, expected_header);

        let mut arr = [0_u8; SERVER_HEADER_MAXIMUM_LENGTH as usize];
        for (i, b) in header.iter().enumerate() {
            arr[i] = *b;
        }
        let header = client.decrypt_server_header(&arr);
        assert_eq!(header.opcode, 0x1ee);
        assert_eq!(header.size, 0x08);
    }

    #[test]
    fn verify_server_header_read_write() {
        let session_key = [
            1, 51, 81, 113, 146, 209, 181, 133, 131, 129, 50, 206, 122, 228, 208, 115, 52, 15, 132,
            54, 189, 17, 178, 157, 178, 3, 35, 186, 202, 151, 226, 58, 162, 188, 65, 174, 60, 18,
            152, 7,
        ];

        let mut server = ServerCrypto::new(session_key);
        let mut client = ClientCrypto::new(session_key);

        let mut header = [0_u8; SERVER_HEADER_MAXIMUM_LENGTH as usize];
        server
            .write_encrypted_server_header(&mut header.as_mut_slice(), 0x8008, 0x1ee)
            .unwrap();
        let expected_header = [0x97, 0x27, 0x32, 0xa3, 0x1a];
        assert_eq!(header, expected_header);

        let server_header = client.decrypt_server_header(&header);
        assert_eq!(server_header.opcode, 0x1ee);
        assert_eq!(server_header.size, 0x8008);

        let mut header = [0_u8; SERVER_HEADER_MINIMUM_LENGTH as usize];
        server
            .write_encrypted_server_header(&mut header.as_mut_slice(), 0x08, 0x1ee)
            .unwrap();
        let expected_header = [0x89_u8, 0x4F, 0xFE, 0x11];
        assert_eq!(header, expected_header);

        let mut arr = [0_u8; SERVER_HEADER_MAXIMUM_LENGTH as usize];
        for (i, b) in header.iter().enumerate() {
            arr[i] = *b;
        }
        let header = client.decrypt_server_header(&arr);
        assert_eq!(header.opcode, 0x1ee);
        assert_eq!(header.size, 0x08);
    }
}
