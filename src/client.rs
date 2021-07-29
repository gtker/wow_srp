//! Contains all functionality related to the client part.
//!
//! All arrays are **little endian**.
//! See `examples/client.rs` for how to authenticate with a server.
//!
//! # Usage
//!
//! The [Typestate](https://yoric.github.io/post/rust-typestate/) pattern is used
//! in order to prevent incorrect use.
//! This means that whenever the next step of computation takes place, you call a function
//! taking `self`, consuming the old object, and returning the new object.
//!
//! The state machine goes like this:
//! ```text
//! SrpClientUser -> SrpClientChallenge -> SrpClient -| -> SrpClientReconnection
//!                                            ^      |
//!                                            |------|
//! ```
//! Where an [`SrpClientReconnection`] object is a temporary data struct from
//! [`SrpClient::calculate_reconnect_values`]
//! that contains only the necessary reconnect values.
//!
//! When reaching [`SrpClient`] the client has fully authenticated with the server and should be able to
//! send the [`CMD_REALM_LIST_Client`](https://wowdev.wiki/CMD_REALM_LIST_Client) packet.
//!
//! # Example
//!
//! The chain starts with an [`SrpClientUser`], then goes to an [`SrpClientChallenge`] and ends
//! with the [`SrpClient`] which returns [`SrpClientReconnection`]s for reconnecting challenges.
//!
//! The full example including network code can be found in `examples/client.rs`.
//!
//! # Limitations
//!
//! The client has some limitations that enable a simpler overall design:
//!
//! * Fixed [32 byte](`LARGE_SAFE_PRIME_LENGTH`) large safe prime length.
//! Despite the field in the packet being variable the client is unable
//! to use values greater than 32 bytes.
//! * Only accepting valid [`NormalizedString`] values.
//! This is done to unify the server and client implementations.
//! * [GENERATOR](crate::GENERATOR) can be only be a u8 despite the
//! [`CMD_AUTH_LOGON_CHALLENGE_Server`](https://wowdev.wiki/CMD_AUTH_LOGON_CHALLENGE_Server)
//! packet having a variable sized generator field.
//! This is done because there are no generator values larger than 255.
//!

use crate::error::MatchProofsError;
use crate::key::{
    PrivateKey, Proof, PublicKey, ReconnectData, Salt, SessionKey, PRIVATE_KEY_LENGTH,
    PROOF_LENGTH, PUBLIC_KEY_LENGTH, RECONNECT_CHALLENGE_DATA_LENGTH, SALT_LENGTH,
    SESSION_KEY_LENGTH,
};
use crate::normalized_string::NormalizedString;
use crate::primes::{Generator, LargeSafePrime, LARGE_SAFE_PRIME_LENGTH};
use crate::srp_internal::{
    calculate_interleaved, calculate_reconnect_proof, calculate_server_proof, calculate_u,
};
use crate::srp_internal_client::{calculate_client_S, calculate_client_proof_with_custom_value};
use crate::{srp_internal, srp_internal_client};

/// Contains the challenge data and proof for reconnection.
///
/// This is tied completely to the server challenge data passed to
/// [`SrpClient::calculate_reconnect_values`].
///
/// Both arrays are **little endian**.
pub struct SrpClientReconnection {
    /// Random data used in the reconnect challenge.
    pub challenge_data: [u8; RECONNECT_CHALLENGE_DATA_LENGTH as usize],
    /// Proof that the client knows the session key.
    pub proof: [u8; PROOF_LENGTH as usize],
}

/// Represents a connection with the server. The final part of the state machine, previous was
/// [`SrpClientChallenge`].
///
/// Once this struct has been created the client and server have proven to each other that they
/// both have the same password, and that they have an identical session key.
///
/// This is also used to prove to the server during reconnection that the client knows the
/// session key.
///
/// The session key is used later for encrypting/decrypting traffic.
///
/// All arrays are **little endian**.
pub struct SrpClient {
    username: NormalizedString,
    session_key: SessionKey,
}

impl SrpClient {
    /// Called `K` in [RFC2945](https://tools.ietf.org/html/rfc2945), and sometimes `S` in other places.
    ///
    /// The session key is always [40 bytes (320 bits)](SESSION_KEY_LENGTH) in length because it is
    /// created from 2 SHA-1 hashes of [20 bytes (160 bits)](PROOF_LENGTH).
    #[doc(alias = "S")]
    #[doc(alias = "K")]
    pub const fn session_key(&self) -> [u8; SESSION_KEY_LENGTH as usize] {
        *self.session_key.as_le()
    }

    /// Calculates the client challenge data and proof found in [`SrpClientReconnection`].
    ///
    /// The server challenge data is sent in the
    /// [`CMD_AUTH_RECONNECT_CHALLENGE_Server`](https://wowdev.wiki/CMD_AUTH_RECONNECT_CHALLENGE_Server)
    /// packet.
    ///
    /// The client challenge, and therefore also the proof, is changed every time this is called.
    pub fn calculate_reconnect_values(
        &self,
        server_challenge_data: [u8; RECONNECT_CHALLENGE_DATA_LENGTH as usize],
    ) -> SrpClientReconnection {
        let client_challenge = ReconnectData::randomized();

        let client_proof = calculate_reconnect_proof(
            &self.username,
            &client_challenge,
            &ReconnectData::from_le_bytes(server_challenge_data),
            &self.session_key,
        );

        SrpClientReconnection {
            challenge_data: *client_challenge.as_le(),
            proof: *client_proof.as_le(),
        }
    }
}

/// Second step of the client connection. First is [`SrpClientUser`]. Next is [`SrpClient`].
///
/// The client proof and public key must be sent to the server in the
/// [`CMD_AUTH_LOGON_PROOF_Client`](https://wowdev.wiki/CMD_AUTH_LOGON_PROOF_Client)
/// packet before the server proof is available.
///
/// All arrays are **little endian**.
///
/// The CRC check also present in the same network packet is out of scope for this crate.
pub struct SrpClientChallenge {
    username: NormalizedString,
    client_proof: Proof,
    client_public_key: PublicKey,

    session_key: SessionKey,
}

impl SrpClientChallenge {
    /// Called `M` in [RFC2945](https://tools.ietf.org/html/rfc2945), called `M1` in other literature.
    /// `M2` is the argument passed to [`SrpClientChallenge::verify_server_proof`].
    #[doc(alias = "M")]
    #[doc(alias = "M1")]
    #[doc(alias = "M2")]
    pub const fn client_proof(&self) -> &[u8; PROOF_LENGTH as usize] {
        self.client_proof.as_le()
    }

    /// Called `A` in [RFC2945](https://tools.ietf.org/html/rfc2945).
    /// Also sometimes referred to as `a`, although this is the abbreviation of the private key.
    /// If the lowercase version appears in a packet table it is referring to the public key.
    #[doc(alias = "A")]
    pub const fn client_public_key(&self) -> &[u8; PUBLIC_KEY_LENGTH as usize] {
        self.client_public_key.as_le()
    }

    /// Verifies that the server knows the same password as was initially used in [`SrpClientUser::new`].
    ///
    /// # Errors
    ///
    /// This should very rarely return an error unless something weird is going on with the server,
    /// ther server deliberately sends an incorrect value, or the packet has been read incorrectly.
    pub fn verify_server_proof(
        self,
        server_proof: [u8; PROOF_LENGTH as usize],
    ) -> Result<SrpClient, MatchProofsError> {
        let client_server_proof = calculate_server_proof(
            &self.client_public_key,
            &self.client_proof,
            &self.session_key,
        );

        let server_proof = Proof::from_le_bytes(server_proof);
        if server_proof != client_server_proof {
            return Err(MatchProofsError {
                client_proof: *client_server_proof.as_le(),
                server_proof: *server_proof.as_le(),
            });
        }

        Ok(SrpClient {
            username: self.username,
            session_key: self.session_key,
        })
    }
}

/// Starting point of the client. Next step is [`SrpClientChallenge`].
///
/// Uses [`NormalizedString`]s for the reasons described there.
///
/// All arrays are **little endian**.
pub struct SrpClientUser {
    username: NormalizedString,
    password: NormalizedString,
    client_private_key: PrivateKey,
}

impl SrpClientUser {
    /// Creates a new [`SrpClientUser`] from username and password.
    ///
    /// [`NormalizedString`] is used for the reasons described there.
    pub fn new(username: NormalizedString, password: NormalizedString) -> Self {
        let client_private_key = PrivateKey::randomized();

        Self::with_specific_private_key(username, password, *client_private_key.as_le())
    }

    pub(crate) const fn with_specific_private_key(
        username: NormalizedString,
        password: NormalizedString,
        client_private_key: [u8; PRIVATE_KEY_LENGTH as usize],
    ) -> Self {
        let client_private_key = PrivateKey::from_le_bytes(client_private_key);

        Self {
            username,
            password,
            client_private_key,
        }
    }

    /// Takes the server supplied variables and computes the next step.
    ///
    /// The generator and large safe prime are **not** checked for validity.
    ///
    /// All arrays are **little endian**.
    ///
    /// # Panics
    ///
    /// Panics on the extremely unlikely chance that the generated public key is invalid.
    /// See [`PublicKey`] for details on validity.
    ///
    /// There are only two invalid states for the randomly generated server public key:
    /// * All zeros.
    /// * Exactly the same as [the large safe prime](`crate::LARGE_SAFE_PRIME_LITTLE_ENDIAN`).
    ///
    /// This is 2 out of `2^256` possible states. The chances of this occurring naturally are very slim.
    /// It is significantly more likely that the RNG of the system has been compromised in which case
    /// authentication is not possible.
    ///
    pub fn into_challenge(
        self,
        generator: u8,
        large_safe_prime: [u8; LARGE_SAFE_PRIME_LENGTH as usize],
        server_public_key: PublicKey,
        salt: [u8; SALT_LENGTH as usize],
    ) -> SrpClientChallenge {
        let generator = Generator::from(generator);
        let large_safe_prime = LargeSafePrime::from_le_bytes(&large_safe_prime);

        // Creating an invalid public key is extremely rare and is more likely bad crypto
        let client_public_key = srp_internal_client::calculate_client_public_key(
            &self.client_private_key,
            &generator,
            &large_safe_prime,
        )
        .expect("Invalid public key generated for client. This is extremely unlikely.");

        let salt = Salt::from_le_bytes(salt);
        let x = srp_internal::calculate_x(&self.username, &self.password, &salt);

        let u = &calculate_u(&client_public_key, &server_public_key);
        #[allow(non_snake_case)] // No better descriptor
        let S = calculate_client_S(
            &server_public_key,
            &x,
            &self.client_private_key,
            &u,
            &generator,
            &large_safe_prime,
        );
        let session_key = calculate_interleaved(&S);

        let client_proof = calculate_client_proof_with_custom_value(
            &self.username,
            &session_key,
            &client_public_key,
            &server_public_key,
            &salt,
            large_safe_prime,
            generator,
        );

        SrpClientChallenge {
            username: self.username,
            client_proof,
            client_public_key,
            session_key,
        }
    }
}
