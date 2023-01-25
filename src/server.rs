//! Contains all functionality related to the server part,
//! including the generation of values for the database.
//!
//! All arrays are **little endian**.
//! See `examples/server.rs` for how to interface with real clients.
//!
//! # Generating database values
//!
//! When signing up a new user you want to take their username and password and
//! convert them into the values stored in your database.
//! This is done with the [`SrpVerifier::from_username_and_password`] function.
//! This allows you to get the username, password verifier and salt values.
//! The [`SrpVerifier`] page contains specifics.
//! The [`SrpVerifier`] struct is created using [`NormalizedString`]s, the reasoning is
//! explained on the [`normalized_string`](`crate::normalized_string`) page.
//!
//! This could look something like this:
//! ```
//! use wow_srp::server::SrpVerifier;
//! use wow_srp::{error::NormalizedStringError, SALT_LENGTH, PASSWORD_VERIFIER_LENGTH};
//! use wow_srp::normalized_string::NormalizedString;
//!
//! // Generic function to tie everything together
//! fn get_credentials_and_save_to_database() -> Result<(),
//!                                      NormalizedStringError> {
//!     // This would be gotten from the sign up page
//!     let username = NormalizedString::new("Alice")?;
//!     let password = NormalizedString::new("password123")?;
//!     let v
//!          = SrpVerifier::from_username_and_password(username, password);
//!
//!     // The SrpVerifier is no longer needed after this
//!     // See NormalizedString for whether to save raw username or NormalizedString in Database
//!     save_values_to_database(v.username(),
//!                             &v.password_verifier(),
//!                             &v.salt());
//!     // Return successful
//!     Ok(())
//! }
//!
//! fn save_values_to_database(username: &str,
//!                            password_verifier: &[u8; PASSWORD_VERIFIER_LENGTH as usize],
//!                            salt: &[u8; SALT_LENGTH as usize]) {
//!     // DB specific stuff here.
//! }
//! ```
//!
//! # Authenticating on the server
//!
//! A functional example is included in `examples/server.rs`.
//! This text focuses on a high level overview and important notices.
//!
//! The [Typestate](https://yoric.github.io/post/rust-typestate/) pattern is used
//! in order to prevent incorrect use.
//! This means that whenever the next step of computation takes place, you call a function
//! taking `self`, consuming the old object, and returning the new object.
//!
//! When authenticating players attempting to connect to the server, we start from where we let go
//! with the last example.
//!
//! * First an [`SrpVerifier`] is created using the database values,
//! * Then [`SrpVerifier::into_proof`] is called to convert it into an [`SrpProof`],
//! * Finally [`SrpProof::into_server`] is called to convert it into an [`SrpServer`] and a
//! server proof.
//!
//! The [`SrpServer`] means that the client has been correctly authenticated
//! and can be sent the realmlist.
//! The [`SrpServer`] also provides the possibility of authenticating reconnects.
//! The [`SrpServer`] does _NOT_ provide any rate limiting or time based expiration of the
//! ability to reconnect, this means that the implementer will need to ensure that clients
//! do not abuse the functionality.
//!
//! The state machine goes like this:
//! ```text
//! SrpVerifier -> SrpProof -> mut SrpServer -|
//!                   +                ^      |
//!              server_proof          |      |
//!                                    |------|
//! ```
//! Where you would keep a mutable [`SrpServer`] around for reconnects and using the session key.
//! If any of the steps fail before the [`SrpServer`] has been created all progress will be lost.
//! After the [`SrpServer`] is created, an unlimited amount of reconnection attemps can be made,
//! and the call to [`SrpServer::verify_reconnection_attempt`] will automatically refresh the
//! [`SrpServer::reconnect_challenge_data`].
//!
//! ```
//! use wow_srp::server::SrpVerifier;
//! use wow_srp::normalized_string::NormalizedString;
//! use wow_srp::{PASSWORD_VERIFIER_LENGTH, SALT_LENGTH, error::SrpError, error::NormalizedStringError, PublicKey};
//!
//! fn server() -> Result<(), SrpError> {
//!     // Gotten from database
//!     let username = NormalizedString::new("A")?;
//!     let password_verifier = [ 106, 6, 11, 113, 103, 55, 49, 130, 210, 249, 178, 176, 73, 77, 229, 163, 127, 223, 122, 163, 245, 174, 60, 217, 151, 142, 169, 173, 208, 8, 152, 31, ];
//!     let salt = [ 120, 156, 208, 137, 73, 108, 21, 91, 28, 22, 13, 255, 99, 116, 71, 102, 158, 70, 65, 189, 153, 244, 143, 13, 214, 200, 160, 94, 217, 112, 206, 125, ];
//!
//!     let verifier = SrpVerifier::from_database_values(username, password_verifier, salt);
//!     let proof = verifier.into_proof();
//!
//!     // Gotten from client
//!     let client_public_key = [ 105, 93, 211, 227, 214, 155, 247, 119, 156, 33, 156, 79, 15, 139, 100, 120, 1, 180, 32, 66, 165, 41, 175, 146, 216, 251, 25, 207, 18, 14, 35, 68, ];
//!     // Can fail on invalid public key. See PublicKey for more info.
//!     let client_public_key = PublicKey::from_le_bytes(&client_public_key)?;
//!
//!     let client_proof = [ 228, 40, 212, 74, 196, 143, 169, 148, 201, 150, 184, 123, 205, 40, 103, 234, 99, 155, 193, 7, ];
//!
//!     // Can fail on proof comparison which means the password is incorrect.
//!     // Send a failure packet and drop the connection.
//!     let (mut server, server_proof) = proof.into_server(client_public_key, client_proof)?;
//!     // If this passes the client is successfully authenticated.
//!
//!     // Send the proof to client to prove that the server also knows the correct password.
//!
//!     // Add the server object to e.g. a HashMap of authenticated users.
//!     // Client will now send a 'Send Realmlist' packet
//!
//!     // Client wants to reconnect
//!     let reconnect_data = server.reconnect_challenge_data();
//!     // Send to client
//!     
//!     // Get back from client
//!     let client_data = [ 8, 226, 88, 41, 231, 219, 29, 59, 127, 98, 180, 55, 32, 201, 135, 163, ];
//!     let client_proof = [ 37, 167, 41, 153, 253, 156, 41, 174, 225, 125, 246, 158, 106, 248, 158, 232, 146, 8, 242, 164, ];
//!
//!     // Returns true if the proofs match, client is allowed to reconnect
//!     assert!(server.verify_reconnection_attempt(client_data, client_proof));
//!
//!     Ok(())
//! }
//! ```
//!

use crate::error::MatchProofsError;
use crate::key::{
    PrivateKey, Proof, PublicKey, ReconnectData, Salt, SessionKey, PROOF_LENGTH, PUBLIC_KEY_LENGTH,
    RECONNECT_CHALLENGE_DATA_LENGTH, SALT_LENGTH, SESSION_KEY_LENGTH,
};
use crate::key::{Verifier, PASSWORD_VERIFIER_LENGTH};
use crate::normalized_string::NormalizedString;
use crate::srp_internal::calculate_reconnect_proof;
use crate::{error::InvalidPublicKeyError, srp_internal};

/// Creates and contains the username, password verifier, and salt values.
/// First step of the server, next is [`SrpProof`].
///
/// These are values that should be stored in the database.
/// Do **NOT** store raw passwords in the database.
///
/// The salt is a randomly generated [32 byte](SALT_LENGTH) array of random data used as salt for
/// the password verifier.
/// The verifier is the result of SHA-1 hashing a combination of the username, password and salt.
/// The salt is sent over the network for the client to use.
/// The password verifier is used for generating the server public key, and should never leave the server.
/// The private key is not exposed through any of the structs.
///
/// All byte arrays are **little endian**.
///
/// # Example
///
/// ```rust
/// use wow_srp::normalized_string::NormalizedString;
/// use wow_srp::{error::NormalizedStringError, SALT_LENGTH, PASSWORD_VERIFIER_LENGTH};
/// use wow_srp::server::SrpVerifier;
///
/// // Create salt and password verifier values for signup page
/// fn to_database() -> Result<(), NormalizedStringError> {
///     // See NormalizedString for specifics.
///     let username = NormalizedString::new("Alice")?;
///     let password = NormalizedString::new("password123")?;
///
///     let verifier = SrpVerifier::from_username_and_password(username, password);
///
///     assert_eq!("ALICE", verifier.username());
///
///     // Salt is randomly chosen and password_verifier depends on salt so we can't assert_eq
///     // Store these values in the database for future authentication
///     let password_verifier = verifier.password_verifier();
///     let salt = verifier.salt();
///
///     Ok(())
/// }
///
/// // Authenticate client logging into game server
/// fn from_database() -> Result<(), NormalizedStringError> {
///     // Get these from the database
///     let username = NormalizedString::new("Alice")?;
///     let password_verifier = [0u8; PASSWORD_VERIFIER_LENGTH as usize];
///     let salt = [0u8; SALT_LENGTH as usize];
///
///     let verifier = SrpVerifier::from_database_values(username, password_verifier, salt);
///
///     // Next step is continuing into the state machine, see into_proof() and SrpProof for more.
///     let proof = verifier.into_proof();
///
///     Ok(())
/// }
///
/// # to_database();
/// ```
#[doc(alias = "v")]
#[doc(alias = "salt")]
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SrpVerifier {
    username: NormalizedString,
    password_verifier: Verifier,
    salt: Salt,
}

impl SrpVerifier {
    #[doc(alias = "U")]
    /// The [`normalized_string`](`crate::normalized_string`) representation of the username,
    /// see that for more details.
    ///
    /// Called `U` and `<username>` in [RFC2945](https://tools.ietf.org/html/rfc2945).
    #[must_use]
    pub fn username(&self) -> &str {
        self.username.as_ref()
    }

    #[doc(alias = "v")]
    /// The password verifier. Should not be used except for when saving to the database.
    /// Array is **little endian**.
    ///
    /// Called `v` and `<password verifier>` in [RFC2945](https://tools.ietf.org/html/rfc2945).
    /// Always [32 bytes (256 bits)](crate::PASSWORD_VERIFIER_LENGTH) in length
    /// since the value is generated through
    /// the remainder of a [32 byte value](crate::LARGE_SAFE_PRIME_LENGTH).
    #[must_use]
    pub const fn password_verifier(&self) -> &[u8; PASSWORD_VERIFIER_LENGTH as usize] {
        self.password_verifier.as_le()
    }

    #[doc(alias = "s")]
    /// Salt value used for calculating verifier. Is sent to the client.
    /// Array is **little endian**.
    ///
    /// Called `s`, `<salt from passwd file>` and `<salt>` in [RFC2945](https://tools.ietf.org/html/rfc2945).
    /// Always [32 bytes (256 bits)](crate::SALT_LENGTH) in length since the packet sent to
    /// the client has a fixed width.
    #[must_use]
    pub const fn salt(&self) -> &[u8; SALT_LENGTH as usize] {
        self.salt.as_le()
    }

    /// See [`normalized_string`](`crate::normalized_string`) for more information on the format.
    /// Only use this for generating verifiers and salts to save to the database.
    /// Never use this by saving raw usernames and passwords on the database.
    #[must_use]
    pub fn from_username_and_password(
        username: NormalizedString,
        password: NormalizedString,
    ) -> Self {
        let salt = Salt::randomized();

        Self::with_specific_salt(username, password, &salt)
    }

    /// See [`normalized_string`](`crate::normalized_string`) for more information on the string format.
    /// Both arrays are **little endian**.
    #[must_use]
    pub const fn from_database_values(
        username: NormalizedString,
        password_verifier: [u8; PASSWORD_VERIFIER_LENGTH as usize],
        salt: [u8; SALT_LENGTH as usize],
    ) -> Self {
        Self {
            username,
            password_verifier: Verifier::from_le_bytes(password_verifier),
            salt: Salt::from_le_bytes(salt),
        }
    }

    /// Converts to an [`SrpProof`], consuming the [`SrpVerifier`].
    ///
    /// # Panics:
    ///
    /// * Panics if the RNG returns an error. If RNG does not work the authentication server
    /// should not continue functioning and therefore panics.
    /// * _Very_ rarely panic if the server generated public key is invalid.
    ///
    /// There are only two invalid states for the randomly generated server public key:
    /// * All zeros.
    /// * Exactly the same as [the large safe prime](`crate::LARGE_SAFE_PRIME_LITTLE_ENDIAN`).
    ///
    /// This is 2 out of `2^256` possible states. The chances of this occurring naturally are very slim.
    /// It is significantly more likely that the RNG of the system has been compromised in which case
    /// authentication is not possible.
    #[doc(alias = "M")]
    #[doc(alias = "M1")]
    #[doc(alias = "M2")]
    #[must_use]
    pub fn into_proof(self) -> SrpProof {
        let server_private_key = PrivateKey::randomized();

        Self::with_specific_private_key(self, server_private_key)
            .expect("The generated public key was invalid. This is insanely unlikely and even if you only see this error once you should probably check that your random number generation has not been compromised in some way. See documentation for SrpVerifier. Please report this on Github at 'https://github.com/gtker/wow_srp'.")
    }

    fn with_specific_salt(
        username: NormalizedString,
        password: NormalizedString,
        salt: &Salt,
    ) -> Self {
        let password_verifier =
            srp_internal::calculate_password_verifier(&username, &password, salt);

        Self::from_database_values(username, password_verifier, *salt.as_le())
    }

    fn with_specific_private_key(
        self,
        server_private_key: PrivateKey,
    ) -> Result<SrpProof, InvalidPublicKeyError> {
        let server_public_key = srp_internal::calculate_server_public_key(
            &self.password_verifier,
            &server_private_key,
        )?;

        Ok(SrpProof {
            username: self.username,
            server_public_key,
            salt: self.salt,
            server_private_key,
            password_verifier: self.password_verifier,
        })
    }
}

/// Contains the server public key, private key and salt. Second step of the server, next is [`SrpServer`].
///
/// This struct is created from the [`SrpVerifier::into_proof`] method.
/// The server public key is generated from the verifier and a random private key.
/// The salt is the same as the [`SrpVerifier`].
///
/// The client also requires the [large safe prime](crate::LARGE_SAFE_PRIME_LITTLE_ENDIAN) and the
/// [generator](crate::GENERATOR). These are static values that never change and therefore they
/// have their own const variables.
///
/// The private key used is 32 bytes long.
///
/// See `examples/server.rs` for the full example.
///
/// All byte arrays are **little endian**.
///
/// # Example
///
/// The example cuts out stuff related to [`SrpVerifier`] and [`SrpServer`].
/// ```
/// # use wow_srp::{error::MatchProofsError, PUBLIC_KEY_LENGTH, PROOF_LENGTH, PublicKey, error::InvalidPublicKeyError, LARGE_SAFE_PRIME_LITTLE_ENDIAN, GENERATOR};
/// # use wow_srp::server::{SrpVerifier, SrpServer};
/// # use wow_srp::normalized_string::NormalizedString;
/// # fn server() -> Result<(), MatchProofsError> {
/// #    let verifier = SrpVerifier::from_username_and_password(NormalizedString::new("Alice").unwrap(),
/// #                                                     NormalizedString::new("password123").unwrap());
/// #
/// let proof = verifier.into_proof();
/// let salt = proof.salt();
/// let server_public_key = proof.server_public_key();
///
/// // Not part of this struct, but used in the same network packet and tightly related.
/// let large_safe_prime = LARGE_SAFE_PRIME_LITTLE_ENDIAN;
/// let generator = GENERATOR;
/// #
/// # let client_public_key = [255u8; PUBLIC_KEY_LENGTH as usize];
///
/// // Public key gotten from client
/// let client_public_key = PublicKey::from_le_bytes(&client_public_key);
/// let client_public_key = match client_public_key {
///     Ok(c) => {c}
///     Err(_) => {
///         panic!("Public key is invalid. This is either _very_ rare or malicious.")
///     }
/// };
///
/// // Proof gotten from client
/// let client_proof = [255u8; PROOF_LENGTH as usize];
/// let server = proof.into_server(client_public_key, client_proof);
/// let server = match server {
///     Ok(s) => {s}
///     Err(_) => {
///         panic!("Proofs do not match (password is incorrect). This is common.")
///     }
/// };
/// #    Ok(())
/// # }
/// ```
///
#[doc(alias = "M")]
#[doc(alias = "M1")]
#[doc(alias = "M2")]
#[doc(alias = "B")]
#[doc(alias = "s")]
#[doc(alias = "salt")]
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SrpProof {
    username: NormalizedString,
    server_public_key: PublicKey,
    salt: Salt,

    server_private_key: PrivateKey,

    password_verifier: Verifier,
}

impl SrpProof {
    /// Server public key used in calculations by both the server and client. Is sent to the client.
    /// Array is **little endian**.
    ///
    /// Called `B` in [RFC2945](https://tools.ietf.org/html/rfc2945).
    /// Always [32 bytes (256 bits)](crate::PUBLIC_KEY_LENGTH) in length since the packet sent to the client has a fixed width.
    #[doc(alias = "B")]
    #[must_use]
    pub const fn server_public_key(&self) -> &[u8; PUBLIC_KEY_LENGTH as usize] {
        self.server_public_key.as_le()
    }

    /// Salt value used for calculating verifier. Is sent to the client.
    /// Array is **little endian**.
    ///
    /// Called `s`, `<salt from passwd file>` or `<salt>` in [RFC2945](https://tools.ietf.org/html/rfc2945).
    /// Always [32 bytes (256 bits)](crate::SALT_LENGTH) in length since the packet sent to the client has a fixed width.
    #[doc(alias = "s")]
    #[must_use]
    pub const fn salt(&self) -> &[u8; SALT_LENGTH as usize] {
        self.salt.as_le()
    }

    /// Converts to an [`SrpServer`] and server proof by using the client supplied public key and proof,
    /// consuming the [`SrpProof`].
    ///
    /// The server proof value must be sent to the client in order to prove that the server knows the
    /// same password as the client.
    /// The server proof is called `M` in [RFC2945](https://tools.ietf.org/html/rfc2945),
    /// and `M2` in other litterature.
    /// This is different from the paramter to [`SrpProof::into_server`] which is referred to as `M1`
    /// in other litterature, but both are referred to as `M` in
    /// [RFC2945](https://tools.ietf.org/html/rfc2945).
    ///
    /// The server proof is a **little endian** array.
    /// The server proof is always [20 bytes (160 bits)](crate::PROOF_LENGTH) because it's a SHA-1 hash.
    ///
    /// The [`PublicKey`] is used instead of an array in order to break the validation of the
    /// public key and the calculation of the proof into separate steps.
    /// An invalid [`PublicKey`] is more likely to be the result of the client deliberately sending
    /// known invalid data while the [`MatchProofsError`] just means that the entered password is incorrect.
    ///
    /// The `client_public_key` is called `A` in [RFC2945](https://tools.ietf.org/html/rfc2945) and most other
    /// literature. It is sometimes incorrectly called `a`, but this refers to the client private key.
    /// Private keys are never sent over the network, so if you see `a` in a packet table it is referring
    /// to the client _public_ key and not the private key.
    ///
    /// The `client_proof` is called `M` in [RFC2945](https://tools.ietf.org/html/rfc2945) and `M1` in other
    /// literature. This is different from the server proof returned from [`SrpProof::into_server`] which is often called
    /// `M2`, but is still referred to as `M` in [RFC2945](https://tools.ietf.org/html/rfc2945).
    /// The `client_proof` is always [20 bytes (160 bits)](PROOF_LENGTH) in length because it's a SHA-1 hash.
    ///
    /// # Example
    ///
    /// ```
    /// # use wow_srp::{error::MatchProofsError, PUBLIC_KEY_LENGTH, PROOF_LENGTH, PublicKey, error::InvalidPublicKeyError};
    /// # use wow_srp::server::{SrpVerifier, SrpServer};
    /// # use wow_srp::normalized_string::NormalizedString;
    /// # fn server() -> Result<(), MatchProofsError> {
    /// #    let verifier = SrpVerifier::from_username_and_password(NormalizedString::new("Alice").unwrap(),
    /// #                                                     NormalizedString::new("password123").unwrap());
    /// #
    /// #    let proof = verifier.into_proof();
    /// #
    /// # let client_public_key = [255u8; PUBLIC_KEY_LENGTH as usize];
    /// // This will panic because the public key, username, passwords and proofs are not related
    /// // Public key gotten from client
    /// let client_public_key = PublicKey::from_le_bytes(&client_public_key);
    /// let client_public_key = match client_public_key {
    ///     Ok(c) => {c}
    ///     Err(_) => {
    ///         panic!("Public key is invalid. This is either _very_ rare or malicious.")
    ///     }
    /// };
    /// // Proof gotten from client
    /// let client_proof = [255u8; PROOF_LENGTH as usize];
    ///
    /// let server = proof.into_server(client_public_key, client_proof);
    /// let server = match server {
    ///     Ok(s) => {s}
    ///     Err(_) => {
    ///         panic!("Proofs do not match (password is incorrect). This is common.")
    ///     }
    /// };
    /// #    Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// If the `client_proof` does not match the internal server proof.
    pub fn into_server(
        self,
        client_public_key: PublicKey,
        client_proof: [u8; PROOF_LENGTH as usize],
    ) -> Result<(SrpServer, [u8; PROOF_LENGTH as usize]), MatchProofsError> {
        let session_key = srp_internal::calculate_session_key(
            &client_public_key,
            &self.server_public_key,
            &self.password_verifier,
            &self.server_private_key,
        );

        let server_calculated_proof = srp_internal::calculate_client_proof(
            &self.username,
            &session_key,
            &client_public_key,
            &self.server_public_key,
            &self.salt,
        );

        let client_calculated_proof = Proof::from_le_bytes(client_proof);
        if client_calculated_proof != server_calculated_proof {
            return Err(MatchProofsError {
                client_proof: *client_calculated_proof.as_le(),
                server_proof: *server_calculated_proof.as_le(),
            });
        }

        let server_proof = srp_internal::calculate_server_proof(
            &client_public_key,
            &server_calculated_proof,
            &session_key,
        );

        let reconnect_challenge_data = ReconnectData::randomized();

        Ok((
            SrpServer {
                username: self.username,
                session_key,
                reconnect_challenge_data,
            },
            *server_proof.as_le(),
        ))
    }
}

/// The final step of authentication. Contains the session key, and reconnect logic.
///
/// This represents the final struct used in authentication, if this struct is constructed,
/// the client is correctly authenticated and should be allowed to connect to the server.
/// The session key is used internally in the struct for reconnection,
/// and externally for decryption of packets.
///
/// This struct should be saved in session storage to allow for clients to reconnect.
/// If a client disconnects and reconnects properly again, the old struct should be replaced with
/// the new one because the session key will be different.
///
/// Created from [`SrpProof::into_server`].
///
/// # Examples
///
/// ```rust
/// # use wow_srp::server::{SrpVerifier, SrpServer};
/// # use wow_srp::normalized_string::NormalizedString;
/// # use wow_srp::{PublicKey, PUBLIC_KEY_LENGTH, PROOF_LENGTH, RECONNECT_CHALLENGE_DATA_LENGTH};
/// # use std::collections::HashMap;
/// # fn test() {
/// let username = "Alice";
/// # let verifier = SrpVerifier::from_username_and_password(NormalizedString::new(username).unwrap(), NormalizedString::new("password123").unwrap());
/// # let proof = verifier.into_proof();
/// # let client_public_key = PublicKey::from_le_bytes(&[1u8; PUBLIC_KEY_LENGTH as usize]).unwrap();
/// # let client_proof = [1u8; PROOF_LENGTH as usize];
/// let mut authenticated_clients = HashMap::new();
///
/// // Server is created from unseen elements
/// let mut server = proof.into_server(client_public_key, client_proof);
///  let (server, server_proof) =  match server {
///      Ok(s) => {s}
///      Err(_) => return,
///  };
///
/// // Add the server to session storage, for example a HashMap
/// authenticated_clients.insert(username, server);
///
/// // Client drops connection and tries to reconnect
/// let client = authenticated_clients.get_mut(username);
/// let mut client = match client {
///     // Client does not have an active session, do not proceed
///     None => return,
///     // The username has an active session, but we still need to verify
///     // that the host connecting actually was the host that previously
///     // became authenticated.
///     Some(c) => c,
/// };
///
/// // Send this to the client
/// let server_challenge_data = client.reconnect_challenge_data();
///
/// // Get client data and proof in the response
/// # let client_challenge_data = [1u8; RECONNECT_CHALLENGE_DATA_LENGTH as usize];
/// # let client_proof = [1u8; PROOF_LENGTH as usize];
///
/// let should_allow_connection = client.verify_reconnection_attempt(client_challenge_data,
///                                                                  client_proof);
/// if should_allow_connection {
///     // The client has proven that it knows the session key,
///     // continue with the connection
/// } else {
///     // The client has proven nothing
///     // Send an error back or do nothing
/// }
/// # }
/// ```
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SrpServer {
    username: NormalizedString,
    session_key: SessionKey,
    reconnect_challenge_data: ReconnectData,
}

impl SrpServer {
    /// Called `S` in [RFC2945](https://tools.ietf.org/html/rfc2945) and sometimes `K` or `key`
    /// in other literature.
    ///
    /// After successful authentication both client and server will have the exact same session
    /// key without onlookers being able to figure it out. This is used for decrypting packets later.
    ///
    /// The session key is always [40 bytes (320 bits)](SESSION_KEY_LENGTH) in length because it is
    /// created from 2 SHA-1 hashes of [20 bytes (160 bits)](PROOF_LENGTH).
    #[doc(alias = "K")]
    #[doc(alias = "S")]
    #[must_use]
    pub const fn session_key(&self) -> &[u8; SESSION_KEY_LENGTH as usize] {
        self.session_key.as_le()
    }

    /// Server data to be included in the reconnection challenge.
    ///
    /// Must be sent to the client as random data for the reconnect challenge.
    ///
    /// This is always [16 bytes](RECONNECT_CHALLENGE_DATA_LENGTH) since the field in the packet
    /// sent to the client has a fixed width.
    ///
    /// Not mentioned in [RFC2945](https://tools.ietf.org/html/rfc2945) at all.
    ///
    /// See [`verify_reconnection_attempt`](SrpServer::verify_reconnection_attempt) for more.
    #[must_use]
    pub const fn reconnect_challenge_data(
        &self,
    ) -> &[u8; RECONNECT_CHALLENGE_DATA_LENGTH as usize] {
        self.reconnect_challenge_data.as_le()
    }

    /// Computes a proof from the username, randomized client data, randomized server data,
    /// and session key.
    /// If the proofs match the client has the correct session key and should be allowed to reconnect.
    ///
    /// Returns true if the proof matches and false if it does not. A false return value does not mean
    /// that the [`SrpServer`] should be removed from the list of active sessions, since anybody could
    /// send the reconnect packages and get all the way here knowing only the username.
    ///
    /// After calling this the [`reconnect_challenge_data`](SrpServer::reconnect_challenge_data) has
    /// been randomized again and will need to be sent to the client, you can not keep using the same
    /// data for all reconnection attempts.
    ///
    /// It's important to note that a true value does not mean that the client is the same, it just
    /// means that the session key the reconnecting client has is the same as the one that was originally
    /// computed.
    ///
    /// Not mentioned in [RFC2945](https://tools.ietf.org/html/rfc2945) at all.
    #[must_use]
    pub fn verify_reconnection_attempt(
        &mut self,
        client_data: [u8; RECONNECT_CHALLENGE_DATA_LENGTH as usize],
        client_proof: [u8; PROOF_LENGTH as usize],
    ) -> bool {
        let server_proof = calculate_reconnect_proof(
            &self.username,
            &ReconnectData::from_le_bytes(client_data),
            &self.reconnect_challenge_data,
            &self.session_key,
        );

        let client_proof = Proof::from_le_bytes(client_proof);

        let reconnect_verified = server_proof == client_proof;

        self.reconnect_challenge_data.randomize_data();

        reconnect_verified
    }
}

#[cfg(test)]
mod test {

    use crate::hex::*;
    use crate::key::{PrivateKey, Proof, PublicKey, Salt};
    use crate::normalized_string::NormalizedString;
    use crate::server::SrpVerifier;

    #[test]
    fn verify_known_client_values() {
        let server_private_key = PrivateKey::from_be_hex_str(
            "291BD2A76AAB9E7CDD702AFE1D07FDB316158BC2E4218FFDC32989AD3AF5026E",
        );

        let salt = Salt::from_be_hex_str(
            "65771e13b30bea9f4ef6c8390a594e297c9739e38ab02316bf1522ed5571813c",
        );

        let v = SrpVerifier::with_specific_salt(
            NormalizedString::new("A").unwrap(),
            NormalizedString::new("A").unwrap(),
            &salt,
        );
        let s = v.with_specific_private_key(server_private_key).unwrap();

        // Assert expects big endian
        let mut server_public_key = *s.server_public_key();
        server_public_key.reverse();
        assert_eq!(
            hex_encode(&server_public_key),
            "13ed2108a7c50c4aa451c05e3c8ba779c2201a9dbccc0841041c2466c5e24000"
        );

        assert_eq!(
            hex_encode(s.salt()),
            "3c817155ed2215bf1623b08ae339977c294e590a39c8f64e9fea0bb3131e7765"
        );

        let client_public_key = PublicKey::from_be_hex_str(
            "2e071e645d60721d15e8290dac4a3672d87045c14d2bdac52f1e6c998c7b7efa",
        )
        .unwrap();
        let client_proof = Proof::from_be_hex_str("b91e6e0c8c06969c44585d9f66d73454f60a43e6");

        let (_s, server_proof) = s
            .into_server(client_public_key, *client_proof.as_le())
            .unwrap();
        let server_proof = Proof::from_le_bytes(server_proof);

        assert_eq!(
            server_proof,
            Proof::from_be_hex_str("0e006885b6f27a1843043270d2c83c4e1a22780b")
        );
    }
}
