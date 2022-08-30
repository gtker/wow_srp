//! The various errors that can happen during the SRP6 process.
//!
//! [`SrpError`] is an enum that can represent all the error types.
//!
//! The exact conditions for [`NormalizedStringError`] are described in the
//! [`normalized_string`](`crate::normalized_string`) module.
//!
//! [`InvalidPublicKeyError`] is returned when an invalid value is attempted used as a public key.
//!
//! [`MatchProofsError`] is returned when server and client proofs do not match.
//! Often because of a wrong password.

use crate::error::NormalizedStringError::StringTooLong;
use crate::key::PROOF_LENGTH;
use std::error::Error;
use std::fmt::{Display, Formatter, Result};

/// Enum that covers all SRP error types, except for the crypto error [`UnsplitCryptoError`].
#[derive(Debug)]
pub enum SrpError {
    /// Password is invalid.
    ProofsDoNotMatch(MatchProofsError),
    /// Public key is either 0 or the public key modulus
    /// [the large safe prime](crate::LARGE_SAFE_PRIME_LITTLE_ENDIAN) is 0.
    InvalidPublicKey(InvalidPublicKeyError),
    /// The string either contains an invalid character or is too long.
    NormalizedStringError(NormalizedStringError),
}

impl Error for SrpError {}

impl Display for SrpError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            SrpError::ProofsDoNotMatch(proofs) => {
                write!(f, "{}", proofs)
            }
            SrpError::InvalidPublicKey(error) => {
                write!(f, "{}", error)
            }
            SrpError::NormalizedStringError(error) => {
                write!(f, "{}", error)
            }
        }
    }
}

impl From<InvalidPublicKeyError> for SrpError {
    fn from(i: InvalidPublicKeyError) -> Self {
        Self::InvalidPublicKey(i)
    }
}

impl From<MatchProofsError> for SrpError {
    fn from(m: MatchProofsError) -> Self {
        Self::ProofsDoNotMatch(m)
    }
}

impl From<NormalizedStringError> for SrpError {
    fn from(n: NormalizedStringError) -> Self {
        Self::NormalizedStringError(n)
    }
}

/// [`DecrypterHalf`](crate::vanilla_header::DecrypterHalf) and
/// [`EncrypterHalf`](crate::vanilla_header::EncrypterHalf) do not
/// originate from the same [`HeaderCrypto`](crate::vanilla_header::HeaderCrypto).
///
/// This is a logic bug and should always lead to either a panic or some other highly
/// visible event.
/// If in doubt just call [`unwrap`](std::option::Option::unwrap) on it.
#[derive(Debug)]
pub struct UnsplitCryptoError {}

impl Error for UnsplitCryptoError {}

impl Display for UnsplitCryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "Crypto items do not originate from the same HeaderCrypto. This is a logic bug and should never happen."
        )
    }
}

/// Error for when server and client proofs do not match.
///
/// This is because the client has the wrong password.
#[derive(Debug)]
pub struct MatchProofsError {
    /// Clients calculated proof
    pub client_proof: [u8; PROOF_LENGTH as usize],
    /// Server calculated proof
    pub server_proof: [u8; PROOF_LENGTH as usize],
}

impl Error for MatchProofsError {}

impl Display for MatchProofsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let client_proof = format!("{:x?}", self.client_proof);
        let server_proof = format!("{:x?}", self.server_proof);
        write!(
            f,
            "Proofs do not match. Client proof: '{}', server proof: '{}'",
            client_proof, server_proof,
        )
    }
}

/// A public key is invalid either if it equal to 0, or the public key modulus the
/// [large safe prime](crate::LARGE_SAFE_PRIME_LITTLE_ENDIAN) is zero.
#[derive(Debug)]
pub enum InvalidPublicKeyError {
    /// The public key is zero.
    PublicKeyIsZero,
    /// The public key modulus the [large safe prime](crate::LARGE_SAFE_PRIME_LITTLE_ENDIAN) is zero.
    PublicKeyModLargeSafePrimeIsZero,
}

impl Error for InvalidPublicKeyError {}

impl Display for InvalidPublicKeyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            InvalidPublicKeyError::PublicKeyIsZero => {
                write!(f, "Public key is zero.")
            }
            InvalidPublicKeyError::PublicKeyModLargeSafePrimeIsZero => {
                write!(f, "Public key modulus the large safe prime is zero.")
            }
        }
    }
}

/// Error for the [`normalized_string`](`crate::normalized_string`) module.
#[derive(Debug)]
pub enum NormalizedStringError {
    /// The specific character is not allowed.
    CharacterNotAllowed(char),
    /// The string is too long.
    StringTooLong,
}

impl Error for NormalizedStringError {}

impl Display for NormalizedStringError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            NormalizedStringError::CharacterNotAllowed(c) => {
                write!(f, "Character is not allowed: '{}'", c)
            }
            StringTooLong => {
                write!(f, "String is longer than allowed length.",)
            }
        }
    }
}
