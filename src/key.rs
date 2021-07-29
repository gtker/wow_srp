#[cfg(test)]
use std::convert::TryFrom;

use crate::bigint;

use rand::{thread_rng, RngCore};

use crate::error::InvalidPublicKeyError;
use crate::primes::{LargeSafePrime, LARGE_SAFE_PRIME_LENGTH};
use crate::LARGE_SAFE_PRIME_LITTLE_ENDIAN;

macro_rules! key_bigint {
    ($name: ident) => {
        impl $name {
            pub(crate) fn to_bigint(&self) -> bigint::Integer {
                bigint::Integer::from_bytes_le(&self.key)
            }
        }
    };
}

macro_rules! key_new {
    ($name: ident; $size: expr) => {
        impl Default for $name {
            fn default() -> Self {
                let mut key = [0_u8; $size];
                thread_rng().fill_bytes(&mut key);
                Self::from_le_bytes(key)
            }
        }

        impl $name {
            pub(crate) fn randomized() -> Self {
                Self::default()
            }
        }
    };
}

fn check_public_key(key: &[u8; PUBLIC_KEY_LENGTH as usize]) -> Result<(), InvalidPublicKeyError> {
    for (i, value) in key.iter().enumerate() {
        if *value != LARGE_SAFE_PRIME_LITTLE_ENDIAN[i] && *value != 0 {
            return Ok(());
        }
    }

    match key[0] {
        0 => Err(InvalidPublicKeyError::PublicKeyIsZero),
        _ => Err(InvalidPublicKeyError::PublicKeyModLargeSafePrimeIsZero),
    }
}

macro_rules! key_check_not_zero_initialization {
    ($name: ident; $size: expr) => {
        impl $name {
            /// Creates the struct from little endian bytes.
            ///
            /// Values are stored internally as little endian so no reversal occurs.
            ///
            /// # Errors
            ///
            /// Will error if the public key is invalid. See [`PublicKey`] for specifics.
            ///
            pub fn from_le_bytes(key: &[u8; $size]) -> Result<Self, InvalidPublicKeyError> {
                let key_is_valid = check_public_key(key);
                match key_is_valid {
                    Ok(_) => Ok(Self { key: *key }),
                    Err(e) => Err(e),
                }
            }

            #[cfg(test)]
            pub(crate) fn from_be_hex_str(s: &str) -> Result<Self, InvalidPublicKeyError> {
                let mut key = hex::decode(&s).unwrap();
                key.reverse();

                if key.len() > $size {
                    panic!(
                        "{} from_be_hex_str length is greater than {}",
                        stringify!($name),
                        $size
                    );
                }

                while key.len() < $size {
                    key.push(0);
                }

                let key = <[u8; $size]>::try_from(key).unwrap();

                Self::from_le_bytes(&key)
            }

            // Keep a separate validation function for clients because the large safe prime
            // can't be known ahead of time, meaning we don't have the guarantees for it
            // that we do for the server prime.
            pub(crate) fn client_try_from_bigint(
                b: bigint::Integer,
                large_safe_prime: &LargeSafePrime,
            ) -> Result<Self, InvalidPublicKeyError> {
                if b.is_zero() {
                    return Err(InvalidPublicKeyError::PublicKeyIsZero);
                }
                if b.mod_large_safe_prime_is_zero(&large_safe_prime) {
                    return Err(InvalidPublicKeyError::PublicKeyModLargeSafePrimeIsZero);
                }

                let mut key = [0_u8; $size];

                let b = b.to_bytes_le().to_vec();
                key[0..b.len()].clone_from_slice(&b);

                Ok(Self { key })
            }

            // This should be used on the server.
            // Doesn't use TryFrom<BigInt> because it shows up in the public interface with no way to hide it
            pub(crate) fn try_from_bigint(
                b: bigint::Integer,
            ) -> Result<Self, InvalidPublicKeyError> {
                let mut key = [0_u8; $size];

                let b = b.to_bytes_le().to_vec();
                key[0..b.len()].clone_from_slice(&b);

                Self::from_le_bytes(&key)
            }
        }
    };
}

macro_rules! key_no_checks_initialization {
    ($name: ident; $size: expr) => {
        impl $name {
            #[allow(dead_code)]
            pub const fn from_le_bytes(key: [u8; $size]) -> Self {
                Self { key }
            }

            #[cfg(test)]
            #[allow(dead_code)]
            pub fn from_be_hex_str(s: &str) -> Self {
                let mut key = hex::decode(&s).unwrap();
                key.reverse();

                while key.len() < $size {
                    key.push(0);
                }

                let key = <[u8; $size]>::try_from(key).unwrap();

                Self { key }
            }
        }

        impl From<bigint::Integer> for $name {
            fn from(b: bigint::Integer) -> Self {
                let mut key = [0_u8; $size];

                let b = b.to_bytes_le().to_vec();
                key[0..b.len()].clone_from_slice(&b);

                Self { key }
            }
        }
    };
}

macro_rules! key_wrapper {
    ($name: ident; $size: expr) => {
        /// Represents a public key for both the client and server.
        ///
        /// This is used instead of a raw array in order to move the error of verifying the key out
        /// of the proof functions in order to increase readability.
        ///
        /// Will return an error if all elements are 0, or the bytes represented as an integer modulus
        /// [the large safe prime](crate::LARGE_SAFE_PRIME_LITTLE_ENDIAN) is equal to 0.
        /// Since the large safe prime multiplied by 2 results in a 33 byte value it is unrepresentable
        /// as a public key and thus the only two failure opportunities are if the key is exactly zero
        /// or if it is exactly equal to the large safe prime.
        #[derive(Debug)]
        pub struct $name {
            key: [u8; $size],
        }

        impl $name {
            /// Returns the value as little endian bytes.
            ///
            /// The bytes are stored internally as little endian, so this causes no reversal.
            pub const fn as_le(&self) -> &[u8; $size] {
                &self.key
            }

            #[allow(dead_code)]
            #[cfg(test)]
            pub(crate) fn to_be_hex_string(&self) -> String {
                let mut key = self.key;
                key.reverse();

                let mut s = hex::encode_upper(&key);
                while s.len() < $size * 2 {
                    s = "0".to_owned() + &s;
                }
                s
            }

            #[allow(dead_code)]
            #[cfg(test)]
            pub(crate) fn from_le_hex_str(s: &str) -> Self {
                let key = hex::decode(&s).unwrap();

                let key = <[u8; $size]>::try_from(key).unwrap();

                Self { key }
            }
        }

        impl Eq for $name {}
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                let other = other.as_le();

                for (i, value) in self.key.iter().enumerate() {
                    if *value != other[i] {
                        return false;
                    }
                }

                return true;
            }
        }
    };
}

/// The salt is always 32 bytes since the client expects
/// a 32 byte salt field in the
/// [CMD_AUTH_LOGON_CHALLENGE_Server](https://wowdev.wiki/CMD_AUTH_LOGON_CHALLENGE_Server)
/// packet and will use leading zeros in the calculation.
#[doc(alias = "salt")]
pub const SALT_LENGTH: u8 = 32;
key_wrapper!(Salt; SALT_LENGTH as usize);
key_new!(Salt; SALT_LENGTH as usize);
key_no_checks_initialization!(Salt; SALT_LENGTH as usize);

#[doc(alias = "a")]
#[doc(alias = "b")]
pub const PRIVATE_KEY_LENGTH: u8 = LARGE_SAFE_PRIME_LENGTH;
key_wrapper!(PrivateKey; PRIVATE_KEY_LENGTH as usize);
key_new!(PrivateKey; PRIVATE_KEY_LENGTH as usize);
key_bigint!(PrivateKey);
key_no_checks_initialization!(PrivateKey; PRIVATE_KEY_LENGTH as usize);

/// Length in bytes for both client and server public key.
///
/// Public keys are always 32 bytes because of the fixed width in the
/// [CMD_AUTH_LOGON_PROOF](https://wowdev.wiki/CMD_AUTH_LOGON_PROOF_Client)
/// and
/// [CMD_AUTH_LOGON_PROOF_Server](https://wowdev.wiki/CMD_AUTH_LOGON_CHALLENGE_Server)
/// packets.
#[doc(alias = "A")]
#[doc(alias = "B")]
pub const PUBLIC_KEY_LENGTH: u8 = LARGE_SAFE_PRIME_LENGTH;
key_wrapper!(PublicKey; PUBLIC_KEY_LENGTH as usize);
key_bigint!(PublicKey);
key_check_not_zero_initialization!(PublicKey; PUBLIC_KEY_LENGTH as usize);

/// A SHA1 hash is always 20 bytes (160 bits) as specified in [RFC3174](https://tools.ietf.org/html/rfc3174).
pub const SHA1_HASH_LENGTH: u8 = 20;
key_wrapper!(Sha1Hash; SHA1_HASH_LENGTH as usize);
key_bigint!(Sha1Hash);
key_no_checks_initialization!(Sha1Hash; SHA1_HASH_LENGTH as usize);

/// Password verifier size in bytes.
///
/// Is always the same size as the [large safe prime](LARGE_SAFE_PRIME_LENGTH) because the verifier
/// is generated through modulo of the large safe prime.
#[doc(alias = "v")]
pub const PASSWORD_VERIFIER_LENGTH: u8 = LARGE_SAFE_PRIME_LENGTH;
key_wrapper!(Verifier; PASSWORD_VERIFIER_LENGTH as usize);
key_bigint!(Verifier);
key_no_checks_initialization!(Verifier; PASSWORD_VERIFIER_LENGTH as usize);

/// Length of a proof in bytes.
///
/// Is always 20 bytes because proofs are [SHA-1 hashes](https://en.wikipedia.org/wiki/SHA-1)
/// which have a fixed output size.
///
/// The proof size is the same for all proofs, including reconnect proofs.
#[doc(alias = "M1")]
#[doc(alias = "M2")]
#[doc(alias = "M")]
pub const PROOF_LENGTH: u8 = 20;
key_wrapper!(Proof; PROOF_LENGTH as usize);
key_no_checks_initialization!(Proof; PROOF_LENGTH as usize);

pub const S_LENGTH: u8 = LARGE_SAFE_PRIME_LENGTH;
key_wrapper!(SKey; S_LENGTH as usize);
key_no_checks_initialization!(SKey; S_LENGTH as usize);
impl SKey {
    pub fn to_equal_slice(&self) -> &[u8] {
        let mut s = &self.key[..];

        if *s.first().unwrap() == 0 {
            s = &s[2..];
        }
        s
    }
}

/// The size of the reconnect challenge data in bytes.
///
/// Always 16 since the challenge field of
/// [`CMD_AUTH_RECONNECT_CHALLENGE_Server`](https://wowdev.wiki/CMD_AUTH_RECONNECT_CHALLENGE_Server)
/// has a fixed width.
pub const RECONNECT_CHALLENGE_DATA_LENGTH: u8 = 16;
key_wrapper!(ReconnectData; RECONNECT_CHALLENGE_DATA_LENGTH as usize);
key_new!(ReconnectData; RECONNECT_CHALLENGE_DATA_LENGTH as usize);
key_no_checks_initialization!(ReconnectData; RECONNECT_CHALLENGE_DATA_LENGTH as usize);
impl ReconnectData {
    pub fn randomize_data(&mut self) {
        thread_rng().fill_bytes(&mut self.key);
    }
}

/// Size of the session key in bytes.
///
/// Always 40 bytes since it is the result of 2 SHA-1 [proofs](PROOF_LENGTH) concatenated.
#[doc(alias = "K")]
#[doc(alias = "S")]
pub const SESSION_KEY_LENGTH: u8 = PROOF_LENGTH * 2;
key_wrapper!(SessionKey; SESSION_KEY_LENGTH as usize);
key_no_checks_initialization!(SessionKey; SESSION_KEY_LENGTH as usize);

#[cfg(test)]
mod test {

    use crate::bigint::Integer;
    use crate::key::{PrivateKey, PublicKey, PUBLIC_KEY_LENGTH};
    use crate::primes::LargeSafePrime;
    use crate::LARGE_SAFE_PRIME_LITTLE_ENDIAN;
    use num_bigint::{BigInt, Sign};

    #[test]
    fn double_large_safe_prime_is_unrepresentable() {
        // Only the exact values of the large safe prime and 0 are checked for increased speed.
        // This is dependent on multiples of the large safe prime being unrepresentable in 32 bytes.
        let p = BigInt::from_bytes_le(Sign::Plus, &LARGE_SAFE_PRIME_LITTLE_ENDIAN);
        let p: BigInt = p * 2;
        assert!(p.to_bytes_le().1.len() > PUBLIC_KEY_LENGTH as usize);
    }

    #[test]
    fn public_key_should_not_be_zero() {
        let key = [0u8; PUBLIC_KEY_LENGTH as usize];
        let p = PublicKey::from_le_bytes(&key);
        assert!(p.is_err());
    }

    #[test]
    fn client_public_key_should_not_be_mod_zero() {
        let key = Integer::from_bytes_le(&LARGE_SAFE_PRIME_LITTLE_ENDIAN);
        let large_safe_prime = LargeSafePrime::default();
        let p = PublicKey::client_try_from_bigint(key, &large_safe_prime);
        assert!(p.is_err());
    }

    #[test]
    fn client_public_key_should_not_be_zero() {
        let key = Integer::from_bytes_le(&[0u8; PUBLIC_KEY_LENGTH as usize]);
        let large_safe_prime = LargeSafePrime::default();
        let p = PublicKey::client_try_from_bigint(key, &large_safe_prime);
        assert!(p.is_err());
    }

    #[test]
    fn public_key_should_not_be_zero_from_hex() {
        let p = PublicKey::from_be_hex_str("00");
        assert!(p.is_err());
    }

    #[test]
    fn public_key_should_not_be_mod_large_safe_prime() {
        let p = PublicKey::from_le_bytes(&LARGE_SAFE_PRIME_LITTLE_ENDIAN);
        assert!(p.is_err());
    }

    #[test]
    fn public_key_should_not_be_mod_large_safe_prime_from_hex() {
        let p = PublicKey::from_be_hex_str(
            "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7",
        );
        assert!(p.is_err());
    }

    #[test]
    fn hex_to_hex() {
        const PADDED_DEADBEEF: &str =
            "00000000000000000000000000000000000000000000000000000000DEADBEEF";
        const DEADBEEF: &str = "DEADBEEF";
        let k = PrivateKey::from_be_hex_str(DEADBEEF);
        assert_eq!(&k.to_be_hex_string(), PADDED_DEADBEEF);
    }
}
