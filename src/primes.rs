use crate::bigint;

/// The size in bytes of the [large safe prime](LARGE_SAFE_PRIME_LITTLE_ENDIAN).
///
/// The client does not work with sizes greater than 32 for unknown reasons,
/// despite the field in the
/// [CMD_AUTH_LOGON_CHALLENGE](https://wowdev.wiki/CMD_AUTH_LOGON_CHALLENGE_Server)
/// packet being variable size.
///
/// The [public key](crate::PUBLIC_KEY_LENGTH) field in the same packet is also statically 32 bytes
/// wide and since the public key is generated modulo the large safe prime, large safe prime lengths
/// of greater than 32 could lead to public keys that were unable to be sent over the network.
///
#[doc(alias = "N")]
pub const LARGE_SAFE_PRIME_LENGTH: u8 = 32;

/// Static large safe prime (`N`) value.
/// The big endian version of [LARGE_SAFE_PRIME_LITTLE_ENDIAN].
/// This version should not be sent over the network and should generally not be used.
///
/// Only here for completeness sake.
///
/// Always has the static size of [32 bytes](LARGE_SAFE_PRIME_LENGTH).
///
/// ```rust
/// use hex_literal::hex;
/// use wow_srp::LARGE_SAFE_PRIME_BIG_ENDIAN;
///
/// assert_eq!(LARGE_SAFE_PRIME_BIG_ENDIAN,
///  hex!("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7"));
/// ```
#[doc(alias = "N")]
pub const LARGE_SAFE_PRIME_BIG_ENDIAN: [u8; LARGE_SAFE_PRIME_LENGTH as usize] = [
    137_u8, 75_u8, 100_u8, 94_u8, 137_u8, 225_u8, 83_u8, 91_u8, 189_u8, 173_u8, 91_u8, 139_u8,
    41_u8, 6_u8, 80_u8, 83_u8, 8_u8, 1_u8, 177_u8, 142_u8, 191_u8, 191_u8, 94_u8, 143_u8, 171_u8,
    60_u8, 130_u8, 135_u8, 42_u8, 62_u8, 155_u8, 183_u8,
];

/// Static large safe prime (`N`) value.
/// The little endian version of [LARGE_SAFE_PRIME_BIG_ENDIAN].
/// This is the version that should be sent over the network in the
/// [CMD_AUTH_LOGON_CHALLENGE_Server](https://wowdev.wiki/CMD_AUTH_LOGON_CHALLENGE_Server)
/// packet.
///
/// Always has the static size of [32 bytes](LARGE_SAFE_PRIME_LENGTH).
///
/// ```rust
/// use hex_literal::hex;
/// use wow_srp::LARGE_SAFE_PRIME_LITTLE_ENDIAN;
///
/// assert_eq!(LARGE_SAFE_PRIME_LITTLE_ENDIAN,
///  hex!("b79b3e2a87823cab8f5ebfbf8eb10108535006298b5badbd5b53e1895e644b89"));
/// ```
#[doc(alias = "N")]
pub const LARGE_SAFE_PRIME_LITTLE_ENDIAN: [u8; LARGE_SAFE_PRIME_LENGTH as usize] = [
    183_u8, 155_u8, 62_u8, 42_u8, 135_u8, 130_u8, 60_u8, 171_u8, 143_u8, 94_u8, 191_u8, 191_u8,
    142_u8, 177_u8, 1_u8, 8_u8, 83_u8, 80_u8, 6_u8, 41_u8, 139_u8, 91_u8, 173_u8, 189_u8, 91_u8,
    83_u8, 225_u8, 137_u8, 94_u8, 100_u8, 75_u8, 137_u8,
];

pub(crate) struct LargeSafePrime {
    prime: [u8; LARGE_SAFE_PRIME_LENGTH as usize],
}

impl Default for LargeSafePrime {
    fn default() -> Self {
        Self {
            prime: LARGE_SAFE_PRIME_LITTLE_ENDIAN,
        }
    }
}

impl LargeSafePrime {
    pub const fn from_le_bytes(prime: &[u8; LARGE_SAFE_PRIME_LENGTH as usize]) -> Self {
        Self { prime: *prime }
    }

    pub const fn as_le_bytes(&self) -> &[u8; LARGE_SAFE_PRIME_LENGTH as usize] {
        &self.prime
    }

    pub fn to_bigint(&self) -> bigint::Integer {
        bigint::Integer::from_bytes_le(&self.prime)
    }
}

/// Called `g` in [RFC2945](https://tools.ietf.org/html/rfc2945).
/// Statically set to 7.
/// Used for generating the public keys for both server and client, and the session key.
/// The [length in bytes](GENERATOR_LENGTH) is always 1 since there are no generators greater than 255.
#[doc(alias = "g")]
pub const GENERATOR: u8 = 7;

/// The length in bytes for [GENERATOR].
/// Will always be 1 since there are no generators greater than 255.
/// Constant is provided here since the
/// [CMD_AUTH_LOGON_CHALLENGE](https://wowdev.wiki/CMD_AUTH_LOGON_CHALLENGE_Server)
/// packet requires it.
#[doc(alias = "g")]
pub const GENERATOR_LENGTH: u8 = 1;

pub(crate) struct Generator {
    generator: u8,
}

impl Default for Generator {
    fn default() -> Self {
        Self {
            generator: GENERATOR,
        }
    }
}
impl Generator {
    pub fn to_bigint(&self) -> bigint::Integer {
        bigint::Integer::from(self.generator)
    }

    pub const fn as_u8(&self) -> u8 {
        self.generator
    }
}

impl From<u8> for Generator {
    fn from(g: u8) -> Self {
        Self { generator: g }
    }
}

pub const K_VALUE: u8 = 3;
pub(crate) struct KValue {}
impl KValue {
    pub fn bigint() -> bigint::Integer {
        bigint::Integer::from(K_VALUE)
    }
}
