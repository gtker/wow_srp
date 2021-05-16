//! Internal functions only exposed in order to help other implementations with testing and verification.
//! This module should not be used except for when verifying another implementation.
//!
//! # Structure
//!
//!
//!

use sha1::{Digest, Sha1};
use std::convert::TryFrom;

use crate::error::InvalidPublicKeyError;
use crate::key::{
    PrivateKey, Proof, ReconnectData, SKey, Sha1Hash, Verifier, PROOF_LENGTH, SESSION_KEY_LENGTH,
    SHA1_HASH_LENGTH, S_LENGTH,
};
use crate::key::{PublicKey, Salt};
use crate::key::{SessionKey, PASSWORD_VERIFIER_LENGTH};
use crate::normalized_string::NormalizedString;
use crate::primes::{Generator, KValue, LargeSafePrime};

/// Only used for the [`calculate_client_proof`] function. Since the large safe prime and generator are
/// statically determined we can precalculate it. See also the [`calculate_xor_hash`] function.
const PRECALCULATED_XOR_HASH: [u8; SHA1_HASH_LENGTH] = [
    221, 123, 176, 58, 56, 172, 115, 17, 3, 152, 124, 90, 80, 111, 202, 150, 108, 123, 194, 167,
];

#[doc(hidden)]
#[macro_export]
macro_rules! pad_little_endian_vec_to_array {
    ($name: ident; $size: expr) => {{
        let mut c = [0u8; $size];
        c[0..$name.len()].clone_from_slice(&$name);
        c
    }};
}

/// Calculate the `x` value which is used for generating the password verifier `v`. See [calculate_password_verifier].
///
/// `x` is calculated as `H( salt | H( upper( username | : |  password ) ) )` as described on page 3 of [RFC2945] and page 8 of [RFC5054].
/// Uppercasing is not a requirement for SRP6 itself, only for the WoW client.
///
/// `H()` is the SHA1 hashing function.
/// `:` is the literal character `:`.
///
/// Some implementations assign `p = H( upper( username | : |  password ) )` in an intermediate step, and then `H( salt | p )` later for clarity.
/// Keep in mind that `p` in [RFC2945] refers to only the password string on page 4 as `p = <raw password>`.
///
/// Notice that the `x` value should only be calculated server side when a user registers an account or changes their password, since the database should never contain the raw password.
///
/// # Arguments
///
/// * `username` (`U` in [RFC2945], `I` in [RFC5054]) is an **uppercase** UTF-8 encoded strings.
/// * `password` (`p` in [RFC2945], `P` in [RFC5054]) is an **uppercase** UTF-8 encoded strings.
/// * `salt` (`s` in [RFC2945] and [RFC5054]) is a **little endian** [32][`SALT_LENGTH_IN_BYTES`] byte array of random values.
/// The client will not reject an authentication attempt with a salt of all zeros.
///
/// # Different Implementations
///
/// * [Ember](https://github.com/EmberEmu/Ember/blob/12834cd347472224fa180656222822744be3b1b0/src/libs/srp6/src/Util.cpp#L98)
///
/// [RFC2945]: https://tools.ietf.org/html/rfc2945
/// [RFC5054]: https://tools.ietf.org/html/rfc5054
pub fn calculate_x(
    username: &NormalizedString,
    password: &NormalizedString,
    salt: &Salt,
) -> Sha1Hash {
    let p = Sha1::new()
        .chain(username.as_ref())
        .chain(":")
        .chain(password.as_ref())
        .finalize();

    let x = Sha1::new().chain(salt.as_le()).chain(p).finalize();

    Sha1Hash::from_le_bytes(&x.into())
}

/// Calculate the password verifier `v` used for generating the server public key `B` and the session key intermediate value `S`.
/// See [`calculate_server_public_key`] and [`calculate_S`].
///
/// `v` is calculated as `g^x % N` as described on page 3 of [RFC2945].
/// For `x` see [`calculate_x`].
///
/// # Arguments
///
/// * `username` (`U` in [RFC2945], `I` in [RFC5054]) is an **uppercase** UTF-8 encoded strings.
/// * `password` (`p` in [RFC2945], `P` in [RFC5054]) is an **uppercase** UTF-8 encoded strings.
/// * `salt` (`s` in [RFC2945] and [RFC5054]) is a **little endian** [32 byte][`SALT_LENGTH_IN_BYTES`] array of random values.
/// The client will not reject an authentication attempt with a salt of all zeros.
///
/// # Return value
///
/// A zero padded **little endian** array the [size of N][`N_LENGTH`].
///
/// # Different Implementations
///
/// * [Ember](https://github.com/EmberEmu/Ember/blob/12834cd347472224fa180656222822744be3b1b0/src/libs/srp6/include/srp6/Util.h#L48)
///
/// [RFC2945]: https://tools.ietf.org/html/rfc2945
/// [RFC5054]: https://tools.ietf.org/html/rfc5054
pub fn calculate_password_verifier(
    username: &NormalizedString,
    password: &NormalizedString,
    salt: &Salt,
    // Return an array instead of Verifier because this is never directly used to create a Verifier
) -> [u8; PASSWORD_VERIFIER_LENGTH] {
    let x = calculate_x(username, password, &salt).to_bigint();

    let generator = Generator::default().to_bigint();
    let large_safe_prime = LargeSafePrime::default().to_bigint();

    let password_verifier = generator.modpow(&x, &large_safe_prime).to_bytes_le().1;

    pad_little_endian_vec_to_array!(password_verifier; PASSWORD_VERIFIER_LENGTH)
}

/// Calculate the server public key `B`.
pub fn calculate_server_public_key(
    password_verifier: &Verifier,
    server_private_key: &PrivateKey,
) -> Result<PublicKey, InvalidPublicKeyError> {
    let generator = Generator::default().to_bigint();
    let large_safe_prime = LargeSafePrime::default().to_bigint();

    let server_public_key = (KValue::bigint() * password_verifier.to_bigint()
        + generator.modpow(&server_private_key.to_bigint(), &large_safe_prime))
        % large_safe_prime;

    PublicKey::try_from_bigint(server_public_key)
}

/// Calculate the parameter `u` used for generating the session key.
pub fn calculate_u(client_public_key: &PublicKey, server_public_key: &PublicKey) -> Sha1Hash {
    let s = Sha1::new()
        .chain(client_public_key.as_le())
        .chain(server_public_key.as_le())
        .finalize();
    Sha1Hash::from_le_bytes(&s.into())
}

/// Calculate the `S` value used for generating the session key.
/// Return value is a N sized big endian array.
#[allow(non_snake_case)] // There is no better descriptor than 'S'
pub fn calculate_S(
    client_public_key: &PublicKey,
    password_verifier: &Verifier,
    u: &Sha1Hash,
    server_private_key: &PrivateKey,
) -> SKey {
    let large_safe_prime = LargeSafePrime::default().to_bigint();

    (client_public_key.to_bigint()
        * password_verifier
            .to_bigint()
            .modpow(&u.to_bigint(), &large_safe_prime))
    .modpow(&server_private_key.to_bigint(), &large_safe_prime)
    .into()
}

/// Return value is big endian??
#[allow(non_snake_case)]
pub fn calculate_interleaved(S: &SKey) -> SessionKey {
    let S = S.to_equal_slice();

    let mut E = Vec::with_capacity(S_LENGTH / 2);
    for e in S.iter().step_by(2) {
        E.push(*e);
    }
    let G = Sha1::new().chain(E).finalize();

    let mut F = Vec::with_capacity(S_LENGTH / 2);
    for f in S.iter().skip(1).step_by(2) {
        F.push(*f);
    }
    let H = Sha1::new().chain(F).finalize();

    let mut result = Vec::with_capacity(SESSION_KEY_LENGTH);
    let zip = G.iter().zip(H.iter());
    for r in zip {
        result.push(*r.0);
        result.push(*r.1);
    }

    let result = <[u8; SESSION_KEY_LENGTH]>::try_from(result).unwrap();
    SessionKey::from_le_bytes(&result)
}

// Returns a 40 byte big endian array.
pub fn calculate_session_key(
    client_public_key: &PublicKey,
    server_public_key: &PublicKey,
    password_verifier: &Verifier,
    server_private_key: &PrivateKey,
) -> SessionKey {
    let u = &calculate_u(client_public_key, server_public_key);
    #[allow(non_snake_case)]
    let S = calculate_S(
        &client_public_key,
        &password_verifier,
        &u,
        &server_private_key,
    );

    calculate_interleaved(&S)
}

pub fn calculate_server_proof(
    client_public_key: &PublicKey,
    client_proof: &Proof,
    session_key: &SessionKey,
) -> Proof {
    let s = Sha1::new()
        .chain(client_public_key.as_le())
        .chain(client_proof.as_le())
        .chain(session_key.as_le())
        .finalize();

    Proof::from_le_bytes(&s.into())
}

pub(crate) fn calculate_xor_hash(
    large_safe_prime: &LargeSafePrime,
    generator: &Generator,
) -> Sha1Hash {
    let large_safe_prime_hash = Sha1::new().chain(large_safe_prime.as_le_bytes()).finalize();

    let g_hash = Sha1::new().chain([generator.as_u8()]).finalize();

    let mut xor_hash = Vec::new();
    for (i, n) in large_safe_prime_hash.iter().enumerate() {
        xor_hash.push(*n as u8 ^ g_hash[i]);
    }
    let xor_hash = <[u8; SHA1_HASH_LENGTH]>::try_from(xor_hash).unwrap();
    Sha1Hash::from_le_bytes(&xor_hash)
}

pub fn calculate_client_proof(
    username: &NormalizedString,
    session_key: &SessionKey,
    client_public_key: &PublicKey,
    server_public_key: &PublicKey,
    salt: &Salt,
) -> Proof {
    let username_hash = Sha1::new().chain(username.as_ref()).finalize();

    let out: [u8; PROOF_LENGTH] = Sha1::new()
        .chain(PRECALCULATED_XOR_HASH)
        .chain(username_hash)
        .chain(salt.as_le())
        .chain(client_public_key.as_le())
        .chain(server_public_key.as_le())
        .chain(session_key.as_le())
        .finalize()
        .into();

    Proof::from_le_bytes(&out)
}

pub fn calculate_reconnect_proof(
    username: &NormalizedString,
    client_data: &ReconnectData,
    server_data: &ReconnectData,
    session_key: &SessionKey,
) -> Proof {
    let s = Sha1::new()
        .chain(username.as_ref())
        .chain(client_data.as_le())
        .chain(server_data.as_le())
        .chain(session_key.as_le())
        .finalize();

    Proof::from_le_bytes(&s.into())
}

#[cfg(test)]
mod test {
    use crate::primes::{
        Generator, LargeSafePrime, LARGE_SAFE_PRIME_BIG_ENDIAN, LARGE_SAFE_PRIME_LITTLE_ENDIAN,
    };
    use crate::srp_internal::{calculate_xor_hash, PRECALCULATED_XOR_HASH};

    mod regression {
        use crate::key::{
            PrivateKey, Proof, PublicKey, ReconnectData, SKey, Salt, SessionKey, Sha1Hash, Verifier,
        };
        use crate::normalized_string::NormalizedString;
        use crate::srp_internal::{
            calculate_S, calculate_client_proof, calculate_interleaved,
            calculate_password_verifier, calculate_reconnect_proof, calculate_server_proof,
            calculate_server_public_key, calculate_session_key, calculate_u, calculate_x,
        };
        use std::fs::read_to_string;

        #[test]
        fn verify_reconnection_proof() {
            let contents =
                read_to_string("tests/srp6_internal/calculate_reconnection_values.txt").unwrap();

            for line in contents.lines() {
                let mut line = line.split_whitespace();
                let username = NormalizedString::new(line.next().unwrap()).unwrap();
                let client_data = ReconnectData::from_le_hex_str(line.next().unwrap());
                let server_data = ReconnectData::from_le_hex_str(line.next().unwrap());
                let session_key = SessionKey::from_le_hex_str(line.next().unwrap());
                let expected = Proof::from_le_hex_str(line.next().unwrap());

                let proof =
                    calculate_reconnect_proof(&username, &client_data, &server_data, &session_key);
                assert_eq!(proof, expected);
            }
        }

        #[test]
        fn verify_x_username_and_password() {
            let contents = read_to_string("tests/srp6_internal/calculate_x_values.txt").unwrap();
            let salt = Salt::from_be_hex_str(
                "CAC94AF32D817BA64B13F18FDEDEF92AD4ED7EF7AB0E19E9F2AE13C828AEAF57",
            );
            for line in contents.lines() {
                let mut line = line.split_whitespace();
                let username = NormalizedString::new(line.next().unwrap()).unwrap();
                let password = NormalizedString::new(line.next().unwrap()).unwrap();

                let expected = Sha1Hash::from_be_hex_str(line.next().unwrap());

                let x = calculate_x(&username, &password, &salt);

                // Normalize hex values to uppercase
                assert_eq!(
                    expected,
                    x,
                    "{}",
                    format!("Salt: '{}'", &salt.to_be_hex_string())
                );
            }
        }

        #[test]
        fn verify_x_salt() {
            let contents =
                read_to_string("tests/srp6_internal/calculate_x_salt_values.txt").unwrap();
            let username = NormalizedString::new("USERNAME123").unwrap();
            let password = NormalizedString::new("PASSWORD123").unwrap();

            for line in contents.lines() {
                let mut line = line.split_whitespace();
                let salt = Salt::from_be_hex_str(line.next().unwrap());

                let expected = Sha1Hash::from_be_hex_str(line.next().unwrap());

                let x = calculate_x(&username, &password, &salt);

                // Normalize hex values to uppercase
                assert_eq!(
                    expected,
                    x,
                    "{}",
                    format!("Salt: '{}'", &salt.to_be_hex_string())
                );
            }
        }

        #[test]
        fn verify_password_verifier_username_password_salt() {
            let contents = read_to_string("tests/srp6_internal/calculate_v_values.txt").unwrap();

            for line in contents.lines() {
                let mut line = line.split_whitespace();
                let username = NormalizedString::new(line.next().unwrap()).unwrap();
                let password = NormalizedString::new(line.next().unwrap()).unwrap();

                let salt = Salt::from_be_hex_str(line.next().unwrap());

                let expected = Verifier::from_be_hex_str(line.next().unwrap());

                let v = Verifier::from_le_bytes(&calculate_password_verifier(
                    &username, &password, &salt,
                ));

                // Normalize hex values to uppercase
                assert_eq!(
                    expected,
                    v,
                    "{}",
                    format!(
                        "Username: '{}',\n Password: '{}',\n Salt: '{}'",
                        username,
                        password,
                        &salt.to_be_hex_string()
                    )
                );
            }
        }

        #[test]
        fn verify_server_public_key_calculation() {
            let contents = read_to_string("tests/srp6_internal/calculate_B_values.txt").unwrap();
            for line in contents.lines() {
                let mut line = line.split_whitespace();

                let verifier = Verifier::from_be_hex_str(line.next().unwrap());

                let server_private_key = PrivateKey::from_be_hex_str(line.next().unwrap());

                let expected = PublicKey::from_be_hex_str(line.next().unwrap()).unwrap();

                let server_public_key =
                    calculate_server_public_key(&verifier, &server_private_key).unwrap();

                // Normalize hex values to uppercase
                assert_eq!(
                    expected,
                    server_public_key,
                    "{}",
                    format!(
                        "v: '{}',\n b: '{}'",
                        verifier.to_be_hex_string(),
                        server_private_key.to_be_hex_string(),
                    )
                );
            }
        }

        #[test]
        fn verify_u() {
            let contents = read_to_string("tests/srp6_internal/calculate_u_values.txt").unwrap();

            for line in contents.lines() {
                let mut line = line.split_whitespace();

                let client_public_key = PublicKey::from_be_hex_str(line.next().unwrap()).unwrap();

                let server_public_key = PublicKey::from_be_hex_str(line.next().unwrap()).unwrap();

                let expected = Sha1Hash::from_be_hex_str(line.next().unwrap());

                let u = calculate_u(&client_public_key, &server_public_key);

                assert_eq!(
                    expected,
                    u,
                    "{}",
                    format!(
                        "A: '{}',\n B: '{}'",
                        client_public_key.to_be_hex_string(),
                        server_public_key.to_be_hex_string()
                    )
                );
            }
        }

        #[test]
        #[allow(non_snake_case)]
        fn verify_S() {
            let contents = read_to_string("tests/srp6_internal/calculate_S_values.txt").unwrap();

            for line in contents.lines() {
                let mut line = line.split_whitespace();

                let client_public_key = PublicKey::from_be_hex_str(line.next().unwrap()).unwrap();

                let password_verifier = Verifier::from_be_hex_str(line.next().unwrap());

                let u = Sha1Hash::from_be_hex_str(line.next().unwrap());

                let server_private_key = PrivateKey::from_be_hex_str(line.next().unwrap());

                let expected = SKey::from_be_hex_str(line.next().unwrap());

                let S = calculate_S(
                    &client_public_key,
                    &password_verifier,
                    &u,
                    &server_private_key,
                );

                // Normalize hex values to uppercase
                assert_eq!(
                    expected,
                    S,
                    "{}",
                    format!(
                        "A: '{}',\n v: '{}',\n u: '{}',\n b: '{}'",
                        client_public_key.to_be_hex_string(),
                        password_verifier.to_be_hex_string(),
                        u.to_be_hex_string(),
                        server_private_key.to_be_hex_string(),
                    )
                );
            }
        }

        #[test]
        #[allow(non_snake_case)]
        fn verify_interleaved_key() {
            let contents =
                read_to_string("tests/srp6_internal/calculate_interleaved_values.txt").unwrap();

            for line in contents.lines() {
                let mut line = line.split_whitespace();

                let S = SKey::from_le_hex_str(line.next().unwrap());

                let expected = SessionKey::from_le_hex_str(line.next().unwrap());

                let interleaved = calculate_interleaved(&S);

                // Normalize hex values to uppercase
                assert_eq!(
                    expected,
                    interleaved,
                    "{}",
                    format!("S: '{}'", &S.to_be_hex_string())
                );
            }
        }

        #[test]
        fn verify_session_key() {
            let contents =
                read_to_string("tests/srp6_internal/calculate_session_key_values.txt").unwrap();

            for line in contents.lines() {
                let mut line = line.split_whitespace();
                let client_public_key = PublicKey::from_le_hex_str(line.next().unwrap());
                let password_verifier = Verifier::from_le_hex_str(line.next().unwrap());
                let server_private_key = PrivateKey::from_le_hex_str(line.next().unwrap());

                let expected = SessionKey::from_le_hex_str(line.next().unwrap());

                let server_public_key =
                    calculate_server_public_key(&password_verifier, &server_private_key).unwrap();

                let session_key = calculate_session_key(
                    &client_public_key,
                    &server_public_key,
                    &password_verifier,
                    &server_private_key,
                );

                // Normalize hex values to uppercase
                assert_eq!(
                    expected,
                    session_key,
                    "{}",
                    format!(
                        "client_public_key: '{}',\n password_verifier: '{}',\n server_private_key: '{}',\n server_public_key: '{}'",
                        &client_public_key.to_be_hex_string(),
                        &password_verifier.to_be_hex_string(),
                        &server_private_key.to_be_hex_string(),
                        &server_public_key.to_be_hex_string(),
                    )
                );
            }
        }

        #[test]
        fn verify_client_proof() {
            let contents = read_to_string("tests/srp6_internal/calculate_M1_values.txt").unwrap();

            for line in contents.lines() {
                let mut line = line.split_whitespace();

                let username = NormalizedString::new(line.next().unwrap()).unwrap();

                let session_key = SessionKey::from_le_hex_str(line.next().unwrap());

                let client_public_key = PublicKey::from_be_hex_str(line.next().unwrap()).unwrap();

                let server_public_key = PublicKey::from_be_hex_str(line.next().unwrap()).unwrap();

                let salt = Salt::from_be_hex_str(line.next().unwrap());

                let expected = Proof::from_be_hex_str(line.next().unwrap());

                let client_proof = calculate_client_proof(
                    &username,
                    &session_key,
                    &client_public_key,
                    &server_public_key,
                    &salt,
                );

                // Normalize hex values to uppercase
                assert_eq!(
                    expected,
                    client_proof,
                    "{}",
                    format!(
                        "Username: '{}',\n session_key: '{}',\n client_public_key: '{}',\n server_public_key: '{}',\n salt: '{}'",
                        username,
                        &session_key.to_be_hex_string(),
                        &client_public_key.to_be_hex_string(),
                        &server_public_key.to_be_hex_string(),
                        &salt.to_be_hex_string(),
                    )
                );
            }
        }

        #[test]
        fn verify_server_proof() {
            let contents = read_to_string("tests/srp6_internal/calculate_M2_values.txt").unwrap();

            for line in contents.lines() {
                let mut line = line.split_whitespace();

                let client_public_key = PublicKey::from_be_hex_str(&line.next().unwrap()).unwrap();

                let client_proof = Proof::from_be_hex_str(line.next().unwrap());

                let session_key = SessionKey::from_le_hex_str(line.next().unwrap());

                let expected = Proof::from_be_hex_str(line.next().unwrap());

                let server_proof =
                    calculate_server_proof(&client_public_key, &client_proof, &session_key);

                assert_eq!(
                    expected,
                    server_proof,
                    "{}",
                    format!(
                        "Client public key: '{}',\n client_proof: '{}',\n session_key: '{}'",
                        client_public_key.to_be_hex_string(),
                        client_proof.to_be_hex_string(),
                        session_key.to_be_hex_string(),
                    )
                );
            }
        }
    }

    #[test]
    fn large_safe_prime_same_big_and_little_endian() {
        let large_safe_prime = LARGE_SAFE_PRIME_BIG_ENDIAN;
        let mut large_safe_prime_little_endian = LARGE_SAFE_PRIME_LITTLE_ENDIAN;
        large_safe_prime_little_endian.reverse();
        assert_eq!(large_safe_prime, large_safe_prime_little_endian);
    }

    #[test]
    fn precalculated_xor_hash_is_correct() {
        let large_safe_prime = LargeSafePrime::default();
        let generator = Generator::default();
        let xor_hash = calculate_xor_hash(&large_safe_prime, &generator);

        assert_eq!(xor_hash.as_le(), &PRECALCULATED_XOR_HASH);
    }
}
