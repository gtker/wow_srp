use crate::error::InvalidPublicKeyError;
use crate::key::{PrivateKey, Proof, PublicKey, SKey, Salt, SessionKey, Sha1Hash};
use crate::normalized_string::NormalizedString;
use crate::primes::{Generator, KValue, LargeSafePrime};
use crate::srp_internal::{calculate_interleaved, calculate_u, calculate_xor_hash};
use crate::{srp_internal, PROOF_LENGTH};
use sha1::{Digest, Sha1};

pub(super) fn calculate_client_public_key(
    client_private_key: &PrivateKey,
    generator: &Generator,
    large_safe_prime: &LargeSafePrime,
) -> Result<PublicKey, InvalidPublicKeyError> {
    // `A = g^a % N`
    let client_public_key = generator.to_bigint().modpow(
        &client_private_key.as_bigint(),
        &large_safe_prime.to_bigint(),
    );

    PublicKey::client_try_from_bigint(client_public_key, large_safe_prime)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn calculate_client_session_key(
    username: &NormalizedString,
    password: &NormalizedString,
    server_public_key: &PublicKey,
    client_private_key: &PrivateKey,
    generator: &Generator,
    large_safe_prime: &LargeSafePrime,
    client_public_key: &PublicKey,
    salt: &Salt,
) -> SessionKey {
    let x = srp_internal::calculate_x(username, password, salt);

    let u = calculate_u(client_public_key, server_public_key);
    #[allow(non_snake_case)] // No better descriptor
    let S = calculate_client_S(
        server_public_key,
        &x,
        client_private_key,
        &u,
        generator,
        large_safe_prime,
    );

    calculate_interleaved(&S)
}

#[allow(non_snake_case)]
pub(crate) fn calculate_client_S(
    server_public_key: &PublicKey,
    x: &Sha1Hash,
    client_private_key: &PrivateKey,
    u: &Sha1Hash,
    generator: &Generator,
    large_safe_prime: &LargeSafePrime,
) -> SKey {
    let large_safe_prime = large_safe_prime.to_bigint();
    let k = KValue::bigint();
    let x = x.as_bigint();

    // S = ((B - k) * (g^x % N))^(a + u * x) % N
    let S = (server_public_key.as_bigint()
        - k * generator.to_bigint().modpow(&x, &large_safe_prime))
    .modpow(
        &(client_private_key.as_bigint() + u.as_bigint() * x),
        &large_safe_prime,
    );

    SKey::from_le_bytes(S.to_padded_32_byte_array_le())
}

pub(crate) fn calculate_client_proof_with_custom_value(
    username: &NormalizedString,
    session_key: &SessionKey,
    client_public_key: &PublicKey,
    server_public_key: &PublicKey,
    salt: &Salt,
    large_safe_prime: LargeSafePrime,
    generator: Generator,
) -> Proof {
    let xor_hash = calculate_xor_hash(&large_safe_prime, &generator);

    let username_hash = Sha1::new().chain_update(username.as_ref()).finalize();

    let out: [u8; PROOF_LENGTH as usize] = Sha1::new()
        .chain_update(xor_hash.as_le_bytes())
        .chain_update(username_hash)
        .chain_update(salt.as_le_bytes())
        .chain_update(client_public_key.as_le_bytes())
        .chain_update(server_public_key.as_le_bytes())
        .chain_update(session_key.as_le_bytes())
        .finalize()
        .into();

    Proof::from_le_bytes(out)
}

#[cfg(test)]
mod test {
    use crate::key::{PrivateKey, Proof, PublicKey, SKey, Salt, SessionKey, Sha1Hash};
    use crate::normalized_string::NormalizedString;
    use crate::primes::{Generator, LargeSafePrime};
    use crate::srp_internal_client::{
        calculate_client_S, calculate_client_proof_with_custom_value, calculate_client_public_key,
        calculate_client_session_key,
    };

    #[test]
    fn verify_client_proof() {
        let contents = include_str!("../tests/srp6_internal/calculate_M1_values.txt");

        for line in contents.lines() {
            let mut line = line.split_whitespace();

            let username = NormalizedString::new(line.next().unwrap()).unwrap();

            let session_key = SessionKey::from_be_hex_str(line.next().unwrap());

            let client_public_key = PublicKey::from_be_hex_str(line.next().unwrap()).unwrap();

            let server_public_key = PublicKey::from_be_hex_str(line.next().unwrap()).unwrap();

            let salt = Salt::from_be_hex_str(line.next().unwrap());

            let expected = Proof::from_be_hex_str(line.next().unwrap());

            let client_proof = calculate_client_proof_with_custom_value(
                &username,
                &session_key,
                &client_public_key,
                &server_public_key,
                &salt,
                LargeSafePrime::default(),
                Generator::default(),
            );

            // Normalize hex values to uppercase
            assert_eq!(
                expected,
                client_proof,
                "Username: '{}',\n session_key: '{}',\n client_public_key: '{}',\n server_public_key: '{}',\n salt: '{}'",
                username,
                &session_key.as_be_hex_string(),
                &client_public_key.as_be_hex_string(),
                &server_public_key.as_be_hex_string(),
                &salt.as_be_hex_string(),
            );
        }
    }

    #[test]
    #[allow(non_snake_case)] // No better descriptor for it than 'S'
    fn verify_client_S() {
        let contents = include_str!("../tests/srp6_internal/calculate_client_S_values.txt");

        let g = Generator::default();
        let N = LargeSafePrime::default();

        for line in contents.lines() {
            let mut line = line.split_whitespace();
            let server_public_key = PublicKey::from_be_hex_str(line.next().unwrap()).unwrap();

            let client_private_key = PrivateKey::from_be_hex_str(line.next().unwrap());

            let x = Sha1Hash::from_be_hex_str(line.next().unwrap());

            let u = Sha1Hash::from_be_hex_str(line.next().unwrap());

            let expected = SKey::from_be_hex_str(line.next().unwrap());

            let S = calculate_client_S(&server_public_key, &x, &client_private_key, &u, &g, &N);

            assert_eq!(
                expected,
                S,
                "client_private_key: '{}'",
                &client_private_key.as_be_hex_string()
            );
        }
    }

    #[test]
    fn verify_client_public_key() {
        let contents = include_str!("../tests/srp6_internal/calculate_A_values.txt");

        let generator = Generator::default();
        let large_safe_prime = LargeSafePrime::default();

        for line in contents.lines() {
            let mut line = line.split_whitespace();
            let client_private_key = PrivateKey::from_be_hex_str(line.next().unwrap());

            let expected = PublicKey::from_be_hex_str(line.next().unwrap()).unwrap();

            let client_public_key =
                calculate_client_public_key(&client_private_key, &generator, &large_safe_prime)
                    .unwrap();

            // Normalize hex values to uppercase
            assert_eq!(
                expected,
                client_public_key,
                "a: '{}'",
                &client_private_key.as_be_hex_string()
            );
        }
    }

    #[test]
    fn verify_client_session_key() {
        let contents = include_str!("../tests/srp6_internal/calculate_client_session_key.txt");

        for line in contents.lines() {
            let mut line = line.split_whitespace();

            let username = NormalizedString::new(line.next().unwrap()).unwrap();
            let password = NormalizedString::new(line.next().unwrap()).unwrap();
            let server_public_key = PublicKey::from_be_hex_str(line.next().unwrap()).unwrap();
            let client_private_key = PrivateKey::from_be_hex_str(line.next().unwrap());
            let generator = Generator::from(line.next().unwrap().parse::<u8>().unwrap());
            let large_safe_prime = LargeSafePrime::from_be_hex_str(line.next().unwrap());
            let client_public_key = PublicKey::from_be_hex_str(line.next().unwrap()).unwrap();
            let salt = Salt::from_be_hex_str(line.next().unwrap());
            let expected = SessionKey::from_be_hex_str(line.next().unwrap());

            let actual = calculate_client_session_key(
                &username,
                &password,
                &server_public_key,
                &client_private_key,
                &generator,
                &large_safe_prime,
                &client_public_key,
                &salt,
            );

            assert_eq!(actual, expected);
        }
    }
}
