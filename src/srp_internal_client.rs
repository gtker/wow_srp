use crate::error::InvalidPublicKeyError;
use crate::key::{PrivateKey, Proof, PublicKey, SKey, Salt, SessionKey, Sha1Hash};
use crate::normalized_string::NormalizedString;
use crate::primes::{Generator, KValue, LargeSafePrime};
use crate::srp_internal::calculate_xor_hash;
use crate::PROOF_LENGTH;
use sha1::{Digest, Sha1};

pub(super) fn calculate_client_public_key(
    client_private_key: &PrivateKey,
    generator: &Generator,
    large_safe_prime: &LargeSafePrime,
) -> Result<PublicKey, InvalidPublicKeyError> {
    // `A = g^a % N`
    let client_public_key = generator.to_bigint().modpow(
        &client_private_key.to_bigint(),
        &large_safe_prime.to_bigint(),
    );

    PublicKey::client_try_from_bigint(client_public_key, large_safe_prime)
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
    let k = KValue::bigint();
    // S = ((B - k) * (g^x % N))^(a + u * x) % N
    let S = (server_public_key.to_bigint()
        - k * generator
            .to_bigint()
            .modpow(&x.to_bigint(), &large_safe_prime.to_bigint()))
    .modpow(
        &(client_private_key.to_bigint() + u.to_bigint() * x.to_bigint()),
        &large_safe_prime.to_bigint(),
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

    let username_hash = Sha1::new().chain(username.as_ref()).finalize();

    let out: [u8; PROOF_LENGTH as usize] = Sha1::new()
        .chain(xor_hash.as_le())
        .chain(username_hash)
        .chain(salt.as_le())
        .chain(client_public_key.as_le())
        .chain(server_public_key.as_le())
        .chain(session_key.as_le())
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
    };
    use std::fs::read_to_string;

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
    #[allow(non_snake_case)] // No better descriptor for it than 'S'
    fn verify_client_S() {
        let contents = read_to_string("tests/srp6_internal/calculate_client_S_values.txt").unwrap();

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
                "{}",
                format!(
                    "client_private_key: '{}'",
                    &client_private_key.to_be_hex_string()
                )
            );
        }
    }

    #[test]
    fn verify_client_public_key() {
        let contents = read_to_string("tests/srp6_internal/calculate_A_values.txt").unwrap();

        let generator = Generator::default();
        let large_safe_prime = LargeSafePrime::default();

        for line in contents.lines() {
            let mut line = line.split_whitespace();
            let client_private_key = PrivateKey::from_be_hex_str(&line.next().unwrap());

            let expected = PublicKey::from_be_hex_str(line.next().unwrap()).unwrap();

            let client_public_key =
                calculate_client_public_key(&client_private_key, &generator, &large_safe_prime)
                    .unwrap();

            // Normalize hex values to uppercase
            assert_eq!(
                expected,
                client_public_key,
                "{}",
                format!("a: '{}'", &client_private_key.to_be_hex_string())
            );
        }
    }
}
