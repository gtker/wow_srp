use crate::error::InvalidPublicKeyError;
use crate::key::{PrivateKey, PublicKey, SKey, Sha1Hash};
use crate::pad_little_endian_vec_to_array;
use crate::primes::{Generator, KValue, LargeSafePrime, LARGE_SAFE_PRIME_LENGTH};

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

    PublicKey::try_from_bigint(client_public_key)
}

#[allow(non_snake_case)]
pub fn calculate_client_S(
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

    let S = S.to_bytes_le().1;
    let S = pad_little_endian_vec_to_array!(S; LARGE_SAFE_PRIME_LENGTH);
    SKey::from_le_bytes(&S)
}

#[cfg(test)]
mod test {
    use crate::key::{PrivateKey, PublicKey, SKey, Sha1Hash};
    use crate::primes::{Generator, LargeSafePrime};
    use crate::srp_internal_client::{calculate_client_S, calculate_client_public_key};
    use std::fs::read_to_string;

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
