use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wow_srp::client::{SrpClientChallenge, SrpClientUser};
use wow_srp::normalized_string::NormalizedString;
use wow_srp::server::{SrpProof, SrpVerifier};
use wow_srp::{
    PublicKey, GENERATOR, LARGE_SAFE_PRIME_LITTLE_ENDIAN, PASSWORD_VERIFIER_LENGTH, SALT_LENGTH,
};

const PASSWORD_VERIFIER_1: [u8; PASSWORD_VERIFIER_LENGTH as _] = [
    196, 149, 1, 178, 117, 122, 111, 27, 105, 230, 31, 118, 2, 251, 199, 158, 77, 253, 83, 35, 105,
    147, 231, 67, 85, 68, 13, 15, 144, 185, 226, 10,
];
const SALT_1: [u8; SALT_LENGTH as _] = [
    124, 205, 43, 220, 94, 195, 189, 187, 218, 119, 116, 84, 107, 96, 136, 103, 235, 78, 193, 58,
    99, 199, 238, 202, 122, 221, 160, 63, 186, 122, 4, 186,
];
const USERNAME_1: &str = "longernameforcon";
const PASSWORD_1: &str = "thisismypassword";

const PASSWORD_VERIFIER_2: [u8; PASSWORD_VERIFIER_LENGTH as _] = [
    246, 122, 57, 125, 166, 24, 59, 152, 202, 97, 208, 156, 163, 177, 30, 197, 91, 86, 103, 163,
    35, 20, 111, 185, 82, 93, 207, 16, 196, 41, 55, 102,
];
const SALT_2: [u8; SALT_LENGTH as _] = [
    242, 110, 97, 143, 214, 5, 3, 171, 170, 113, 190, 127, 225, 170, 40, 100, 164, 103, 34, 177,
    13, 80, 232, 49, 161, 207, 140, 113, 131, 10, 137, 48,
];
const USERNAME_2: &str = "secondname";
const PASSWORD_2: &str = "secondpassword";

const PASSWORD_VERIFIER_3: [u8; PASSWORD_VERIFIER_LENGTH as _] = [
    108, 156, 51, 240, 99, 244, 65, 31, 186, 143, 21, 25, 105, 36, 65, 87, 78, 198, 150, 43, 124,
    113, 186, 165, 32, 152, 226, 51, 61, 234, 218, 23,
];
const SALT_3: [u8; SALT_LENGTH as _] = [
    190, 220, 146, 125, 85, 197, 155, 114, 37, 46, 161, 10, 211, 195, 120, 4, 188, 223, 130, 126,
    155, 171, 117, 8, 253, 79, 103, 191, 1, 154, 147, 162,
];
const USERNAME_3: &str = "thirdnamelong";
const PASSWORD_3: &str = "shortp";

fn get_verifier_and_client_values(
    username: &str,
    password: &str,
    verifier: [u8; PASSWORD_VERIFIER_LENGTH as _],
    salt: [u8; SALT_LENGTH as _],
) -> (SrpProof, SrpClientChallenge) {
    let username_norm = NormalizedString::new(black_box(username)).unwrap();
    let password_verifier = black_box(verifier);
    let salt = black_box(salt);

    let verifier = SrpVerifier::from_database_values(username_norm, password_verifier, salt);
    let proof = verifier.into_proof();

    // Client does not have black boxes since that not who we're measuring
    let username = NormalizedString::new(username).unwrap();
    let password = NormalizedString::new(password).unwrap();
    let client = SrpClientUser::new(username, password);
    let challenge = client.into_challenge(
        GENERATOR,
        LARGE_SAFE_PRIME_LITTLE_ENDIAN,
        PublicKey::from_le_bytes(*proof.server_public_key()).unwrap(),
        *proof.salt(),
    );

    (proof, challenge)
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("server");
    group.sample_size(1000);
    // Go through an entire exchange while trying to ignore as much of the client as possible
    group.bench_function("server authentication", |b| {
        b.iter(|| {
            let (proof, challenge) =
                get_verifier_and_client_values(USERNAME_1, PASSWORD_1, PASSWORD_VERIFIER_1, SALT_1);

            let _server = proof
                .into_server(
                    PublicKey::from_le_bytes(*challenge.client_public_key()).unwrap(),
                    *challenge.client_proof(),
                )
                .unwrap();
        })
    });
    // Attempt to measure a server doing one calculation, then waiting for client, and in the meantime
    // doing another calculation
    group.bench_function("server mixed authentication", |b| {
        b.iter(|| {
            let (proof_1, challenge_1) =
                get_verifier_and_client_values(USERNAME_1, PASSWORD_1, PASSWORD_VERIFIER_1, SALT_1);

            let (proof_2, challenge_2) =
                get_verifier_and_client_values(USERNAME_2, PASSWORD_2, PASSWORD_VERIFIER_2, SALT_2);

            let _server = proof_1
                .into_server(
                    PublicKey::from_le_bytes(*challenge_1.client_public_key()).unwrap(),
                    *challenge_1.client_proof(),
                )
                .unwrap();

            let (proof_3, challenge_3) =
                get_verifier_and_client_values(USERNAME_3, PASSWORD_3, PASSWORD_VERIFIER_3, SALT_3);

            let _server = proof_2
                .into_server(
                    PublicKey::from_le_bytes(*challenge_2.client_public_key()).unwrap(),
                    *challenge_2.client_proof(),
                )
                .unwrap();

            let _server = proof_3
                .into_server(
                    PublicKey::from_le_bytes(*challenge_3.client_public_key()).unwrap(),
                    *challenge_3.client_proof(),
                )
                .unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
