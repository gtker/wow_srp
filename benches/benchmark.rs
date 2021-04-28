use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wow_srp::client::SrpClientUser;
use wow_srp::normalized_string::NormalizedString;
use wow_srp::server::SrpVerifier;
use wow_srp::{PublicKey, GENERATOR, LARGE_SAFE_PRIME_LITTLE_ENDIAN};

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("benchmark", |b| {
        b.iter(|| {
            let username = NormalizedString::new(black_box("A")).unwrap();
            let password_verifier = black_box([
                106, 6, 11, 113, 103, 55, 49, 130, 210, 249, 178, 176, 73, 77, 229, 163, 127, 223,
                122, 163, 245, 174, 60, 217, 151, 142, 169, 173, 208, 8, 152, 31,
            ]);
            let salt = black_box([
                120, 156, 208, 137, 73, 108, 21, 91, 28, 22, 13, 255, 99, 116, 71, 102, 158, 70,
                65, 189, 153, 244, 143, 13, 214, 200, 160, 94, 217, 112, 206, 125,
            ]);

            let verifier = SrpVerifier::from_database_values(username, &password_verifier, &salt);
            let proof = verifier.into_proof();

            let username = NormalizedString::new("A").unwrap();
            let password = NormalizedString::new("A").unwrap();
            let client = SrpClientUser::new(username, password);
            let challenge = client.into_challenge(
                GENERATOR,
                LARGE_SAFE_PRIME_LITTLE_ENDIAN,
                PublicKey::from_le_bytes(proof.server_public_key()).unwrap(),
                *proof.salt(),
            );

            let _server = proof
                .into_server(
                    PublicKey::from_le_bytes(challenge.client_public_key()).unwrap(),
                    challenge.client_proof(),
                )
                .unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
