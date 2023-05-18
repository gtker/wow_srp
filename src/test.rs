use crate::client::SrpClientUser;
use crate::normalized_string::NormalizedString;
use crate::server::SrpVerifier;
use crate::{PublicKey, GENERATOR, LARGE_SAFE_PRIME_LITTLE_ENDIAN};

#[test]
fn authenticate_with_self() {
    let username: NormalizedString = NormalizedString::new("A").unwrap();
    let password: NormalizedString = NormalizedString::new("A").unwrap();
    let client = SrpClientUser::new(username, password);

    let username: NormalizedString = NormalizedString::new("A").unwrap();
    let password: NormalizedString = NormalizedString::new("A").unwrap();
    let verifier = SrpVerifier::from_username_and_password(username, password);

    let password_verifier = *verifier.password_verifier();
    let client_salt = *verifier.salt();

    let server = verifier.into_proof();

    let server_salt = *server.salt();
    let server_public_key = *server.server_public_key();

    let client = client.into_challenge(
        GENERATOR,
        LARGE_SAFE_PRIME_LITTLE_ENDIAN,
        PublicKey::from_le_bytes(*server.server_public_key()).unwrap(),
        *server.salt(),
    );
    let client_public_key = *client.client_public_key();

    let (mut server, server_proof) = match server.into_server(
        PublicKey::from_le_bytes(client_public_key).unwrap(),
        *client.client_proof(),
    ) {
        Ok(s) => s,
        Err(e) => {
            panic!(
                "'{}'\
                \nverifier: {:02x?}\
                \nclient_salt: {:02x?}\
                \nserver_salt: {:02x?}\
                \nserver_public_key: {:02x?}\
                \nclient_public_key: {:02x?}",
                e,
                password_verifier,
                client_salt,
                server_salt,
                server_public_key,
                client_public_key,
            )
        }
    };

    let e = client.verify_server_proof(server_proof);

    let client = match e {
        Ok(s) => s,
        Err(e) => {
            panic!(
                "'{}'\
                \nverifier: {:02x?}\
                \nclient_salt: {:02x?}\
                \nserver_salt: {:02x?}\
                \nserver_public_key: {:02x?}\
                \nclient_public_key: {:02x?}",
                e,
                password_verifier,
                client_salt,
                server_salt,
                server_public_key,
                client_public_key,
            )
        }
    };

    assert_eq!(*server.session_key(), client.session_key());
    let reconnection_data = client.calculate_reconnect_values(*server.reconnect_challenge_data());

    let verified = server
        .verify_reconnection_attempt(reconnection_data.challenge_data, reconnection_data.proof);

    assert!(verified);
}
