use std::convert::TryInto;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use wow_srp::client::SrpClientUser;
use wow_srp::normalized_string::NormalizedString;
use wow_srp::{
    PublicKey, PROOF_LENGTH, PUBLIC_KEY_LENGTH, RECONNECT_CHALLENGE_DATA_LENGTH, SALT_LENGTH,
};

// Simple client that authenticates with the server in examples/server.rs and then stops.

// This example uses the same username and password as is default on the server.
// This example skips through as much of the networking and error handling as possible.
// Packet information can be found at:
// https://wowdev.wiki/Packets/Login/Vanilla

// It is recommended to read the example from top to bottom as the control flow is completely linear.

fn main() {
    // Connect to the server
    let authentication_server_port = 3724;
    let address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), authentication_server_port);
    let mut s = TcpStream::connect(address).unwrap();

    // Send a packet that only contains the username since the client disregards everything else
    // Packet name: AuthLogonChallenge_Client
    let mut empty_buffer = [0u8; 49];
    // Adding the length field makes Wireshark debugging easier
    empty_buffer[2] = 46;
    // Set the username to be "A"
    empty_buffer[34] = b'A';
    s.write(&empty_buffer).unwrap();

    // Read the reply
    // Packet name: AuthLogonChallenge_Server
    let mut buffer = [0u8; 119];
    s.read(&mut buffer).unwrap();

    // Server public key is ALWAYS 32 bytes due to how the packet is structured.
    let mut server_public_key = [0u8; PUBLIC_KEY_LENGTH];
    server_public_key.clone_from_slice(&buffer[3..3 + PUBLIC_KEY_LENGTH]);

    // RFC5054 does not specify any generator above one byte, and it is unlikely to happen.
    // The library does not support anything other than 1 byte generators.
    let _generator_length = buffer[35];
    let generator = buffer[36];

    // Large Safe Prime is in theory variable, but in practice is always 32 bytes.
    let large_safe_prime_length = buffer[37];
    let large_safe_prime = buffer[38..38 + large_safe_prime_length as usize].to_vec();
    let large_safe_prime: [u8; 32] = large_safe_prime.try_into().unwrap();

    // Salt is ALWAYS 32 bytes due to how the packet is structured
    let mut salt = [0u8; SALT_LENGTH];
    salt.clone_from_slice(&buffer[70..70 + SALT_LENGTH]);

    let client = SrpClientUser::new(
        NormalizedString::new("A").unwrap(),
        NormalizedString::new("A").unwrap(),
    );
    let server_public_key = PublicKey::from_le_bytes(&server_public_key).unwrap();
    let client = client.into_challenge(generator, large_safe_prime, server_public_key, salt);

    // Send back the public key and proof
    // Packet name: AuthLogonProof_Client
    let mut send = [0u8; 0x50];
    send[0] = 1;
    send[1..1 + PUBLIC_KEY_LENGTH].clone_from_slice(client.client_public_key());
    send[33..33 + PROOF_LENGTH].clone_from_slice(client.client_proof());
    s.write(&send).unwrap();

    // Receive the server proof and verify
    // Packet name: AuthLogonProof_Server
    let mut buffer = [0u8; 0x20];
    s.read(&mut buffer).unwrap();
    let mut server_proof = [0u8; PROOF_LENGTH];
    server_proof.clone_from_slice(&buffer[2..2 + PROOF_LENGTH]);

    let client = client.verify_server_proof(&server_proof).unwrap();

    // Reply with 'Send Realmlist' as server expects
    // Packet name: RealmList_Client
    let mut buffer = [0u8; 5];
    buffer[0] = 0x10;
    s.write(&buffer).unwrap();

    // Drop connection to enable us to attempt a reconnect
    drop(s);

    // Reconnect
    let mut s = TcpStream::connect(address).unwrap();

    // Reconnect package is same as original except for the command field
    // Packet name: AuthReconnectionChallenge_Client
    let mut send = [0u8; 49];
    // Set command to be reconnect
    send[0] = 2;
    // Set the username to be "A"
    send[34] = b'A';
    s.write(&send).unwrap();

    // Receive the challenge
    // Packet name: AuthReconnectionChallenge_Server
    let mut buffer = [0u8; 34];
    s.read(&mut buffer).unwrap();

    let mut server_challenge_data = [0u8; RECONNECT_CHALLENGE_DATA_LENGTH];
    server_challenge_data.clone_from_slice(&buffer[2..2 + RECONNECT_CHALLENGE_DATA_LENGTH]);

    let reconnection_data = client.calculate_reconnect_values(&server_challenge_data);

    // Send the proof and client challenge data
    // Packet name: AuthReconnectionProof_Client
    let mut send = [0u8; 64];
    send[0] = 3;
    send[1..1 + RECONNECT_CHALLENGE_DATA_LENGTH]
        .clone_from_slice(&reconnection_data.challenge_data);
    send[17..17 + PROOF_LENGTH].clone_from_slice(&reconnection_data.proof);
    s.write(&send).unwrap();

    // Receive validation of reconnect
    // Packet name: AuthReconnectionProof_Server
    let mut buffer = [0u8; 2];
    s.read(&mut buffer).unwrap();
    assert_eq!(buffer[0], 3);

    // Reply with 'Send Realmlist' as server expects
    // Packet name: RealmList_Client
    let mut buffer = [0u8; 5];
    buffer[0] = 0x10;
    s.write(&buffer).unwrap();
}
