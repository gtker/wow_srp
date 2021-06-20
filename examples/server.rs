use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use wow_srp::normalized_string::NormalizedString;
use wow_srp::server::{SrpServer, SrpVerifier};
use wow_srp::{
    PublicKey, GENERATOR, GENERATOR_LENGTH, LARGE_SAFE_PRIME_LENGTH,
    LARGE_SAFE_PRIME_LITTLE_ENDIAN, PROOF_LENGTH, PUBLIC_KEY_LENGTH, SALT_LENGTH,
};

// Simple server that authenticates a single client and then hangs on the 'Send Realmlist' command.

// This example only accepts the username and password "A" and "A".
// The values do not have to be uppercase on the client, they will be automatically uppercased when sent.
// The example deliberately avoids all error handling in order to make the successful path clearer.
// The example ignores as much of the actual networking as possible to focus on the use of the library.
// Packet information can be found at:
// https://wowdev.wiki/Packets/Login/Vanilla

// It is recommended to read the example from top to bottom, as functions have been placed in order
// of decreasing importance.

fn main() {
    // Keep a list of authorized clients.
    // If a client loses connection they will send a reconnect challenge along with their username.
    // If clients were successfully authenticated the server and client will both have a session key.
    // This session key is used to prove that the client is the same one that lost connection.
    let mut active_clients = HashMap::<String, SrpServer>::new();

    // Start a TCP server on 3724. This is the default port for authentication.
    let authentication_server_port = 3724;
    let address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), authentication_server_port);
    let listener = TcpListener::bind(address).expect("unable to start TCP server on 3724");

    // Accept requests in a blocking fashion.
    // This will only accept and handle 1 request at a time.
    for stream in listener.incoming() {
        handle_client(&mut stream.unwrap(), &mut active_clients);
    }
}

// Read the first byte of the packet and determine if the client is attempting to authenticate (0)
// or reconnect (2)
fn handle_client(stream: &mut TcpStream, active_clients: &mut HashMap<String, SrpServer>) {
    let mut command = [0u8; 1];
    stream.read_exact(&mut command).unwrap();
    println!("Command: {}", command[0]);
    match command[0] {
        0 => authentication_logon_challenge(stream, active_clients),
        2 => handle_reconnect(stream, active_clients),
        _ => panic!("Unknown command: {}!", command[0]),
    }
}

fn authentication_logon_challenge(
    stream: &mut TcpStream,
    active_clients: &mut HashMap<String, SrpServer>,
) {
    // Ignore the first packet except the first letter of the account name.
    // Note that due to reading an exact amount, entering an account name
    // with more than one character will be interpreted as being part of the next packet and will fail.
    // Packet name: AuthLogonChallenge_Client
    let mut buffer = [0u8; 49];
    stream.read(&mut buffer).unwrap();
    let username = String::from_utf8([buffer[33]].to_vec()).unwrap();

    // Assume username and password is 'a' (client automatically uppercases)
    // Retrieve the password verifier and salt values from the database.
    let v = get_database_values(&username);

    // Create SrpServer struct in order to get values for first server packet.
    let s = v.into_proof();

    // Send server challenge
    // Packet name: AuthLogonChallenge_Server
    let mut send = [0u8; 119];
    send[3..=3 + 31].clone_from_slice(s.server_public_key());
    send[35] = GENERATOR_LENGTH;
    send[36] = GENERATOR;
    send[37] = LARGE_SAFE_PRIME_LENGTH;
    send[38..38 + LARGE_SAFE_PRIME_LENGTH as usize]
        .clone_from_slice(&LARGE_SAFE_PRIME_LITTLE_ENDIAN);
    send[70..70 + SALT_LENGTH as usize].clone_from_slice(s.salt());
    stream.write_all(&send).unwrap();

    // Read client reply
    // Packet name: AuthLogonProof_Client
    let mut buffer = [0; 100];
    stream.read(&mut buffer).unwrap();

    let mut client_public_key = [0u8; PUBLIC_KEY_LENGTH as usize];
    client_public_key.clone_from_slice(&buffer[1..1 + PUBLIC_KEY_LENGTH as usize]);
    let client_public_key = PublicKey::from_le_bytes(&client_public_key);
    // Protect against losing connection and reading the unmodified buffer
    // If this happens try restarting the server and client
    let client_public_key = match client_public_key {
        Ok(p) => p,
        Err(_) => {
            panic!("Invalid client public key. This is likely a result of malformed packets.")
        }
    };

    let mut client_proof = [0u8; PROOF_LENGTH as usize];
    client_proof.clone_from_slice(&buffer[33..33 + PROOF_LENGTH as usize]);

    let (s, server_proof) = s.into_server(client_public_key, &client_proof).unwrap();

    // Send the proof to the client.
    // Packet name: AuthLogonProof_Server
    let mut send = [0u8; 26];
    const LOGIN_PROOF: u8 = 1;
    send[0] = LOGIN_PROOF;
    send[2..=2 + 19].clone_from_slice(&server_proof);
    stream.write_all(&send).unwrap();

    // Expect the client to send a 'Send Realmlist' packet header
    // Packet name: RealmList_Client
    let mut buffer = [0; 100];
    stream.read(&mut buffer).unwrap();
    assert!(buffer[0] == 0x10);

    // Add the account to the list of active accounts.
    // This allows the client to avoid the full auth in case it loses connection.
    active_clients.insert(username, s);
}

// Happens if the client presses cancel on the "Success!" box
fn handle_reconnect(stream: &mut TcpStream, active_clients: &mut HashMap<String, SrpServer>) {
    // Ignore the first packet except the first letter of the account name.
    // Note that due to reading an exact amount, entering an accout name
    // with more than one character will be interpreted as being part of the next packet and will fail.
    // Packet name: AuthReconnectionChallenge_Client
    let mut buffer = [0u8; 49];
    stream.read(&mut buffer).unwrap();
    let username = String::from_utf8([buffer[33]].to_vec()).unwrap();

    // Look up the relevant struct
    let s = active_clients.get_mut(&username).unwrap();

    // Send the reconnect challenge.
    // Packet name: AuthReconnectionChallenge_Server
    let mut send = [0u8; 0x1A + 8];
    send[0] = 2;
    send[2..2 + 16].clone_from_slice(s.reconnect_challenge_data());
    stream.write_all(&send).unwrap();

    // Read the reply
    // Packet name: AuthReconnectionProof_Client
    let mut buffer = [0u8; 100];
    stream.read(&mut buffer).unwrap();
    let mut proof_data = [0u8; 16];
    proof_data.clone_from_slice(&buffer[1..1 + 16]);
    let mut client_proof = [0u8; 20];
    client_proof.clone_from_slice(&buffer[0x11..0x11 + 20]);

    // Verify that the proof is correct.
    let verified = s.verify_reconnection_attempt(&proof_data, &client_proof);
    assert_eq!(verified, true);

    // Send the result
    // Packet name: AuthReconnectionProof_Server
    let mut send = [0u8; 2];
    send[0] = 3;
    stream.write(&send).unwrap();

    // Expect the client to send a 'Send Realmlist' packet header
    let mut buffer = [0; 100];
    stream.read(&mut buffer).unwrap();
    assert!(buffer[0] == 0x10);
    println!("Successfully reconnected.");
}

fn get_database_values(username: &str) -> SrpVerifier {
    // Pretend that only the user A exists. Panic to avoid doing error handling logic.
    match username {
        "A" => (),
        _ => panic!("Invalid username. Only 'A' is supported"),
    }

    // Verifier and salt values retrieved from the database, previously created using
    // SrpVerifier::new(username, password) when the user created their account.
    let password_verifier = [
        215, 47, 230, 15, 63, 23, 36, 233, 197, 246, 150, 203, 225, 175, 88, 91, 223, 174, 20, 17,
        203, 167, 28, 111, 91, 10, 160, 65, 219, 191, 149, 59,
    ];
    let salt = [
        234, 133, 84, 36, 86, 83, 127, 51, 183, 244, 145, 149, 19, 12, 154, 213, 179, 96, 183, 90,
        52, 89, 136, 194, 38, 180, 62, 145, 35, 125, 33, 80,
    ];

    let username = NormalizedString::new(username).unwrap();
    SrpVerifier::from_database_values(username, &password_verifier, &salt)
}
