use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use wow_srp::normalized_string::NormalizedString;
use wow_srp::server::{SrpServer, SrpVerifier};
use wow_srp::{
    PublicKey, GENERATOR, LARGE_SAFE_PRIME_LENGTH, LARGE_SAFE_PRIME_LITTLE_ENDIAN, PROOF_LENGTH,
    PUBLIC_KEY_LENGTH, SALT_LENGTH,
};

/*
Connect with a 1.12.1 client.

The client should display the 'Success!' message.
You should then press enter and test for reconnection.
On pass the client says "Session Expired" after sending a 'Send Realmlist' packet
and the test passes.
 */
#[test]
#[ignore] // Requires manually verifying with actual client
fn authenticate_with_real_client_1_12_1_reconnect() {
    let mut client = Vec::new();
    let authentication_server_port = 3724;
    let address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), authentication_server_port);
    let listener = TcpListener::bind(address).expect("unable to start TCP server on 3724");
    {
        let (mut stream, _a) = listener.accept().unwrap();
        handle_client(&mut stream, &mut client);
        // drop the connection in order to make client reconnect
    }
    {
        let (mut stream, _a) = listener.accept().unwrap();
        handle_client(&mut stream, &mut client);
    }
}
fn handle_client(stream: &mut TcpStream, client: &mut Vec<SrpServer>) {
    let mut command = [0u8; 1];
    stream.read_exact(&mut command).unwrap();
    println!("Command: {}", command[0]);
    if command[0] == 0 {
        authentication_logon_challenge(stream, client);
    } else if command[0] == 2 {
        handle_reconnect(stream, client);
        println!("Reconnect command received.");
    } else {
        panic!("Unknown command: {}!", command[0]);
    }
}

fn handle_reconnect(stream: &mut TcpStream, client: &mut Vec<SrpServer>) {
    // Ignore the first packet, assume the account name is just "A"
    let mut buffer = [0u8; 49];
    stream.read(&mut buffer).unwrap();

    let mut s = client.pop().unwrap();

    let mut send = [0u8; 0x1A + 8];
    send[0] = 2;
    send[2..2 + 16].clone_from_slice(s.reconnect_challenge_data());
    stream.write_all(&send).unwrap();

    let mut buffer = [0u8; 100];
    stream.read(&mut buffer).unwrap();
    let mut proof_data = [0u8; 16];
    proof_data.clone_from_slice(&buffer[1..1 + 16]);
    let mut client_proof = [0u8; 20];
    client_proof.clone_from_slice(&buffer[0x11..0x11 + 20]);
    println!("proof_data: {:?}", &proof_data);
    println!("client_proof: {:?}", client_proof);
    let verified = s.verify_reconnection_attempt(proof_data, client_proof);
    assert_eq!(verified, true);
    let mut send = [0u8; 2];
    send[0] = 3;
    stream.write(&send).unwrap();

    let mut buffer = [0; 100];
    stream.read(&mut buffer).unwrap();

    // Expect the client to send a 'Send Realmlist' packet header
    assert!(buffer[0] == 0x10);
}

fn authentication_logon_challenge(stream: &mut TcpStream, client: &mut Vec<SrpServer>) {
    // Ignore the first packet, assume the account name is just "A"
    let mut buffer = [0u8; 49];
    stream.read(&mut buffer).unwrap();

    // Assume username and password is 'a' (client automatically uppercases)
    let v = SrpVerifier::from_username_and_password(
        NormalizedString::new("A").unwrap(),
        NormalizedString::new("A").unwrap(),
    );
    let s = v.into_proof();

    let mut send = [0u8; 119];
    send[3..=3 + 31].clone_from_slice(s.server_public_key());
    const LOGIN_PROOF: u8 = 1;
    send[35] = LOGIN_PROOF;
    send[36] = GENERATOR;
    send[37] = LARGE_SAFE_PRIME_LENGTH as u8;
    send[38..38 + LARGE_SAFE_PRIME_LENGTH as usize]
        .clone_from_slice(&LARGE_SAFE_PRIME_LITTLE_ENDIAN);
    send[70..70 + SALT_LENGTH as usize].clone_from_slice(s.salt());

    stream.write_all(&send).unwrap();

    let mut buffer = [0; 100];
    stream.read(&mut buffer).unwrap();
    let mut client_public_key = [0u8; PUBLIC_KEY_LENGTH as usize];
    client_public_key.clone_from_slice(&buffer[1..1 + PUBLIC_KEY_LENGTH as usize]);
    let client_public_key = PublicKey::from_le_bytes(&client_public_key);
    let client_public_key = match client_public_key {
        Ok(p) => p,
        Err(_) => {
            panic!("Invalid client public key. This is likely a result of malformed packets.")
        }
    };
    let client_public_key_hex = *client_public_key.as_le();

    let mut client_proof = [0u8; PROOF_LENGTH as usize];
    client_proof.clone_from_slice(&buffer[33..33 + PROOF_LENGTH as usize]);

    let s = s.into_server(client_public_key, client_proof);
    let (s, server_proof) = match s {
        Ok(s) => s,
        Err(_) => {
            println!(
                "Client public key: '{:02x?}', Client proof: '{:02x?}'",
                client_public_key_hex, &client_proof
            );
            panic!("error in proof");
        }
    };

    let mut send = [0u8; 26];
    send[0] = 1;
    send[2..=2 + 19].clone_from_slice(&server_proof);

    stream.write_all(&send).unwrap();

    let mut buffer = [0; 100];
    stream.read(&mut buffer).unwrap();

    // Expect the client to send a 'Send Realmlist' packet header
    assert!(buffer[0] == 0x10);
    client.push(s);
}
