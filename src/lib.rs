//! An implementation of the World of Warcraft flavor of SRP6 used for authentication with the Login Server.
//! It is only tested and verified on 1.12.1, but should work for other versions.
//!
//! The implementation is intended to abstract away as much of the protocol as possible,
//! and limits itself to the specific requirements of the World of Warcraft implementation.
//! For example, all key sizes are limited to exactly [32 bytes](LARGE_SAFE_PRIME_LENGTH) since
//! the network packet fields describing public keys are of a fixed size in the protocol
//! and key sizes of any other sizes are not possible.
//!
//! This crate does not deal with parsing the network packets necessary to obtain the required parameters.
//! The [WoWDev wiki](https://wowdev.wiki/Login_Packet) ([archive]) contains a reference list of packets
//! and the examples implement the required functionality.
//!
//! **THIS SHOULD NOT BE USED FOR ANYTHING OTHER THAN WORLD OF WARCRAFT EMULATION.
//! THE CODE IS NOT CRYPTOGRAPHICALLY VERIFIED, HAS VERY LOW KEY SIZES BECAUSE OF
//! PACKET REQUIREMENTS AND MOST LIKELY CONTAINS EXPLOITS.**
//!
//! # Usage
//!
//! The crate is split into:
//! * A [`server`] module containing structs for use on the server.
//! * A [`client`] module containing structs for use on the client.
//! * A [`header_crypto`] module containing structs and traits for decrypting world packets.
//! * An [`error`] module for errors that are shared by all modules.
//! * A [`normalized_string`] module used for all modules to correctly handle strings.
//!
//! A server example can be found in `examples/server.rs`
//! and a client example can be found in `examples/client.rs`.
//! These examples will perform the full SRP6 connection and reconnection.
//! The server will work with a 1.12.1 client,
//! using the username and password `a` and `a`.
//! The client will work not with any other server since it ignores everything
//! that is not absolutely necessary for showcasing the crate.
//!
//! ## Running the examples
//!
//! 1. Clone the repo with `git clone https://github.com/gtker/wow_srp`.
//! 2. Run the server with `cargo run --example server` inside the directory.
//! This runs a simple authentication server that accepts the username "a" and the password "a". Anything else panics.
//! 3. Run a real client with the realmlist set to `localhost`
//! or run the client example with `cargo run --example client`.
//!
//! ## Usage
//!
//! Add the following to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! wow_srp = "0.2"
//! ```
//!
//! Then go to either the [`client`] module or [`server`] module for specific instructions.
//!
//! # Other implementations
//!
//! * [Ember](https://github.com/EmberEmu/Ember/tree/development/src/libs/srp6) is a C++ implementation for 1.12 with a clean, tested implementation of the protocol.
//! * [ArcEmu](https://github.com/arcemu/arcemu/blob/00355000cac5d0b9bce42bf6d03d4aeda9e396ea/src/logon/Auth/AuthSocket.cpp#L74) is a C++ implementation for 3.3.5.
//! * [vMangos](https://github.com/vmangos/core/blob/fa9351de7e832510309209351c17f5c53f3155ef/src/realmd/AuthSocket.cpp#L350) is a C++ implementation.
//! * [WoWCore](https://github.com/RomanRom2/WoWCore/blob/92b7646c2bafb22ad6dca0acc9496a35561292c4/05875_1.12.1/pas/sandbox/AuthServer.pas#L133) is a Pascal implementation that has 1.12, 2.4.3 and 3.3.5 versions.
//! * [Shadowburn](https://gitlab.com/shadowburn/shadowburn/-/blob/ac905fabf56579b3bda6f16689c74f544da043e2/apps/common/lib/accounts/accounts.ex#L88) is an Elixir implementation.
//!
//! [archive]: https://web.archive.org/web/20210620154707/https://wowdev.wiki/Login_Packet

#![doc(html_root_url = "https://docs.rs/wow_srp/0.2.0")]
#![forbid(unsafe_code)]
#![warn(
    clippy::perf,
    clippy::correctness,
    clippy::style,
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::unseparated_literal_suffix,
    missing_docs
)]

pub use key::PublicKey;
pub use key::PASSWORD_VERIFIER_LENGTH;
pub use key::PROOF_LENGTH;
pub use key::PUBLIC_KEY_LENGTH;
pub use key::RECONNECT_CHALLENGE_DATA_LENGTH;
pub use key::SALT_LENGTH;
pub use key::SESSION_KEY_LENGTH;
pub use primes::GENERATOR;
pub use primes::GENERATOR_LENGTH;
pub use primes::LARGE_SAFE_PRIME_BIG_ENDIAN;
pub use primes::LARGE_SAFE_PRIME_LENGTH;
pub use primes::LARGE_SAFE_PRIME_LITTLE_ENDIAN;

pub(crate) mod bigint;
pub mod client;
pub mod error;
pub mod header_crypto;
mod key;
pub mod normalized_string;
pub(crate) mod primes;
pub mod server;
pub(crate) mod srp_internal;
pub(crate) mod srp_internal_client;
