//! An implementation of the World of Warcraft flavor of SRP6 used for authentication with the Login Server.
//! This should work on all versions from 1.2 to 3.3.5.
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
//! * A [`vanilla_header`] module containing structs for decrypting Vanilla and TBC world packets.
//! * A [`wrath_header`] module containing structs for decrypting Wrath world packets.
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
//! ## Examples
//!
//! The [`wow_messages`](https://github.com/gtker/wow_messages) repo has examples that uses the
//! [`wow_login_messages`](https://docs.rs/wow_login_messages/latest/wow_login_messages/)
//! and `wow_vanilla_messages` library message definitions to showcase both crates.
//!
//! ## Usage
//!
//! Add the following to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! wow_srp = { version = "0.4.2" }
//! ```
//!
//! Then go to either the [`client`] module or [`server`] module for specific instructions.
//!
//! ## Features
//!
//! Two different arbitrary precision integer libraries can be used, either:
//!
//! * [num-bigint](https://crates.io/crates/num-bigint). A slow pure Rust implementation without
//! external dependencies. This is enabled by default, and requires no opt in.
//!
//! * [rug](https://crates.io/crates/rug). A fast wrapper around the [GMP library](https://gmplib.org/)
//! with external dependencies, as described in the [gmp_mpfr_sys documentation](https://docs.rs/gmp-mpfr-sys/1.4.6/gmp_mpfr_sys/index.html#building-on-gnulinux).
//! This is enabled with the `fast-math` feature and disabling default features.
//! So **instead** of the above do this:
//!
//! ```toml
//! [dependencies]
//! wow_srp = { version = "0.4.2", default-features = false, features = ["fast-math"] }
//! ```
//!
//! The `fast-math` feature leads to a 50% decrease in total time. It is highly recommended to enable
//! this feature for production usage since it also theoretically has better security.
//!
//! To see the performance difference on your setup you can run `cargo bench` for the default version,
//! and `cargo bench --features fast-math --no-default-features` for the `fast-math` version.
//!
//! # MSRV
//!
//! `wow_srp` has a Minimum Supported Rust Version (MSRV) of 1.48.0.
//! The MSRV may be increased in `PATCH` versions before `wow_srp` reaches `1.0.0` (`MAJOR.MINOR.PATCH`).
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

#![doc(html_root_url = "https://docs.rs/wow_srp/0.4.2")]
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
mod key;
pub mod normalized_string;
pub(crate) mod primes;
pub mod server;
pub(crate) mod srp_internal;
pub(crate) mod srp_internal_client;
pub mod vanilla_header;
pub mod wrath_header;

#[cfg(test)]
pub(crate) mod hex;
