# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased] - ReleaseDate

### Added

* `integrity` module for calculating the client file integrity. Used during authentication but ignored by most
  emulators.
* `pin` module for calculating the PIN hashes used during authentication.
* `matrix_card` module for calculating Matrix Card codes added in TBC clients.

## [0.7.0] - 2024-02-12

### Added

* `Ord`, `PartialOrd`, `Eq`, `PartialEq`, and `Hash` for `wrath_header` types.
* `read_and_decrypt_server_header` to `wrath_header::ClientDecrypterHalf` and `wrath_header::ClientCrypto`.
* BREAKING: `ClientDecrypterHalf/ClientCrypto::attempt_decrypt_server_header` and `*::decrypt_large_server_header`.
  This handles the problem of Wrath big headers better than supplying a fixed array.

### Changed

* BREAKING: `ProofSeed::into_header_crypto` renamed to `ProofSeed::into_server_header_crypto`.
* BREAKING: `ProofSeed::into_proof_and_header_crypto` renamed to `ProofSeed::into_client_header_crypto`.
* BREAKING: `ClientCrypto::decrypt_server_header` `data` parameter changed from `&[u8]` to `[u8]`.
  This makes it align more with the rest of the library.
* Updated `criterion` to `0.5` from `0.3`.
* BREAKING: Deduplicated header struct types. There is now only one `ClientHeader` and one vanilla/TBC `ServerHeader`
  plus a Wrath `ServerHeader`.
* BREAKING: `SrpClient::session_key` now returns a reference to a 40 byte array in order to make it similar to other
  functions in the library.
* BREAKING: `NormalizedString::new` changed to take `AsRef<str>` instead of `Into<String>`.
* BREAKING: `NormalizedString::from` renamed to `from_str` to more accurately reflect what it does.

### Removed

* `rc4` dependency.
* BREAKING: `ClientDecrypterHalf::decrypt_server_header` and `ClientCrypto::decrypt_server_header`.
  These have been replaced by a better API in `decrypt_internal_server_header` and `get_header_buffer`.
* BREAKING: `SrpClientUser`. This class did not have any accessors so it might as well be a `new` function
  on `SrpClientChallenge`.
  `SrpClientChallenge::new` replaces this functionality.
* BREAKING: `Copy` from `wrath_header` types that needed to uphold internal invariants that were easily broken
  by `Copy`.

## [0.6.0] - 2023-05-20

### Added

* BREAKING: `must_use` for all functions that do not return a `Result` type. This make it more difficult to use the
  library incorrectly.

### Changed

* BREAKING: `PublicKey::from_le_bytes` from taking a `&[u8; 32]` to a `[u8; 32]` to remain consistent with the remaining
  API.
* BREAKING: `PublicKey::as_le` renamed to `PublicKey::as_le_bytes` for consistency with the standard library and other
  functions in this library.
* BREAKING: Changed all functions taking `&mut Read/Write` to just take `Read/Write` as specified
  in [the library guidelines](https://rust-lang.github.io/api-guidelines/interoperability.html#c-rw-value).

## [0.5.3] - 2022-11-04

### Added

* `Debug` for `ServerEncrypterHalf`, `ServerDecrypterHalf`, `ClientEncrypterHalf`, and `ClientDecrypterHalf`
  in `wrath_header`.

## [0.5.2] - 2022-10-19

### Added

* Missing derives for all types. Most types now have `Debug`, `Clone`, `PartialEq`, `Eq`, `PartialOrd` and `Ord`.

## [0.5.1] - 2022-09-10

### Added

* Support for encrypting/decrypting TBC headers. This was mistakenly thought to be doable through the
  Vanilla `HeaderCrypto`. This is enabled with the `tbc-header` feature.

## [0.5.0] - 2022-09-06

### Added

* Supporting for encrypting/decrypting Wrath headers. This is enabled with the `wrath-header` feature.
* Ability to not have a Bigint library dependency. Compiling with no features will no longer be a compile error.

### Changed

* BREAKING: `header_crypto` moved to `vanilla_header` to make way for Wrath header crypto.
* Updated `sha-1` dependency to `0.10.0` from `0.9`.

### Removed

* BREAKING: `Decrypter` and `Encrypter` traits. Instead the `decrypter` and `encrypter` functions on the `HeaderCrypto`
  should be used. This is because the header crypto used for Wrath of the Lich King does not follow the same rules
  as `HeaderCrypto`, so there's no commonality.

## [0.4.2] - 2022-06-03

### Fixed

* `NormalizedString` accepting empty usernames and passwords.

## [0.4.1] - 2022-05-09

### Added

* Explicit Minimum Supported Rust Version (MSRV) of 1.48.0.
  When `wow_srp` is version `<1.0.0` the MSRV may be bumped in `PATCH` releases (`MAJOR.MINOR.PATCH`).

### Removed

* Developer dependencies on `hex_literal` and `hex`.

* Default features from `num_bigint`.

## [0.4.0] - 2022-02-20

### Added

* `TryFrom<&str>` and `TryFrom<String>` for `NormalizedString`.
* `NormalizedString::from` and `NormalizedString::from_string`.
  These are intended to be the default way of constructing the struct from either a `&str` or `String`.

### Changed

* BREAKING: `NormalizedString::new` no longer has the guarantee of breaking API changes requiring a major version
  update.
  This is in order to switch to a stack allocated string type in the future, foregoing the allocation and heap
  fragmentation of a string that's smaller than the bookkeeping data.
  This will also alert users `NormalizedString::new` that internal changes have been made that could result in potential
  performance problems.
* BREAKING: Changed named of features `num-bigint` and `rug` to `srp-default-math` and `srp-fast-math` respectively.
  This is in order to not be locked into specific libraries.

### Removed

* Default features from `sha-1` dependency.

## [0.3.0] - 2021-08-05

### Added

- `DecrypterHalf` and `EncrypterHalf`. Some TCP implementations allow separating reading and writing. If the encryption
  is under a Mutex it would not be optimal to make reads wait for writes and the other way around.
- `ProofSeed` struct that generates a random u32 server seed for world servers, used to build `HeaderCrypto`.
- Added `UnsplitCryptoError`. This is used instead of a panic when unsplitting two halves.
- `rug` feature that uses the [rug](https://crates.io/crates/rug) crate instead of the
  default [num_bigint](https://crates.io/crates/num-bigint) crate. Using the `rug` feature leads to a ~100% performance
  increase (50% decrease in benchmark time). The difference can be tested using `cargo bench` for the default crate
  and `cargo bench --features rug --no-default-features` for the `rug` crate.

### Changed

- BREAKING: `Decryptor` and `Encryptor` have been renamed to `Decrypter` and `Encrypter` to better reflect namings in
  the stdlib.
- BREAKING: `read_decrypted_server_header` renamed to `read_and_decrypt_server_header`
  and `read_decrypted_client_header` renamed to `read_and_decrypt_client_header` to better describe what happens.
- `Decryptor` and `Encryptor` traits now have default methods for everything but `encrypt` and `decrypt`.
- BREAKING: `HeaderCrypto` can now only be built from a `ProofSeed`. This is to encode more information into the type
  system instead of in documentation.
- BREAKING: `EncrypterHalf::unsplit` is now fallible and returns a `Result<HeaderCrypto, UnsplitCryptoError>`.

### Removed

- BREAKING: `HeaderCrypto::new`. Use `ProofSeed::into_server_header_crypto` instead.

## [0.2.0] - 2021-07-05

### Added

- Added `Encryption` struct which allows for encryption/decryption of [World Packet](https://wowdev.wiki/World_Packet)
  headers.

### Changed

- BREAKING: `SrpProof::into_server` function now returns a tuple of `(SrpServer, [u8; PROOF_LENGTH)`.
  This makes for more ergonomic usage since the server proof does not need to be queried through a getter afterwards.
- BREAKING: Public constants have been turned from `usize`s to `u8`s.
  This is because casting from a larger integer to a smaller one will possibly truncate, while casting from a smaller
  integer to a larger one will zero extend (on unsigned).
  The smaller integer size indicates that the value fits into a u8 without truncation.

### Removed

- BREAKING: `SrpServer::server_proof` removed due to changes to `SrpProof::into_server`.
- `hex` dependency for normal builds.

### Security

- Fixed Client public key not being correctly verified against a custom large safe prime.

## [0.1.1] - 2021-05-17

### Changed

- Change several allocations to be statically sized instead, improving performance slightly.

### Removed

- Dependency on `num_traits`.

### Fixed

- Error in calculating the S key that resulted in an incorrect proof once every ~250 authentications.
- Bug where client version always used the static version of the large safe prime.

## [0.1.0] - 2021-04-21

### Added

- Initial release

<!-- next-url -->

[Unreleased]: https://github.com/gtker/wow_srp/compare/v0.7.0...HEAD

[0.7.0]: https://github.com/gtker/wow_srp/compare/v0.6.0...v0.7.0

[0.6.0]: https://github.com/gtker/wow_srp/compare/v0.5.3...v0.6.0

[0.5.3]: https://github.com/gtker/wow_srp/releases/tag/v0.5.3

[0.5.2]: https://github.com/gtker/wow_srp/releases/tag/v0.5.2

[0.5.1]: https://github.com/gtker/wow_srp/releases/tag/v0.5.1

[0.5.0]: https://github.com/gtker/wow_srp/releases/tag/v0.5.0

[0.4.2]: https://github.com/gtker/wow_srp/releases/tag/v0.4.2

[0.4.1]: https://github.com/gtker/wow_srp/releases/tag/v0.4.1

[0.4.0]: https://github.com/gtker/wow_srp/releases/tag/v0.4.0

[0.3.0]: https://github.com/gtker/wow_srp/releases/tag/v0.3.0

[0.2.0]: https://github.com/gtker/wow_srp/releases/tag/0.2.0

[0.1.1]: https://github.com/gtker/wow_srp/releases/tag/v0.1.1

[0.1.0]: https://github.com/gtker/wow_srp/tree/39f5ef7ce9e17dd85381b2c48c06b174777469c1
