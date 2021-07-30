# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `DecrypterHalf` and `EncrypterHalf`. Some TCP implementations allow separating reading and writing. If the encryption is under a Mutex it would not be optimal to make reads wait for writes and the other way around.
- `ServerSeed` struct that generates a random u32 server seed for world servers, used to build `HeaderCrypto`.

### Changed
- BREAKING: `Decryptor` and `Encryptor` have been renamed to `Decrypter` and `Encrypter` to better reflect namings in the stdlib.
- BREAKING: `read_decrypted_server_header` renamed to `read_and_decrypt_server_header` and `read_decrypted_client_header` renamed to `read_and_decrypt_client_header` to better describe what happens.
- `Decryptor` and `Encryptor` traits now have default methods for everything but `encrypt` and `decrypt`.
- BREAKING: `HeaderCrypto` can now only be built from a `ServerSeed`. This is to encode more information into the type system instead of in documentation.

### Deprecated

### Removed
- BREAKING: `HeaderCrypto::new`. Use `ServerSeed::into_header_crypto` instead.

### Fixed

### Security


## [0.2.0] - 2021-07-05

### Added
- Added `Encryption` struct which allows for encryption/decryption of [World Packet](https://wowdev.wiki/World_Packet) headers.

### Changed
- BREAKING: `SrpProof::into_server` function now returns a tuple of `(SrpServer, [u8; PROOF_LENGTH)`.
This makes for more ergonomic usage since the server proof does not need to be queried through a getter afterwards.
- BREAKING: Public constants have been turned from `usize`s to `u8`s.
This is because casting from a larger integer to a smaller one will possibly truncate, while casting from a smaller integer to a larger one will zero extend (on unsigned).
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

[0.2.0]: https://github.com/gtker/wow_srp/releases/tag/0.2.0
[0.1.1]: https://github.com/gtker/wow_srp/releases/tag/v0.1.1
[0.1.0]: https://github.com/gtker/wow_srp/tree/39f5ef7ce9e17dd85381b2c48c06b174777469c1
