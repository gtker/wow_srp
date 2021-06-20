# `WoW_SRP`

A standalone Rust library for the World of Warcraft flavor of SRP6.
Has functionality for both the client and server.

# Usage

Add the following to `Cargo.toml`:

```
[dependencies]
wow_srp = "0.2"
```

Or install with [cargo edit](https://crates.io/crates/cargo-edit):
```
cargo add wow_srp
```

Then read the documentation at [docs.rs](https://docs.rs/wow_srp).

Client and server examples which will authenticate with a 1.12 server/client are located in the `examples/` directory.
Run them with `cargo run --example server` or `cargo run --example client`.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

