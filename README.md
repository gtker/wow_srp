# `WoW_SRP`

A standalone Rust library for the World of Warcraft flavor of SRP6.
Has functionality for both the client and server.

# Usage

Add the following to `Cargo.toml`:

```
[dependencies]
wow_srp = "0.5"
```

Or install with [cargo edit](https://crates.io/crates/cargo-edit):
```
cargo add wow_srp
```

Then read the documentation at [docs.rs](https://docs.rs/wow_srp).


## Examples

The [`wow_messages`](https://github.com/gtker/wow_messages) repo has examples that uses the
[`wow_login_messages`](https://docs.rs/wow_login_messages/latest/wow_login_messages/)
and `wow_vanilla_messages` library message definitions to showcase both crates.

## Features

Two different arbitrary precision integer libraries can be used, either:

* [num_bigint](https://crates.io/crates/num-bigint). A slow pure Rust implementation without external dependencies. This is enabled by default, and requires no opt in.

* [rug](https://crates.io/crates/rug). A fast wrapper around the [GMP library](https://gmplib.org/) with external dependencies, as described in the [gmp_mpfr_sys documentation](https://docs.rs/gmp-mpfr-sys/1.4.6/gmp_mpfr_sys/index.html#building-on-gnulinux). This is enabled with the `srp-fast-math` feature and disabling default features. So **instead** of the above do this:

```toml
[dependencies]
wow_srp = { version = "0.5", default-features = false, features = ["srp-fast-math", "wrath-header"] }
```

The `srp-fast-math` feature leads to a 50% decrease in total time. It is highly recommended to enable
this feature for production usage since it also theoretically has better security.

To see the performance difference on your setup you can run `cargo bench` for the default version,
and `cargo bench --features srp-fast-math --no-default-features` for the `srp-fast-math` version.

The `wrath-header` feature gates features and dependencies related to [`wrath-header`].

# MSRV

`wow_srp` has a Minimum Supported Rust Version (MSRV) of 1.57.0.
The MSRV may be increased in `PATCH` versions before `wow_srp` reaches `1.0.0` (`MAJOR.MINOR.PATCH`).

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

