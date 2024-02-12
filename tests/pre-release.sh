#!/usr/bin/env bash
set -e

export RUSTFLAGS="-D warnings"
export CARGO_INCREMENTAL=0

cargo install cargo-hack --locked

cargo hack test --feature-powerset
cargo hack clippy --feature-powerset

