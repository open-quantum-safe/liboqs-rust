# FFI Rust binding to [Open Quantum Safe][oqs]'s [liboqs][]

[![crates.io](https://img.shields.io/crates/v/oqs-sys)](https://crates.io/crates/oqs-sys)
[![crates.io/docs](https://img.shields.io/docsrs/oqs-sys)](https://docs.rs/oqs/latest/oqs-sys/)

This crate provides the unsafe `ffi` bindings to [liboqs][].

## Features

* `vendored` (default): Compile the included version of liboqs instead of linking to the system version.
* `openssl` (default): Compile with OpenSSL features (mostly symmetric cryptography)
* `non_portable`: Don't build a portable library.
* `kems` (default): Compile with all KEMs enabled
    * `bike`  (only on non-Windows)
    * `classic_mceliece`
    * `frodokem`
    * `hqc`
    * `kyber`
    * `ml_kem`
    * `ntruprime`
* `sigs` (default): Compile with all signature schemes enabled
    * `cross`
    * `dilithium`
    * `falcon`
    * `mayo`
    * `ml_dsa`
    * `slh_dsa`: SPHINCS+
    * `uov`

[oqs]: https://openquantumsafe.org
[liboqs]: https://github.com/Open-Quantum-Safe/liboqs

## Reproducible builds

Set `OQS_REPRODUCIBLE_BUILD=1` to enable reproducibility settings
when building the vendored liboqs library.

On macOS, this sets `ZERO_AR_DATE=1` for the native CMake build and
enables C compiler source-path remapping. On Linux, it enables
C compiler source-path remapping.

The setting does not configure Rust compiler path remapping.
For reproducible Rust artifacts, configure it separately:

    export OQS_REPRODUCIBLE_BUILD=1
    export CARGO_INCREMENTAL=0
    export RUSTFLAGS="--remap-path-prefix=$(pwd -P)=/src"

    cargo build --release --locked -p oqs --features vendored

Use identical Rust and native toolchains, dependency versions,
features, SDKs, external libraries, and build profiles.

This option applies only when building the vendored liboqs source.
It does not affect an installed system liboqs library.

Reproducibility has been verified on macOS ARM64 using independent
source directories and matching build inputs. Reproducibility across
different platforms or toolchain versions is not guaranteed.
