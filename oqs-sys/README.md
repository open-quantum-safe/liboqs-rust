# FFI Rust binding to [Open Quantum Safe][oqs]'s [liboqs][]

[![crates.io](https://img.shields.io/crates/v/oqs-sys)](https://crates.io/crates/oqs-sys)
[![crates.io/docs](https://img.shields.io/docsrs/oqs-sys)](https://docs.rs/oqs/0.7.1/oqs-sys/)

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
    * `ntruprime`
* `sigs` (default): Compile with all signature schemes enabled
    * `dilithium`
    * `falcon`
    * `sphincs`: SPHINCS+

[oqs]: https://openquantumsafe.org
[liboqs]: https://github.com/Open-Quantum-Safe/liboqs
