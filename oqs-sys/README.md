# FFI Rust binding to [Open Quantum Safe][oqs]'s [liboqs][]

[![crates.io](https://img.shields.io/crates/v/oqs-sys)](https://crates.io/crates/oqs-sys)
[![crates.io/docs](https://img.shields.io/docsrs/oqs-sys)](https://docs.rs/oqs/0.7.1/oqs-sys/)

This crate provides the unsafe `ffi` bindings to [liboqs][].

## Features

* `openssl` (default): Compile with OpenSSL features (mostly symmetric cryptography)
* `non_portable`: Don't build a portable library.
* `kems` (default): Compile with all KEMs enabled
    * `bike`  (only on non-Windows)
    * `classic_mceliece`
    * `frodokem`
    * `hqc`
    * `kyber`
    * `ntru`
    * `ntruprime`
    * `saber`
    * `sidh`
    * `sike`
* `sigs` (default): Compile with all signature schemes enabled
    * `dilithium`
    * `falcon`
    * `picnic`
    * `rainbow`
    * `sphincs`: SPHINCS+

[oqs]: https://openquantumsafe.org
[liboqs]: https://github.com/Open-Quantum-Safe/liboqs
