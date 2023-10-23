# Bindings to Open-Quantum-Safe's [liboqs][]

[![crates.io](https://img.shields.io/crates/v/oqs)](https://crates.io/crates/oqs)
[![crates.io/docs](https://img.shields.io/docsrs/oqs)](https://docs.rs/oqs/0.7.1/oqs/)

This crate provides convenience wrappers to access the functionality provided by [liboqs][].
For the ``ffi`` interface bindings, see ``oqs-sys``.

[liboqs]: https://github.com/Open-Quantum-Safe/liboqs

## Features

* `std`: (default) build with `std` support. This adds handly `Display` and `Error` implementations
  to relevant types. If you want a `#![no_std]` library, disable this feature (and you
  probably want to disable the default features because they pull in OpenSSL through `oqs-sys`).
* `non_portable`: Don't build a portable library.
* `vendored`: (default) Controls the `oqs-sys/vendored` feature which enables building the included version of liboqs.
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
