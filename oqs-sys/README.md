# FFI Rust binding to [Open Quantum Safe][oqs]'s [liboqs][]

This crate provides the unsafe `ffi` bindings to [liboqs][].

## Features

* `openssl` (default): Compile with OpenSSL features (mostly symmetric cryptography)
* `non_portable`: Don't build a portable library.
* `kems` (default): Compile with all KEMs enabled
    * `bike`
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
