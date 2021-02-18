# FFI Rust binding to [Open Quantum Safe][oqs]'s [liboqs][]

This crate provides the unsafe `ffi` bindings to [liboqs][].

## Features

* `openssl`: Compile with OpenSSL features (mostly symmetric cryptography)
* `minimal`: Only build OQS default KEM and Signature scheme
* `non_portable`: Don't build a portable library.

[oqs]: https://openquantumsafe.org
[liboqs]: https://github.com/Open-Quantum-Safe/liboqs
