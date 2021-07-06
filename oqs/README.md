# Bindings to Open-Quantum-Safe's [liboqs][]

This crate provides convenience wrappers to access the functionality provided by [liboqs][].
For the ``ffi`` interface bindings, see ``oqs-sys``.

[liboqs]: https://github.com/Open-Quantum-Safe/liboqs

## Features

* `no_std`: build without `std` support (probably want to disable the default
  features because they pull in OpenSSL through `oqs-sys`).
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