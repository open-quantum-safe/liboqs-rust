# Rust binding to [Open Quantum Safe][oqs]'s [liboqs][]

This crate provides bindings to [liboqs][]. It provides unsafe `ffi` bindings in the `oqs-sys` crate.
Safe wrappers are offered via the `oqs` crate.


## Adding new algorithms

### KEMs:

1. Update the Git submodule
1. `oqs-sys` will now update when you build again
1. Add it to the ``implement_kems!`` macro call in ``oqs/src/kems.rs``

### Signature schemes:

1. Update the Git submodule
1. `oqs-sys` is now up-to-date when you build again
1. Add it to ``implement_sigs!`` macro call in ``oqs/src/sig.rs``.

[oqs]: https://openquantumsafe.org
[liboqs]: https://github.com/Open-Quantum-Safe/liboqs
