liboqs-rust: Rust bindings for liboqs
=====================================

[![Build status](https://github.com/open-quantum-safe/liboqs-rust/workflows/Continuous%20integration/badge.svg)](https://github.com/open-quantum-safe/liboqs-rust/actions?query=workflow%3A"Continuous+integration")

**liboqs-rust** offers two Rust wrappers for the [Open Quantum Safe](https://openquantumsafe.org/) [liboqs](https://github.com/open-quantum-safe/liboqs/) C library, which is a C library for quantum-resistant cryptographic algorithms.

* The ``oqs-rs`` crate compiles and builds ``liboqs`` and generates ``unsafe`` bindings to the C library.
* The ``oqs`` crate offers a Rust-style safe interface to the schemes included in ``liboqs``.

Pre-requisites
--------------

``oqs-sys`` depends on the [liboqs](https://github.com/open-quantum-safe/liboqs) C library.
It will build ``liboqs`` automatically.

Contents
--------

This crate provides unsafe `ffi` bindings in the `oqs-sys` crate, and safe wrappers are offered via the `oqs` crate.
The rendered rustdoc documentation can be [found here](https://open-quantum-safe.github.io/liboqs-rust/oqs/)

Usage
-----

Update your ``Cargo.toml`` and include ``oqs``:

```toml
[dependencies]
oqs = "0.2"
```

``oqs-sys`` can be specified equivalently.

Running
-------

```rust
/// # Example: Some signed KEX
/// This protocol has no replay protection!
///
use oqs::*;
fn main() -> Result<()> {
    let sigalg = sig::Sig::new(sig::Algorithm::Dilithium2)?;
    let kemalg = kem::Kem::new(kem::Algorithm::Kyber512)?;
    // A's long-term secrets
    let (a_sig_pk, a_sig_sk) = sigalg.keypair()?;
    // B's long-term secrets
    let (b_sig_pk, b_sig_sk) = sigalg.keypair()?;

    // assumption: A has (a_sig_sk, a_sig_pk, b_sig_pk)
    // assumption: B has (b_sig_sk, b_sig_pk, a_sig_pk)

    // A -> B: kem_pk, signature
    let (kem_pk, kem_sk) = kemalg.keypair()?;
    let signature = sigalg.sign(kem_pk.as_ref(), &a_sig_sk)?;

    // B -> A: kem_ct, signature
    sigalg.verify(kem_pk.as_ref(), &signature, &a_sig_pk)?;
    let (kem_ct, b_kem_ss) = kemalg.encapsulate(&kem_pk)?;
    let signature = sigalg.sign(kem_ct.as_ref(), &b_sig_sk)?;

    // A verifies, decapsulates, now both have kem_ss
    sigalg.verify(kem_ct.as_ref(), &signature, &b_sig_pk)?;
    let a_kem_ss = kemalg.decapsulate(&kem_sk, &kem_ct)?;
    assert_eq!(a_kem_ss, b_kem_ss);

    Ok(())
}
```


Adding new algorithms
---------------------

### KEMs

1. Update the Git submodule
2. `oqs-sys` will now update when you build again
3. Add it to the ``implement_kems!`` macro call in ``oqs/src/kem.rs``:
  - The structure is a name for the algorithm in CamelCase, and the name of the constant of the algorithm (``OQS_KEM_alg_...``)

### Signature schemes:

1. Update the Git submodule
2. `oqs-sys` is now up-to-date when you build again
3. Add it to ``implement_sigs!`` macro call in ``oqs/src/sig.rs``.
  - The structure is a name for the algorithm in CamelCase, and the name of the constant of the algorithm (``OQS_SIG_alg_...``)

Limitations and security
------------------------

liboqs is designed for prototyping and evaluating quantum-resistant cryptography. Security of proposed quantum-resistant algorithms may rapidly change as research advances, and may ultimately be completely insecure against either classical or quantum computers.

We believe that the NIST Post-Quantum Cryptography standardization project is currently the best avenue to identifying potentially quantum-resistant algorithms. liboqs does not intend to "pick winners", and we strongly recommend that applications and protocols rely on the outcomes of the NIST standardization project when deploying post-quantum cryptography.

We acknowledge that some parties may want to begin deploying post-quantum cryptography prior to the conclusion of the NIST standardization project. We strongly recommend that any attempts to do make use of so-called **hybrid cryptography**, in which post-quantum public-key algorithms are used alongside traditional public key algorithms (like RSA or elliptic curves) so that the solution is at least no less secure than existing traditional cryptography.

Just like liboqs, liboqs-rust is provided "as is", without warranty of any kind. See [LICENSE.txt](https://github.com/open-quantum-safe/liboqs-rust/blob/master/LICENSE.txt) for the full disclaimer.

License
-------

liboqs-rust is dual-licensed under the MIT and Apache-2.0 licenses.

The included library ``liboqs`` is covered by the [``liboqs`` license](https://github.com/open-quantum-safe/liboqs/blob/master/LICENSE.txt).

Team
----

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

liboqs-rust was developed by [Thom Wiggers](https://thomwiggers.nl) at Radboud University.

### Support

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Tutte Institute for Mathematics and Computing.

We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, Cisco Systems, evolutionQ, IBM Research, and Microsoft Research.

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see the source papers for funding acknowledgments.

Thom Wiggers was supported by the European Research Council through Starting Grant No. 805031 (EPOQUE).
