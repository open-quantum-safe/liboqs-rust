liboqs-rust: Rust bindings for liboqs
=====================================

[![Build status](https://github.com/dstebila/oqs-rs/workflows/Continuous%20integration/badge.svg)](https://github.com/dstebila/oqs-rs/actions?query=workflow%3A"Continuous+integration")

**liboqs-rust** offers two Rust wrappers for the [Open Quantum Safe](https://openquantumsafe.org/) [liboqs](https://github.com/open-quantum-safe/liboqs/) C library, which is a C library for quantum-resistant cryptographic algorithms.

Pre-requisites
--------------

liboqs-rust depends on the [liboqs](https://github.com/open-quantum-safe/liboqs) C library; liboqs must first be compiled as a Linux/macOS/Windows library (i.e. using `ninja install` with `-DBUILD_SHARED_LIBS=ON` during configuration), see the specific platform building instructions below.

<span style="color: red;">TODO: Check?</span>

Contents
--------

This crate provides unsafe `ffi` bindings in the `oqs-sys` crate, and safe wrappers are offered via the `oqs` crate.

Usage
-----

<span style="color: red;">TODO</span>

Running
-------

<span style="color: red;">TODO</span>

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

<span style="color: red;">TODO: Is this the correct license, Thom?</span>

liboqs-rust is licensed under the MIT License; see [LICENSE.txt](https://github.com/open-quantum-safe/liboqs-rust/blob/master/LICENSE.txt) for details.

Team
----

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

liboqs-rust was developed by [Thom Wiggers](https://thomwiggers.nl) at Radboud University.

### Support

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Tutte Institute for Mathematics and Computing.

We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, Cisco Systems, evolutionQ, IBM Research, and Microsoft Research.

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see the source papers for funding acknowledgments.

Thom Wiggers was supported by the European Research Council through Starting Grant No. 805031 (EPOQUE).
