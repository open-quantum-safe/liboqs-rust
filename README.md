# liboqs-rust: Rust bindings for liboqs

[![Build status](https://github.com/open-quantum-safe/liboqs-rust/workflows/Continuous%20integration/badge.svg)](https://github.com/open-quantum-safe/liboqs-rust/actions?query=workflow%3A"Continuous+integration")

| crate   | crates.io                                                                                  | docs.rs                                                                                           | License                                             |
| ------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| oqs-sys | [ ![crates.io](https://img.shields.io/crates/v/oqs-sys)](https://crates.io/crates/oqs-sys) | [![crates.io/docs](https://img.shields.io/docsrs/oqs-sys)](https://docs.rs/crate/oqs-sys/latest/) | ![License](https://img.shields.io/crates/l/oqs-sys) |
| oqs     | [![crates.io](https://img.shields.io/crates/v/oqs)](https://crates.io/crates/oqs)          | [![crates.io/docs](https://img.shields.io/docsrs/oqs)](https://docs.rs/crate/oqs/latest/)         | ![License](https://img.shields.io/crates/l/oqs)     |

**liboqs-rust** offers two Rust wrappers for the [Open Quantum Safe](https://openquantumsafe.org/) [liboqs](https://github.com/open-quantum-safe/liboqs/) C library, which is a C library for quantum-resistant cryptographic algorithms.

- The `oqs-sys` crate compiles and builds `liboqs` and generates `unsafe` bindings to the C library.
- The `oqs` crate offers a Rust-style safe interface to the schemes included in `liboqs`.

## Versioning

Releases up to and including release `0.9.0` of `oqs` and `oqs-sys` followed the `liboqs` versioning 1-on-1.
**Starting from release `0.9.0`, this is no longer guaranteed.**
These crates will now receive version bumps as necessary.
We will include the version number of `liboqs` that is distributed by `liboqs-sys` in the version number of `liboqs-sys`
as `0.9.0+liboqs-0.9.0`.

## Pre-requisites

`oqs-sys` depends on the [liboqs](https://github.com/open-quantum-safe/liboqs) C library.
It will build `liboqs` automatically with the default-enabled `vendored` feature.
See below for more information.

## Contents

This crate provides unsafe `ffi` bindings in the `oqs-sys` crate, and safe wrappers are offered via the `oqs` crate.
The rendered Rustdoc documentation can be [found here](https://open-quantum-safe.github.io/liboqs-rust/oqs/)

## Usage

Update your `Cargo.toml` and include `oqs`:

```toml
[dependencies]
oqs = "0.9.0"
```

`oqs-sys` can be specified equivalently.

## Minimal builds

The default-on `kems` and `sigs` features turn on all supported KEMs and signature schemes. If you want a smaller build, turn off these default features and opt-in to individual algorithms.
Note that if you specify `default-features = false`, you may also want to re-include the `oqs-sys/openssl` feature.

## Vendored `liboqs`

By default `oqs-sys` attempts to find a system-provided version of `liboqs` and build against it,
falling back to vendored from-source build otherwise.
You can opt into forcing the vendored build by enabling the `vendored` feature.

Otherwise, if you want to force using the system-provided `liboqs`,
you can set the `LIBOQS_NO_VENDOR=1` environment variable and the build will fail if the library is not found.

## Serde support

You can enable `serde` serialization support by enabling the `serde` feature on the `oqs` crate.

## `std` support

The `oqs-sys` crate does not use `std` at all.
Note that the default features do enable building `liboqs` with `openssl`, so use `default-features = false`.

To make `oqs` a `#![no_std]` crate make sure the `std` feature is disabled.
Make sure to also disable the `oqs-sys/openssl` feature by specifying `default-features = false`.

As `default-features` includes the `kems` and `sigs` features, consider re-adding them as well. This results into:

```toml
[dependencies.oqs]
version = "*"
default-features = false
features = ["sigs", "kems"]
```

You will probably want to change the random-number generator through the [`OQS_RAND` API][] offered by `oqs-sys`.

[`OQS_RAND` API]: https://open-quantum-safe.github.io/liboqs-rust/oqs_sys/rand/index.html

## `non_portable` feature

If compiled with the `non_portable` feature, `liboqs-sys` will not enable CPU feature detection and
always use the best implementation on your current platform. This enables support for implementations
where feature detection is not functional.

## Stack usage

Some algorithms use large amounts of stack space. This means that you may need
to specify `RUST_MIN_STACK` in your environment. This for example affects
tests.

## Algorithm features

- `kems` (default): Compile with all KEMs enabled
  - `bike`
  - `classic_mceliece`
  - `frodokem`
  - `hqc`
  - `kyber`
  - `ntruprime`
  - `saber`
- `sigs` (default): Compile with all signature schemes enabled
  - `dilithium`
  - `falcon`
  - `picnic`
  - `rainbow`
  - `sphincs`: SPHINCS<sup>+</sup>

## Running

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

## Limitations and security

liboqs is designed for prototyping and evaluating quantum-resistant cryptography. Security of proposed quantum-resistant algorithms may rapidly change as research advances, and may ultimately be completely insecure against either classical or quantum computers.

We believe that the NIST Post-Quantum Cryptography standardization project is currently the best avenue to identifying potentially quantum-resistant algorithms. liboqs does not intend to "pick winners", and we strongly recommend that applications and protocols rely on the outcomes of the NIST standardization project when deploying post-quantum cryptography.

We acknowledge that some parties may want to begin deploying post-quantum cryptography prior to the conclusion of the NIST standardization project. We strongly recommend that any attempts to do make use of so-called **hybrid cryptography**, in which post-quantum public-key algorithms are used alongside traditional public key algorithms (like RSA or elliptic curves) so that the solution is at least no less secure than existing traditional cryptography.

Just like liboqs, liboqs-rust is provided "as is", without warranty of any kind. See [LICENSE-MIT](https://github.com/open-quantum-safe/liboqs-rust/blob/main/LICENSE-MIT) for the full disclaimer.

## License

liboqs-rust is dual-licensed under the MIT and Apache-2.0 licenses.

The included library `liboqs` is covered by the [`liboqs` license](https://github.com/open-quantum-safe/liboqs/blob/main/LICENSE.txt).

## Team

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

liboqs-rust was developed by [Thom Wiggers](https://thomwiggers.nl) at Radboud University.

### Support

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Canadian Centre for Cyber Security.

We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, Cisco Systems, evolutionQ, IBM Research, and Microsoft Research.

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see the source papers for funding acknowledgments.

Thom Wiggers' contributions before May 2023 were supported by the European Research Council through Starting Grant No. 805031 (EPOQUE).
