# FFI Rust binding to [Open Quantum Safe][oqs]'s [liboqs][]

[![crates.io](https://img.shields.io/crates/v/oqs-sys)](https://crates.io/crates/oqs-sys)
[![crates.io/docs](https://img.shields.io/docsrs/oqs-sys)](https://docs.rs/oqs/latest/oqs-sys/)

This crate provides the unsafe `ffi` bindings to [liboqs][].

## Features

* `vendored` (default): Compile the included version of liboqs instead of linking to the system version.
* `openssl` (default): Compile with OpenSSL features (mostly symmetric cryptography)
* `vendored_openssl`: Use vendored OpenSSL (includes `openssl` feature)
* `no_openssl`: Force disable OpenSSL on all platforms
* `non_portable`: Don't build a portable library.
* `kems` (default): Compile with all KEMs enabled
    * `bike`  (only on non-Windows)
    * `classic_mceliece`
    * `frodokem`
    * `hqc`
    * `kyber`
    * `ml_kem`
    * `ntruprime`
* `sigs` (default): Compile with all signature schemes enabled
    * `cross`
    * `dilithium`
    * `falcon`
    * `mayo`
    * `ml_dsa`
    * `sphincs`: SPHINCS+
    * `uov`

## Platform-Specific Behavior

### iOS Support
iOS builds automatically disable OpenSSL by default to avoid compilation issues. The crate will:
- Automatically set `OQS_USE_OPENSSL=OFF` when building for iOS targets
- Link against iOS system frameworks (`Security.framework`) for cryptographic functions
- Use system random number generation instead of OpenSSL

### Other Platforms
- **macOS/Linux**: OpenSSL enabled by default (can be overridden)
- **Windows**: OpenSSL enabled by default (vendored OpenSSL recommended)
- **Android**: Follows same behavior as Linux

## Environment Variables

You can override the OpenSSL configuration using environment variables:

- `OQS_USE_OPENSSL=OFF` or `OQS_USE_OPENSSL=NO`: Force disable OpenSSL
- `OQS_USE_OPENSSL=ON` or `OQS_USE_OPENSSL=YES`: Force enable OpenSSL

These environment variables take precedence over feature flags and platform defaults.

## Examples

### Building for iOS without OpenSSL
```bash
# iOS builds automatically disable OpenSSL
cargo build --target aarch64-apple-ios

# Or explicitly disable OpenSSL
cargo build --target aarch64-apple-ios --features no_openssl
```

### Building without OpenSSL on any platform
```bash
cargo build --features no_openssl
# or
OQS_USE_OPENSSL=OFF cargo build
```

### Building with vendored OpenSSL
```bash
cargo build --features vendored_openssl
```

[oqs]: https://openquantumsafe.org
[liboqs]: https://github.com/Open-Quantum-Safe/liboqs
