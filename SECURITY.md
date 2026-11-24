# Security Policy

## Scope and support

liboqs-rust provides Rust bindings to liboqs through the
`oqs` and `oqs-sys` crates.

The security support scope and coordinated vulnerability
response procedures are defined by the
[OQS coordinated vulnerability disclosure process](https://github.com/open-quantum-safe/tsc/blob/main/security/response-process.md).

Security issues originating in liboqs are subject to the
[liboqs security policy](https://github.com/open-quantum-safe/liboqs/blob/main/SECURITY.md),
including its supported-version and threat-model provisions.

Vulnerabilities specific to the Rust bindings may be
addressed on a best-effort basis, consistent with the
scope of the OQS coordinated vulnerability disclosure
process.

## Dependency security

Users should consult the liboqs security policy when
selecting a liboqs version.

Build compatibility with a liboqs version does not imply
that the version receives upstream security support.

When using a bundled liboqs implementation, users should
verify the liboqs version included in their crate release.
When linking against a system-installed liboqs library,
users should ensure that the installed version is supported
under the upstream security policy.

## Reporting security issues

For vulnerabilities originating in liboqs, follow the
[upstream reporting instructions](https://github.com/open-quantum-safe/liboqs/blob/main/SECURITY.md).

For suspected serious vulnerabilities specific to
liboqs-rust, use the
[GitHub private vulnerability reporting form](https://github.com/open-quantum-safe/liboqs-rust/security/advisories/new).

Please do not disclose suspected non-public vulnerabilities
in public issues or pull requests.

Ordinary bugs, build failures, documentation issues, and
other non-sensitive problems may be reported through the
[public issue tracker](https://github.com/open-quantum-safe/liboqs-rust/issues).

## Coordinated security releases

Security-related releases of the Rust bindings are
coordinated in accordance with the
[OQS coordinated vulnerability disclosure process](https://github.com/open-quantum-safe/tsc/blob/main/security/response-process.md).

Please also review the upstream
[liboqs support limitations](https://github.com/open-quantum-safe/liboqs/blob/main/README.md#support-limitations).
