# Contributing

## Conventional commits

Please use the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) style when creating PRs.

## Adding new algorithms

### KEMs

1. Update the Git submodule
2. `oqs-sys` will now update when you build again
3. Add it to the `implement_kems!` macro call in `oqs/src/kem.rs`:

- The structure is a name for the algorithm in CamelCase, and the name of the constant of the algorithm (`OQS_KEM_alg_...`)

4. Add the necessary features to `Cargo.toml` and `oqs-sys/build.rs`.

### Signature schemes:

1. Update the Git submodule
2. `oqs-sys` is now up-to-date when you build again
3. Add it to `implement_sigs!` macro call in `oqs/src/sig.rs`.

- The structure is a name for the algorithm in CamelCase, and the name of the constant of the algorithm (`OQS_SIG_alg_...`)

4. Add the necessary features to `Cargo.toml` and `oqs-sys/build.rs`.
