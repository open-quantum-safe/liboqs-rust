//! ML-DSA verification regressions for issue #320.
//!
//! Includes malformed signatures that previously passed verification
//! in affected optimized implementations, plus valid boundary cases.

#![cfg(feature = "ml_dsa")]

use oqs::sig::{Algorithm, Sig};

fn decode_hex(input: &str) -> Vec<u8> {
    let input = input.trim();
    assert_eq!(input.len() % 2, 0, "odd-length hexadecimal value");

    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(pair, 16).expect("valid hex")
        })
        .collect()
}

fn check_vectors(algorithm: Algorithm, vectors: &str) {
    oqs::init();

    let verifier = Sig::new(algorithm).expect("ML-DSA algorithm must be enabled");

    let mut checked = 0usize;
    let mut valid_cases = 0usize;
    let mut invalid_cases = 0usize;

    for line in vectors.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<_> = line.splitn(7, '|').collect();

        assert_eq!(fields.len(), 7, "unexpected vector format");

        let tcid = fields[0];
        let expected = match fields[1].trim() {
            "valid" => {
                valid_cases += 1;
                true
            }
            "invalid" => {
                invalid_cases += 1;
                false
            }
            other => panic!("unexpected expected result: {other}"),
        };

        let pk = decode_hex(fields[2]);
        let msg = decode_hex(fields[3]);
        let ctx = decode_hex(fields[4]);
        let signature = decode_hex(fields[5]);

        let accepted = match (
            verifier.public_key_from_bytes(&pk),
            verifier.signature_from_bytes(&signature),
        ) {
            (Some(pk), Some(signature)) if ctx.is_empty() => {
                verifier.verify(&msg, signature, pk).is_ok()
            }
            (Some(pk), Some(signature)) if ctx.len() <= 255 => verifier
                .verify_with_ctx_str(&msg, signature, &ctx, pk)
                .is_ok(),
            _ => false,
        };

        assert_eq!(
            accepted, expected,
            "{algorithm:?} tcId={tcid}: unexpected signature verification result"
        );

        checked += 1;
    }

    assert!(checked > 0, "no vectors processed");
    assert!(valid_cases > 0, "no valid cases tested");
    assert!(invalid_cases > 0, "no invalid cases tested");
}

#[test]
fn mldsa44_verification_regression() {
    check_vectors(
        Algorithm::MlDsa44,
        include_str!("fixtures/mldsa/mldsa_44.txt"),
    );
}

#[test]
fn mldsa65_verification_regression() {
    check_vectors(
        Algorithm::MlDsa65,
        include_str!("fixtures/mldsa/mldsa_65.txt"),
    );
}

#[test]
fn mldsa87_verification_regression() {
    check_vectors(
        Algorithm::MlDsa87,
        include_str!("fixtures/mldsa/mldsa_87.txt"),
    );
}
