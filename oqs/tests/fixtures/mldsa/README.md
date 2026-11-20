# ML-DSA verification regression vectors

These fixtures contain selected test cases from the C2SP
Wycheproof ML-DSA verification test vectors.

Source:
https://github.com/C2SP/wycheproof

Source revision:
65ca494727a5

Original files:
- testvectors_v1/mldsa_44_verify_test.json
- testvectors_v1/mldsa_65_verify_test.json
- testvectors_v1/mldsa_87_verify_test.json

The test cases were converted to a pipe-delimited text
format using the conversion script from:

https://github.com/RatioLabsEU/pqc-field-notes

Format:
tcId|result|publicKey|msg|ctx|sig|comment

Selected cases target signature verification regressions,
including infinity-norm violations, boundary conditions,
and valid signatures.

Original vectors: Copyright 2016-2026 The Wycheproof Authors.
Licensed under the Apache License, Version 2.0.
See https://github.com/C2SP/wycheproof/blob/main/LICENSE

These fixtures are modified, selected subsets of the original
Wycheproof JSON vectors, converted to pipe-delimited text.
Conversion script: RatioLabsEU/pqc-field-notes
(Apache-2.0, as identified in the reporter's script).
