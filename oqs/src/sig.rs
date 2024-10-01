//! Signature API
//!
//! See [`Sig`] for the main functionality and [`Algorithm`]
//! for the list of supported algorithms.
use alloc::vec::Vec;

use core::ptr::NonNull;
use core::str::FromStr;

#[cfg(not(feature = "std"))]
use cstr_core::CStr;
#[cfg(feature = "std")]
use std::ffi::CStr;

use crate::ffi::sig as ffi;
use crate::newtype_buffer;
use crate::*;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

newtype_buffer!(PublicKey, PublicKeyRef);
newtype_buffer!(SecretKey, SecretKeyRef);
newtype_buffer!(Signature, SignatureRef);

/// Message type
pub type Message = [u8];

macro_rules! implement_sigs {
    { $(($feat: literal) $sig: ident: $oqs_id: ident: $str_name: literal),* $(,)? } => (
        /// Supported algorithms by liboqs
        ///
        /// They may not all be enabled
        ///
        /// Optional support for `serde` if that feature is enabled.
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[allow(missing_docs)]
        pub enum Algorithm {
            $(
                $sig,
            )*
        }

        fn algorithm_to_id(algorithm: Algorithm) -> *const libc::c_char {
            let id: &[u8] = match algorithm {
                $(
                    Algorithm::$sig => &ffi::$oqs_id[..],
                )*
            };
            id as *const _ as *const libc::c_char
        }

        impl FromStr for Algorithm {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self> {
                match s {
                    $(
                        $str_name => Ok(Algorithm::$sig),
                    )*
                    _ => Err(Error::AlgorithmNotSupportedOrKnown),
                }
            }
        }

        $(
            #[cfg(test)]
            #[allow(non_snake_case)]
            mod $sig {
                use super::*;

                #[test]
                #[cfg(feature = $feat)]
                fn test_signing() -> Result<()> {
                    crate::init();
                    let message = [0u8; 100];
                    let sig = Sig::new(Algorithm::$sig)?;
                    let (pk, sk) = sig.keypair()?;
                    let signature = sig.sign(&message, &sk)?;
                    sig.verify(&message, &signature, &pk)
                }

                #[test]
                fn test_enabled() {
                    crate::init();
                    if cfg!(feature = $feat) {
                        assert!(Algorithm::$sig.is_enabled());
                    } else {
                        assert!(!Algorithm::$sig.is_enabled())
                    }
                }

                #[test]
                fn test_name() {
                    let algo = Algorithm::$sig;
                    // Just make sure the name impl does not panic or crash.
                    let name = algo.name();

                    #[cfg(feature = "std")]
                    assert_eq!(name, algo.to_string());

                    // ... And actually contains something.
                    assert!(!name.is_empty());
                }

                #[test]
                fn test_get_algorithm_back() {
                    let algorithm = Algorithm::$sig;
                    if algorithm.is_enabled() {
                        let sig = Sig::new(algorithm).unwrap();
                        assert_eq!(algorithm, sig.algorithm());
                    }
                }

                #[test]
                fn test_version() {
                    if let Ok(sig) = Sig::new(Algorithm::$sig) {
                        // Just make sure the version can be called without panic
                        let version = sig.version();
                        // ... And actually contains something.
                        assert!(!version.is_empty());
                    }
                }


                #[test]
                fn test_from_str() {
                    let algo = Algorithm::$sig;
                    let name = algo.to_string();
                    let res = name.parse::<Algorithm>();
                    if res.is_err() {
                        eprintln!("Failed to parse: {}", name);
                    }
                    let algo2 = res.unwrap();
                    assert_eq!(algo, algo2);
                }
            }
        )*
    )
}

// List of supported Sig algorithms found in liboqs/src/sig/sig.h
implement_sigs! {
    ("dilithium") Dilithium2: OQS_SIG_alg_dilithium_2: "Dilithium2",
    ("dilithium") Dilithium3: OQS_SIG_alg_dilithium_3: "Dilithium3",
    ("dilithium") Dilithium5: OQS_SIG_alg_dilithium_5: "Dilithium5",
    ("falcon") Falcon512: OQS_SIG_alg_falcon_512: "Falcon-512",
    ("falcon") Falcon1024: OQS_SIG_alg_falcon_1024: "Falcon-1024",
    ("falcon") FalconPadded512: OQS_SIG_alg_falcon_padded_512: "Falcon-padded-512",
    ("falcon") FalconPadded1024: OQS_SIG_alg_falcon_padded_1024: "Falcon-padded-1024",
    ("sphincs") SphincsSha2128fSimple: OQS_SIG_alg_sphincs_sha2_128f_simple: "SPHINCS+-SHA2-128f-simple",
    ("sphincs") SphincsSha2128sSimple: OQS_SIG_alg_sphincs_sha2_128s_simple: "SPHINCS+-SHA2-128s-simple",
    ("sphincs") SphincsSha2192fSimple: OQS_SIG_alg_sphincs_sha2_192f_simple: "SPHINCS+-SHA2-192f-simple",
    ("sphincs") SphincsSha2192sSimple: OQS_SIG_alg_sphincs_sha2_192s_simple: "SPHINCS+-SHA2-192s-simple",
    ("sphincs") SphincsSha2256fSimple: OQS_SIG_alg_sphincs_sha2_256f_simple: "SPHINCS+-SHA2-256f-simple",
    ("sphincs") SphincsSha2256sSimple: OQS_SIG_alg_sphincs_sha2_256s_simple: "SPHINCS+-SHA2-256s-simple",
    ("sphincs") SphincsShake128fSimple: OQS_SIG_alg_sphincs_shake_128f_simple: "SPHINCS+-SHAKE-128f-simple",
    ("sphincs") SphincsShake128sSimple: OQS_SIG_alg_sphincs_shake_128s_simple: "SPHINCS+-SHAKE-128s-simple",
    ("sphincs") SphincsShake192fSimple: OQS_SIG_alg_sphincs_shake_192f_simple: "SPHINCS+-SHAKE-192f-simple",
    ("sphincs") SphincsShake192sSimple: OQS_SIG_alg_sphincs_shake_192s_simple: "SPHINCS+-SHAKE-192s-simple",
    ("sphincs") SphincsShake256fSimple: OQS_SIG_alg_sphincs_shake_256f_simple: "SPHINCS+-SHAKE-256f-simple",
    ("sphincs") SphincsShake256sSimple: OQS_SIG_alg_sphincs_shake_256s_simple: "SPHINCS+-SHAKE-256s-simple",
    ("ml_dsa") MlDsa44Ipd: OQS_SIG_alg_ml_dsa_44_ipd: "ML-DSA-44-ipd",
    ("ml_dsa") MlDsa65Ipd: OQS_SIG_alg_ml_dsa_65_ipd: "ML-DSA-65-ipd",
    ("ml_dsa") MlDsa87Ipd: OQS_SIG_alg_ml_dsa_87_ipd: "ML-DSA-87-ipd",
    ("ml_dsa") MlDsa44: OQS_SIG_alg_ml_dsa_44: "ML-DSA-44",
    ("ml_dsa") MlDsa65: OQS_SIG_alg_ml_dsa_65: "ML-DSA-65",
    ("ml_dsa") MlDsa87: OQS_SIG_alg_ml_dsa_87: "ML-DSA-87",
    ("mayo") Mayo1: OQS_SIG_alg_mayo_1: "MAYO-1",
    ("mayo") Mayo2: OQS_SIG_alg_mayo_2: "MAYO-2",
    ("mayo") Mayo3: OQS_SIG_alg_mayo_3: "MAYO-3",
    ("mayo") Mayo5: OQS_SIG_alg_mayo_5: "MAYO-5",
    ("cross") CrossRsdp128Balanced: OQS_SIG_alg_cross_rsdp_128_balanced: "cross-rsdp-128-balanced",
    ("cross") CrossRspd128Fast: OQS_SIG_alg_cross_rsdp_128_fast: "cross-rsdp-128-fast",
    ("cross") CrossRspd128Small: OQS_SIG_alg_cross_rsdp_128_small: "cross-rsdp-128-small",
    ("cross") CrossRspd192Balanced: OQS_SIG_alg_cross_rsdp_192_balanced: "cross-rsdp-192-balanced",
    ("cross") CrossRspd192Fast: OQS_SIG_alg_cross_rsdp_192_fast: "cross-rsdp-192-fast",
    ("cross") CrossRspd192Small: OQS_SIG_alg_cross_rsdp_192_small: "cross-rsdp-192-small",
    ("cross") CrossRspd256Balanced: OQS_SIG_alg_cross_rsdp_256_balanced: "cross-rsdp-256-balanced",
    ("cross") CrossRspd256Fast: OQS_SIG_alg_cross_rsdp_256_fast: "cross-rsdp-256-fast",
    ("cross") CrossRspd256Small: OQS_SIG_alg_cross_rsdp_256_small: "cross-rsdp-256-small",
    ("cross") CrossRspdg128Balanced: OQS_SIG_alg_cross_rsdpg_128_balanced: "cross-rsdpg-128-balanced",
    ("cross") CrossRspdg128Fast: OQS_SIG_alg_cross_rsdpg_128_fast: "cross-rsdpg-128-fast",
    ("cross") CrossRspdg128Small: OQS_SIG_alg_cross_rsdpg_128_small: "cross-rsdpg-128-small",
    ("cross") CrossRspdg192Balanced: OQS_SIG_alg_cross_rsdpg_192_balanced: "cross-rsdpg-192-balanced",
    ("cross") CrossRspdg192Fast: OQS_SIG_alg_cross_rsdpg_192_fast: "cross-rsdpg-192-fast",
    ("cross") CrossRspdg192Small: OQS_SIG_alg_cross_rsdpg_192_small: "cross-rsdpg-192-small",
    ("cross") CrossRspdg256Balanced: OQS_SIG_alg_cross_rsdpg_256_balanced: "cross-rsdpg-256-balanced",
    ("cross") CrossRspdg256Fast: OQS_SIG_alg_cross_rsdpg_256_fast: "cross-rsdpg-256-fast",
    ("cross") CrossRspdg256Small: OQS_SIG_alg_cross_rsdpg_256_small: "cross-rsdpg-256-small",
}

impl Algorithm {
    /// Returns true if this algorithm is enabled in the linked version
    /// of liboqs
    pub fn is_enabled(self) -> bool {
        unsafe { ffi::OQS_SIG_alg_is_enabled(algorithm_to_id(self)) == 1 }
    }

    /// Provides a pointer to the id of the algorithm
    ///
    /// For use with the FFI api methods
    pub fn to_id(self) -> *const libc::c_char {
        algorithm_to_id(self)
    }

    /// Returns the algorithm's name as a static Rust string.
    ///
    /// This is the same as the `to_id`, but as a safe Rust string.
    pub fn name(&self) -> &'static str {
        // SAFETY: The id from ffi must be a proper null terminated C string
        let id = unsafe { CStr::from_ptr(self.to_id()) };
        id.to_str().expect("OQS algorithm names must be UTF-8")
    }
}

/// Signature scheme
///
/// # Example
/// ```rust
/// # if !cfg!(feature = "dilithium") { return; }
/// use oqs;
/// oqs::init();
/// let scheme = oqs::sig::Sig::new(oqs::sig::Algorithm::Dilithium2).unwrap();
/// let message = [0u8; 100];
/// let (pk, sk) = scheme.keypair().unwrap();
/// let signature = scheme.sign(&message, &sk).unwrap();
/// assert!(scheme.verify(&message, &signature, &pk).is_ok());
/// ```
pub struct Sig {
    algorithm: Algorithm,
    sig: NonNull<ffi::OQS_SIG>,
}

impl Debug for Sig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sig")
            .field("algorithm", &self.algorithm)
            .field(
                "method_name",
                &unsafe { CStr::from_ptr(self.sig.as_ref().method_name) }
                    .to_str()
                    .expect("method name"),
            )
            .field(
                "alg_version",
                &unsafe { CStr::from_ptr(self.sig.as_ref().alg_version) }
                    .to_str()
                    .expect("alg_version"),
            )
            .field(
                "claimed_nist_level",
                &unsafe { self.sig.as_ref() }.claimed_nist_level,
            )
            .field("euf_cma", &unsafe { self.sig.as_ref() }.euf_cma)
            .field(
                "length_public_key",
                &unsafe { self.sig.as_ref() }.length_public_key,
            )
            .field(
                "length_secret_key",
                &unsafe { self.sig.as_ref() }.length_secret_key,
            )
            .field(
                "length_signature",
                &unsafe { self.sig.as_ref() }.length_signature,
            )
            .finish()
    }
}

unsafe impl Sync for Sig {}
unsafe impl Send for Sig {}

impl Drop for Sig {
    fn drop(&mut self) {
        unsafe { ffi::OQS_SIG_free(self.sig.as_ptr()) };
    }
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self.name(), f)
    }
}

impl TryFrom<Algorithm> for Sig {
    type Error = Error;
    fn try_from(alg: Algorithm) -> Result<Sig> {
        Sig::new(alg)
    }
}

impl Sig {
    /// Construct a new algorithm
    ///
    /// May fail if the algorithm is not available
    pub fn new(algorithm: Algorithm) -> Result<Self> {
        let sig = unsafe { ffi::OQS_SIG_new(algorithm_to_id(algorithm)) };
        NonNull::new(sig).map_or_else(
            || Err(Error::AlgorithmDisabled),
            |sig| Ok(Self { algorithm, sig }),
        )
    }

    /// Get the algorithm used by this `Sig`
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Get the version of the implementation
    pub fn version(&self) -> &'static str {
        let sig = unsafe { self.sig.as_ref() };
        // SAFETY: The alg_version from ffi must be a proper null terminated C string
        let cstr = unsafe { CStr::from_ptr(sig.alg_version) };
        cstr.to_str()
            .expect("Algorithm version strings must be UTF-8")
    }

    /// Obtain the claimed nist level
    pub fn claimed_nist_level(&self) -> u8 {
        let sig = unsafe { self.sig.as_ref() };
        sig.claimed_nist_level
    }

    /// Is this algorithm EUF-CMA?
    pub fn is_euf_cma(&self) -> bool {
        let sig = unsafe { self.sig.as_ref() };
        sig.euf_cma
    }

    /// Length of the public key
    pub fn length_public_key(&self) -> usize {
        let sig = unsafe { self.sig.as_ref() };
        sig.length_public_key
    }

    /// Length of the secret key
    pub fn length_secret_key(&self) -> usize {
        let sig = unsafe { self.sig.as_ref() };
        sig.length_secret_key
    }

    /// Maximum length of a signature
    pub fn length_signature(&self) -> usize {
        let sig = unsafe { self.sig.as_ref() };
        sig.length_signature
    }

    /// Construct a secret key object from bytes
    pub fn secret_key_from_bytes<'a>(&self, buf: &'a [u8]) -> Option<SecretKeyRef<'a>> {
        if buf.len() != self.length_secret_key() {
            None
        } else {
            Some(SecretKeyRef::new(buf))
        }
    }

    /// Construct a public key object from bytes
    pub fn public_key_from_bytes<'a>(&self, buf: &'a [u8]) -> Option<PublicKeyRef<'a>> {
        if buf.len() != self.length_public_key() {
            None
        } else {
            Some(PublicKeyRef::new(buf))
        }
    }

    /// Construct a signature object from bytes
    pub fn signature_from_bytes<'a>(&self, buf: &'a [u8]) -> Option<SignatureRef<'a>> {
        if buf.len() > self.length_signature() {
            None
        } else {
            Some(SignatureRef::new(buf))
        }
    }

    /// Generate a new keypair
    pub fn keypair(&self) -> Result<(PublicKey, SecretKey)> {
        let sig = unsafe { self.sig.as_ref() };
        let func = sig.keypair.expect("keypair function not available");
        let mut pk = PublicKey {
            bytes: Vec::with_capacity(sig.length_public_key),
        };
        let mut sk = SecretKey {
            bytes: Vec::with_capacity(sig.length_secret_key),
        };
        let status = unsafe { func(pk.bytes.as_mut_ptr(), sk.bytes.as_mut_ptr()) };
        // update the lengths of the vecs
        unsafe {
            pk.bytes.set_len(sig.length_public_key);
            sk.bytes.set_len(sig.length_secret_key);
        }
        status_to_result(status)?;
        Ok((pk, sk))
    }

    /// Sign a message
    pub fn sign<'a, S: Into<SecretKeyRef<'a>>>(
        &self,
        message: &Message,
        sk: S,
    ) -> Result<Signature> {
        let sk = sk.into();
        let sig = unsafe { self.sig.as_ref() };
        let func = sig.sign.expect("sign function not available");
        let mut sig = Signature {
            bytes: Vec::with_capacity(sig.length_signature),
        };
        let mut sig_len = 0;
        let status = unsafe {
            func(
                sig.bytes.as_mut_ptr(),
                &mut sig_len,
                message.as_ptr(),
                message.len(),
                sk.bytes.as_ptr(),
            )
        };
        status_to_result(status)?;
        // This is safe to do as it's initialised now.
        unsafe {
            sig.bytes.set_len(sig_len);
        }
        Ok(sig)
    }

    /// Verify a message
    pub fn verify<'a, 'b>(
        &self,
        message: &Message,
        signature: impl Into<SignatureRef<'a>>,
        pk: impl Into<PublicKeyRef<'b>>,
    ) -> Result<()> {
        let signature = signature.into();
        let pk = pk.into();
        if signature.bytes.len() > self.length_signature()
            || pk.bytes.len() != self.length_public_key()
        {
            return Err(Error::InvalidLength);
        }
        let sig = unsafe { self.sig.as_ref() };
        let func = sig.verify.expect("verify function not available");
        let status = unsafe {
            func(
                message.as_ptr(),
                message.len(),
                signature.bytes.as_ptr(),
                signature.len(),
                pk.bytes.as_ptr(),
            )
        };
        status_to_result(status)
    }
}
