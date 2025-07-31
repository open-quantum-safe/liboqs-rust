//! Signature API
//!
//! See [`Sig`] for the main functionality and [`Algorithm`]
//! for the list of supported algorithms.
use alloc::vec::Vec;

use core::ptr::{null, NonNull};
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
/// Context string type
pub type CtxStr = [u8];

macro_rules! implement_sigs {
    { $(($feat: literal) $sig: ident: $oqs_id: ident),* $(,)? } => (
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
            type Err = crate::Error;

            fn from_str(s: &str) -> Result<Self> {
                $(
                    if s == Algorithm::$sig.name() {
                        return Ok(Algorithm::$sig);
                    }
                )*
                Err(crate::Error::AlgorithmParsingError)
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
                #[cfg(feature = $feat)]
                fn test_signing_with_empty_context_string() -> Result<()> {
                    crate::init();
                    let message = [0u8; 100];
                    let ctx_str: [u8; 0] = [];
                    let sig = Sig::new(Algorithm::$sig)?;
                    let (pk, sk) = sig.keypair()?;
                    let signature = sig.sign_with_ctx_str(&message, &ctx_str, &sk)?;
                    sig.verify_with_ctx_str(&message, &signature, &ctx_str, &pk)
                }

                #[test]
                #[cfg(feature = $feat)]
                fn test_signing_with_nonempty_context_string() -> Result<()> {
                    crate::init();
                    let message = [0u8; 100];
                    let ctx_str = [0u8; 100];
                    let sig = Sig::new(Algorithm::$sig)?;
                    let (pk, sk) = sig.keypair()?;
                    if sig.has_ctx_str_support() {
                        let signature = sig.sign_with_ctx_str(&message, &ctx_str, &sk)?;
                        sig.verify_with_ctx_str(&message, &signature, &ctx_str, &pk)
                    } else {
                        let sig_result = sig.sign_with_ctx_str(&message, &ctx_str, &sk);
                        // Expect a generic error
                        let sig_result: Result<()> = match sig_result {
                            Err(Error::Error) => Ok(()),
                            Ok(_) => Err(Error::Error),
                            Err(e) => Err(e)
                        };
                        if sig_result.is_ok() {
                            // get a valid signature with which to test verify
                            let signature = sig.sign(&message, &sk)?;
                            // Expect a generic error
                            match sig.verify_with_ctx_str(&message, &signature, &ctx_str, &pk) {
                                Err(Error::Error) => Ok(()),
                                Ok(_) => Err(Error::Error),
                                Err(e) => Err(e)

                            }
                        } else {
                            sig_result
                        }
                    }
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
                    let algorithm = Algorithm::$sig;
                    let name = algorithm.name();
                    let parsed = Algorithm::from_str(name).unwrap();
                    assert_eq!(algorithm, parsed);}
            }
        )*
    )
}

implement_sigs! {
    ("cross") CrossRsdp128Balanced: OQS_SIG_alg_cross_rsdp_128_balanced,
    ("cross") CrossRsdp128Fast: OQS_SIG_alg_cross_rsdp_128_fast,
    ("cross") CrossRsdp128Small: OQS_SIG_alg_cross_rsdp_128_small,
    ("cross") CrossRsdp192Balanced: OQS_SIG_alg_cross_rsdp_192_balanced,
    ("cross") CrossRsdp192Fast: OQS_SIG_alg_cross_rsdp_192_fast,
    ("cross") CrossRsdp192Small: OQS_SIG_alg_cross_rsdp_192_small,
    ("cross") CrossRsdp256Balanced: OQS_SIG_alg_cross_rsdp_256_balanced,
    ("cross") CrossRsdp256Fast: OQS_SIG_alg_cross_rsdp_256_fast,
    ("cross") CrossRsdp256Small: OQS_SIG_alg_cross_rsdp_256_small,
    ("cross") CrossRsdpg128Balanced: OQS_SIG_alg_cross_rsdpg_128_balanced,
    ("cross") CrossRsdpg128Fast: OQS_SIG_alg_cross_rsdpg_128_fast,
    ("cross") CrossRsdpg128Small: OQS_SIG_alg_cross_rsdpg_128_small,
    ("cross") CrossRsdpg192Balanced: OQS_SIG_alg_cross_rsdpg_192_balanced,
    ("cross") CrossRsdpg192Fast: OQS_SIG_alg_cross_rsdpg_192_fast,
    ("cross") CrossRsdpg192Small: OQS_SIG_alg_cross_rsdpg_192_small,
    ("cross") CrossRsdpg256Balanced: OQS_SIG_alg_cross_rsdpg_256_balanced,
    ("cross") CrossRsdpg256Fast: OQS_SIG_alg_cross_rsdpg_256_fast,
    ("cross") CrossRsdpg256Small: OQS_SIG_alg_cross_rsdpg_256_small,
    ("dilithium") Dilithium2: OQS_SIG_alg_dilithium_2,
    ("dilithium") Dilithium3: OQS_SIG_alg_dilithium_3,
    ("dilithium") Dilithium5: OQS_SIG_alg_dilithium_5,
    ("falcon") Falcon512: OQS_SIG_alg_falcon_512,
    ("falcon") Falcon1024: OQS_SIG_alg_falcon_1024,
    ("mayo") Mayo1: OQS_SIG_alg_mayo_1,
    ("mayo") Mayo2: OQS_SIG_alg_mayo_2,
    ("mayo") Mayo3: OQS_SIG_alg_mayo_3,
    ("mayo") Mayo5: OQS_SIG_alg_mayo_5,
    ("ml_dsa") MlDsa44: OQS_SIG_alg_ml_dsa_44,
    ("ml_dsa") MlDsa65: OQS_SIG_alg_ml_dsa_65,
    ("ml_dsa") MlDsa87: OQS_SIG_alg_ml_dsa_87,
    ("sphincs") SphincsSha2128fSimple: OQS_SIG_alg_sphincs_sha2_128f_simple,
    ("sphincs") SphincsSha2128sSimple: OQS_SIG_alg_sphincs_sha2_128s_simple,
    ("sphincs") SphincsSha2192fSimple: OQS_SIG_alg_sphincs_sha2_192f_simple,
    ("sphincs") SphincsSha2192sSimple: OQS_SIG_alg_sphincs_sha2_192s_simple,
    ("sphincs") SphincsSha2256fSimple: OQS_SIG_alg_sphincs_sha2_256f_simple,
    ("sphincs") SphincsSha2256sSimple: OQS_SIG_alg_sphincs_sha2_256s_simple,
    ("sphincs") SphincsShake128fSimple: OQS_SIG_alg_sphincs_shake_128f_simple,
    ("sphincs") SphincsShake128sSimple: OQS_SIG_alg_sphincs_shake_128s_simple,
    ("sphincs") SphincsShake192fSimple: OQS_SIG_alg_sphincs_shake_192f_simple,
    ("sphincs") SphincsShake192sSimple: OQS_SIG_alg_sphincs_shake_192s_simple,
    ("sphincs") SphincsShake256fSimple: OQS_SIG_alg_sphincs_shake_256f_simple,
    ("sphincs") SphincsShake256sSimple: OQS_SIG_alg_sphincs_shake_256s_simple,
    ("uov") UovOvIs: OQS_SIG_alg_uov_ov_Is,
    ("uov") UovOvIp: OQS_SIG_alg_uov_ov_Ip,
    ("uov") UovOvIII: OQS_SIG_alg_uov_ov_III,
    ("uov") UovOvV: OQS_SIG_alg_uov_ov_V,
    ("uov") UovOvIsPkc: OQS_SIG_alg_uov_ov_Is_pkc,
    ("uov") UovOvIpPkc: OQS_SIG_alg_uov_ov_Ip_pkc,
    ("uov") UovOvIIIPkc: OQS_SIG_alg_uov_ov_III_pkc,
    ("uov") UovOvVPkc: OQS_SIG_alg_uov_ov_V_pkc,
    ("uov") UovOvIsPkcSkc: OQS_SIG_alg_uov_ov_Is_pkc_skc,
    ("uov") UovOvIpPkcSkc: OQS_SIG_alg_uov_ov_Ip_pkc_skc,
    ("uov") UovOvIIIPkcSkc: OQS_SIG_alg_uov_ov_III_pkc_skc,
    ("uov") UovOvVPkcSkc: OQS_SIG_alg_uov_ov_V_pkc_skc,
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
/// # if !cfg!(feature = "ml_dsa") { return; }
/// use oqs;
/// oqs::init();
/// let scheme = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa44).unwrap();
/// let message = [0u8; 100];
/// let (pk, sk) = scheme.keypair().unwrap();
/// let signature = scheme.sign(&message, &sk).unwrap();
/// assert!(scheme.verify(&message, &signature, &pk).is_ok());
/// ```
pub struct Sig {
    algorithm: Algorithm,
    sig: NonNull<ffi::OQS_SIG>,
}

unsafe impl Sync for Sig {}
unsafe impl Send for Sig {}

impl Drop for Sig {
    fn drop(&mut self) {
        unsafe { ffi::OQS_SIG_free(self.sig.as_ptr()) };
    }
}

#[cfg(feature = "std")]
impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.name().fmt(f)
    }
}

impl core::convert::TryFrom<Algorithm> for Sig {
    type Error = crate::Error;
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

    /// Does this algorithm support signing with a context string?
    pub fn has_ctx_str_support(&self) -> bool {
        let sig = unsafe { self.sig.as_ref() };
        sig.sig_with_ctx_support
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
        let func = sig.keypair.unwrap();
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
        let func = sig.sign.unwrap();
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

    /// Sign a message with a context string
    pub fn sign_with_ctx_str<'a, S: Into<SecretKeyRef<'a>>>(
        &self,
        message: &Message,
        ctx_str: &CtxStr,
        sk: S,
    ) -> Result<Signature> {
        let sk = sk.into();
        let sig = unsafe { self.sig.as_ref() };
        let func = sig.sign_with_ctx_str.unwrap();
        let mut sig = Signature {
            bytes: Vec::with_capacity(sig.length_signature),
        };
        let mut sig_len = 0;
        // For algorithms without context string support, liboqs
        // expects the context to be NULL. Converting an empty
        // slice to a pointer doesn't actually do this.
        let ctx_str_ptr = if !ctx_str.is_empty() {
            ctx_str.as_ptr()
        } else {
            null()
        };
        let status = unsafe {
            func(
                sig.bytes.as_mut_ptr(),
                &mut sig_len,
                message.as_ptr(),
                message.len(),
                ctx_str_ptr,
                ctx_str.len(),
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
        let func = sig.verify.unwrap();
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

    /// Verify a message with a context string
    pub fn verify_with_ctx_str<'a, 'b>(
        &self,
        message: &Message,
        signature: impl Into<SignatureRef<'a>>,
        ctx_str: &CtxStr,
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
        let func = sig.verify_with_ctx_str.unwrap();
        // For algorithms without context string support, liboqs
        // expects the context to be NULL. Converting an empty
        // slice to a pointer doesn't actually do this.
        let ctx_str_ptr = if !ctx_str.is_empty() {
            ctx_str.as_ptr()
        } else {
            null()
        };
        let status = unsafe {
            func(
                message.as_ptr(),
                message.len(),
                signature.bytes.as_ptr(),
                signature.len(),
                ctx_str_ptr,
                ctx_str.len(),
                pk.bytes.as_ptr(),
            )
        };
        status_to_result(status)
    }
}
