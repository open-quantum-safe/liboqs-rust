//! Signature API
//!
//! See [`Sig`] for the main functionality
use alloc::borrow;
use alloc::vec::Vec;

use core::ptr::NonNull;

#[cfg(feature = "no_std")]
use cstr_core::CStr;
#[cfg(not(feature = "no_std"))]
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
    { $( $sig: ident: $oqs_id: ident),* $(,)? } => (
        /// Supported algorithms by liboqs
        ///
        /// They may not all be enabled
        ///
        /// Optional support for `serde` if that feature is enabled.
        #[derive(Clone, Copy, Debug)]
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
            id as *const _ as *const i8
        }

        $(
            #[cfg(test)]
            #[allow(non_snake_case)]
            mod $sig {
                use super::*;

                #[test]
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
                    assert!(Algorithm::$sig.is_enabled());
                }
            }
        )*
    )
}

implement_sigs! {
    Default: OQS_SIG_alg_default,
    Dilithium2: OQS_SIG_alg_dilithium_2,
    Dilithium3: OQS_SIG_alg_dilithium_3,
    Dilithium4: OQS_SIG_alg_dilithium_4,
    Falcon512: OQS_SIG_alg_falcon_512,
    Falcon1024: OQS_SIG_alg_falcon_1024,
    Picnic3L1: OQS_SIG_alg_picnic3_L1,
    Picnic3L3: OQS_SIG_alg_picnic3_L3,
    Picnic3L5: OQS_SIG_alg_picnic3_L5,
    PicnicL1Fs: OQS_SIG_alg_picnic_L1_FS,
    PicnicL1Ur: OQS_SIG_alg_picnic_L1_UR,
    PicnicL1Full: OQS_SIG_alg_picnic_L1_full,
    PicnicL3Fs: OQS_SIG_alg_picnic_L3_FS,
    PicnicL3Ur: OQS_SIG_alg_picnic_L3_UR,
    PicnicL3Full: OQS_SIG_alg_picnic_L3_full,
    PicnicL5Fs: OQS_SIG_alg_picnic_L5_FS,
    PicnicL5Ur: OQS_SIG_alg_picnic_L5_UR,
    PicnicL5Full: OQS_SIG_alg_picnic_L5_full,
    RainbowIaClassic: OQS_SIG_alg_rainbow_Ia_classic,
    RainbowIaCyclic: OQS_SIG_alg_rainbow_Ia_cyclic,
    RainbowIaCyclicCompressed: OQS_SIG_alg_rainbow_Ia_cyclic_compressed,
    RainbowIIIcCyclic: OQS_SIG_alg_rainbow_IIIc_cyclic,
    RainbowIIIcCyclicCompressed: OQS_SIG_alg_rainbow_IIIc_cyclic_compressed,
    RainbowIIIcclassic: OQS_SIG_alg_rainbow_IIIc_classic,
    RainbowVcClassic: OQS_SIG_alg_rainbow_Vc_classic,
    RainbowVcCyclic: OQS_SIG_alg_rainbow_Vc_cyclic,
    RainbowVcCyclicCompressed: OQS_SIG_alg_rainbow_Vc_cyclic_compressed,
    SphincsHaraka128fRobust: OQS_SIG_alg_sphincs_haraka_128f_robust,
    SphincsHaraka128fSimple: OQS_SIG_alg_sphincs_haraka_128f_simple,
    SphincsHaraka128sRobust: OQS_SIG_alg_sphincs_haraka_128s_robust,
    SphincsHaraka128sSimple: OQS_SIG_alg_sphincs_haraka_128s_simple,
    SphincsHaraka192fRobust: OQS_SIG_alg_sphincs_haraka_192f_robust,
    SphincsHaraka192fSimple: OQS_SIG_alg_sphincs_haraka_192f_simple,
    SphincsHaraka192sRobust: OQS_SIG_alg_sphincs_haraka_192s_robust,
    SphincsHaraka192sSimple: OQS_SIG_alg_sphincs_haraka_192s_simple,
    SphincsHaraka256fRobust: OQS_SIG_alg_sphincs_haraka_256f_robust,
    SphincsHaraka256fSimple: OQS_SIG_alg_sphincs_haraka_256f_simple,
    SphincsHaraka256sRobust: OQS_SIG_alg_sphincs_haraka_256s_robust,
    SphincsHaraka256sSimple: OQS_SIG_alg_sphincs_haraka_256s_simple,
    SphincsSha256128fRobust: OQS_SIG_alg_sphincs_sha256_128f_robust,
    SphincsSha256128fSimple: OQS_SIG_alg_sphincs_sha256_128f_simple,
    SphincsSha256128sRobust: OQS_SIG_alg_sphincs_sha256_128s_robust,
    SphincsSha256128sSimple: OQS_SIG_alg_sphincs_sha256_128s_simple,
    SphincsSha256192fRobust: OQS_SIG_alg_sphincs_sha256_192f_robust,
    SphincsSha256192fSimple: OQS_SIG_alg_sphincs_sha256_192f_simple,
    SphincsSha256192sRobust: OQS_SIG_alg_sphincs_sha256_192s_robust,
    SphincsSha256192sSimple: OQS_SIG_alg_sphincs_sha256_192s_simple,
    SphincsSha256256fRobust: OQS_SIG_alg_sphincs_sha256_256f_robust,
    SphincsSha256256fSimple: OQS_SIG_alg_sphincs_sha256_256f_simple,
    SphincsSha256256sRobust: OQS_SIG_alg_sphincs_sha256_256s_robust,
    SphincsSha256256sSimple: OQS_SIG_alg_sphincs_sha256_256s_simple,
    SphincsShake256128fRobust: OQS_SIG_alg_sphincs_shake256_128f_robust,
    SphincsShake256128fSimple: OQS_SIG_alg_sphincs_shake256_128f_simple,
    SphincsShake256128sRobust: OQS_SIG_alg_sphincs_shake256_128s_robust,
    SphincsShake256128sSimple: OQS_SIG_alg_sphincs_shake256_128s_simple,
    SphincsShake256192fRobust: OQS_SIG_alg_sphincs_shake256_192f_robust,
    SphincsShake256192fSimple: OQS_SIG_alg_sphincs_shake256_192f_simple,
    SphincsShake256192sRobust: OQS_SIG_alg_sphincs_shake256_192s_robust,
    SphincsShake256192sSimple: OQS_SIG_alg_sphincs_shake256_192s_simple,
    SphincsShake256256fRobust: OQS_SIG_alg_sphincs_shake256_256f_robust,
    SphincsShake256256fSimple: OQS_SIG_alg_sphincs_shake256_256f_simple,
    SphincsShake256256sRobust: OQS_SIG_alg_sphincs_shake256_256s_robust,
    SphincsShake256256sSimple: OQS_SIG_alg_sphincs_shake256_256s_simple,
}

impl core::default::Default for Algorithm {
    fn default() -> Self {
        Algorithm::Default
    }
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
}

/// Algorithm wrapper
pub struct Sig {
    sig: NonNull<ffi::OQS_SIG>,
}

impl Drop for Sig {
    fn drop(&mut self) {
        unsafe { ffi::OQS_SIG_free(self.sig.as_ptr()) };
    }
}

impl Sig {
    /// Construct a new algorithm
    ///
    /// May fail if the algorithm is not available
    pub fn new(algorithm: Algorithm) -> Result<Self> {
        let sig = unsafe { ffi::OQS_SIG_new(algorithm_to_id(algorithm)) };
        NonNull::new(sig).map_or_else(|| Err(Error::AlgorithmDisabled), |sig| Ok(Self { sig }))
    }

    /// Get the name of this signature algorithm
    pub fn name(&self) -> borrow::Cow<str> {
        let sig = unsafe { self.sig.as_ref() };
        let cstr = unsafe { CStr::from_ptr(sig.method_name) };
        cstr.to_string_lossy()
    }

    /// Version of this implementation
    pub fn version(&self) -> borrow::Cow<str> {
        let sig = unsafe { self.sig.as_ref() };
        let cstr = unsafe { CStr::from_ptr(sig.method_name) };
        cstr.to_string_lossy()
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
    pub fn secret_key_from_bytes<'a>(&self, buf: &'a [u8]) -> SecretKeyRef<'a> {
        let sig = unsafe { self.sig.as_ref() };
        assert_eq!(buf.len(), sig.length_secret_key);
        SecretKeyRef::new(buf)
    }

    /// Construct a public key object from bytes
    pub fn public_key_from_bytes<'a>(&self, buf: &'a [u8]) -> PublicKeyRef<'a> {
        let sig = unsafe { self.sig.as_ref() };
        assert_eq!(buf.len(), sig.length_public_key);
        PublicKeyRef::new(buf)
    }

    /// Construct a signature object from bytes
    pub fn signature_from_bytes<'a>(&self, buf: &'a [u8]) -> SignatureRef<'a> {
        let sig = unsafe { self.sig.as_ref() };
        assert!(buf.len() <= sig.length_signature);
        SignatureRef::new(buf)
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
        let sig = unsafe { self.sig.as_ref() };
        assert!(
            signature.len() <= sig.length_signature,
            "Signature is too long?"
        );
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
}
