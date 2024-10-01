#![warn(
    clippy::unwrap_used,
    missing_debug_implementations,
    missing_docs,
    trivial_numeric_casts,
    unused_qualifications
)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
//! Friendly bindings to liboqs
//!
//! See the [`kem::Kem`](crate::kem::Kem) and [`sig::Sig`](crate::sig::Sig) structs for how to use this crate.
//!
//! # Example: Some signed KEX
//!
//! This protocol has no replay protection!
//! ```
//! use oqs::*;
//! # #[cfg(all(feature = "dilithium2", feature = "kyber"))]
//! fn main() -> Result<()> {
//!     oqs::init(); // Important: initialize liboqs
//!     let sigalg = sig::Sig::new(sig::Algorithm::Dilithium2)?;
//!     let kemalg = kem::Kem::new(kem::Algorithm::Kyber512)?;
//!     // A's long-term secrets
//!     let (a_sig_pk, a_sig_sk) = sigalg.keypair()?;
//!     // B's long-term secrets
//!     let (b_sig_pk, b_sig_sk) = sigalg.keypair()?;
//!
//!     // assumption: A has (a_sig_sk, a_sig_pk, b_sig_pk)
//!     // assumption: B has (b_sig_sk, b_sig_pk, a_sig_pk)
//!
//!     // A -> B: kem_pk, signature
//!     let (kem_pk, kem_sk) = kemalg.keypair()?;
//!     let signature = sigalg.sign(kem_pk.as_ref(), &a_sig_sk)?;
//!
//!     // B -> A: kem_ct, signature
//!     sigalg.verify(kem_pk.as_ref(), &signature, &a_sig_pk)?;
//!     let (kem_ct, b_kem_ss) = kemalg.encapsulate(&kem_pk)?;
//!     let signature = sigalg.sign(kem_ct.as_ref(), &b_sig_sk)?;
//!
//!     // A verifies, decapsulates, now both have kem_ss
//!     sigalg.verify(kem_ct.as_ref(), &signature, &b_sig_pk)?;
//!     let a_kem_ss = kemalg.decapsulate(&kem_sk, &kem_ct)?;
//!     assert_eq!(a_kem_ss, b_kem_ss);
//!
//!     Ok(())
//! }
//! # #[cfg(not(all(feature = "dilithium2", feature = "kyber")))]
//! # fn main() {}
//! ```
// needs to be imported to be made available
extern crate alloc;

use ffi::common::OQS_STATUS;

/// Access the OQS ffi through this crate.
pub use oqs_sys as ffi;

use core::fmt::{self, Debug, Display, Formatter};

mod macros;

/// Initialize liboqs
///
/// Make sure to call this before you use any of the functions.
///
/// When the ``std`` feature is enabled, this method is thread-safe
/// and can be called more than once.
#[cfg(feature = "std")]
pub fn init() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        unsafe { ffi::common::OQS_init() };
    });
}

/// Initialize liboqs
///
/// Needs to be called before you use any of the functions.
///
/// This ``no_std`` variant is not thread-safe.
#[cfg(not(feature = "std"))]
pub fn init() {
    unsafe { ffi::common::OQS_init() };
}

#[derive(Debug)]
#[non_exhaustive]
/// Possible errors
pub enum Error {
    /// Indicates an algorithm has been disabled
    AlgorithmDisabled,
    /// Algorithm not supported or unknown
    AlgorithmNotSupportedOrKnown,
    /// Generic error
    Error,
    /// Error occurred in OpenSSL functions external to liboqs
    #[allow(clippy::upper_case_acronyms)]
    ErrorExternalOpenSSL,
    /// Invalid length of a public object
    InvalidLength,
}
#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result type for operations that may fail
pub type Result<T> = core::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::AlgorithmDisabled => write!(f, "OQS Error: Algorithm has been disabled"),
            Error::AlgorithmNotSupportedOrKnown => write!(
                f,
                "OQS Error: Algorithm not supported, has been disabled or is unknown"
            ),
            Error::ErrorExternalOpenSSL => write!(f, "OQS error: OpenSSL call failed"),
            _ => write!(f, "OQS Error!"),
        }
    }
}

/// Convert an OQS_STATUS to the Result type.
fn status_to_result(status: OQS_STATUS) -> Result<()> {
    match status {
        OQS_STATUS::OQS_SUCCESS => Ok(()),
        OQS_STATUS::OQS_ERROR => Err(Error::Error),
        OQS_STATUS::OQS_EXTERNAL_LIB_ERROR_OPENSSL => Err(Error::ErrorExternalOpenSSL),
    }
}

pub mod kem;
pub mod sig;
