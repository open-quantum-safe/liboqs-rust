#![warn(missing_docs)]
//! Friendly bindings to liboqs
//!
//! See the [`kem::Kem`] and [`sig::Sig`] structs for how to use this crate.

use std::sync::Once;

use ffi::common::OQS_STATUS;

/// Access the OQS ffi through this crate.
pub use oqs_sys as ffi;

mod macros;

/// Initialize liboqs
///
/// Make sure to call this before you use any of the functions.
///
/// This method is thread-safe and can be called more than once.
pub fn init() {
    static mut INIT: Once = Once::new();
    // Unsafe is necessary for mutually accessing static var INIT
    unsafe {
        INIT.call_once(|| {
            ffi::common::OQS_init();
        });
    }
}

#[derive(Debug)]
#[non_exhaustive]
/// Possible errors
pub enum Error {
    /// Indicates an algorithm has been disabled
    AlgorithmDisabled,
    /// Generic error
    Error,
    /// Error occurred in OpenSSL functions external to liboqs
    ErrorExternalOpenSSL,
}
impl std::error::Error for Error {}

/// Result type for operations that may fail
#[must_use]
pub type Result<T> = std::result::Result<T, Error>;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::AlgorithmDisabled => write!(f, "Algorithm has been disabled"),
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
