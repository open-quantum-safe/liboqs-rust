#![allow(clippy::mutex_atomic)]

use std::sync::{Arc, Mutex};

use lazy_static::lazy_static;

use ffi::common::OQS_STATUS;
pub use oqs_sys as ffi;

mod macros;

/// Initialize liboqs
pub fn init() {
    lazy_static! {
        static ref OQS_INITIALIZED: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    }
    let mut init = OQS_INITIALIZED.lock().unwrap();
    if !*init {
        unsafe { ffi::common::OQS_init() };
        *init = true;
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    AlgorithmDisabled,
    Error,
    ErrorExternalOpenSSL,
}
impl std::error::Error for Error {}

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

fn status_to_result(status: OQS_STATUS) -> Result<()> {
    match status {
        OQS_STATUS::OQS_SUCCESS => Ok(()),
        OQS_STATUS::OQS_ERROR => Err(Error::Error),
        OQS_STATUS::OQS_EXTERNAL_LIB_ERROR_OPENSSL => Err(Error::ErrorExternalOpenSSL),
    }
}

pub mod kem;
pub mod sig;
