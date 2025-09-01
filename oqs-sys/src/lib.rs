//! Bindings to liboqs
#![no_std]

#[allow(clippy::all)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod common {
    include!(concat!(env!("OUT_DIR"), "/common_bindings.rs"));
}

#[allow(clippy::all)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod rand {
    pub use super::common::OQS_STATUS;
    include!(concat!(env!("OUT_DIR"), "/rand_bindings.rs"));
}

#[allow(clippy::all)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod kem {
    pub use super::common::OQS_STATUS;
    include!(concat!(env!("OUT_DIR"), "/kem_bindings.rs"));
}

#[allow(clippy::all)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod sig {
    pub use super::common::OQS_STATUS;
    include!(concat!(env!("OUT_DIR"), "/sig_bindings.rs"));
}
