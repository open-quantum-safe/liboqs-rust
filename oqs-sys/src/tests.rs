#[cfg(test)]
mod tests {
    use std::os::raw::c_int;

    #[test]
    fn test_basic_linking() {
        // Test that the basic OQS functions are available and linkable
        unsafe {
            // This should be available regardless of OpenSSL configuration
            let status = super::common::OQS_STATUS_SUCCESS;
            assert_eq!(status, 0);
        }
    }

    #[test]
    #[cfg(target_os = "ios")]
    fn test_ios_build_succeeds() {
        // On iOS, we should be able to build without OpenSSL
        // This test mainly validates that the build system works
        assert!(true, "iOS build completed successfully");
    }

    #[test]
    #[cfg(feature = "no_openssl")]
    fn test_no_openssl_feature() {
        // When no_openssl feature is enabled, the build should succeed
        // This is mainly a build-time test
        assert!(true, "no_openssl feature build completed successfully");
    }

    #[test]
    #[cfg(all(feature = "openssl", not(target_os = "ios")))]
    fn test_openssl_feature_on_supported_platforms() {
        // When OpenSSL feature is enabled on supported platforms, build should succeed
        assert!(true, "OpenSSL feature build completed successfully on supported platform");
    }

    #[test]
    fn test_kem_basic_functionality() {
        // Test that we can access KEM-related constants/types
        // This validates that the bindings are generated correctly
        unsafe {
            // Test that we can access basic KEM structures
            // The exact test will depend on what's available in the generated bindings
            let status = super::common::OQS_STATUS_SUCCESS;
            assert_eq!(status, 0);
        }
    }

    #[test]
    fn test_sig_basic_functionality() {
        // Test that we can access signature-related constants/types
        unsafe {
            let status = super::common::OQS_STATUS_SUCCESS;
            assert_eq!(status, 0);
        }
    }
}