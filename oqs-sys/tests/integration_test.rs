use std::process::Command;

#[test]
fn test_build_with_no_openssl_feature() {
    // Test building with the no_openssl feature
    let output = Command::new("cargo")
        .args(&["build", "--features", "no_openssl"])
        .env_remove("OQS_USE_OPENSSL") // Remove any env var that might interfere
        .output()
        .expect("Failed to execute cargo build");

    assert!(output.status.success(), 
           "Build failed with no_openssl feature: {}", 
           String::from_utf8_lossy(&output.stderr));
    
    // Check that the feature warning appears
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    assert!(stderr_str.contains("no_openssl feature enabled - disabling OpenSSL"),
           "Expected no_openssl feature warning not found in output: {}", stderr_str);
}

#[test]
#[cfg(target_os = "ios")]
fn test_ios_build_without_openssl() {
    // Test that iOS builds work without OpenSSL
    let output = Command::new("cargo")
        .args(&["build", "--target", "aarch64-apple-ios"])
        .output()
        .expect("Failed to execute cargo build for iOS");

    assert!(output.status.success(), 
           "iOS build failed: {}", 
           String::from_utf8_lossy(&output.stderr));
    
    // Check that iOS warning appears
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    assert!(stderr_str.contains("iOS target detected - disabling OpenSSL"),
           "Expected iOS detection warning not found in output: {}", stderr_str);
}

#[test]
fn test_oqs_use_openssl_env_var_off() {
    // Test that OQS_USE_OPENSSL=OFF works
    let output = Command::new("cargo")
        .args(&["build"])
        .env("OQS_USE_OPENSSL", "OFF")
        .output()
        .expect("Failed to execute cargo build");

    assert!(output.status.success(), 
           "Build failed with OQS_USE_OPENSSL=OFF: {}", 
           String::from_utf8_lossy(&output.stderr));
    
    // Check that the warning message appears in the output
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    assert!(stderr_str.contains("OpenSSL explicitly disabled via OQS_USE_OPENSSL"),
           "Expected OpenSSL disable warning not found in output: {}", stderr_str);
}

#[test]
fn test_oqs_use_openssl_env_var_on() {
    // Test that OQS_USE_OPENSSL=ON works (may fail due to missing OpenSSL, but should show correct message)
    let output = Command::new("cargo")
        .args(&["build"])
        .env("OQS_USE_OPENSSL", "ON")
        .output()
        .expect("Failed to execute cargo build");

    // Check that the enable warning appears (regardless of build success)
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    assert!(stderr_str.contains("OpenSSL explicitly enabled via OQS_USE_OPENSSL"),
           "Expected OpenSSL enable warning not found in output: {}", stderr_str);
}

#[test]
fn test_invalid_oqs_use_openssl_env_var() {
    // Test that invalid OQS_USE_OPENSSL values are handled gracefully
    let output = Command::new("cargo")
        .args(&["build"])
        .env("OQS_USE_OPENSSL", "INVALID_VALUE")
        .output()
        .expect("Failed to execute cargo build");

    // Check that the invalid value warning appears
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    assert!(stderr_str.contains("Invalid OQS_USE_OPENSSL value 'INVALID_VALUE', ignoring"),
           "Expected invalid value warning not found in output: {}", stderr_str);
}