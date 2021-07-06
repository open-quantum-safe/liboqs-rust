fn main() {
    if cfg!(feature = "kems") && !(cfg!(windows) || cfg!(target_arch = "arm")) {
        // this can't enable the feature in oqs-sys, which is enabled
        // through oqs-sys/kems in Cargo.toml
        println!("cargo:rustc-cfg=feature=\"bike\"");
    }
}
