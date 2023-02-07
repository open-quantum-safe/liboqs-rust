use std::path::Path;

fn generate_bindings(outdir: &Path, headerfile: &str, filter: &str) {
    let includedir = outdir.join("build").join("include");
    bindgen::Builder::default()
        .clang_arg(format!("-I{}", includedir.display()))
        .header(
            includedir
                .join("oqs")
                .join(format!("{headerfile}.h"))
                .to_str()
                .unwrap(),
        )
        // Options
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .size_t_is_usize(true)
        // Don't generate docs unless enabled
        // Otherwise it breaks tests
        .generate_comments(cfg!(feature = "docs"))
        // Whitelist OQS stuff
        .allowlist_recursively(false)
        .allowlist_type(filter)
        .allowlist_function(filter)
        .allowlist_var(filter)
        // Use core and libc
        .use_core()
        .ctypes_prefix("::libc")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings")
        .write_to_file(outdir.join(format!("{headerfile}_bindings.rs")))
        .expect("Couldn't write bindings!");
}

fn main() {
    // Check if clang is available before compiling anything.
    bindgen::clang_version();

    let mut config = cmake::Config::new("liboqs");
    config.profile("Release");
    config.define("OQS_BUILD_ONLY_LIB", "Yes");

    if cfg!(feature = "non_portable") {
        // Build with CPU feature detection or just enable whatever is available for this CPU
        config.define("OQS_DIST_BUILD", "No");
    } else {
        config.define("OQS_DIST_BUILD", "Yes");
    }

    macro_rules! algorithm_feature {
        ($typ:literal, $feat: literal) => {
            let configflag = format!("OQS_ENABLE_{}_{}", $typ, $feat.to_ascii_uppercase());
            let value = if cfg!(feature = $feat) { "Yes" } else { "No" };
            config.define(&configflag, value);
        };
    }

    // KEMs
    // BIKE is not supported on Windows or Arm32, so if either is in the mix,
    // have it be opt-in explicitly except through the default kems feature.
    if cfg!(feature = "kems") && !(cfg!(windows) || cfg!(target_arch = "arm")) {
        println!("cargo:rustc-cfg=feature=\"bike\"");
        config.define("OQS_ENABLE_KEM_BIKE", "Yes");
    } else {
        algorithm_feature!("KEM", "bike");
    }
    algorithm_feature!("KEM", "classic_mceliece");
    algorithm_feature!("KEM", "frodokem");
    algorithm_feature!("KEM", "hqc");
    algorithm_feature!("KEM", "kyber");

    // signature schemes
    algorithm_feature!("SIG", "dilithium");
    algorithm_feature!("SIG", "falcon");
    algorithm_feature!("SIG", "sphincs");

    if cfg!(windows) {
        // Select the latest available Windows SDK
        // SDK version 10.0.17763.0 seems broken
        config.define("CMAKE_SYSTEM_VERSION", "10.0");
    }

    if cfg!(feature = "openssl") {
        config.define("OQS_USE_OPENSSL", "Yes");
        if cfg!(windows) {
            // Windows doesn't prefix with lib
            println!("cargo:rustc-link-lib=libcrypto");
        } else {
            println!("cargo:rustc-link-lib=crypto");
        }

        println!("cargo:rerun-if-env-changed=OPENSSL_ROOT_DIR");
        if let Ok(dir) = std::env::var("OPENSSL_ROOT_DIR") {
            let dir = Path::new(&dir).join("lib");
            println!("cargo:rustc-link-search={}", dir.display());
        } else if cfg!(target_os = "windows") || cfg!(target_os = "macos") {
            println!("cargo:warning=You may need to specify OPENSSL_ROOT_DIR or disable the default `openssl` feature.");
        }
    } else {
        config.define("OQS_USE_OPENSSL", "No");
    }
    let outdir = config.build_target("oqs").build();

    // lib is put into $outdir/build/lib
    let mut libdir = outdir.join("build").join("lib");
    if cfg!(windows) {
        libdir.push("Release");
        // Static linking doesn't work on Windows
        println!("cargo:rustc-link-lib=oqs");
    } else {
        // Statically linking makes it easier to use the sys crate
        println!("cargo:rustc-link-lib=static=oqs");
    }
    println!("cargo:rustc-link-search=native={}", libdir.display());

    let gen_bindings = |file, filter| generate_bindings(&outdir, file, filter);

    gen_bindings("common", "OQS_.*");
    gen_bindings("rand", "OQS_(randombytes|RAND)_.*");
    gen_bindings("kem", "OQS_KEM.*");
    gen_bindings("sig", "OQS_SIG.*");

    // https://docs.rs/build-deps/0.1.4/build_deps/fn.rerun_if_changed_paths.html
    build_deps::rerun_if_changed_paths("liboqs/src/**/*").unwrap();
    build_deps::rerun_if_changed_paths("liboqs/src").unwrap();
    build_deps::rerun_if_changed_paths("liboqs/src/*").unwrap();
}
