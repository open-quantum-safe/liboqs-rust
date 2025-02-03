use std::path::{Path, PathBuf};

fn generate_bindings(includedir: &Path, headerfile: &str, allow_filter: &str, block_filter: &str) {
    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
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
        // Allowlist/blocklist OQS stuff
        .allowlist_recursively(false)
        .allowlist_type(allow_filter)
        .allowlist_function(allow_filter)
        .allowlist_var(allow_filter)
        .blocklist_type(block_filter)
        .blocklist_function(block_filter)
        .allowlist_var(block_filter)
        // Use core and libc
        .use_core()
        .ctypes_prefix("::libc")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join(format!("{headerfile}_bindings.rs")))
        .expect("Couldn't write bindings!");
}

fn build_from_source() -> PathBuf {
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
    algorithm_feature!("KEM", "ml_kem");
    algorithm_feature!("KEM", "ntruprime");

    // signature schemes
    algorithm_feature!("SIG", "cross");
    algorithm_feature!("SIG", "dilithium");
    algorithm_feature!("SIG", "falcon");
    algorithm_feature!("SIG", "mayo");
    algorithm_feature!("SIG", "ml_dsa");
    algorithm_feature!("SIG", "sphincs");

    if cfg!(windows) {
        // Select the latest available Windows SDK
        // SDK version 10.0.17763.0 seems broken
        config.define("CMAKE_SYSTEM_VERSION", "10.0");
    }

    // link the openssl libcrypto
    if cfg!(any(feature = "openssl", feature = "vendored_openssl")) {
        config.define("OQS_USE_OPENSSL", "Yes");
        if cfg!(windows) {
            // Windows doesn't prefix with lib
            println!("cargo:rustc-link-lib=libcrypto");
        } else {
            println!("cargo:rustc-link-lib=crypto");
        }
    } else {
        config.define("OQS_USE_OPENSSL", "No");
    }

    // let the linker know where to search for openssl libcrypto
    if cfg!(feature = "vendored_openssl") {
        // DEP_OPENSSL_ROOT is set by openssl-sys if a vendored build was used.
        // We point CMake towards this so that the vendored openssl is preferred
        // over the system openssl.
        let vendored_openssl_root = std::env::var("DEP_OPENSSL_ROOT")
            .expect("The `vendored_openssl` feature was enabled, but DEP_OPENSSL_ROOT was not set");
        config.define("OPENSSL_ROOT_DIR", vendored_openssl_root);
    } else if cfg!(feature = "openssl") {
        println!("cargo:rerun-if-env-changed=OPENSSL_ROOT_DIR");
        if let Ok(dir) = std::env::var("OPENSSL_ROOT_DIR") {
            let dir = Path::new(&dir).join("lib");
            println!("cargo:rustc-link-search={}", dir.display());
        } else if cfg!(target_os = "windows") || cfg!(target_os = "macos") {
            println!("cargo:warning=You may need to specify OPENSSL_ROOT_DIR or disable the default `openssl` feature.");
        }
    }

    let permit_unsupported = "OQS_PERMIT_UNSUPPORTED_ARCHITECTURE";
    if let Ok(str) = std::env::var(permit_unsupported) {
        config.define(permit_unsupported, str);
    }

    // build the default (install) target.
    let outdir = config.build();

    // remove the build folder
    let temp_build = outdir.join("build");
    if let Err(e) = std::fs::remove_dir_all(temp_build) {
        println!(
            "cargo:warning=unexpected error while cleaning build files:{}",
            e
        );
    }

    // lib is installed to $outdir/lib or lib64, depending on CMake conventions
    let libdir = outdir.join("lib");
    let libdir64 = outdir.join("lib64");

    if cfg!(windows) {
        // Static linking doesn't work on Windows
        println!("cargo:rustc-link-lib=oqs");
    } else {
        // Statically linking makes it easier to use the sys crate
        println!("cargo:rustc-link-lib=static=oqs");
    }
    println!("cargo:rustc-link-search=native={}", libdir.display());
    println!("cargo:rustc-link-search=native={}", libdir64.display());

    outdir
}

fn includedir_from_source() -> PathBuf {
    let outdir = build_from_source();
    outdir.join("include")
}

fn probe_includedir() -> PathBuf {
    if cfg!(feature = "vendored") {
        return includedir_from_source();
    }

    println!("cargo:rerun-if-env-changed=LIBOQS_NO_VENDOR");
    let force_no_vendor = std::env::var_os("LIBOQS_NO_VENDOR").map_or(false, |v| v != "0");

    let version = env!("CARGO_PKG_VERSION");
    let (_, liboqs_version) = version.split_once("+liboqs-").unwrap();
    let &[major_version, minor_version, _] =
        liboqs_version.split('.').collect::<Vec<_>>().as_slice()
    else {
        panic!("Failed to parse target liboqs version");
    };
    let minor_num: usize = minor_version.parse().unwrap();
    let upper_bound = format!("{}.{}.0", major_version, minor_num + 1);
    let config = pkg_config::Config::new()
        .range_version(liboqs_version..upper_bound.as_str())
        .probe("liboqs");

    match config {
        Ok(lib) => lib.include_paths.first().cloned().unwrap(),
        _ => {
            if force_no_vendor {
                panic!("The env variable LIBOQS_NO_VENDOR has been set but a suitable system liboqs could not be found.");
            }

            includedir_from_source()
        }
    }
}

fn main() {
    // Check if clang is available before compiling anything.
    bindgen::clang_version();

    let includedir = probe_includedir();
    let gen_bindings = |file, allow_filter, block_filter| {
        generate_bindings(&includedir, file, allow_filter, block_filter)
    };

    gen_bindings("common", "OQS_.*", "");
    gen_bindings("rand", "OQS_(randombytes|RAND)_.*", "");
    gen_bindings("kem", "OQS_KEM.*", "");
    gen_bindings("sig", "OQS_SIG.*", "OQS_SIG_STFL.*");

    // https://docs.rs/build-deps/0.1.4/build_deps/fn.rerun_if_changed_paths.html
    build_deps::rerun_if_changed_paths("liboqs/src/**/*").unwrap();
    build_deps::rerun_if_changed_paths("liboqs/src").unwrap();
    build_deps::rerun_if_changed_paths("liboqs/src/*").unwrap();
}
