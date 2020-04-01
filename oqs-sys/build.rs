use cmake;
use bindgen;

use std::path::PathBuf;

fn generate_bindings(outdir: &PathBuf, headerfile: &str, filter: &str) {
    let includedir = outdir.join("build").join("include");
    bindgen::Builder::default()
        .clang_arg(format!("-I{}", includedir.display()))
        .header(includedir.join("oqs").join(format!("{}.h", headerfile)).to_str().unwrap())
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Options
        .default_enum_style(bindgen::EnumVariation::Rust { non_exhaustive: false })
        .size_t_is_usize(true)
        // Whitelist OQS stuff
        .whitelist_recursively(false)
        .whitelist_type(filter)
        .whitelist_function(filter)
        .whitelist_var(filter)
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings")
        .write_to_file(outdir.join(format!("{}_bindings.rs", headerfile)))

        .expect("Couldn't write bindings!");
}

fn main() {
    let outdir = cmake::Config::new("liboqs")
        .profile("Optimized")
        .build_target("oqs")
        .build();

    // lib is put into $outdir/build/lib
    let libdir = outdir.join("build").join("lib");
    println!("cargo:rustc-link-search=native={}", libdir.display());
    println!("cargo:rustc-link-lib=static=oqs");
    let gen_bindings = |file, filter| generate_bindings(&outdir, file, filter);

    gen_bindings("common", "OQS_.*");
    gen_bindings("kem", "OQS_KEM.*");
    gen_bindings("sig", "OQS_SIG.*");
}
