use cmake;
use bindgen;

fn main() {
    let outdir = cmake::Config::new("liboqs")
        .profile("Optimized")
        .build_target("oqs")
        .build();

    // lib is put into $outdir/build/lib
    let libdir = outdir.join("build").join("lib");
    // includes are in $outdor/build/include
    let includedir = outdir.join("build").join("include");
    println!("cargo:rustc-link-search=native={}", libdir.display());
    println!("cargo:rustc-link-lib=static=oqs");

    let bindings = bindgen::Builder::default()
        .clang_arg(format!("-I{}", includedir.display()))
        .header(includedir.join("oqs").join("oqs.h").to_str().unwrap())
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Whitelist OQS stuff
        .whitelist_type("OQS_.*")
        .whitelist_function("OQS_.*")
        .whitelist_var("OQS_.*")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    bindings
        .write_to_file(outdir.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

