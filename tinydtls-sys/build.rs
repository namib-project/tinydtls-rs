use std::{
    env,
    io::ErrorKind,
    path::{Path, PathBuf},
    process::Command,
};

use bindgen::EnumVariation;

fn main() {
    println!("cargo:rerun-if-changed=src/tinydtls");
    println!("cargo:rerun-if-changed=tinydtls_wrapper.h");
    println!("cargo:rerun-if-changed=build.rs");
    let mut bindgen_builder = bindgen::Builder::default();

    // Build vendored library if feature was set.
    if cfg!(feature = "vendored") {
        // Read required environment variables.
        let out_dir = std::env::var_os("OUT_DIR").unwrap();
        let tinydtls_src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("tinydtls");
        // Read Makeflags into vector of strings
        let make_flags = std::env::var_os("CARGO_MAKEFLAGS")
            .unwrap()
            .into_string()
            .unwrap()
            .split(" ")
            .map(String::from)
            .collect();

        Command::new("autoconf")
            .current_dir(&tinydtls_src_dir)
            .status()
            .unwrap();

        autotools::Config::new(&tinydtls_src_dir)
            .insource(true)
            .out_dir(&out_dir)
            .make_target("clean")
            .build();
        let mut build_config = autotools::Config::new(&tinydtls_src_dir);
        build_config.insource(true).out_dir(out_dir);

        // Is not deleted by default for some reason
        if let Err(e) = std::fs::remove_dir_all(&tinydtls_src_dir.join("include").join("tinydtls")) {
            match e.kind() {
                ErrorKind::NotFound => {},
                e => panic!("Error deleting old tinydtls include directory: {:?}", e),
            }
        }

        // Set Makeflags
        build_config.make_args(make_flags);

        // Enable debug symbols if enabled in Rust
        match std::env::var_os("DEBUG").unwrap().to_str().unwrap() {
            "0" | "false" => {},
            _ => {
                build_config.with("debug", None);
            },
        }

        // Enable dependency features based on selected cargo features.
        build_config
            .enable("ecc", Some(if cfg!(feature = "ecc") { "yes" } else { "no" }))
            .enable("psk", Some(if cfg!(feature = "psk") { "yes" } else { "no" }));

        // Run build
        let dst = build_config.build();

        // Add the built library to the search path
        println!("cargo:rustc-link-search=native={}", dst.join("lib").to_str().unwrap());
        println!("cargo:include={}", dst.join("include").to_str().unwrap());
        println!("cargo:libs={}", dst.to_str().unwrap());
        bindgen_builder = bindgen_builder
            .clang_arg(format!("-I{}", dst.join("include").join("tinydtls").to_str().unwrap()))
            .clang_arg(format!("-I{}", dst.join("include").to_str().unwrap()));
    }

    println!(
        "cargo:rustc-link-lib={}tinydtls",
        cfg!(feature = "static").then(|| "static=").unwrap_or("")
    );

    bindgen_builder = bindgen_builder
        .header("src/wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .default_enum_style(EnumVariation::Rust { non_exhaustive: true })
        .rustfmt_bindings(false)
        .allowlist_function("dtls_.*")
        .allowlist_type("dtls_.*")
        .allowlist_var("dtls_.*")
        .allowlist_function("DTLS_.*")
        .allowlist_type("DTLS_.*")
        .allowlist_var("DTLS_.*")
        .allowlist_type("seqnum_t")
        .allowlist_type("__attribute__")
        .allowlist_type("clock_time_t")
        .allowlist_var("CLOCK_SECOND")
        .allowlist_var("TLS_.*")
        .allowlist_var("DTLSv12")
        .allowlist_function("memxor")
        .allowlist_function("equals")
        .allowlist_var("WITH_.*")
        .allowlist_type("WITH_.*")
        .allowlist_function("WITH_.*")
        .allowlist_var("PACKAGE_.*")
        .allowlist_type("PACKAGE_.*")
        .allowlist_function("PACKAGE_.*")
        .allowlist_function("netq_.*")
        .allowlist_type("netq_.*")
        .allowlist_var("netq_.*")
        .allowlist_function("NETQ_.*")
        .allowlist_type("NETQ_.*")
        .allowlist_var("NETQ_.*")
        .allowlist_type("session_t")
        // We use the definitions made by the libc crate instead
        .blocklist_type("sockaddr(_in|_in6|_storage)?")
        .blocklist_type("in6?_(addr|port)(_t)?")
        .blocklist_type("in6_addr__bindgen_ty_1")
        .blocklist_type("(__)?socklen_t")
        .blocklist_type("sa_family_t")
        .blocklist_type("__fd_mask")
        // Are generated because they are typedef-ed inside of the C headers, blocklisting them
        // will instead replace them with the appropriate rust types.
        // See https://github.com/rust-lang/rust-bindgen/issues/1215 for an open issue concerning
        // this problem.
        .size_t_is_usize(true);
    let bindings = bindgen_builder.generate().unwrap();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join("bindings.rs")).unwrap();
}
