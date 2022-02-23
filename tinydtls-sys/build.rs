// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE
/*
 * build.rs - build script for TinyDTLS Rust bindings.
 * Copyright (c) 2021 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

use bindgen::EnumVariation;

fn main() {
    println!("cargo:rerun-if-changed=src/tinydtls/");
    println!("cargo:rerun-if-changed=tinydtls_wrapper.h");
    println!("cargo:rerun-if-changed=build.rs");
    let mut bindgen_builder = bindgen::Builder::default();

    // Build vendored library if feature was set.
    if cfg!(feature = "vendored") {
        // Read required environment variables.
        let out_dir = std::env::var_os("OUT_DIR").unwrap();

        // TinyDTLS does not like being built out of source, but we get verification errors if files
        // in the source package are modified.
        // Therefore, we copy tinydtls over to the output directory and build from there.
        let copy_options = fs_extra::dir::CopyOptions {
            overwrite: true,
            ..Default::default()
        };
        fs_extra::dir::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("tinydtls"),
            &out_dir,
            &copy_options,
        )
        .unwrap();
        let tinydtls_src_dir = Path::new(&out_dir).join("tinydtls");

        // Read Makeflags into vector of strings
        let _make_flags: String = std::env::var_os("CARGO_MAKEFLAGS")
            .unwrap()
            .into_string()
            .unwrap()
            .split(' ')
            .map(String::from)
            .collect();

        // Run autogen to generate necessary build files.
        Command::new(tinydtls_src_dir.join("autogen.sh"))
            .current_dir(&tinydtls_src_dir)
            .status()
            .unwrap();

        // Run make clean
        autotools::Config::new(&tinydtls_src_dir)
            .insource(true)
            .out_dir(&out_dir)
            .make_target("clean")
            .build();

        // Create build configuration instance and enable in-source builds.
        let mut build_config = autotools::Config::new(&tinydtls_src_dir);
        build_config.insource(true).out_dir(&out_dir);

        // Set Makeflags
        //build_config.make_args(make_flags);

        // Enable debug symbols if enabled in Rust.
        match std::env::var_os("DEBUG").unwrap().to_str().unwrap() {
            "0" | "false" => {}
            _ => {
                build_config.with("debug", None);
            }
        }

        // Enable dependency features based on selected cargo features.
        if !cfg!(feature = "ecc") {
            build_config.without("ecc", None);
        }
        if !cfg!(feature = "psk") {
            build_config.without("psk", None);
        }

        // Run build
        let dst = build_config.build();

        // Add the built library to the search path
        println!("cargo:rustc-link-search=native={}", dst.join("lib").to_str().unwrap());
        // Set some values that can be used by other crates that have to interact with the C library
        // directly, see https://doc.rust-lang.org/cargo/reference/build-scripts.html#the-links-manifest-key
        // for more info.
        println!("cargo:include={}", dst.join("include").to_str().unwrap());
        println!("cargo:libs={}", dst.to_str().unwrap());

        // Tell bindgen to look for the right header files.
        bindgen_builder = bindgen_builder
            .clang_arg(format!("-I{}", dst.join("include").join("tinydtls").to_str().unwrap()))
            .clang_arg(format!("-I{}", dst.join("include").to_str().unwrap()));
    }

    // Instruct cargo to link to the TinyDTLS C library, either statically or dynamically.
    println!(
        "cargo:rustc-link-lib={}tinydtls",
        cfg!(feature = "static").then(|| "static=").unwrap_or("")
    );

    // Customize and configure generated bindings.
    bindgen_builder = bindgen_builder
        .header("src/wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .default_enum_style(EnumVariation::Rust { non_exhaustive: true })
        .rustfmt_bindings(false)
        // Declarations that should be part of the bindings.
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
        // size_t matches usize in our case here.
        .size_t_is_usize(true);

    // Run binding generation and write the output to a file.
    let bindings = bindgen_builder.generate().expect("Could not generate bindings!");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join("bindings.rs")).unwrap();
}
