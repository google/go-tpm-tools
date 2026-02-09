// Copyright 2021 The BoringSSL Authors
// FORKED FROM upstream BoringSSL. Modified to include implicit cmake build via cmake crate.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::env;
use std::path::Path;
use std::process::Command;

// Keep in sync with the list in include/openssl/opensslconf.h
const OSSL_CONF_DEFINES: &[&str] = &[
    "OPENSSL_NO_ASYNC",
    "OPENSSL_NO_BF",
    "OPENSSL_NO_BLAKE2",
    "OPENSSL_NO_BUF_FREELISTS",
    "OPENSSL_NO_CAMELLIA",
    "OPENSSL_NO_CAPIENG",
    "OPENSSL_NO_CAST",
    "OPENSSL_NO_CMS",
    "OPENSSL_NO_COMP",
    "OPENSSL_NO_CT",
    "OPENSSL_NO_DANE",
    "OPENSSL_NO_DEPRECATED",
    "OPENSSL_NO_DGRAM",
    "OPENSSL_NO_DYNAMIC_ENGINE",
    "OPENSSL_NO_EC_NISTP_64_GCC_128",
    "OPENSSL_NO_EC2M",
    "OPENSSL_NO_EGD",
    "OPENSSL_NO_ENGINE",
    "OPENSSL_NO_GMP",
    "OPENSSL_NO_GOST",
    "OPENSSL_NO_HEARTBEATS",
    "OPENSSL_NO_HW",
    "OPENSSL_NO_IDEA",
    "OPENSSL_NO_JPAKE",
    "OPENSSL_NO_KRB5",
    "OPENSSL_NO_MD2",
    "OPENSSL_NO_MDC2",
    "OPENSSL_NO_OCB",
    "OPENSSL_NO_OCSP",
    "OPENSSL_NO_RC2",
    "OPENSSL_NO_RC5",
    "OPENSSL_NO_RFC3779",
    "OPENSSL_NO_RIPEMD",
    "OPENSSL_NO_RMD160",
    "OPENSSL_NO_SCTP",
    "OPENSSL_NO_SEED",
    "OPENSSL_NO_SM2",
    "OPENSSL_NO_SM3",
    "OPENSSL_NO_SM4",
    "OPENSSL_NO_SRP",
    "OPENSSL_NO_SSL_TRACE",
    "OPENSSL_NO_SSL2",
    "OPENSSL_NO_SSL3",
    "OPENSSL_NO_SSL3_METHOD",
    "OPENSSL_NO_STATIC_ENGINE",
    "OPENSSL_NO_STORE",
    "OPENSSL_NO_WHIRLPOOL",
];

fn get_cpp_runtime_lib() -> Option<String> {
    println!("cargo:rerun-if-env-changed=BORINGSSL_RUST_CPPLIB");

    if let Ok(cpp_lib) = env::var("BORINGSSL_RUST_CPPLIB") {
        return Some(cpp_lib);
    }

    if env::var_os("CARGO_CFG_UNIX").is_some() {
        match env::var("CARGO_CFG_TARGET_OS").unwrap().as_ref() {
            "macos" => Some("c++".into()),
            _ => Some("stdc++".into()),
        }
    } else {
        None
    }
}

fn main() {
    let target = env::var("TARGET").unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Locate the BoringSSL source relative to this cargo manifest
    // keymanager/third_party/bssl-sys -> keymanager/boringssl
    let bssl_source_dir = Path::new(&manifest_dir).join("../../boringssl");

    // Auto-init git submodule if BoringSSL source is missing.
    if !bssl_source_dir.join("CMakeLists.txt").exists() {
        let _ = Command::new("git")
            .args(["submodule", "update", "--init", "--recursive", "boringssl"])
            .current_dir(Path::new(&manifest_dir).join("../.."))
            .status();
    }

    if !bssl_source_dir.join("CMakeLists.txt").exists() {
        panic!(
            "BoringSSL source not found at {}. Run 'git submodule update --init --recursive'",
            bssl_source_dir.display()
        );
    }

    // Rebuild when the BoringSSL source tree changes (e.g. submodule update).
    // Cargo 1.50+ recursively scans directories for mtime changes.
    println!("cargo:rerun-if-changed={}", bssl_source_dir.display());

    // Use cmake crate to build BoringSSL.
    // The cmake crate itself panics with a diagnostic "is `cmake` not installed?"
    // message if cmake is not found, so no pre-check is needed (standard practice
    // per cmake-rs, libz-sys, and other sys crates).
    let dst = cmake::Config::new(&bssl_source_dir)
        .define("RUST_BINDINGS", &target)
        .build_target("bssl_sys") // We specifically want this target which generates bindings
        .build();

    // The cmake crate installs artifacts to `dst`.
    // However, BoringSSL's internal structure when built might be different.
    // Usually artifacts are in `dst/build` if we didn't install, but `cmake` crate defaults to install.
    // BoringSSL install target puts libs in `lib/` and includes in `include/`.
    // BUT `bssl_sys` target might not install the wrapper?
    // Let's verify where `cmake` crate puts it. It usually puts build artifacts in `build/`.

    // cmake::Config::build() guarantees this path exists on success (it
    // panics on failure), but assert for clarity since the layout matters.
    let build_dir = dst.join("build");
    assert!(
        build_dir.exists(),
        "Expected cmake build directory not found at {}. This is a bug in the build script.",
        build_dir.display()
    );

    // Link Search Paths
    // Note: We might need to look in `dst/lib` if it was installed, or `build_dir` if not.
    // BoringSSL puts static libs in the top level of build dir usually, or `crypto/` `ssl/` subdirs.
    // Let's add multiple search paths to be safe, similar to original script logic but adapted.

    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!(
        "cargo:rustc-link-search=native={}/crypto",
        build_dir.display()
    );
    println!("cargo:rustc-link-search=native={}/ssl", build_dir.display());
    println!(
        "cargo:rustc-link-search=native={}/rust/bssl-sys",
        build_dir.display()
    );

    // Also check `dst/lib` just in case `cmake` crate installed them there
    println!("cargo:rustc-link-search=native={}/lib", dst.display());

    // Link Libraries
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");
    println!("cargo:rustc-link-lib=static=rust_wrapper");

    if let Some(cpp_lib) = get_cpp_runtime_lib() {
        println!("cargo:rustc-link-lib={}", cpp_lib);
    }

    println!("cargo:conf={}", OSSL_CONF_DEFINES.join(","));

    // Generate/Copy Bindings
    // The `bssl_sys` target generates `wrapper_{target}.rs` in `rust/bssl-sys` inside build dir.
    let bssl_sys_build_dir = build_dir.join("rust/bssl-sys");
    let bindgen_source_file = bssl_sys_build_dir.join(format!("wrapper_{}.rs", target));

    // We also need the prefix header from source
    let prefix_inc_source_file =
        bssl_source_dir.join("rust/bssl-sys/boringssl_prefix_symbols_bindgen.rs.in");

    let bindgen_out_file = Path::new(&out_dir).join("bindgen.rs");

    let bindgen_source = std::fs::read_to_string(&bindgen_source_file).expect(&format!(
        "Could not read bindings from '{}'. Did the build fail?",
        bindgen_source_file.display(),
    ));

    println!("cargo:rerun-if-changed={}", bindgen_source_file.display());

    let prefix_source = match env::var("BORINGSSL_PREFIX") {
        Ok(prefix) => std::fs::read_to_string(&prefix_inc_source_file)
            .expect(&format!(
                "Could not read prefixing data from '{}'",
                prefix_inc_source_file.display(),
            ))
            .replace("${BORINGSSL_PREFIX}", prefix.as_str()),
        Err(env::VarError::NotPresent) => "".to_string(),
        Err(e) => panic!("failed to read BORINGSSL_PREFIX variable: {}", e),
    };

    std::fs::write(
        &bindgen_out_file,
        format!("{}{}", bindgen_source, prefix_source),
    )
    .expect(&format!(
        "Could not write bindings to '{}'",
        bindgen_out_file.display()
    ));

    println!(
        "cargo:rerun-if-changed={}",
        prefix_inc_source_file.display()
    );
    println!("cargo:rerun-if-env-changed=BORINGSSL_PREFIX");
}
