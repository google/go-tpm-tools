use std::io::Result;

fn main() -> Result<()> {
    println!("cargo::rerun-if-changed=proto");
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());
    }

    let mut config = prost_build::Config::new();

    // Output the generated code to src/ so cbindgen can find it.
    config.out_dir("src");

    config.compile_protos(
        &["proto/algorithms.proto", "proto/status.proto"],
        &["proto/"],
    )?;

    Ok(())
}
