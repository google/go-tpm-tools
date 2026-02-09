use std::io::Result;

fn main() -> Result<()> {
    println!("cargo::rerun-if-changed=proto");
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());
    }
    prost_build::compile_protos(&["proto/algorithms.proto"], &["proto/"])?;
    Ok(())
}
