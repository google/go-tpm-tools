use std::io::Result;

fn main() -> Result<()> {
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());
    }

    let mut config = prost_build::Config::new();
    config.type_attribute("HpkeAlgorithm", "#[repr(C)]");
    config.compile_protos(&["proto/algorithms.proto"], &["proto/"])?;

    Ok(())
}
