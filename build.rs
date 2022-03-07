use std::io::Result;

#[cfg(feature = "galmon")]
fn build_galmon_protobuf() -> Result<()> {
    prost_build::Config::new()
        .default_package_filename("navmon_protobuf")
        .compile_protos(&["src/galmon/navmon.proto"], &["src/galmon"])
}

#[cfg(not(feature = "galmon"))]
fn build_galmon_protobuf() -> Result<()> {
    Ok(())
}

fn main() -> Result<()> {
    build_galmon_protobuf()?;
    Ok(())
}
