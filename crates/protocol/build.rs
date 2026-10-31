//! Generates Rust types from the `.proto` definitions.
//!
//! Uses `protox` (a pure-Rust protobuf compiler), so building the workspace
//! does not require an external `protoc` installation.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = ["proto/omegadesk/v1/session.proto"];
    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }

    let descriptors = protox::compile(protos, ["proto"])?;
    prost_build::Config::new()
        .bytes(["."])
        .compile_fds(descriptors)?;
    Ok(())
}
