//! Compiles the vendored platform protos (client and server stubs).

use std::io;
use std::path::PathBuf;

fn main() -> io::Result<()> {
    let protos = [
        "proto/gateway/v1/gateway.proto",
        "proto/auth/v1/auth.proto",
        "proto/lcm/v1/lcm.proto",
    ];
    for p in &protos {
        println!("cargo:rerun-if-changed={p}");
    }
    let protoc = protoc_bin_vendored::protoc_bin_path().map_err(io::Error::other)?;
    let wkt_include = protoc_bin_vendored::include_path().map_err(io::Error::other)?;
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    let includes = [PathBuf::from("proto"), wkt_include];
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_with_config(
            config,
            &protos.iter().map(PathBuf::from).collect::<Vec<_>>(),
            &includes,
        )
}
