#![allow(missing_docs)]
fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    let mut prost = tonic_prost_build::Config::new();
    prost.protoc_executable(protoc);
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_with_config(
            prost,
            &["../../proto/piquel/auth/v1/auth.proto"],
            &["../../proto"],
        )
        .expect("compile versioned auth protocol");
    println!("cargo:rerun-if-changed=../../proto/piquel/auth/v1/auth.proto");
}
