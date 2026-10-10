use std::env;
use std::path::{Path, PathBuf};

fn main() {
    const SOURCE: &str = "bpf/osmanthus_lsm.bpf.c";

    println!("cargo:rerun-if-changed={SOURCE}");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    let architecture = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set for the BPF build");
    let (bpf_architecture, multiarch_include) = match architecture.as_str() {
        "x86_64" => ("x86", "/usr/include/x86_64-linux-gnu"),
        "aarch64" => ("arm64", "/usr/include/aarch64-linux-gnu"),
        unsupported => panic!("unsupported Osmanthus BPF build architecture: {unsupported}"),
    };

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"))
        .join("osmanthus_lsm.skel.rs");
    let mut clang_args = vec![format!("-D__TARGET_ARCH_{bpf_architecture}")];
    if Path::new(multiarch_include).is_dir() {
        clang_args.push(format!("-I{multiarch_include}"));
    }

    libbpf_cargo::SkeletonBuilder::new()
        .source(SOURCE)
        .clang_args(clang_args)
        .build_and_generate(output)
        .expect("failed to compile the Osmanthus BPF LSM and generate its skeleton");
}
