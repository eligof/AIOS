use std::{env, path::PathBuf, process::Command};
fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bc = out.join("core.bc");
    let status = Command::new("clang")
        .args(["-target","bpfel","-O2","-g","-emit-llvm","-Wno-unknown-attributes","-c","c/core.c","-o"])
        .arg(&bc).status().expect("clang for the C shim");
    assert!(status.success(), "C shim failed to compile");
    println!("cargo:rustc-link-arg=--btf");
    println!("cargo:rustc-link-arg={}", bc.display());
    println!("cargo:rerun-if-changed=c/core.c");
    println!("cargo:rerun-if-changed=c/vmlinux_min.h");
    println!("cargo:rerun-if-changed=c/shim_types.h");
}
