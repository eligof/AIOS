use aya_build::{build_ebpf, Package, Toolchain};
use cargo_metadata::MetadataCommand;

fn main() -> anyhow::Result<()> {
    // Rebuild the embedded object whenever any kernel or shared-contract source changes,
    // not just this build script (sentinel-ebpf is outside the host workspace).
    let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for rel in [
        "../sentinel-ebpf/src",
        "../sentinel-ebpf/c",
        "../sentinel-ebpf/Cargo.toml",
        "../sentinel-ebpf/build.rs",
        "../sentinel-common/src",
    ] {
        println!("cargo:rerun-if-changed={}", here.join(rel).display());
    }
    // sentinel-ebpf is excluded from the workspace, so query its manifest directly.
    let manifest =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../sentinel-ebpf/Cargo.toml");
    let md = MetadataCommand::new()
        .manifest_path(manifest)
        .no_deps()
        .exec()?;
    let p = md
        .packages
        .into_iter()
        .find(|p| p.name == "sentinel-ebpf")
        .expect("sentinel-ebpf package not found in workspace metadata");
    let root = p.manifest_path.parent().unwrap().to_string();
    // aya-build runs `cargo build --package` in the current directory, which must therefore
    // be inside the (separate) sentinel-ebpf workspace rather than the host workspace.
    std::env::set_current_dir(&root)?;
    // Pin the eBPF object to the project's nightly rather than aya-build's default
    // (`Toolchain::Nightly` == rolling `nightly`). `Toolchain::Nightly` is passed to
    // `rustup run nightly`, which does NOT auto-install, so it builds only where a
    // generic `nightly` happens to be installed (dev boxes) and fails on a clean CI
    // runner that carries only the pinned toolchain. Keep this in sync with the
    // `nightly-2026-11-03` channel in sentinel/{,crates/sentinel-ebpf/}rust-toolchain.toml.
    build_ebpf(
        [Package {
            name: "sentinel-ebpf",
            root_dir: &root,
            ..Default::default()
        }],
        Toolchain::Custom("nightly-2026-11-03"),
    )?;
    Ok(())
}
