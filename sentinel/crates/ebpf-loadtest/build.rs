use aya_build::{build_ebpf, Package, Toolchain};
use cargo_metadata::MetadataCommand;

fn main() -> anyhow::Result<()> {
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
    build_ebpf(
        [Package {
            name: "sentinel-ebpf",
            root_dir: &root,
            ..Default::default()
        }],
        Toolchain::default(),
    )?;
    Ok(())
}
