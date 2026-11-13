use anyhow::Result;

fn main() -> Result<()> {
    println!("sentinel {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
