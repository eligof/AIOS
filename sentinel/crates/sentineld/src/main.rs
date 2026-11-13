use anyhow::Result;

fn main() -> Result<()> {
    println!("sentineld {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
