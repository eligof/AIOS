use anyhow::Result;
use clap::{Parser, Subcommand};

const MAP_NAMES: [&str; 13] = [
    "EVENTS",
    "DROPS",
    "HEARTBEAT",
    "LOCKDOWN_COUNTS",
    "RULES",
    "RULE_COUNT",
    "MOUNTS",
    "CIDRS",
    "PORTS",
    "UID_LITERALS",
    "QUARANTINE",
    "GUARDED_INODES",
    "CONFIG",
];

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Selftest,
    Maps,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Selftest => {
            let data = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sentinel-ebpf"));
            let bpf = aya::Ebpf::load(data)?;
            let names: Vec<_> = bpf.programs().map(|(n, _)| n.to_string()).collect();
            println!("loaded object with {} programs: {:?}", names.len(), names);
            Ok(())
        }
        Cmd::Maps => {
            let data = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sentinel-ebpf"));
            let bpf = aya::Ebpf::load(data)?;
            let mut missing = 0;
            for name in MAP_NAMES {
                if bpf.map(name).is_some() {
                    println!("map {name}: found");
                } else {
                    println!("map {name}: MISSING");
                    missing += 1;
                }
            }
            if missing > 0 {
                anyhow::bail!("{missing} map(s) MISSING");
            }
            Ok(())
        }
    }
}
