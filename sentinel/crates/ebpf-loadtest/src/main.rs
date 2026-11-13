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
    /// Single-process heartbeat/lockdown check (fresh -> stale).
    HeartbeatSelftest,
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
        Cmd::HeartbeatSelftest => heartbeat_selftest(),
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

/// Local newtype: `Pod` is a foreign trait, so it cannot be implemented on
/// `KConfig` (foreign type) directly.
#[derive(Clone, Copy)]
#[repr(transparent)]
struct PodConfig(sentinel_common::wire::KConfig);
// SAFETY: KConfig is repr(C), Copy, and fully initialised plain data.
unsafe impl aya::Pod for PodConfig {}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid out-pointer; CLOCK_MONOTONIC matches bpf_ktime_get_ns.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Fire a real getpid syscall (glibc may cache getpid()) and read the flag
/// the probe wrote into LOCKDOWN_COUNTS[7].
fn trigger_and_read(bpf: &aya::Ebpf) -> Result<u64> {
    // SAFETY: getpid takes no arguments and cannot fail.
    unsafe { libc::syscall(libc::SYS_getpid) };
    let counts = aya::maps::Array::<_, u64>::try_from(
        bpf.map("LOCKDOWN_COUNTS")
            .ok_or_else(|| anyhow::anyhow!("LOCKDOWN_COUNTS missing"))?,
    )?;
    Ok(counts.get(&7, 0)?)
}

fn heartbeat_selftest() -> Result<()> {
    use aya::maps::Array;
    use aya::programs::TracePoint;
    use sentinel_common::wire::KConfig;

    let data = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sentinel-ebpf"));
    let mut bpf = aya::Ebpf::load(data)?;
    let prog: &mut TracePoint = bpf
        .program_mut("probe")
        .ok_or_else(|| anyhow::anyhow!("program probe missing"))?
        .try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_enter_getpid")?;

    let cfg = KConfig {
        lockdown_after_ns: 200_000_000,
        sentineld_tgid: std::process::id(),
        flags: 0,
    };
    {
        let mut config = Array::<_, PodConfig>::try_from(
            bpf.map_mut("CONFIG")
                .ok_or_else(|| anyhow::anyhow!("CONFIG missing"))?,
        )?;
        config.set(0, &PodConfig(cfg), 0)?;
    }
    {
        let mut hb = Array::<_, u64>::try_from(
            bpf.map_mut("HEARTBEAT")
                .ok_or_else(|| anyhow::anyhow!("HEARTBEAT missing"))?,
        )?;
        hb.set(0, &monotonic_ns(), 0)?;
    }

    let fresh = trigger_and_read(&bpf)?;
    if fresh != 0 {
        println!("heartbeat-lockdown: FAIL (lockdown active with fresh heartbeat)");
        std::process::exit(1);
    }
    std::thread::sleep(std::time::Duration::from_millis(400));
    let stale = trigger_and_read(&bpf)?;
    if stale != 1 {
        println!("heartbeat-lockdown: FAIL (lockdown not active with stale heartbeat)");
        std::process::exit(1);
    }
    println!("heartbeat-lockdown: PASS");
    Ok(())
}
