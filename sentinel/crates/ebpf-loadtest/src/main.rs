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
    /// Attach the observers and stream every ring-buffer event as a JSON line
    /// on stdout until SIGINT/SIGTERM.
    Load,
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
        Cmd::Load => load(),
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

static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Attach one LSM program (`name`) to its kernel hook (`hook`). Later observers add a line in `load`.
fn attach_lsm(bpf: &mut aya::Ebpf, btf: &aya::Btf, name: &str, hook: &str) -> Result<()> {
    let prog: &mut aya::programs::Lsm = bpf
        .program_mut(name)
        .ok_or_else(|| anyhow::anyhow!("program {name} missing"))?
        .try_into()?;
    prog.load(hook, btf)?;
    prog.attach()?;
    Ok(())
}

/// Attach one BTF tracepoint program (`name`) to tracepoint `tp`.
fn attach_btf_tp(bpf: &mut aya::Ebpf, btf: &aya::Btf, name: &str, tp: &str) -> Result<()> {
    let prog: &mut aya::programs::BtfTracePoint = bpf
        .program_mut(name)
        .ok_or_else(|| anyhow::anyhow!("program {name} missing"))?
        .try_into()?;
    prog.load(tp, btf)?;
    prog.attach()?;
    Ok(())
}

/// Render one decoded event as a single JSON line. Payload fields are added
/// per kind by later observers.
fn event_json(ev: &sentinel_common::wire::RawEvent) -> String {
    use sentinel_common::event::EventKind;
    use sentinel_common::facts::{F_DELETED, F_MEMFD, G_FLAGS};
    let h = &ev.hdr;
    let facts = h.facts.map(|f| f.to_string()).join(",");
    let flags = h.facts[G_FLAGS];
    let proc_json = if h.kind == EventKind::Fork as u8 || h.kind == EventKind::Exit as u8 {
        // SAFETY: for Fork/Exit events the kernel side wrote the proc_ variant.
        let p = unsafe { ev.payload.proc_ };
        format!(
            ",\"child_pid\":{},\"exit_code\":{}",
            p.child_pid, p.exit_code
        )
    } else if h.kind == EventKind::Connect as u8 {
        // SAFETY: for Connect events the kernel side wrote the net variant.
        let n = unsafe { ev.payload.net };
        let a = &n.addr;
        let addr = if n.family == 2 {
            format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        } else {
            let g: Vec<String> = (0..8)
                .map(|i| format!("{:x}", u16::from_be_bytes([a[2 * i], a[2 * i + 1]])))
                .collect();
            format!("[{}]", g.join(":"))
        };
        format!(
            ",\"family\":{},\"addr\":\"{}\",\"port\":{}",
            n.family, addr, n.port
        )
    } else {
        String::new()
    };
    format!(
        "{{\"kind\":{},\"pid\":{},\"tid\":{},\"ppid\":{},\"uid\":{},\"euid\":{},\"cgroup\":{},\"ts_ns\":{},\"matched_rule\":{},\"kverdict\":{},\"facts\":[{}],\"flags_memfd\":{},\"flags_deleted\":{}{}}}",
        h.kind, h.pid, h.tid, h.ppid, h.uid, h.euid, h.cgroup_id, h.ts_ns,
        h.matched_rule, h.kverdict, facts,
        flags & F_MEMFD != 0,
        flags & F_DELETED != 0,
        proc_json,
    )
}

fn load() -> Result<()> {
    use std::io::Write;
    use std::sync::atomic::Ordering;

    let data = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sentinel-ebpf"));
    let mut bpf = aya::Ebpf::load(data)?;
    let btf = aya::Btf::from_sys_fs()?;
    attach_lsm(&mut bpf, &btf, "exec", "bprm_check_security")?;
    attach_lsm(&mut bpf, &btf, "connect", "socket_connect")?;
    attach_btf_tp(&mut bpf, &btf, "fork", "sched_process_fork")?;
    attach_btf_tp(&mut bpf, &btf, "exit", "sched_process_exit")?;

    let mut ring = aya::maps::RingBuf::try_from(
        bpf.take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("EVENTS missing"))?,
    )?;

    // SAFETY: the handler only stores to an atomic (async-signal-safe).
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }
    eprintln!("load: attached, streaming events");

    let stdout = std::io::stdout();
    while !STOP.load(Ordering::Relaxed) {
        let mut out = stdout.lock();
        while let Some(item) = ring.next() {
            if item.len() < core::mem::size_of::<sentinel_common::wire::RawEvent>() {
                continue;
            }
            // SAFETY: length checked above; RawEvent is repr(C) POD and the
            // ring item is not necessarily aligned.
            let ev = unsafe {
                core::ptr::read_unaligned(item.as_ptr() as *const sentinel_common::wire::RawEvent)
            };
            writeln!(out, "{}", event_json(&ev))?;
        }
        out.flush()?;
        drop(out);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Ok(())
}
