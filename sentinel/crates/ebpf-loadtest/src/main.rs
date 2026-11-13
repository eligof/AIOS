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
    /// Single-process quarantine check: a forked child in a quarantined
    /// cgroup gets EPERM on connect, the parent does not.
    QuarantineSelftest,
    /// Attach the observers and stream every ring-buffer event as a JSON line
    /// on stdout until SIGINT/SIGTERM.
    Load {
        /// Set CFG_ENFORCE so Deny+Enforce kernel rules actually block.
        #[arg(long)]
        enforce: bool,
        /// Set CFG_SELFGUARD: refuse user signals aimed at the daemon.
        #[arg(long)]
        selfguard: bool,
        /// Seed GUARDED_INODES from this dir and the files directly inside it.
        #[arg(long)]
        guard_dir: Option<std::path::PathBuf>,
    },
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
        Cmd::QuarantineSelftest => quarantine_selftest(),
        Cmd::Load {
            enforce,
            selfguard,
            guard_dir,
        } => load(enforce, selfguard, guard_dir),
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

/// Same orphan-rule workaround for the compiled kernel rule.
#[derive(Clone, Copy)]
#[repr(transparent)]
struct PodRule(sentinel_common::rule::KRule);
// SAFETY: KRule is repr(C), Copy, and fully initialised plain data.
unsafe impl aya::Pod for PodRule {}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct PodCidr(sentinel_common::wire::CidrEntry);
// SAFETY: CidrEntry is repr(C), Copy, plain data with no padding.
unsafe impl aya::Pod for PodCidr {}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct PodPort(sentinel_common::wire::PortRange);
// SAFETY: PortRange is repr(C), Copy, explicit padding field.
unsafe impl aya::Pod for PodPort {}

/// Mount id of the mount whose mount point is exactly `path`, from
/// /proc/self/mountinfo (field 1 = mount id, field 5 = mount point). When
/// several mounts share a mount point the last (topmost) one wins.
fn mount_id_for(path: &str) -> Result<Option<u64>> {
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.into());
    let canon = canon.to_string_lossy().into_owned();
    let info = std::fs::read_to_string("/proc/self/mountinfo")?;
    let mut found = None;
    for line in info.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        if f.len() < 5 {
            continue;
        }
        // mountinfo escapes space as \040.
        let mp = f[4].replace("\\040", " ");
        if mp == canon {
            found = f[0].parse::<u64>().ok();
        }
    }
    Ok(found)
}

/// Write the runtime-resolved MOUNTS and the static CIDRS/PORTS/UID_LITERALS.
fn populate_lookups(bpf: &mut aya::Ebpf, t: &sentinel_rules::compile::Tables) -> Result<()> {
    use sentinel_common::facts::slot_bit;
    use sentinel_common::rule::{MAX_CIDRS, MAX_PORT_SETS, MAX_UID_LITERALS};
    use sentinel_common::wire::{CidrEntry, PortRange};
    {
        let mut m = aya::maps::HashMap::<_, u64, u32>::try_from(
            bpf.map_mut("MOUNTS")
                .ok_or_else(|| anyhow::anyhow!("MOUNTS missing"))?,
        )?;
        for (slot, path) in t.mounts.iter().enumerate() {
            match mount_id_for(path)? {
                Some(id) => {
                    let cur = m.get(&id, 0).unwrap_or(0);
                    m.insert(&id, &(cur | slot_bit(slot)), 0)?;
                    eprintln!("mount slot {slot}: {path} -> mnt_id {id}");
                }
                None => eprintln!(
                    "warning: exe_on path {path} is not a mount point; rules on it cannot match"
                ),
            }
        }
    }
    {
        let mut a = aya::maps::Array::<_, PodCidr>::try_from(
            bpf.map_mut("CIDRS")
                .ok_or_else(|| anyhow::anyhow!("CIDRS missing"))?,
        )?;
        anyhow::ensure!(t.cidrs.len() <= MAX_CIDRS, "too many CIDRs");
        for (slot, net) in t.cidrs.iter().enumerate() {
            let mut e = CidrEntry {
                addr: [0; 16],
                prefix: net.prefix_len(),
                family: 0,
                slot: slot as u8,
                used: 1,
            };
            match net.network() {
                std::net::IpAddr::V4(v) => {
                    e.addr[..4].copy_from_slice(&v.octets());
                    e.family = 2;
                }
                std::net::IpAddr::V6(v) => {
                    e.addr = v.octets();
                    e.family = 10;
                }
            }
            a.set(slot as u32, &PodCidr(e), 0)?;
        }
    }
    {
        let mut a = aya::maps::Array::<_, PodPort>::try_from(
            bpf.map_mut("PORTS")
                .ok_or_else(|| anyhow::anyhow!("PORTS missing"))?,
        )?;
        let mut idx = 0u32;
        for (slot, set) in t.port_sets.iter().enumerate() {
            for &(lo, hi) in set {
                anyhow::ensure!((idx as usize) < MAX_PORT_SETS, "too many port ranges");
                let r = PortRange {
                    lo,
                    hi,
                    slot: slot as u8,
                    used: 1,
                    _pad: [0; 2],
                };
                a.set(idx, &PodPort(r), 0)?;
                idx += 1;
            }
        }
    }
    {
        let mut a = aya::maps::Array::<_, u32>::try_from(
            bpf.map_mut("UID_LITERALS")
                .ok_or_else(|| anyhow::anyhow!("UID_LITERALS missing"))?,
        )?;
        for i in 0..MAX_UID_LITERALS {
            // u32::MAX marks an unused slot (array default would be uid 0 = root).
            let v = t.uid_lits.get(i).copied().unwrap_or(u32::MAX);
            a.set(i as u32, &v, 0)?;
        }
    }
    Ok(())
}

/// Compile the rule pack (a directory of *.toml, default: the repo pack) with
/// the S1 `sentinel-rules` crate and write the kernel rules into RULES and
/// RULE_COUNT, then populate the lookup tables.
fn populate_rules(bpf: &mut aya::Ebpf) -> Result<()> {
    let dir = std::env::var("SENTINEL_RULES_DIR").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../manifest/sentinel/rules"
        )
        .to_string()
    });
    let rules = sentinel_rules::load_dir(std::path::Path::new(&dir)).map_err(|errs| {
        anyhow::anyhow!(
            "rule pack invalid: {}",
            errs.iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        )
    })?;
    let tables = sentinel_rules::compile::compile_kernel(&rules).map_err(|errs| {
        anyhow::anyhow!(
            "rule compile failed: {}",
            errs.iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        )
    })?;
    {
        let mut arr = aya::maps::Array::<_, PodRule>::try_from(
            bpf.map_mut("RULES")
                .ok_or_else(|| anyhow::anyhow!("RULES missing"))?,
        )?;
        for (i, kr) in tables.rules.iter().enumerate() {
            arr.set(i as u32, &PodRule(*kr), 0)?;
            eprintln!("rule {} -> {}", i, rules[kr.index as usize].id);
        }
    }
    populate_lookups(bpf, &tables)?;
    {
        let mut cnt = aya::maps::Array::<_, u32>::try_from(
            bpf.map_mut("RULE_COUNT")
                .ok_or_else(|| anyhow::anyhow!("RULE_COUNT missing"))?,
        )?;
        cnt.set(0, &(tables.rules.len() as u32), 0)?;
    }
    Ok(())
}

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
        usr_mnt_id: 0,
        _pad: 0,
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

/// connect() to a non-loopback address; returns errno (0 if it succeeded).
fn probe_connect() -> i32 {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
        if fd < 0 {
            return -1;
        }
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        sa.sin_family = libc::AF_INET as u16;
        sa.sin_port = 9u16.to_be();
        sa.sin_addr.s_addr = u32::from_ne_bytes([10, 0, 2, 2]);
        let r = libc::connect(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        let e = if r == 0 { 0 } else { *libc::__errno_location() };
        libc::close(fd);
        e
    }
}

fn quarantine_selftest() -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let data = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sentinel-ebpf"));
    let mut bpf = aya::Ebpf::load(data)?;
    let btf = aya::Btf::from_sys_fs()?;
    {
        let cfg = sentinel_common::wire::KConfig {
            lockdown_after_ns: 0,
            sentineld_tgid: std::process::id(),
            flags: sentinel_common::wire::CFG_ENFORCE,
            usr_mnt_id: 0,
            _pad: 0,
        };
        let mut config = aya::maps::Array::<_, PodConfig>::try_from(
            bpf.map_mut("CONFIG")
                .ok_or_else(|| anyhow::anyhow!("CONFIG missing"))?,
        )?;
        config.set(0, &PodConfig(cfg), 0)?;
    }
    // HEARTBEAT stays 0 => lockdown inactive (lockdown_after_ns irrelevant).
    attach_lsm(&mut bpf, &btf, "connect", "socket_connect")?;
    attach_lsm(&mut bpf, &btf, "sendmsg", "socket_sendmsg")?;

    let cg = "/sys/fs/cgroup/q";
    let _ = std::fs::create_dir(cg);
    let cgid = std::fs::metadata(cg)?.ino();
    {
        let mut q = aya::maps::HashMap::<_, u64, u8>::try_from(
            bpf.map_mut("QUARANTINE")
                .ok_or_else(|| anyhow::anyhow!("QUARANTINE missing"))?,
        )?;
        q.insert(&cgid, &1u8, 0)?;
    }
    eprintln!("quarantine: cgroup id {cgid}");

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        anyhow::bail!("fork failed");
    }
    if pid == 0 {
        let code =
            match std::fs::write(format!("{cg}/cgroup.procs"), std::process::id().to_string()) {
                Ok(()) => probe_connect(),
                Err(_) => 255,
            };
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let child = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    let parent = probe_connect();
    let _ = std::fs::remove_dir(cg);
    println!("quarantine: child errno {child}, parent errno {parent}");
    if child == libc::EPERM && parent != libc::EPERM {
        println!("quarantine: PASS");
        Ok(())
    } else {
        println!("quarantine: FAIL");
        std::process::exit(1);
    }
}

static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, std::sync::atomic::Ordering::Relaxed);
}

static STOP_HB: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn on_usr1(_: libc::c_int) {
    STOP_HB.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// mnt_id of the mount holding /usr/bin (longest mountinfo mount point that is a path prefix).
fn usr_mnt_id() -> Result<u32> {
    let info = std::fs::read_to_string("/proc/self/mountinfo")?;
    let target = "/usr/bin";
    let mut best: Option<(usize, u32)> = None;
    for line in info.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 5 {
            continue;
        }
        let mp = f[4];
        let is_prefix = mp == "/"
            || target == mp
            || (target.starts_with(mp) && target.as_bytes().get(mp.len()) == Some(&b'/'));
        if is_prefix && best.is_none_or(|(l, _)| mp.len() >= l) {
            best = Some((mp.len(), f[0].parse()?));
        }
    }
    best.map(|(_, id)| id)
        .ok_or_else(|| anyhow::anyhow!("no mount found for /usr"))
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
    use sentinel_common::facts::{F_DELETED, F_LISTEN_NON_LOOPBACK, F_MEMFD, G_FLAGS};
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
    } else if h.kind == EventKind::Connect as u8 || h.kind == EventKind::Listen as u8 {
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
        if h.kind == EventKind::Listen as u8 {
            format!(
                ",\"family\":{},\"laddr\":\"{}\",\"port\":{},\"flags_listen_nonloopback\":{}",
                n.family,
                addr,
                n.port,
                flags & F_LISTEN_NON_LOOPBACK != 0
            )
        } else {
            format!(
                ",\"family\":{},\"addr\":\"{}\",\"port\":{}",
                n.family, addr, n.port
            )
        }
    } else if h.kind == EventKind::Exec as u8 {
        // SAFETY: for Exec events the kernel side wrote the exec variant.
        let x = unsafe { ev.payload.exec };
        format!(",\"mnt_id\":{}", x.mnt_id)
    } else if h.kind == EventKind::Open as u8 {
        // SAFETY: for Open events the kernel side wrote the open variant.
        let o = unsafe { ev.payload.open };
        let label = match o.dev_class {
            1 => "camera",
            2 => "mic",
            3 => "input",
            4 => "uinput",
            5 => "hidraw",
            _ => "none",
        };
        let n = (o.path_len as usize).min(64);
        let name = String::from_utf8_lossy(&o.path[..n]).replace(['"', '\\'], "?");
        format!(
            ",\"dev_class\":{},\"device\":\"{}\",\"name\":\"{}\"",
            o.dev_class, label, name
        )
    } else if h.kind == EventKind::WriteRefused as u8 {
        // SAFETY: for WriteRefused events the kernel side wrote the open variant.
        let o = unsafe { ev.payload.open };
        let n = (o.path_len as usize).min(o.path.len());
        let path = String::from_utf8_lossy(&o.path[..n]).replace(['"', '\\'], "?");
        format!(",\"path\":\"{}\"", path)
    } else if h.kind == EventKind::Ptrace as u8 {
        use sentinel_common::facts::{G_PTRACE, P_ANY, P_NON_DESCENDANT, P_OTHER_UID};
        // SAFETY: for Ptrace events the kernel side wrote the ptrace variant.
        let t = unsafe { ev.payload.ptrace };
        let pf = h.facts[G_PTRACE];
        format!(
            ",\"target_pid\":{},\"target_uid\":{},\"mode\":{},\"p_any\":{},\"p_other_uid\":{},\"p_non_descendant\":{}",
            t.target_pid,
            t.target_uid,
            t.mode,
            pf & P_ANY != 0,
            pf & P_OTHER_UID != 0,
            pf & P_NON_DESCENDANT != 0
        )
    } else if h.kind == EventKind::Module as u8 {
        // SAFETY: for Module events the kernel side wrote the module variant.
        let m = unsafe { ev.payload.module };
        let end = m.name.iter().position(|b| *b == 0).unwrap_or(m.name.len());
        let name = String::from_utf8_lossy(&m.name[..end]).replace(['"', '\\'], "?");
        format!(",\"read_id\":{},\"module_name\":\"{}\"", m.read_id, name)
    } else if h.kind == EventKind::Bpf as u8 {
        // SAFETY: for Bpf events the kernel side wrote the bpf variant.
        let b = unsafe { ev.payload.bpf };
        format!(",\"bpf_cmd\":{},\"prog_type\":{}", b.cmd, b.prog_type)
    } else if h.kind == EventKind::Signal as u8 {
        // SAFETY: for Signal events the kernel side wrote the signal variant.
        let s = unsafe { ev.payload.signal };
        format!(",\"target_pid\":{},\"sig\":{}", s.target_pid, s.sig)
    } else if h.kind == EventKind::Memfd as u8 {
        // SAFETY: for Memfd events the kernel side wrote the memfd variant.
        let m = unsafe { ev.payload.memfd };
        let end = m.name.iter().position(|b| *b == 0).unwrap_or(m.name.len());
        let name = String::from_utf8_lossy(&m.name[..end]).replace(['"', '\\'], "?");
        format!(",\"memfd_name\":\"{}\",\"memfd_flags\":{}", name, m.flags)
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

fn load(enforce: bool, selfguard: bool, guard_dir: Option<std::path::PathBuf>) -> Result<()> {
    use std::io::Write;
    use std::sync::atomic::Ordering;

    let data = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sentinel-ebpf"));
    let mut bpf = aya::Ebpf::load(data)?;
    let btf = aya::Btf::from_sys_fs()?;
    {
        let usr = usr_mnt_id()?;
        eprintln!("load: /usr mnt_id {usr}");
        let cfg = sentinel_common::wire::KConfig {
            lockdown_after_ns: 1_500_000_000,
            sentineld_tgid: std::process::id(),
            flags: (if enforce {
                sentinel_common::wire::CFG_ENFORCE
            } else {
                0
            }) | (if selfguard {
                sentinel_common::wire::CFG_SELFGUARD
            } else {
                0
            }),
            usr_mnt_id: usr,
            _pad: 0,
        };
        let mut config = aya::maps::Array::<_, PodConfig>::try_from(
            bpf.map_mut("CONFIG")
                .ok_or_else(|| anyhow::anyhow!("CONFIG missing"))?,
        )?;
        config.set(0, &PodConfig(cfg), 0)?;
    }
    let mut hb_map = aya::maps::Array::<_, u64>::try_from(
        bpf.take_map("HEARTBEAT")
            .ok_or_else(|| anyhow::anyhow!("HEARTBEAT missing"))?,
    )?;
    hb_map.set(0, &monotonic_ns(), 0)?;
    populate_rules(&mut bpf)?;
    if let Some(dir) = guard_dir {
        use std::os::unix::fs::MetadataExt;
        let mut inodes = aya::maps::HashMap::<_, u64, u8>::try_from(
            bpf.map_mut("GUARDED_INODES")
                .ok_or_else(|| anyhow::anyhow!("GUARDED_INODES missing"))?,
        )?;
        inodes.insert(&std::fs::metadata(&dir)?.ino(), &1u8, 0)?;
        for ent in std::fs::read_dir(&dir)? {
            inodes.insert(&std::fs::metadata(ent?.path())?.ino(), &1u8, 0)?;
        }
    }
    attach_lsm(&mut bpf, &btf, "exec", "bprm_check_security")?;
    attach_lsm(&mut bpf, &btf, "connect", "socket_connect")?;
    attach_lsm(&mut bpf, &btf, "sendmsg", "socket_sendmsg")?;
    attach_lsm(&mut bpf, &btf, "listen", "socket_listen")?;
    attach_lsm(&mut bpf, &btf, "open", "file_open")?;
    attach_lsm(&mut bpf, &btf, "ptrace", "ptrace_access_check")?;
    attach_lsm(&mut bpf, &btf, "module_read", "kernel_read_file")?;
    attach_lsm(&mut bpf, &btf, "module_data", "kernel_load_data")?;
    attach_lsm(&mut bpf, &btf, "signal", "task_kill")?;
    attach_lsm(&mut bpf, &btf, "guard_unlink", "inode_unlink")?;
    attach_lsm(&mut bpf, &btf, "guard_rename", "inode_rename")?;
    attach_lsm(&mut bpf, &btf, "guard_truncate", "path_truncate")?;
    attach_btf_tp(&mut bpf, &btf, "fork", "sched_process_fork")?;
    attach_btf_tp(&mut bpf, &btf, "exit", "sched_process_exit")?;

    {
        let prog: &mut aya::programs::FExit = bpf
            .program_mut("write_refused")
            .ok_or_else(|| anyhow::anyhow!("program write_refused missing"))?
            .try_into()?;
        prog.load("path_openat", &btf)?;
        prog.attach()?;
    }
    {
        let prog: &mut aya::programs::TracePoint = bpf
            .program_mut("memfd")
            .ok_or_else(|| anyhow::anyhow!("program memfd missing"))?
            .try_into()?;
        prog.load()?;
        prog.attach("syscalls", "sys_enter_memfd_create")?;
    }

    let mut ring = aya::maps::RingBuf::try_from(
        bpf.take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("EVENTS missing"))?,
    )?;

    // Attach last so the loader's own setup bpf() calls are not observed.
    attach_lsm(&mut bpf, &btf, "bpf", "bpf")?;

    // SAFETY: the handler only stores to an atomic (async-signal-safe).
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }
    // Heartbeat thread: refreshes HEARTBEAT[0] until SIGUSR1 (then the
    // heartbeat goes stale and the kernel side locks down).
    // SAFETY: the handler only stores to an atomic (async-signal-safe).
    unsafe {
        libc::signal(libc::SIGUSR1, on_usr1 as *const () as libc::sighandler_t);
    }
    std::thread::spawn(move || {
        while !STOP_HB.load(Ordering::Relaxed) {
            let _ = hb_map.set(0, &monotonic_ns(), 0);
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    });
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
