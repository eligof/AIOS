//! The real [`Kernel`]: loads the embedded object, attaches every program,
//! pins everything under `/sys/fs/bpf/aios-sentinel/` (spec §8.1, §12).

use std::path::{Path, PathBuf};

use crate::kernel::{Kernel, KernelError, NHOOKS};

/// Where programs, links and maps are pinned (spec §8.1).
pub const PIN_ROOT: &str = "/sys/fs/bpf/aios-sentinel";

/// Every map the daemon binds, from the S2 ABI.
pub const MAP_NAMES: [&str; 13] = [
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

/// LSM programs as `(program name, kernel hook name)`. `Lsm::load` takes the
/// **hook** name (§17.7). `bpf` is last on purpose: attaching it earlier would
/// make the loader observe its own setup `bpf()` calls.
pub const LSM_PROGRAMS: [(&str, &str); 13] = [
    ("exec", "bprm_check_security"),
    ("connect", "socket_connect"),
    ("sendmsg", "socket_sendmsg"),
    ("listen", "socket_listen"),
    ("open", "file_open"),
    ("ptrace", "ptrace_access_check"),
    ("module_read", "kernel_read_file"),
    ("module_data", "kernel_load_data"),
    ("signal", "task_kill"),
    ("guard_unlink", "inode_unlink"),
    ("guard_rename", "inode_rename"),
    ("guard_truncate", "path_truncate"),
    ("bpf", "bpf"),
];

/// The non-LSM programs: two BTF tracepoints, one fexit, one tracepoint.
pub const OTHER_PROGRAMS: [&str; 4] = ["fork", "exit", "write_refused", "memfd"];

/// The programs whose links can be pinned, and so survive a restart.
///
/// `memfd` is missing on purpose: it attaches through a perf event, and aya
/// gives no `FdLink` for a `TracePointLink`, so there is nothing to pin. A
/// restart that reuses the pins therefore re-attaches that one program —
/// cheap, and the alternative is losing memfd events after every restart.
pub const PINNED_LINKS: [&str; 16] = [
    "exec",
    "connect",
    "sendmsg",
    "listen",
    "open",
    "ptrace",
    "module_read",
    "module_data",
    "signal",
    "guard_unlink",
    "guard_rename",
    "guard_truncate",
    "bpf",
    "fork",
    "exit",
    "write_refused",
];

pub fn map_pin_path(name: &str) -> PathBuf {
    Path::new(PIN_ROOT).join("maps").join(name)
}

pub fn link_pin_path(program: &str) -> PathBuf {
    Path::new(PIN_ROOT).join("links").join(program)
}

/// Is a complete pin set already in place — that is, did a previous instance
/// attach everything (spec §8.1)?
pub fn pins_complete(root: &Path) -> bool {
    MAP_NAMES.iter().all(|m| root.join("maps").join(m).exists())
        && PINNED_LINKS
            .iter()
            .all(|p| root.join("links").join(p).exists())
}

/// The cgroup v2 path out of a `/proc/<pid>/cgroup` body.
pub fn cgroup_rel(body: &str) -> String {
    body.lines()
        .next()
        .and_then(|l| l.rsplit("::").next())
        .filter(|s| !s.is_empty())
        .unwrap_or("/")
        .to_string()
}

fn ke<T>(msg: impl Into<String>) -> Result<T, KernelError> {
    Err(KernelError(msg.into()))
}

/// Local newtypes, because `aya::Pod` is a foreign trait and the wire types
/// are foreign too (the same workaround `ebpf-loadtest` uses).
#[derive(Clone, Copy)]
#[repr(transparent)]
struct PodConfig(sentinel_common::wire::KConfig);
// SAFETY: KConfig is repr(C), Copy, fully initialised plain data.
unsafe impl aya::Pod for PodConfig {}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct PodRule(sentinel_common::rule::KRule);
// SAFETY: KRule is repr(C), Copy, fully initialised plain data.
unsafe impl aya::Pod for PodRule {}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct PodCidr(sentinel_common::wire::CidrEntry);
// SAFETY: CidrEntry is repr(C), Copy, plain data with no padding.
unsafe impl aya::Pod for PodCidr {}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct PodPort(sentinel_common::wire::PortRange);
// SAFETY: PortRange is repr(C), Copy, with an explicit padding field.
unsafe impl aya::Pod for PodPort {}

/// Whether the LSM half attached (spec §12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Full,
    /// Tracing works, LSM does not: no deny, no self-guard, no lockdown.
    Degraded,
}

pub struct RealKernel {
    bpf: aya::Ebpf,
    pub mode: Mode,
    pub attached: Vec<String>,
    /// Taken out of `bpf` so the drain thread can own it.
    pub ring: Option<aya::maps::RingBuf<aya::maps::MapData>>,
    /// True when this instance re-used a previous instance's pins and so did
    /// not attach anything itself (spec §8.1: a restart leaves no gap). Every
    /// map access then has to go through the pins, because the freshly loaded
    /// object's own maps are not the ones the attached programs read.
    pub reused_pins: bool,
}

impl RealKernel {
    /// Load, configure, attach and pin. `enforce` and `selfguard` set the
    /// `CONFIG` flags; `guarded` seeds `GUARDED_INODES` (spec §8.2).
    pub fn load(
        lockdown_after_ns: u64,
        enforce: bool,
        selfguard: bool,
        tables: &sentinel_rules::compile::Tables,
        guarded: &[PathBuf],
    ) -> Result<RealKernel, KernelError> {
        use aya::programs::{BtfTracePoint, FExit, Lsm};

        let cfg = sentinel_common::wire::KConfig {
            lockdown_after_ns,
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
            usr_mnt_id: usr_mnt_id()?,
            _pad: 0,
        };

        let reuse = pins_complete(Path::new(PIN_ROOT));

        let data = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sentinel-ebpf"));
        let mut bpf = match aya::Ebpf::load(data) {
            Ok(b) => b,
            Err(e) => return ke(format!("cannot load the eBPF object: {e}")),
        };
        let btf = match aya::Btf::from_sys_fs() {
            Ok(b) => b,
            Err(e) => return ke(format!("BTF is unavailable: {e}")),
        };

        for sub in ["maps", "links"] {
            if let Err(e) = std::fs::create_dir_all(Path::new(PIN_ROOT).join(sub)) {
                return ke(format!("cannot create {PIN_ROOT}/{sub}: {e}"));
            }
        }

        // A complete pin set means the previous instance is still attached.
        // Re-open its maps rather than attaching again, so a restart leaves no
        // window in which nothing is observing (spec §8.1). Only `memfd` is
        // attached here, because a perf-event link cannot be pinned.
        if reuse {
            let ring = aya::maps::RingBuf::try_from(pinned_map("EVENTS")?)
                .map_err(|e| KernelError(format!("pinned EVENTS: {e}")))?;
            let mut k = RealKernel {
                bpf,
                mode: Mode::Full,
                attached: PINNED_LINKS.iter().map(|p| (*p).to_string()).collect(),
                ring: Some(ring),
                reused_pins: true,
            };
            k.config(cfg)?;
            k.swap_rules(tables)?;
            k.seed_guarded(guarded)?;
            k.attach_memfd()?;
            return Ok(k);
        }

        // 1. CONFIG, before attaching anything.
        set_array(&mut bpf, "CONFIG", 0, PodConfig(cfg))?;

        // 2. Rules and lookup tables.
        write_tables(&mut bpf, tables)?;

        // 3. Guarded inodes (the alert store and the pin directory).
        seed_guarded_inodes(&mut bpf, guarded)?;

        // 4. Pin every map, before EVENTS is taken for the drain thread: a
        //    `RingBuf` has no pin of its own, only the `Map` it came from.
        pin_maps(&bpf)?;

        // 5. Attach. The tracing programs first: if LSM fails we still observe.
        let mut attached = Vec::new();
        for (name, tp) in [
            ("fork", "sched_process_fork"),
            ("exit", "sched_process_exit"),
        ] {
            let prog: &mut BtfTracePoint =
                match bpf.program_mut(name).and_then(|p| p.try_into().ok()) {
                    Some(p) => p,
                    None => return ke(format!("program {name} missing")),
                };
            prog.load(tp, &btf)
                .map_err(|e| KernelError(format!("{name}: {e}")))?;
            let id = prog
                .attach()
                .map_err(|e| KernelError(format!("{name}: {e}")))?;
            let link = prog
                .take_link(id)
                .map_err(|e| KernelError(format!("{name}: {e}")))?;
            pin_link(link.into(), name)?;
            attached.push(name.to_string());
        }
        {
            let prog: &mut FExit = match bpf
                .program_mut("write_refused")
                .and_then(|p| p.try_into().ok())
            {
                Some(p) => p,
                None => return ke("program write_refused missing"),
            };
            prog.load("path_openat", &btf)
                .map_err(|e| KernelError(format!("write_refused: {e}")))?;
            let id = prog
                .attach()
                .map_err(|e| KernelError(format!("write_refused: {e}")))?;
            let link = prog
                .take_link(id)
                .map_err(|e| KernelError(format!("write_refused: {e}")))?;
            pin_link(link.into(), "write_refused")?;
            attached.push("write_refused".to_string());
        }
        attach_memfd_on(&mut bpf)?;
        attached.push("memfd".to_string());

        // The ring is taken before the bpf self-guard attaches, exactly as the
        // reference loader does.
        let ring = aya::maps::RingBuf::try_from(
            bpf.take_map("EVENTS")
                .ok_or_else(|| KernelError("EVENTS missing".to_string()))?,
        )
        .map_err(|e| KernelError(format!("EVENTS: {e}")))?;

        let mut mode = Mode::Full;
        for (name, hook) in LSM_PROGRAMS {
            let Some(prog) = bpf.program_mut(name) else {
                return ke(format!("program {name} missing"));
            };
            let prog: &mut Lsm = match prog.try_into() {
                Ok(p) => p,
                Err(e) => return ke(format!("{name} is not an LSM program: {e}")),
            };
            let one = prog
                .load(hook, &btf)
                .map_err(|e| e.to_string())
                .and_then(|()| prog.attach().map_err(|e| e.to_string()));
            match one {
                Ok(id) => {
                    let link = prog
                        .take_link(id)
                        .map_err(|e| KernelError(format!("{name}: {e}")))?;
                    pin_link(link.into(), name)?;
                    attached.push(name.to_string());
                }
                Err(e) => {
                    // Spec §12: tracing works, LSM does not — observe only.
                    eprintln!("sentineld: LSM {name} ({hook}) did not attach: {e}");
                    mode = Mode::Degraded;
                    break;
                }
            }
        }

        Ok(RealKernel {
            bpf,
            mode,
            attached,
            ring: Some(ring),
            reused_pins: false,
        })
    }

    /// Attach `memfd`, the one program whose link cannot be pinned.
    fn attach_memfd(&mut self) -> Result<(), KernelError> {
        attach_memfd_on(&mut self.bpf)
    }

    /// Write `CONFIG`, the one map that must reflect *this* process: its tgid
    /// is what the self-guard compares against.
    fn config(&mut self, cfg: sentinel_common::wire::KConfig) -> Result<(), KernelError> {
        if self.reused_pins {
            let mut m = pinned_array::<PodConfig>("CONFIG")?;
            return m
                .set(0, &PodConfig(cfg), 0)
                .map_err(|e| KernelError(format!("pinned CONFIG: {e}")));
        }
        set_array(&mut self.bpf, "CONFIG", 0, PodConfig(cfg))
    }

    fn seed_guarded(&mut self, guarded: &[PathBuf]) -> Result<(), KernelError> {
        if !self.reused_pins {
            return seed_guarded_inodes(&mut self.bpf, guarded);
        }
        use std::os::unix::fs::MetadataExt;
        if guarded.is_empty() {
            return Ok(());
        }
        let mut m = pinned_hash::<u64, u8>("GUARDED_INODES")?;
        for p in guarded {
            if let Ok(meta) = std::fs::metadata(p) {
                let _ = m.insert(&meta.ino(), &1u8, 0);
            }
        }
        Ok(())
    }

    /// Take the ring buffer for the drain thread.
    pub fn take_ring(&mut self) -> Option<aya::maps::RingBuf<aya::maps::MapData>> {
        self.ring.take()
    }
}

/// Pin every map so the kernel side outlives this process (spec §8.1).
/// Already-pinned paths are left alone.
fn pin_maps(bpf: &aya::Ebpf) -> Result<(), KernelError> {
    for name in MAP_NAMES {
        let path = map_pin_path(name);
        if path.exists() {
            continue;
        }
        if let Some(m) = bpf.map(name) {
            if let Err(e) = m.pin(&path) {
                return ke(format!("cannot pin map {name}: {e}"));
            }
        }
    }
    Ok(())
}

/// Load and attach the memfd tracepoint. Its link is a perf event, which has
/// no `FdLink`, so there is nothing to pin and a restart re-attaches it.
fn attach_memfd_on(bpf: &mut aya::Ebpf) -> Result<(), KernelError> {
    let prog: &mut aya::programs::TracePoint =
        match bpf.program_mut("memfd").and_then(|p| p.try_into().ok()) {
            Some(p) => p,
            None => return ke("program memfd missing"),
        };
    prog.load()
        .map_err(|e| KernelError(format!("memfd: {e}")))?;
    prog.attach("syscalls", "sys_enter_memfd_create")
        .map(|_| ())
        .map_err(|e| KernelError(format!("memfd: {e}")))
}

/// Pin one link, leaving an existing pin in place.
fn pin_link(link: aya::programs::links::FdLink, name: &str) -> Result<(), KernelError> {
    let path = link_pin_path(name);
    if path.exists() {
        return Ok(());
    }
    link.pin(&path)
        .map(|_| ())
        .map_err(|e| KernelError(format!("cannot pin link {name}: {e}")))
}

fn array<'a, T: aya::Pod>(
    bpf: &'a mut aya::Ebpf,
    name: &'static str,
) -> Result<aya::maps::Array<&'a mut aya::maps::MapData, T>, KernelError> {
    let m = bpf
        .map_mut(name)
        .ok_or_else(|| KernelError(format!("{name} missing")))?;
    aya::maps::Array::try_from(m).map_err(|e| KernelError(format!("{name}: {e}")))
}

/// One map re-opened from its pin. `Map::from_map_data` is aya's documented
/// route from a `MapData` obtained with `from_pin` to a typed handle.
fn pinned_map(name: &str) -> Result<aya::maps::Map, KernelError> {
    let data = aya::maps::MapData::from_pin(map_pin_path(name))
        .map_err(|e| KernelError(format!("pinned {name}: {e}")))?;
    aya::maps::Map::from_map_data(data).map_err(|e| KernelError(format!("pinned {name}: {e}")))
}

/// An array map re-opened from its pin, for the restart path.
fn pinned_array<T: aya::Pod>(
    name: &'static str,
) -> Result<aya::maps::Array<aya::maps::MapData, T>, KernelError> {
    aya::maps::Array::try_from(pinned_map(name)?)
        .map_err(|e| KernelError(format!("pinned {name}: {e}")))
}

/// A hash map re-opened from its pin, for the restart path.
fn pinned_hash<K: aya::Pod, V: aya::Pod>(
    name: &'static str,
) -> Result<aya::maps::HashMap<aya::maps::MapData, K, V>, KernelError> {
    aya::maps::HashMap::try_from(pinned_map(name)?)
        .map_err(|e| KernelError(format!("pinned {name}: {e}")))
}

fn hash_map<'a, K: aya::Pod, V: aya::Pod>(
    bpf: &'a mut aya::Ebpf,
    name: &'static str,
) -> Result<aya::maps::HashMap<&'a mut aya::maps::MapData, K, V>, KernelError> {
    let m = bpf
        .map_mut(name)
        .ok_or_else(|| KernelError(format!("{name} missing")))?;
    aya::maps::HashMap::try_from(m).map_err(|e| KernelError(format!("{name}: {e}")))
}

fn set_array<T: aya::Pod>(
    bpf: &mut aya::Ebpf,
    name: &'static str,
    index: u32,
    value: T,
) -> Result<(), KernelError> {
    let mut a = array::<T>(bpf, name)?;
    a.set(index, &value, 0)
        .map_err(|e| KernelError(format!("{name}[{index}]: {e}")))
}

fn seed_guarded_inodes(bpf: &mut aya::Ebpf, guarded: &[PathBuf]) -> Result<(), KernelError> {
    use std::os::unix::fs::MetadataExt;
    if guarded.is_empty() {
        return Ok(());
    }
    let mut m = hash_map::<u64, u8>(bpf, "GUARDED_INODES")?;
    for p in guarded {
        if let Ok(meta) = std::fs::metadata(p) {
            let _ = m.insert(&meta.ino(), &1u8, 0);
        }
    }
    Ok(())
}

/// mnt_id of the mount holding `/usr/bin` (longest matching mount point).
/// Copied from the reference loader; lockdown allows exec only from here.
fn usr_mnt_id() -> Result<u32, KernelError> {
    let info = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|e| KernelError(format!("mountinfo: {e}")))?;
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
            if let Ok(id) = f[0].parse() {
                best = Some((mp.len(), id));
            }
        }
    }
    best.map(|(_, id)| id)
        .ok_or_else(|| KernelError("no mount found for /usr".to_string()))
}

/// Write RULES, the lookup tables, then RULE_COUNT — count last, so a hook
/// never walks a half-written set.
fn write_tables(
    bpf: &mut aya::Ebpf,
    t: &sentinel_rules::compile::Tables,
) -> Result<(), KernelError> {
    use sentinel_common::facts::slot_bit;
    use sentinel_common::rule::{MAX_CIDRS, MAX_PORT_SETS, MAX_UID_LITERALS};
    use sentinel_common::wire::{CidrEntry, PortRange};

    {
        let mut a = array::<PodRule>(bpf, "RULES")?;
        for (i, kr) in t.rules.iter().enumerate() {
            a.set(i as u32, &PodRule(*kr), 0)
                .map_err(|e| KernelError(format!("RULES[{i}]: {e}")))?;
        }
    }
    {
        let mut m = hash_map::<u64, u32>(bpf, "MOUNTS")?;
        for (slot, path) in t.mounts.iter().enumerate() {
            match mount_id_for(path) {
                Some(id) => {
                    let cur = m.get(&id, 0).unwrap_or(0);
                    let _ = m.insert(&id, &(cur | slot_bit(slot)), 0);
                }
                None => eprintln!(
                    "sentineld: exe_on path {path} is not a mount point; rules on it cannot match"
                ),
            }
        }
    }
    {
        let mut a = array::<PodCidr>(bpf, "CIDRS")?;
        if t.cidrs.len() > MAX_CIDRS {
            return ke("too many CIDRs");
        }
        for (slot, net) in t.cidrs.iter().enumerate() {
            a.set(slot as u32, &PodCidr(cidr_entry(net, slot)), 0)
                .map_err(|err| KernelError(format!("CIDRS[{slot}]: {err}")))?;
        }
        let _ = std::mem::size_of::<CidrEntry>();
    }
    {
        let mut a = array::<PodPort>(bpf, "PORTS")?;
        let mut idx = 0u32;
        for (slot, set) in t.port_sets.iter().enumerate() {
            for &(lo, hi) in set {
                if idx as usize >= MAX_PORT_SETS {
                    return ke("too many port ranges");
                }
                a.set(
                    idx,
                    &PodPort(PortRange {
                        lo,
                        hi,
                        slot: slot as u8,
                        used: 1,
                        _pad: [0; 2],
                    }),
                    0,
                )
                .map_err(|e| KernelError(format!("PORTS[{idx}]: {e}")))?;
                idx += 1;
            }
        }
    }
    {
        let mut a = array::<u32>(bpf, "UID_LITERALS")?;
        for i in 0..MAX_UID_LITERALS {
            // u32::MAX marks an unused slot: an unwritten slot reads 0, which
            // would match root (§17.7).
            let v = t.uid_lits.get(i).copied().unwrap_or(u32::MAX);
            a.set(i as u32, &v, 0)
                .map_err(|e| KernelError(format!("UID_LITERALS[{i}]: {e}")))?;
        }
    }
    set_array(bpf, "RULE_COUNT", 0, t.rules.len() as u32)
}

/// One `CIDRS` entry for a compiled network.
fn cidr_entry(net: &ipnet::IpNet, slot: usize) -> sentinel_common::wire::CidrEntry {
    let mut e = sentinel_common::wire::CidrEntry {
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
    e
}

/// `write_tables` against the pinned maps, for a restart that reused the pins:
/// the loaded object's own maps are not the ones the attached programs read.
fn write_tables_pinned(t: &sentinel_rules::compile::Tables) -> Result<(), KernelError> {
    use sentinel_common::facts::slot_bit;
    use sentinel_common::rule::{MAX_CIDRS, MAX_PORT_SETS, MAX_UID_LITERALS};
    use sentinel_common::wire::PortRange;

    {
        let mut a = pinned_array::<PodRule>("RULES")?;
        for (i, kr) in t.rules.iter().enumerate() {
            a.set(i as u32, &PodRule(*kr), 0)
                .map_err(|e| KernelError(format!("RULES[{i}]: {e}")))?;
        }
    }
    {
        let mut m = pinned_hash::<u64, u32>("MOUNTS")?;
        for (slot, path) in t.mounts.iter().enumerate() {
            if let Some(id) = mount_id_for(path) {
                let cur = m.get(&id, 0).unwrap_or(0);
                let _ = m.insert(&id, &(cur | slot_bit(slot)), 0);
            }
        }
    }
    {
        let mut a = pinned_array::<PodCidr>("CIDRS")?;
        if t.cidrs.len() > MAX_CIDRS {
            return ke("too many CIDRs");
        }
        for (slot, net) in t.cidrs.iter().enumerate() {
            a.set(slot as u32, &PodCidr(cidr_entry(net, slot)), 0)
                .map_err(|err| KernelError(format!("CIDRS[{slot}]: {err}")))?;
        }
    }
    {
        let mut a = pinned_array::<PodPort>("PORTS")?;
        let mut idx = 0u32;
        for (slot, set) in t.port_sets.iter().enumerate() {
            for &(lo, hi) in set {
                if idx as usize >= MAX_PORT_SETS {
                    return ke("too many port ranges");
                }
                a.set(
                    idx,
                    &PodPort(PortRange {
                        lo,
                        hi,
                        slot: slot as u8,
                        used: 1,
                        _pad: [0; 2],
                    }),
                    0,
                )
                .map_err(|e| KernelError(format!("PORTS[{idx}]: {e}")))?;
                idx += 1;
            }
        }
    }
    {
        let mut a = pinned_array::<u32>("UID_LITERALS")?;
        for i in 0..MAX_UID_LITERALS {
            let v = t.uid_lits.get(i).copied().unwrap_or(u32::MAX);
            a.set(i as u32, &v, 0)
                .map_err(|e| KernelError(format!("UID_LITERALS[{i}]: {e}")))?;
        }
    }
    let mut a = pinned_array::<u32>("RULE_COUNT")?;
    a.set(0, &(t.rules.len() as u32), 0)
        .map_err(|e| KernelError(format!("RULE_COUNT: {e}")))
}

/// mnt_id of the mount whose mount point is exactly `path` (`exe_on` needs an
/// exact match; longest-prefix would map everything to `/`, §17.7).
fn mount_id_for(path: &str) -> Option<u64> {
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.into());
    let canon = canon.to_string_lossy().into_owned();
    let info = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut found = None;
    for line in info.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        if f.len() < 5 {
            continue;
        }
        if f[4].replace("\\040", " ") == canon {
            found = f[0].parse::<u64>().ok();
        }
    }
    found
}

fn monotonic_ns_now() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid out-pointer; CLOCK_MONOTONIC matches bpf_ktime_get_ns.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

impl Kernel for RealKernel {
    fn monotonic_ns(&self) -> u64 {
        monotonic_ns_now()
    }

    fn wall_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn heartbeat(&mut self, ns: u64) -> Result<(), KernelError> {
        if self.reused_pins {
            let mut a = pinned_array::<u64>("HEARTBEAT")?;
            return a
                .set(0, &ns, 0)
                .map_err(|e| KernelError(format!("pinned HEARTBEAT: {e}")));
        }
        set_array(&mut self.bpf, "HEARTBEAT", 0, ns)
    }

    fn heartbeat_value(&self) -> Result<u64, KernelError> {
        if self.reused_pins {
            let a = pinned_array::<u64>("HEARTBEAT")?;
            return a
                .get(&0, 0)
                .map_err(|e| KernelError(format!("pinned HEARTBEAT: {e}")));
        }
        let m = self
            .bpf
            .map("HEARTBEAT")
            .ok_or_else(|| KernelError("HEARTBEAT missing".to_string()))?;
        let a = aya::maps::Array::<_, u64>::try_from(m)
            .map_err(|e| KernelError(format!("HEARTBEAT: {e}")))?;
        a.get(&0, 0)
            .map_err(|e| KernelError(format!("HEARTBEAT: {e}")))
    }

    fn drops(&self) -> Result<u64, KernelError> {
        let per_cpu = if self.reused_pins {
            let a = aya::maps::PerCpuArray::<_, u64>::try_from(pinned_map("DROPS")?)
                .map_err(|e| KernelError(format!("pinned DROPS: {e}")))?;
            a.get(&0, 0)
                .map_err(|e| KernelError(format!("DROPS: {e}")))?
        } else {
            let m = self
                .bpf
                .map("DROPS")
                .ok_or_else(|| KernelError("DROPS missing".to_string()))?;
            let a = aya::maps::PerCpuArray::<_, u64>::try_from(m)
                .map_err(|e| KernelError(format!("DROPS: {e}")))?;
            a.get(&0, 0)
                .map_err(|e| KernelError(format!("DROPS: {e}")))?
        };
        Ok(per_cpu.iter().sum())
    }

    fn lockdown_counts(&self) -> Result<[u64; NHOOKS], KernelError> {
        let mut out = [0u64; NHOOKS];
        if self.reused_pins {
            let a = pinned_array::<u64>("LOCKDOWN_COUNTS")?;
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = a.get(&(i as u32), 0).unwrap_or(0);
            }
            return Ok(out);
        }
        let m = self
            .bpf
            .map("LOCKDOWN_COUNTS")
            .ok_or_else(|| KernelError("LOCKDOWN_COUNTS missing".to_string()))?;
        let a = aya::maps::Array::<_, u64>::try_from(m)
            .map_err(|e| KernelError(format!("LOCKDOWN_COUNTS: {e}")))?;
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = a.get(&(i as u32), 0).unwrap_or(0);
        }
        Ok(out)
    }

    fn swap_rules(&mut self, tables: &sentinel_rules::compile::Tables) -> Result<(), KernelError> {
        if self.reused_pins {
            return write_tables_pinned(tables);
        }
        write_tables(&mut self.bpf, tables)
    }

    fn quarantine_add(&mut self, cgroup_id: u64) -> Result<(), KernelError> {
        if self.reused_pins {
            let mut m = pinned_hash::<u64, u8>("QUARANTINE")?;
            return m
                .insert(&cgroup_id, &1u8, 0)
                .map_err(|e| KernelError(format!("QUARANTINE insert: {e}")));
        }
        let mut m = hash_map::<u64, u8>(&mut self.bpf, "QUARANTINE")?;
        m.insert(&cgroup_id, &1u8, 0)
            .map_err(|e| KernelError(format!("QUARANTINE insert: {e}")))
    }

    fn quarantine_remove(&mut self, cgroup_id: u64) -> Result<(), KernelError> {
        if self.reused_pins {
            let mut m = pinned_hash::<u64, u8>("QUARANTINE")?;
            return m
                .remove(&cgroup_id)
                .map_err(|e| KernelError(format!("QUARANTINE remove: {e}")));
        }
        let mut m = hash_map::<u64, u8>(&mut self.bpf, "QUARANTINE")?;
        m.remove(&cgroup_id)
            .map_err(|e| KernelError(format!("QUARANTINE remove: {e}")))
    }

    fn cgroup_create(&mut self, path: &str) -> Result<u64, KernelError> {
        use std::os::unix::fs::MetadataExt;
        if let Err(e) = std::fs::create_dir_all(path) {
            return ke(format!("cgroup_create {path}: {e}"));
        }
        std::fs::metadata(path)
            .map(|m| m.ino())
            .map_err(|e| KernelError(format!("cgroup_create {path}: {e}")))
    }

    fn cgroup_remove(&mut self, path: &str) -> Result<(), KernelError> {
        std::fs::remove_dir(path).map_err(|e| KernelError(format!("cgroup_remove {path}: {e}")))
    }

    fn cgroup_attach(&mut self, path: &str, pid: u32) -> Result<(), KernelError> {
        std::fs::write(format!("{path}/cgroup.procs"), pid.to_string())
            .map_err(|e| KernelError(format!("cgroup_attach {path} {pid}: {e}")))
    }

    fn cgroup_freeze(&mut self, path: &str, on: bool) -> Result<(), KernelError> {
        std::fs::write(format!("{path}/cgroup.freeze"), if on { "1" } else { "0" })
            .map_err(|e| KernelError(format!("cgroup_freeze {path}: {e}")))
    }

    fn cgroup_kill(&mut self, path: &str) -> Result<(), KernelError> {
        std::fs::write(format!("{path}/cgroup.kill"), "1")
            .map_err(|e| KernelError(format!("cgroup_kill {path}: {e}")))
    }

    fn cgroup_of(&self, pid: u32) -> Result<String, KernelError> {
        let body = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .map_err(|e| KernelError(format!("cgroup_of {pid}: {e}")))?;
        Ok(format!("/sys/fs/cgroup{}", cgroup_rel(&body)))
    }

    fn destroy_sockets(&mut self, pids: &[u32]) -> Result<usize, KernelError> {
        crate::sockdestroy::destroy_for_pids(pids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_paths_live_under_the_sentinel_directory() {
        assert_eq!(
            map_pin_path("EVENTS"),
            std::path::Path::new("/sys/fs/bpf/aios-sentinel/maps/EVENTS")
        );
        assert_eq!(
            link_pin_path("exec"),
            std::path::Path::new("/sys/fs/bpf/aios-sentinel/links/exec")
        );
    }

    #[test]
    fn the_pin_set_is_complete_only_with_every_map_and_link() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("maps")).unwrap();
        std::fs::create_dir_all(dir.path().join("links")).unwrap();
        assert!(
            !pins_complete(dir.path()),
            "an empty directory is not a pin set"
        );
        for m in MAP_NAMES {
            std::fs::write(dir.path().join("maps").join(m), b"").unwrap();
        }
        assert!(!pins_complete(dir.path()), "maps alone are not enough");
        for (prog, _) in LSM_PROGRAMS {
            std::fs::write(dir.path().join("links").join(prog), b"").unwrap();
        }
        for p in OTHER_PROGRAMS {
            std::fs::write(dir.path().join("links").join(p), b"").unwrap();
        }
        assert!(pins_complete(dir.path()));
    }

    #[test]
    fn every_lsm_program_names_its_kernel_hook() {
        // The hook name, not the program name, is what Lsm::load takes (§17.7).
        let by_prog: std::collections::HashMap<&str, &str> = LSM_PROGRAMS.iter().copied().collect();
        assert_eq!(by_prog["exec"], "bprm_check_security");
        assert_eq!(by_prog["connect"], "socket_connect");
        assert_eq!(by_prog["signal"], "task_kill");
        assert_eq!(by_prog["guard_truncate"], "path_truncate");
        assert_eq!(by_prog["bpf"], "bpf");
        assert_eq!(LSM_PROGRAMS.len(), 13);
    }

    #[test]
    fn the_bpf_self_guard_is_attached_last() {
        assert_eq!(
            LSM_PROGRAMS.last().map(|(p, _)| *p),
            Some("bpf"),
            "attaching it earlier would make the loader observe its own setup calls"
        );
    }

    #[test]
    fn the_cgroup_path_of_a_pid_is_read_from_proc_cgroup() {
        assert_eq!(
            cgroup_rel("0::/user.slice/user-1000.slice/session-2.scope\n"),
            "/user.slice/user-1000.slice/session-2.scope"
        );
        assert_eq!(cgroup_rel("0::/\n"), "/");
        assert_eq!(cgroup_rel(""), "/");
    }
}
