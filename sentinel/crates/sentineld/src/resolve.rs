//! Turning a `RawEvent` into an owned, fully resolved event (spec §7, §17.7).

use std::collections::HashSet;

use sentinel_common::event::EventKind;
use sentinel_common::facts::{Facts, F_ENV_LD, F_STDIO_SOCKET, G_FLAGS};
use sentinel_common::wire::{EventHeader, KVerdict, RawEvent};
use sentinel_rules::matcher::ResolvedEvent;

use crate::proc::ProcSource;
use crate::table::Table;

/// The manifest-managed home targets (Base ISO §4.4), which `sentineld` fills
/// from the rendered home binds. `managed_home = true` holds for these paths
/// (spec amendment 5).
#[derive(Debug, Clone, Default)]
pub struct HomeBinds(HashSet<String>);

impl HomeBinds {
    pub fn new(paths: Vec<String>) -> HomeBinds {
        HomeBinds(paths.into_iter().collect())
    }
    pub fn contains(&self, path: &str) -> bool {
        self.0.contains(path)
    }
}

/// An event with every string resolved and every fact filled.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub kind: EventKind,
    pub facts: Facts,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub ts_ns: u64,
    pub matched_rule: i32,
    pub kverdict: KVerdict,
    pub exe: String,
    pub argv: String,
    pub parent_exe: String,
    /// Ancestor executables, nearest first — what `ancestors` globs match.
    pub ancestors: Vec<String>,
    /// The same chain by pid, for the alert record.
    pub ancestor_pids: Vec<u32>,
    pub unit: String,
    pub path: String,
    pub managed_home: bool,
    /// Destination of a connect or listen, as `(address, port)`.
    pub net: Option<(String, u16)>,
    /// The decoded payload, which becomes the alert's `event` object.
    pub detail: serde_json::Value,
}

fn kind_name(k: EventKind) -> &'static str {
    match k {
        EventKind::Exec => "exec",
        EventKind::Fork => "fork",
        EventKind::Exit => "exit",
        EventKind::Connect => "connect",
        EventKind::Listen => "listen",
        EventKind::Open => "open",
        EventKind::WriteRefused => "write_refused",
        EventKind::Memfd => "memfd",
        EventKind::Ptrace => "ptrace",
        EventKind::Module => "module",
        EventKind::Bpf => "bpf",
        EventKind::Signal => "signal",
        EventKind::Dns => "dns",
    }
}

fn device_name(c: u8) -> &'static str {
    match c {
        1 => "camera",
        2 => "mic",
        3 => "input",
        4 => "uinput",
        5 => "hidraw",
        _ => "none",
    }
}

/// `addr` as text: dotted quad for family 2, bracketed groups for family 10.
fn render_addr(family: u16, addr: &[u8; 16]) -> String {
    if family == 2 {
        format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
    } else {
        let groups: Vec<String> = (0..8)
            .map(|i| format!("{:x}", u16::from_be_bytes([addr[2 * i], addr[2 * i + 1]])))
            .collect();
        format!("[{}]", groups.join(":"))
    }
}

/// A fixed-size, length-prefixed byte field as a string.
fn field_str(buf: &[u8], len: usize) -> String {
    let n = len.min(buf.len());
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// A NUL-terminated byte field as a string.
fn cstr(buf: &[u8]) -> String {
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

impl Resolved {
    /// Resolve one raw event, or `None` if its `kind` byte decodes to no known
    /// [`EventKind`].
    ///
    /// The kernel object is embedded at build time, so the two sides cannot
    /// drift and an unknown kind means a corrupt or forged record. It is
    /// dropped rather than defaulted: calling it an exec would hand the
    /// payload union's bytes to the exec arm and expose it to every
    /// `on = "exec"` rule, including ones whose action is `freeze` or `kill`.
    pub fn from_raw(
        ev: &RawEvent,
        table: &Table,
        src: &dyn ProcSource,
        binds: &HomeBinds,
    ) -> Option<Resolved> {
        let h: &EventHeader = &ev.hdr;
        let kind = EventKind::from_u8(h.kind)?;
        let mut facts = Facts(h.facts);

        let me = table.get(h.pid);
        let mut exe = me.map(|p| p.exe.clone()).unwrap_or_default();
        let argv = me.map(|p| p.argv.clone()).unwrap_or_default();
        let unit = me.map(|p| p.unit.clone()).unwrap_or_default();
        let chain = table.ancestors(h.pid);
        let parent_exe = chain.first().map(|p| p.exe.clone()).unwrap_or_default();
        let ancestors: Vec<String> = chain.iter().map(|p| p.exe.clone()).collect();
        let ancestor_pids: Vec<u32> = chain.iter().map(|p| p.pid).collect();

        let mut detail = serde_json::json!({ "on": kind_name(kind) });
        let mut path = String::new();
        let mut net = None;

        match kind {
            EventKind::Exec => {
                // SAFETY: the kernel wrote the exec variant for this kind.
                let x = unsafe { ev.payload.exec };
                // The executable comes from the kernel's own read of
                // `bprm->filename`, not from `/proc/<pid>/exe`: the hook runs
                // at bprm_check_security, before the new image is installed,
                // so the table's entry for this pid is still the *caller's*
                // image, and resolving from it matched every exec against the
                // forking shell. A relative path is no use to an absolute
                // glob, so that case falls back to the table.
                let from_kernel = field_str(&x.exe, x.exe_len as usize);
                if from_kernel.starts_with('/') {
                    exe = from_kernel;
                }
                if src.has_env_ld(h.pid) {
                    facts.set(G_FLAGS, F_ENV_LD);
                }
                if src.has_stdio_socket(h.pid) {
                    facts.set(G_FLAGS, F_STDIO_SOCKET);
                }
                detail["mnt_id"] = x.mnt_id.into();
                detail["memfd"] = facts.has(G_FLAGS, sentinel_common::facts::F_MEMFD).into();
                detail["deleted"] = facts.has(G_FLAGS, sentinel_common::facts::F_DELETED).into();
                detail["outside_usr"] = facts
                    .has(G_FLAGS, sentinel_common::facts::F_OUTSIDE_USR)
                    .into();
                detail["env_ld"] = facts.has(G_FLAGS, F_ENV_LD).into();
                detail["stdio_socket"] = facts.has(G_FLAGS, F_STDIO_SOCKET).into();
            }
            EventKind::Fork | EventKind::Exit => {
                // SAFETY: the kernel wrote the proc_ variant for these kinds.
                let p = unsafe { ev.payload.proc_ };
                detail["child_pid"] = p.child_pid.into();
                detail["exit_code"] = p.exit_code.into();
            }
            EventKind::Connect | EventKind::Listen => {
                // SAFETY: the kernel wrote the net variant for these kinds.
                let n = unsafe { ev.payload.net };
                let addr = render_addr(n.family, &n.addr);
                detail["family"] = n.family.into();
                detail["addr"] = addr.clone().into();
                detail["port"] = n.port.into();
                detail["proto"] = n.proto.into();
                net = Some((addr, n.port));
            }
            EventKind::Open | EventKind::WriteRefused => {
                // SAFETY: the kernel wrote the open variant for these kinds.
                let o = unsafe { ev.payload.open };
                path = field_str(&o.path, o.path_len as usize);
                detail["path"] = path.clone().into();
                detail["device"] = device_name(o.dev_class).into();
                detail["mode"] = o.mode.into();
            }
            EventKind::Memfd => {
                // SAFETY: the kernel wrote the memfd variant for this kind.
                let m = unsafe { ev.payload.memfd };
                detail["name"] = cstr(&m.name).into();
                detail["flags"] = m.flags.into();
            }
            EventKind::Ptrace => {
                // SAFETY: the kernel wrote the ptrace variant for this kind.
                let t = unsafe { ev.payload.ptrace };
                detail["target_pid"] = t.target_pid.into();
                detail["target_uid"] = t.target_uid.into();
                detail["mode"] = t.mode.into();
            }
            EventKind::Module => {
                // SAFETY: the kernel wrote the module variant for this kind.
                let m = unsafe { ev.payload.module };
                detail["name"] = cstr(&m.name).into();
                detail["read_id"] = m.read_id.into();
            }
            EventKind::Bpf => {
                // SAFETY: the kernel wrote the bpf variant for this kind.
                let b = unsafe { ev.payload.bpf };
                detail["cmd"] = b.cmd.into();
                detail["prog_type"] = b.prog_type.into();
            }
            EventKind::Signal => {
                // SAFETY: the kernel wrote the signal variant for this kind.
                let s = unsafe { ev.payload.signal };
                detail["target_pid"] = s.target_pid.into();
                detail["sig"] = s.sig.into();
            }
            // No kernel program emits Dns: the DNS detector synthesizes it in
            // user space from port-53 connects, so the union holds no variant
            // for it and there is nothing here to decode.
            EventKind::Dns => {}
        }

        let managed_home =
            matches!(kind, EventKind::WriteRefused | EventKind::Open) && binds.contains(&path);

        Some(Resolved {
            kind,
            facts,
            pid: h.pid,
            ppid: h.ppid,
            uid: h.uid,
            cgroup_id: h.cgroup_id,
            ts_ns: h.ts_ns,
            matched_rule: h.matched_rule,
            kverdict: match h.kverdict {
                1 => KVerdict::Denied,
                2 => KVerdict::WouldDeny,
                _ => KVerdict::None,
            },
            exe,
            argv,
            parent_exe,
            ancestors,
            ancestor_pids,
            unit,
            path,
            managed_home,
            net,
            detail,
        })
    }

    /// The borrowed view `sentinel-rules` matches against.
    pub fn as_event(&self) -> ResolvedEvent<'_> {
        ResolvedEvent {
            kind: self.kind,
            facts: self.facts,
            exe: &self.exe,
            argv: &self.argv,
            parent_exe: &self.parent_exe,
            ancestors: &self.ancestors,
            unit: &self.unit,
            path: &self.path,
            managed_home: self.managed_home,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc::{FakeProc, Proc};
    use crate::table::Table;
    use sentinel_common::facts::F_MEMFD;
    use sentinel_common::wire::{EventPayload, ExecPayload, NetPayload, OpenPayload, RawEvent};

    fn hdr(kind: EventKind, pid: u32) -> EventHeader {
        let mut h: EventHeader = unsafe { std::mem::zeroed() };
        h.kind = kind as u8;
        h.pid = pid;
        h.ppid = 100;
        h.uid = 1000;
        h.cgroup_id = 77;
        h.ts_ns = 5_000_000_000;
        h.matched_rule = -1;
        h
    }

    fn exec_payload(mnt_id: u32) -> EventPayload {
        EventPayload {
            exec: ExecPayload {
                exe: [0; 256],
                argv: [0; 256],
                exe_len: 0,
                argv_len: 0,
                mnt_id,
            },
        }
    }

    fn open_payload(path_bytes: &[u8], dev_class: u8) -> EventPayload {
        let mut path = [0u8; 256];
        path[..path_bytes.len()].copy_from_slice(path_bytes);
        EventPayload {
            open: OpenPayload {
                path,
                path_len: path_bytes.len() as u16,
                dev_class,
                _pad: 0,
                mode: 0,
            },
        }
    }

    fn fixture() -> (Table, FakeProc) {
        let mut src = FakeProc::default();
        for (pid, ppid, exe) in [
            (1u32, 0u32, "/usr/lib/systemd/systemd"),
            (100, 1, "/usr/bin/sshd"),
            (200, 100, "/usr/bin/bash"),
        ] {
            src.add(Proc {
                pid,
                ppid,
                exe: exe.to_string(),
                argv: format!("{exe} -i"),
                uid: 1000,
                unit: "session-2.scope".to_string(),
                cgroup_id: 77,
            });
        }
        let mut t = Table::default();
        t.seed(&src);
        (t, src)
    }

    #[test]
    fn exec_fills_exe_and_argv_from_proc_not_the_kernel() {
        let (t, src) = fixture();
        let mut ev = RawEvent {
            hdr: hdr(EventKind::Exec, 200),
            payload: exec_payload(42),
        };
        ev.hdr.facts[G_FLAGS] = F_MEMFD;
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default()).expect("a known kind");
        assert_eq!(r.exe, "/usr/bin/bash");
        assert_eq!(r.argv, "/usr/bin/bash -i");
        assert_eq!(r.parent_exe, "/usr/bin/sshd");
        assert_eq!(
            r.ancestors,
            vec!["/usr/bin/sshd", "/usr/lib/systemd/systemd"]
        );
        assert_eq!(r.unit, "session-2.scope");
        assert_eq!(r.detail["on"], "exec");
        assert_eq!(r.detail["mnt_id"], 42);
        assert_eq!(r.detail["memfd"], true);
    }

    /// An exec payload carrying the path the kernel read out of `bprm`.
    fn exec_payload_with_path(path: &[u8]) -> EventPayload {
        let mut exe = [0u8; 256];
        exe[..path.len()].copy_from_slice(path);
        EventPayload {
            exec: ExecPayload {
                exe,
                argv: [0; 256],
                exe_len: path.len() as u16,
                argv_len: 0,
                mnt_id: 0,
            },
        }
    }

    #[test]
    fn the_kernels_exec_path_wins_over_the_table() {
        let (t, src) = fixture();
        // The table holds the caller's image, which is what /proc still says
        // at bprm_check_security. The rule has to see the new one.
        let ev = RawEvent {
            hdr: hdr(EventKind::Exec, 200),
            payload: exec_payload_with_path(b"/tmp/marker"),
        };
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default()).expect("a known kind");
        assert_eq!(r.exe, "/tmp/marker");
        assert_eq!(
            r.as_event().exe,
            "/tmp/marker",
            "the matcher sees the program being executed"
        );
        assert_eq!(
            r.ancestors,
            vec!["/usr/bin/sshd", "/usr/lib/systemd/systemd"],
            "the chain still comes from the table"
        );
    }

    #[test]
    fn a_relative_exec_path_falls_back_to_the_table() {
        let (t, src) = fixture();
        // `./x` cannot satisfy an absolute glob, and the kernel does not
        // resolve it for us; the table's answer is the better of the two.
        let ev = RawEvent {
            hdr: hdr(EventKind::Exec, 200),
            payload: exec_payload_with_path(b"./marker"),
        };
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default()).expect("a known kind");
        assert_eq!(r.exe, "/usr/bin/bash");
    }

    #[test]
    fn exec_adds_the_user_space_facts() {
        let (t, mut src) = fixture();
        src.env_ld.insert(200);
        src.stdio_socket.insert(200);
        let ev = RawEvent {
            hdr: hdr(EventKind::Exec, 200),
            payload: exec_payload(0),
        };
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default()).expect("a known kind");
        assert!(
            r.facts.has(G_FLAGS, F_ENV_LD),
            "env_ld filled in user space"
        );
        assert!(r.facts.has(G_FLAGS, F_STDIO_SOCKET));
        assert_eq!(r.detail["env_ld"], true);
        assert_eq!(r.detail["stdio_socket"], true);
    }

    #[test]
    fn non_exec_kinds_do_not_pay_for_the_proc_fact_reads() {
        let (t, mut src) = fixture();
        src.env_ld.insert(200);
        let ev = RawEvent {
            hdr: hdr(EventKind::Connect, 200),
            payload: EventPayload {
                net: NetPayload {
                    family: 2,
                    proto: 6,
                    addr: [10, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    port: 443,
                    _pad: 0,
                },
            },
        };
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default()).expect("a known kind");
        assert!(
            !r.facts.has(G_FLAGS, F_ENV_LD),
            "env_ld is an exec-only fact"
        );
        assert_eq!(r.net, Some(("10.0.2.2".to_string(), 443)));
        assert_eq!(r.detail["addr"], "10.0.2.2");
        assert_eq!(r.detail["port"], 443);
    }

    #[test]
    fn ipv6_connect_renders_a_bracketed_address() {
        let (t, src) = fixture();
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[15] = 1;
        let ev = RawEvent {
            hdr: hdr(EventKind::Connect, 200),
            payload: EventPayload {
                net: NetPayload {
                    family: 10,
                    proto: 6,
                    addr,
                    port: 53,
                    _pad: 0,
                },
            },
        };
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default()).expect("a known kind");
        assert_eq!(r.net.unwrap().0, "[2001:0:0:0:0:0:0:1]");
    }

    #[test]
    fn open_decodes_the_path_and_the_device_class() {
        let (t, src) = fixture();
        let ev = RawEvent {
            hdr: hdr(EventKind::Open, 200),
            payload: open_payload(b"/dev/video0", 1),
        };
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default()).expect("a known kind");
        assert_eq!(r.path, "/dev/video0");
        assert_eq!(r.detail["device"], "camera");
    }

    #[test]
    fn write_refused_sets_managed_home_for_a_bind_target() {
        let (t, src) = fixture();
        let binds = HomeBinds::new(vec!["/home/user/.bashrc".to_string()]);
        let ev = RawEvent {
            hdr: hdr(EventKind::WriteRefused, 200),
            payload: open_payload(b"/home/user/.bashrc", 0),
        };
        let r = Resolved::from_raw(&ev, &t, &src, &binds).expect("a known kind");
        assert!(r.managed_home);

        let other = RawEvent {
            hdr: hdr(EventKind::WriteRefused, 200),
            payload: open_payload(b"/home/user/notes.txt", 0),
        };
        let r2 = Resolved::from_raw(&other, &t, &src, &binds).expect("a known kind");
        assert!(!r2.managed_home);
    }

    #[test]
    fn as_event_lends_the_matcher_view() {
        let (t, src) = fixture();
        let ev = RawEvent {
            hdr: hdr(EventKind::Exec, 200),
            payload: exec_payload(0),
        };
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default()).expect("a known kind");
        let view = r.as_event();
        assert_eq!(view.exe, "/usr/bin/bash");
        assert_eq!(view.kind, EventKind::Exec);
        assert_eq!(view.ancestors.len(), 2);
    }

    #[test]
    fn an_unknown_pid_still_resolves_with_header_facts() {
        let (t, src) = fixture();
        let ev = RawEvent {
            hdr: hdr(EventKind::Exec, 9999),
            payload: exec_payload(0),
        };
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default()).expect("a known kind");
        assert_eq!(r.exe, "");
        assert!(r.ancestors.is_empty());
        assert_eq!(r.pid, 9999);
    }

    #[test]
    fn an_undecodable_kind_is_dropped_rather_than_read_as_an_exec() {
        let (t, src) = fixture();
        let mut ev = RawEvent {
            hdr: hdr(EventKind::Exec, 200),
            payload: exec_payload(0),
        };
        ev.hdr.kind = 200;
        assert!(
            Resolved::from_raw(&ev, &t, &src, &HomeBinds::default()).is_none(),
            "an unknown kind must not become an exec: `on = \"exec\"` rules can freeze"
        );
    }

    #[test]
    fn a_dns_kind_carries_no_kernel_payload() {
        let (t, src) = fixture();
        // Nothing in sentinel-ebpf emits Dns; the detector synthesizes it from
        // port-53 connects. Reaching the ring at all, it must decode to no
        // payload rather than to another variant's bytes.
        let ev = RawEvent {
            hdr: hdr(EventKind::Dns, 200),
            payload: exec_payload(42),
        };
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default()).expect("a known kind");
        assert_eq!(r.detail["on"], "dns");
        assert!(r.detail.get("mnt_id").is_none(), "no payload was decoded");
        assert_eq!(r.path, "");
        assert_eq!(r.net, None);
    }
}
