//! Reading /proc, behind a trait (spec §7, §17.7).

use std::collections::{HashMap, HashSet};

/// One process as the daemon knows it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub exe: String,
    pub argv: String,
    pub uid: u32,
    pub unit: String,
    pub cgroup_id: u64,
}

/// Everything the daemon reads out of `/proc`.
pub trait ProcSource: Send {
    /// A full snapshot of one process, or `None` if it is already gone.
    fn read(&self, pid: u32) -> Option<Proc>;
    /// Every pid currently alive (the start-up scan).
    fn pids(&self) -> Vec<u32>;
    /// `LD_PRELOAD` or `LD_LIBRARY_PATH` in the environment (`F_ENV_LD`).
    fn has_env_ld(&self, pid: u32) -> bool;
    /// fd 0, 1 or 2 is a socket (`F_STDIO_SOCKET`).
    fn has_stdio_socket(&self, pid: u32) -> bool;
}

/// The systemd unit is the last unit-like component of the cgroup v2 path.
pub fn unit_from_cgroup(line: &str) -> String {
    let path = line.rsplit("::").next().unwrap_or("");
    path.rsplit('/')
        .find(|c| {
            c.ends_with(".service")
                || c.ends_with(".scope")
                || c.ends_with(".slice")
                || c.ends_with(".socket")
                || c.ends_with(".mount")
        })
        .unwrap_or("")
        .to_string()
}

/// `/proc/<pid>/cmdline` is NUL-separated; join with spaces.
pub fn argv_from_cmdline(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .split('\0')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `LD_PRELOAD=` or `LD_LIBRARY_PATH=` at the start of a NUL-separated entry.
pub fn environ_has_ld(raw: &[u8]) -> bool {
    raw.split(|b| *b == 0)
        .any(|e| e.starts_with(b"LD_PRELOAD=") || e.starts_with(b"LD_LIBRARY_PATH="))
}

/// The real `/proc`.
#[derive(Default)]
pub struct RealProc;

impl RealProc {
    fn read_bytes(pid: u32, what: &str) -> Option<Vec<u8>> {
        std::fs::read(format!("/proc/{pid}/{what}")).ok()
    }
}

impl ProcSource for RealProc {
    fn read(&self, pid: u32) -> Option<Proc> {
        use std::os::unix::fs::MetadataExt;
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let mut ppid = 0u32;
        let mut uid = 0u32;
        for line in status.lines() {
            if let Some(v) = line.strip_prefix("PPid:") {
                ppid = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("Uid:") {
                // "Uid:\treal\teffective\tsaved\tfs"
                uid = v
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }
        let cgroup_file =
            std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
        let first = cgroup_file.lines().next().unwrap_or("");
        let unit = unit_from_cgroup(first);
        // The cgroup id is the inode of the cgroup directory, which is what
        // bpf_get_current_cgroup_id() returns on the kernel side.
        let rel = first.rsplit("::").next().unwrap_or("/");
        let cgroup_id = std::fs::metadata(format!("/sys/fs/cgroup{rel}"))
            .map(|m| m.ino())
            .unwrap_or(0);
        Some(Proc {
            pid,
            ppid,
            exe: std::fs::read_link(format!("/proc/{pid}/exe"))
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            argv: argv_from_cmdline(&Self::read_bytes(pid, "cmdline").unwrap_or_default()),
            uid,
            unit,
            cgroup_id,
        })
    }

    fn pids(&self) -> Vec<u32> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir("/proc") {
            for ent in rd.flatten() {
                if let Ok(pid) = ent.file_name().to_string_lossy().parse::<u32>() {
                    out.push(pid);
                }
            }
        }
        out.sort_unstable();
        out
    }

    fn has_env_ld(&self, pid: u32) -> bool {
        // Only the first 4 KiB, as the spec's env_ld flag describes (§4).
        match Self::read_bytes(pid, "environ") {
            Some(raw) => environ_has_ld(&raw[..raw.len().min(4096)]),
            None => false,
        }
    }

    fn has_stdio_socket(&self, pid: u32) -> bool {
        (0..3).any(|fd| {
            std::fs::read_link(format!("/proc/{pid}/fd/{fd}"))
                .map(|t| t.to_string_lossy().starts_with("socket:["))
                .unwrap_or(false)
        })
    }
}

/// A `ProcSource` built from literals, for tests.
#[derive(Default)]
pub struct FakeProc {
    pub procs: HashMap<u32, Proc>,
    pub env_ld: HashSet<u32>,
    pub stdio_socket: HashSet<u32>,
}

impl FakeProc {
    pub fn add(&mut self, p: Proc) {
        self.procs.insert(p.pid, p);
    }
}

impl ProcSource for FakeProc {
    fn read(&self, pid: u32) -> Option<Proc> {
        self.procs.get(&pid).cloned()
    }
    fn pids(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.procs.keys().copied().collect();
        v.sort_unstable();
        v
    }
    fn has_env_ld(&self, pid: u32) -> bool {
        self.env_ld.contains(&pid)
    }
    fn has_stdio_socket(&self, pid: u32) -> bool {
        self.stdio_socket.contains(&pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_is_the_last_unit_like_component() {
        assert_eq!(
            unit_from_cgroup("0::/user.slice/user-1000.slice/session-2.scope"),
            "session-2.scope"
        );
        assert_eq!(
            unit_from_cgroup("0::/system.slice/sshd.service"),
            "sshd.service"
        );
        assert_eq!(
            unit_from_cgroup("0::/system.slice/system-getty.slice/getty@tty1.service"),
            "getty@tty1.service"
        );
        assert_eq!(unit_from_cgroup("0::/"), "");
        assert_eq!(unit_from_cgroup(""), "");
    }

    #[test]
    fn argv_joins_nul_separated_cmdline() {
        assert_eq!(argv_from_cmdline(b"bash\0-i\0"), "bash -i");
        assert_eq!(argv_from_cmdline(b"/usr/bin/true\0"), "/usr/bin/true");
        assert_eq!(argv_from_cmdline(b""), "");
    }

    #[test]
    fn env_ld_is_set_by_either_variable() {
        assert!(environ_has_ld(b"PATH=/usr/bin\0LD_PRELOAD=/tmp/x.so\0"));
        assert!(environ_has_ld(b"LD_LIBRARY_PATH=/tmp\0"));
        assert!(!environ_has_ld(b"PATH=/usr/bin\0HOME=/root\0"));
        // Must match only at the start of a variable, never inside a value.
        assert!(!environ_has_ld(b"NOTE=see LD_PRELOAD docs\0"));
    }

    #[test]
    fn fake_proc_answers_every_field() {
        let mut p = FakeProc::default();
        p.add(Proc {
            pid: 4242,
            ppid: 4100,
            exe: "/usr/bin/bash".to_string(),
            argv: "bash -i".to_string(),
            uid: 1000,
            unit: "session-2.scope".to_string(),
            cgroup_id: 77,
        });
        assert_eq!(p.read(4242).unwrap().exe, "/usr/bin/bash");
        assert!(p.read(9999).is_none());
        assert_eq!(p.pids(), vec![4242]);
    }

    #[test]
    fn fake_proc_reports_the_configured_facts() {
        let mut p = FakeProc::default();
        p.env_ld.insert(7);
        p.stdio_socket.insert(7);
        assert!(p.has_env_ld(7));
        assert!(p.has_stdio_socket(7));
        assert!(!p.has_env_ld(8));
        assert!(!p.has_stdio_socket(8));
    }

    #[test]
    fn real_proc_reads_this_process() {
        let me = std::process::id();
        let p = RealProc.read(me).expect("own /proc entry");
        assert_eq!(p.pid, me);
        assert!(!p.exe.is_empty(), "exe should resolve for the test binary");
        assert!(RealProc.pids().contains(&me));
    }
}
