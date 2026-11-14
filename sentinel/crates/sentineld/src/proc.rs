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

/// The cgroup v2 (unified-hierarchy) line out of the full contents of
/// `/proc/<pid>/cgroup` -- the one line starting `0::`. This project is
/// cgroup-v2-only by design (`sentinel-ebpf`'s `guard.rs` keys off
/// `bpf_get_current_cgroup_id()`'s v2 id). On a hybrid host that still has
/// legacy v1 controllers mounted, earlier lines look like
/// `7:memory:/user.slice`: no `::` in them at all. Blindly taking the
/// first line (rather than picking out the `0::` one) would hand a v1
/// line to `rsplit("::")`, which returns the whole line unchanged -- a
/// bogus path that silently resolves to nothing. Returns `""` when there
/// is no `0::` line (not a cgroup v2 host, or the file was empty):
/// callers must treat that as "unknown", not fall back to the root path.
pub fn cgroup_v2_line(contents: &str) -> &str {
    contents
        .lines()
        .find(|l| l.starts_with("0::"))
        .unwrap_or("")
}

/// The systemd unit is the last unit-like component of the cgroup v2 path,
/// read out of the full contents of `/proc/<pid>/cgroup`.
pub fn unit_from_cgroup(contents: &str) -> String {
    let path = cgroup_v2_line(contents).strip_prefix("0::").unwrap_or("");
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
///
/// Known lossy edge case, left as-is: a NUL or empty `argv[0]` (a known
/// process-identity-spoofing trick) collapses indistinguishably into
/// whatever argv would look like without it, since empty elements are
/// filtered out below. Acceptable here because `argv` is a display and
/// glob-match string, not an identity field -- `Proc.exe` carries that.
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

/// The slice of `raw` to hand to [`environ_has_ld`] for the "first 4 KiB
/// of environ" scan the spec describes (§4). A raw byte-offset cut at
/// `window` would slice straight through whichever entry happens to sit
/// on the boundary, e.g. turning a real `LD_PRELOAD=/tmp/evil.so` into a
/// truncated `LD_PRELOA` with no `=` -- a false negative on exactly the
/// thing this flag exists to catch. Instead: include every COMPLETE
/// entry that STARTS before `window` (even one that extends past it),
/// and exclude any entry that starts at or after `window`. If the naive
/// `window`-byte prefix contains no `\0` at all, there is not even one
/// entry boundary to trust, so the result is empty.
pub fn environ_window(raw: &[u8], window: usize) -> &[u8] {
    let cap = raw.len().min(window);
    if !raw[..cap].contains(&0) {
        return &[];
    }
    let mut end = 0usize;
    let mut next_start = 0usize;
    for entry in raw.split(|&b| b == 0) {
        if next_start >= window {
            break;
        }
        end = next_start + entry.len();
        next_start = end + 1;
    }
    &raw[..end.min(raw.len())]
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
        let unit = unit_from_cgroup(&cgroup_file);
        // The cgroup id is the inode of the cgroup directory, which is what
        // bpf_get_current_cgroup_id() returns on the kernel side -- but
        // only for the cgroup v2 (unified-hierarchy) line. `cgroup_v2_line`
        // is what finds that line rather than just taking the first one.
        let v2_line = cgroup_v2_line(&cgroup_file);
        let cgroup_id = if v2_line.is_empty() {
            // Not a cgroup v2 host (or /proc/<pid>/cgroup was unreadable):
            // there is no unified-hierarchy path to resolve, and the eBPF
            // side only ever reports a v2 id, so there is nothing to
            // compare against. This 0 is a deliberate "unknown", not an
            // accidental fallback from a bad path string.
            0
        } else {
            let rel = v2_line.strip_prefix("0::").unwrap_or("/");
            std::fs::metadata(format!("/sys/fs/cgroup{rel}"))
                .map(|m| m.ino())
                .unwrap_or(0)
        };
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
        // Only the first 4 KiB, as the spec's env_ld flag describes (§4);
        // `environ_window` keeps that bound without chopping an entry
        // that straddles it.
        match Self::read_bytes(pid, "environ") {
            Some(raw) => environ_has_ld(environ_window(&raw, 4096)),
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

    // Review finding 1: a hard byte cut at the window boundary can chop a
    // genuine LD_PRELOAD entry in half, producing a false negative. Pin
    // that it survives intact when it straddles the boundary: a filler
    // entry ending at offset 4090, then the real entry running from 4091
    // to past 4096.
    #[test]
    fn environ_window_completes_an_entry_that_straddles_the_boundary() {
        let mut raw = vec![b'A'; 4090];
        raw.push(0); // filler entry ends at offset 4090
        raw.extend_from_slice(b"LD_PRELOAD=/tmp/evil.so"); // starts at 4091
        raw.push(0);
        assert!(
            environ_has_ld(environ_window(&raw, 4096)),
            "an entry starting before the window must be seen in full, even past it"
        );
    }

    // Complement of the above: an entry that begins entirely after the
    // window must stay out of scope, since the spec deliberately bounds
    // the scan to the first 4 KiB.
    #[test]
    fn environ_window_excludes_an_entry_that_starts_after_the_boundary() {
        let mut raw = vec![b'A'; 4090];
        raw.push(0); // filler #1 ends at offset 4090
        raw.extend_from_slice(&[b'B'; 10]); // filler #2: 4091..4101
        raw.push(0); // filler #2 ends at offset 4101
        raw.extend_from_slice(b"LD_PRELOAD=/tmp/x.so"); // starts at 4102
        raw.push(0);
        assert!(
            !environ_has_ld(environ_window(&raw, 4096)),
            "an entry starting at or after the window must not be seen at all"
        );
    }

    // Pins the prefix-only semantics `env_ld_is_set_by_either_variable`
    // already covers for "mentioned inside a value", extended to "a
    // variable name that merely contains LD_PRELOAD as a substring".
    #[test]
    fn environ_has_ld_requires_the_variable_name_as_a_prefix() {
        assert!(!environ_has_ld(b"MY_LD_PRELOAD=x\0"));
    }

    // Review finding 2: a hybrid host's legacy v1 cgroup lines
    // (`N:controller:path`) have no "::" at all. Taking the first line
    // blindly would feed one of those to the v2 path logic; selecting the
    // "0::" line explicitly must skip them and find the unified line
    // wherever it sits.
    #[test]
    fn cgroup_v2_line_skips_legacy_v1_lines() {
        let body = "12:pids:/user.slice\n\
                     7:memory:/user.slice/user-1000.slice\n\
                     0::/user.slice/user-1000.slice/session-2.scope\n";
        assert_eq!(
            cgroup_v2_line(body),
            "0::/user.slice/user-1000.slice/session-2.scope"
        );
        assert_eq!(unit_from_cgroup(body), "session-2.scope");
    }

    #[test]
    fn cgroup_v2_line_is_empty_when_there_is_no_unified_hierarchy_line() {
        assert_eq!(
            cgroup_v2_line("12:pids:/user.slice\n7:memory:/user.slice\n"),
            ""
        );
        assert_eq!(unit_from_cgroup("12:pids:/user.slice\n"), "");
    }
}
