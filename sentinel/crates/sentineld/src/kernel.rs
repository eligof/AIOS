//! Every effect the daemon has on the kernel, behind one trait (spec §14).

use std::collections::{HashMap, HashSet};

use sentinel_rules::compile::Tables;

/// Number of enforcement hooks counted in `LOCKDOWN_COUNTS` (S2's `NHOOKS`).
pub const NHOOKS: usize = 8;

#[derive(Debug)]
pub struct KernelError(pub String);

impl std::fmt::Display for KernelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KernelError {}

/// Maps, cgroupfs, socket destruction and the clock — every effect the daemon
/// has on the kernel.
pub trait Kernel: Send {
    /// `CLOCK_MONOTONIC` in ns — the clock `bpf_ktime_get_ns` reads.
    fn monotonic_ns(&self) -> u64;
    /// Wall clock in ms since the epoch, for an alert's `ts`.
    fn wall_ms(&self) -> u64;

    fn heartbeat(&mut self, ns: u64) -> Result<(), KernelError>;
    fn heartbeat_value(&self) -> Result<u64, KernelError>;
    fn drops(&self) -> Result<u64, KernelError>;
    fn lockdown_counts(&self) -> Result<[u64; NHOOKS], KernelError>;

    /// Replace `RULES`, `RULE_COUNT` and the lookup tables (spec §11.3). Write
    /// the new rules first and `RULE_COUNT` last, so a hook never walks a
    /// half-written set.
    fn swap_rules(&mut self, tables: &Tables) -> Result<(), KernelError>;

    fn quarantine_add(&mut self, cgroup_id: u64) -> Result<(), KernelError>;
    fn quarantine_remove(&mut self, cgroup_id: u64) -> Result<(), KernelError>;

    /// Create the cgroup directory and return its id (its inode).
    fn cgroup_create(&mut self, path: &str) -> Result<u64, KernelError>;
    fn cgroup_remove(&mut self, path: &str) -> Result<(), KernelError>;
    fn cgroup_attach(&mut self, path: &str, pid: u32) -> Result<(), KernelError>;
    fn cgroup_freeze(&mut self, path: &str, on: bool) -> Result<(), KernelError>;
    fn cgroup_kill(&mut self, path: &str) -> Result<(), KernelError>;
    /// The cgroup path of a live process, recorded before a freeze so
    /// `release` can put it back (spec §6).
    fn cgroup_of(&self, pid: u32) -> Result<String, KernelError>;

    /// Destroy the TCP and UDP sockets of these pids (spec §17.2). Returns how
    /// many were destroyed.
    fn destroy_sockets(&mut self, pids: &[u32]) -> Result<usize, KernelError>;
}

/// A `Kernel` that records calls instead of making them.
#[derive(Default)]
pub struct FakeKernel {
    /// Every call, in order, as `"<op> <args>"`.
    pub calls: Vec<String>,
    /// Calls that should fail, matched against the same strings as `calls`.
    pub fail_on: HashSet<String>,
    pub quarantined: HashSet<u64>,
    pub cgroups: HashMap<String, u64>,
    pub frozen: HashSet<String>,
    pub killed: HashSet<String>,
    /// What `cgroup_of` answers, per pid.
    pub pid_cgroups: HashMap<u32, String>,
    pub heartbeat_ns: u64,
    pub drops_value: u64,
    pub lockdown: [u64; NHOOKS],
    pub destroyed: Vec<u32>,
    pub rule_swaps: usize,
    now_ms: u64,
    next_cgroup_id: u64,
}

impl FakeKernel {
    /// Move the fake clock forward.
    pub fn advance_ms(&mut self, ms: u64) {
        self.now_ms += ms;
    }

    fn record(&mut self, call: String) -> Result<(), KernelError> {
        let fail = self.fail_on.contains(&call);
        self.calls.push(call.clone());
        if fail {
            Err(KernelError(format!("fake failure: {call}")))
        } else {
            Ok(())
        }
    }
}

impl Kernel for FakeKernel {
    fn monotonic_ns(&self) -> u64 {
        self.now_ms * 1_000_000
    }
    fn wall_ms(&self) -> u64 {
        self.now_ms
    }
    fn heartbeat(&mut self, ns: u64) -> Result<(), KernelError> {
        self.heartbeat_ns = ns;
        Ok(())
    }
    fn heartbeat_value(&self) -> Result<u64, KernelError> {
        Ok(self.heartbeat_ns)
    }
    fn drops(&self) -> Result<u64, KernelError> {
        Ok(self.drops_value)
    }
    fn lockdown_counts(&self) -> Result<[u64; NHOOKS], KernelError> {
        Ok(self.lockdown)
    }
    fn swap_rules(&mut self, tables: &Tables) -> Result<(), KernelError> {
        self.rule_swaps += 1;
        self.record(format!("swap_rules {}", tables.rules.len()))
    }
    fn quarantine_add(&mut self, cgroup_id: u64) -> Result<(), KernelError> {
        self.record(format!("quarantine_add {cgroup_id}"))?;
        self.quarantined.insert(cgroup_id);
        Ok(())
    }
    fn quarantine_remove(&mut self, cgroup_id: u64) -> Result<(), KernelError> {
        self.record(format!("quarantine_remove {cgroup_id}"))?;
        self.quarantined.remove(&cgroup_id);
        Ok(())
    }
    fn cgroup_create(&mut self, path: &str) -> Result<u64, KernelError> {
        self.record(format!("cgroup_create {path}"))?;
        self.next_cgroup_id += 1;
        let id = 1000 + self.next_cgroup_id;
        self.cgroups.insert(path.to_string(), id);
        Ok(id)
    }
    fn cgroup_remove(&mut self, path: &str) -> Result<(), KernelError> {
        self.record(format!("cgroup_remove {path}"))?;
        self.cgroups.remove(path);
        Ok(())
    }
    fn cgroup_attach(&mut self, path: &str, pid: u32) -> Result<(), KernelError> {
        self.record(format!("cgroup_attach {path} {pid}"))
    }
    fn cgroup_freeze(&mut self, path: &str, on: bool) -> Result<(), KernelError> {
        self.record(format!(
            "cgroup_freeze {path} {}",
            if on { "on" } else { "off" }
        ))?;
        if on {
            self.frozen.insert(path.to_string());
        } else {
            self.frozen.remove(path);
        }
        Ok(())
    }
    fn cgroup_kill(&mut self, path: &str) -> Result<(), KernelError> {
        self.record(format!("cgroup_kill {path}"))?;
        self.killed.insert(path.to_string());
        Ok(())
    }
    fn cgroup_of(&self, pid: u32) -> Result<String, KernelError> {
        self.pid_cgroups
            .get(&pid)
            .cloned()
            .ok_or_else(|| KernelError(format!("no cgroup recorded for pid {pid}")))
    }
    fn destroy_sockets(&mut self, pids: &[u32]) -> Result<usize, KernelError> {
        self.record(format!(
            "destroy_sockets {}",
            pids.iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ))?;
        self.destroyed.extend_from_slice(pids);
        Ok(pids.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fake_records_every_call_in_order() {
        let mut k = FakeKernel::default();
        let id = k
            .cgroup_create("/sys/fs/cgroup/aios-sentinel.slice/q-A")
            .unwrap();
        k.cgroup_attach("/sys/fs/cgroup/aios-sentinel.slice/q-A", 42)
            .unwrap();
        k.cgroup_freeze("/sys/fs/cgroup/aios-sentinel.slice/q-A", true)
            .unwrap();
        k.quarantine_add(id).unwrap();
        assert_eq!(
            k.calls,
            vec![
                "cgroup_create /sys/fs/cgroup/aios-sentinel.slice/q-A".to_string(),
                "cgroup_attach /sys/fs/cgroup/aios-sentinel.slice/q-A 42".to_string(),
                "cgroup_freeze /sys/fs/cgroup/aios-sentinel.slice/q-A on".to_string(),
                format!("quarantine_add {id}"),
            ]
        );
        assert!(k.quarantined.contains(&id));
    }

    #[test]
    fn the_fake_clock_advances_only_when_told() {
        let mut k = FakeKernel::default();
        assert_eq!(k.monotonic_ns(), 0);
        k.advance_ms(1500);
        assert_eq!(k.monotonic_ns(), 1_500_000_000);
        assert_eq!(k.wall_ms(), 1500);
    }

    #[test]
    fn a_configured_failure_surfaces_as_an_error() {
        let mut k = FakeKernel::default();
        k.fail_on.insert("cgroup_freeze /x on".to_string());
        assert!(k.cgroup_freeze("/x", true).is_err());
        // The attempt is still recorded, so a test can assert it was tried.
        assert_eq!(k.calls, vec!["cgroup_freeze /x on".to_string()]);
    }

    #[test]
    fn heartbeat_and_counters_round_trip() {
        let mut k = FakeKernel::default();
        k.heartbeat(123).unwrap();
        assert_eq!(k.heartbeat_value().unwrap(), 123);
        k.drops_value = 7;
        assert_eq!(k.drops().unwrap(), 7);
        k.lockdown = [1, 0, 0, 0, 0, 0, 0, 2];
        assert_eq!(k.lockdown_counts().unwrap()[7], 2);
    }

    #[test]
    fn release_undoes_quarantine() {
        let mut k = FakeKernel::default();
        let id = k.cgroup_create("/q").unwrap();
        k.quarantine_add(id).unwrap();
        k.quarantine_remove(id).unwrap();
        assert!(!k.quarantined.contains(&id));
    }

    #[test]
    fn cgroup_of_answers_from_the_configured_map() {
        let mut k = FakeKernel::default();
        k.pid_cgroups
            .insert(42, "/user.slice/session-2.scope".to_string());
        assert_eq!(k.cgroup_of(42).unwrap(), "/user.slice/session-2.scope");
        assert!(k.cgroup_of(43).is_err());
    }
}
