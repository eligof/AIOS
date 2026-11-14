//! freeze, kill and release over the [`Kernel`] trait (spec §6).

use std::collections::{HashMap, HashSet};

use crate::kernel::{Kernel, KernelError};
use crate::proc::ProcSource;
use crate::table::Table;

/// Parent slice of every quarantine cgroup (spec §6).
pub const QUARANTINE_SLICE: &str = "/sys/fs/cgroup/aios-sentinel.slice";

/// How many times the descendant rescan runs before giving up. A tree that
/// keeps forking faster than this is a `kill` case, not a `freeze` case.
const RESCAN_ROUNDS: usize = 4;

/// One live quarantine.
#[derive(Debug, Clone)]
pub struct Quarantine {
    /// The alert that caused it; also the cgroup's name suffix.
    pub alert_id: String,
    pub cgroup: String,
    pub cgroup_id: u64,
    /// Every pid moved into the quarantine cgroup.
    pub pids: Vec<u32>,
    /// Where each pid came from, so `release` can put it back.
    pub original: HashMap<u32, String>,
    /// The process the rule actually hit.
    pub root_pid: u32,
    pub killed: bool,
}

/// What a half-finished freeze has done so far, so it can be undone.
struct Partial {
    cgroup: String,
    cgroup_id: u64,
    moved: Vec<u32>,
    in_cgroup: HashSet<u32>,
    original: HashMap<u32, String>,
    froze: bool,
    mapped: bool,
}

impl Partial {
    /// Put the machine back as it was. Spec §6: after a failed action the
    /// process is neither frozen nor killed — and it must not be left in a
    /// cgroup that nothing holds a record of either, because the caller is
    /// about to drop this state and no `release` could ever reach it.
    ///
    /// Best effort by design: an error here cannot be surfaced without losing
    /// the original one, which is the error worth reporting.
    fn undo(self, k: &mut dyn Kernel) {
        if self.mapped {
            let _ = k.quarantine_remove(self.cgroup_id);
        }
        if self.froze {
            let _ = k.cgroup_freeze(&self.cgroup, false);
        }
        for pid in &self.moved {
            if let Some(from) = self.original.get(pid) {
                let _ = k.cgroup_attach(from, *pid);
            }
        }
        let _ = k.cgroup_remove(&self.cgroup);
    }
}

/// Move `root_pid` and its descendants into a fresh quarantine cgroup, freeze
/// them, deny their network and destroy their sockets. With `kill`, also set
/// `cgroup.kill` once the tree is frozen (spec §6).
///
/// `src` is read for the rescan: a process that forked while its siblings were
/// being moved is in `/proc` but not in `table`, which is a snapshot taken
/// before the move began.
pub fn freeze(
    k: &mut dyn Kernel,
    table: &Table,
    src: &dyn ProcSource,
    alert_id: &str,
    root_pid: u32,
    kill: bool,
) -> Result<Quarantine, KernelError> {
    let cgroup = format!("{QUARANTINE_SLICE}/q-{alert_id}");
    let cgroup_id = k.cgroup_create(&cgroup)?;
    let mut st = Partial {
        cgroup,
        cgroup_id,
        moved: Vec::new(),
        in_cgroup: HashSet::new(),
        original: HashMap::new(),
        froze: false,
        mapped: false,
    };

    match take_tree(k, table, src, root_pid, kill, &mut st) {
        Ok(()) => Ok(Quarantine {
            alert_id: alert_id.to_string(),
            cgroup: st.cgroup,
            cgroup_id: st.cgroup_id,
            pids: st.moved,
            original: st.original,
            root_pid,
            killed: kill,
        }),
        Err(e) => {
            st.undo(k);
            Err(e)
        }
    }
}

/// The body of [`freeze`], split out so every exit path can be rolled back.
fn take_tree(
    k: &mut dyn Kernel,
    table: &Table,
    src: &dyn ProcSource,
    root_pid: u32,
    kill: bool,
    st: &mut Partial,
) -> Result<(), KernelError> {
    for pid in table.descendants(root_pid) {
        attach(k, st, pid)?;
    }

    // Rescan until a round adds nothing. The table is a snapshot, so a child
    // forked during the move only shows up in `/proc`; a child of a process
    // already moved inherits the quarantine cgroup, but one forked by a
    // process still waiting its turn does not.
    for _ in 0..RESCAN_ROUNDS {
        let mut added = 0;
        for pid in src.pids() {
            if st.in_cgroup.contains(&pid) {
                continue;
            }
            let Some(p) = src.read(pid) else { continue };
            if !st.in_cgroup.contains(&p.ppid) {
                continue;
            }
            if attach(k, st, pid)? {
                added += 1;
            }
        }
        if added == 0 {
            break;
        }
    }

    if st.moved.is_empty() {
        // Freezing an empty cgroup would report a successful quarantine of
        // nothing; §6's failure path (a critical alert naming the error) is
        // the honest answer.
        return Err(KernelError(format!(
            "nothing to freeze: pid {root_pid} and its tree are already gone"
        )));
    }

    // Freeze before touching the quarantine map, so nothing in the tree runs
    // while the map entry is going in.
    k.cgroup_freeze(&st.cgroup, true)?;
    st.froze = true;
    k.quarantine_add(st.cgroup_id)?;
    st.mapped = true;
    // New connections are already denied by the LSM hooks; this closes the
    // ones that were open before (spec §17.2).
    k.destroy_sockets(&st.moved)?;

    if kill {
        k.cgroup_kill(&st.cgroup)?;
    }
    Ok(())
}

/// Move one pid in, recording where it came from first. Returns `false` for a
/// process that is already gone: it has no cgroup to record, and skipping it
/// is not a failure of the whole action.
fn attach(k: &mut dyn Kernel, st: &mut Partial, pid: u32) -> Result<bool, KernelError> {
    if st.in_cgroup.contains(&pid) {
        return Ok(false);
    }
    let Ok(from) = k.cgroup_of(pid) else {
        return Ok(false);
    };
    k.cgroup_attach(&st.cgroup, pid)?;
    st.original.insert(pid, from);
    st.moved.push(pid);
    st.in_cgroup.insert(pid);
    Ok(true)
}

/// Unfreeze, drop the quarantine map entry, put every process back in its
/// original cgroup and remove the quarantine cgroup (spec §6 `release`).
pub fn release(k: &mut dyn Kernel, q: &Quarantine) -> Result<(), KernelError> {
    k.quarantine_remove(q.cgroup_id)?;
    k.cgroup_freeze(&q.cgroup, false)?;
    for pid in &q.pids {
        if let Some(from) = q.original.get(pid) {
            // A process that exited while frozen cannot be moved; that is not
            // a failure of the release.
            let _ = k.cgroup_attach(from, *pid);
        }
    }
    k.cgroup_remove(&q.cgroup)?;
    Ok(())
}

/// `cgroup.kill = 1` on an existing quarantine (spec §6 `kill`).
pub fn kill_quarantine(k: &mut dyn Kernel, q: &Quarantine) -> Result<(), KernelError> {
    k.cgroup_kill(&q.cgroup)
}

/// The live quarantines, keyed by alert id.
#[derive(Default)]
pub struct Registry {
    items: HashMap<String, Quarantine>,
}

impl Registry {
    pub fn insert(&mut self, q: Quarantine) {
        self.items.insert(q.alert_id.clone(), q);
    }
    pub fn get(&self, alert_id: &str) -> Option<&Quarantine> {
        self.items.get(alert_id)
    }
    /// Remove and return one, for `Release` and `Kill`. The caller owns the
    /// record from then on: if its release fails it must put it back, or the
    /// quarantine becomes unreachable.
    pub fn take(&mut self, alert_id: &str) -> Option<Quarantine> {
        self.items.remove(alert_id)
    }
    /// Every quarantine, sorted by alert id so `ListQuarantine` is stable.
    pub fn list(&self) -> Vec<&Quarantine> {
        let mut v: Vec<&Quarantine> = self.items.values().collect();
        v.sort_by(|a, b| a.alert_id.cmp(&b.alert_id));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::FakeKernel;
    use crate::proc::{FakeProc, Proc, ProcSource};
    use crate::table::Table;

    fn p(pid: u32, ppid: u32) -> Proc {
        Proc {
            pid,
            ppid,
            exe: "/usr/bin/bash".to_string(),
            argv: "bash -i".to_string(),
            uid: 1000,
            unit: "session-2.scope".to_string(),
            cgroup_id: 77,
        }
    }

    fn setup() -> (Table, FakeKernel, FakeProc) {
        let mut t = Table::default();
        let mut src = FakeProc::default();
        for (pid, ppid) in [(1u32, 0u32), (200, 1), (201, 200)] {
            t.insert(p(pid, ppid));
            src.add(p(pid, ppid));
        }
        let mut k = FakeKernel::default();
        for pid in [200u32, 201] {
            k.pid_cgroups
                .insert(pid, "/user.slice/session-2.scope".to_string());
        }
        (t, k, src)
    }

    fn ops(k: &FakeKernel) -> Vec<&str> {
        k.calls
            .iter()
            .map(|c| c.split(' ').next().unwrap())
            .collect()
    }

    #[test]
    fn freeze_moves_the_whole_tree_then_freezes_then_cuts_the_network() {
        let (t, mut k, src) = setup();
        let q = freeze(&mut k, &t, &src, "A1", 200, false).expect("freeze succeeds");
        assert_eq!(q.cgroup, "/sys/fs/cgroup/aios-sentinel.slice/q-A1");
        let mut pids = q.pids.clone();
        pids.sort_unstable();
        assert_eq!(pids, vec![200, 201]);

        // The order is the guarantee: attach, freeze, quarantine, destroy.
        let ops = ops(&k);
        let freeze_at = ops.iter().position(|o| *o == "cgroup_freeze").unwrap();
        let quarantine_at = ops.iter().position(|o| *o == "quarantine_add").unwrap();
        let destroy_at = ops.iter().position(|o| *o == "destroy_sockets").unwrap();
        let last_attach = ops.iter().rposition(|o| *o == "cgroup_attach").unwrap();
        assert!(
            last_attach < freeze_at,
            "every pid is attached before the freeze"
        );
        assert!(
            freeze_at < quarantine_at,
            "freeze before the quarantine map"
        );
        assert!(
            quarantine_at < destroy_at,
            "map entry before destroying sockets"
        );
        assert!(k.frozen.contains(&q.cgroup));
        assert!(k.quarantined.contains(&q.cgroup_id));
    }

    #[test]
    fn freeze_records_the_original_cgroup_of_each_process() {
        let (t, mut k, src) = setup();
        let q = freeze(&mut k, &t, &src, "A1", 200, false).unwrap();
        assert_eq!(
            q.original.get(&200).map(String::as_str),
            Some("/user.slice/session-2.scope")
        );
        assert_eq!(q.original.len(), 2);
    }

    #[test]
    fn kill_freezes_first_then_kills() {
        let (t, mut k, src) = setup();
        let q = freeze(&mut k, &t, &src, "A2", 200, true).unwrap();
        let ops = ops(&k);
        let freeze_at = ops.iter().position(|o| *o == "cgroup_freeze").unwrap();
        let kill_at = ops.iter().position(|o| *o == "cgroup_kill").unwrap();
        assert!(freeze_at < kill_at, "freeze stops forking before the kill");
        assert!(k.killed.contains(&q.cgroup));
    }

    #[test]
    fn a_failed_freeze_reports_the_error_and_leaves_nothing_quarantined() {
        let (t, mut k, src) = setup();
        k.fail_on
            .insert("cgroup_freeze /sys/fs/cgroup/aios-sentinel.slice/q-A3 on".to_string());
        let e = freeze(&mut k, &t, &src, "A3", 200, false).unwrap_err();
        assert!(e.to_string().contains("cgroup_freeze"), "error was {e}");
        assert!(
            k.quarantined.is_empty(),
            "a failed freeze must not leave a quarantine entry"
        );
    }

    #[test]
    fn a_failed_freeze_puts_every_process_back_and_drops_the_cgroup() {
        let (t, mut k, src) = setup();
        let cgroup = "/sys/fs/cgroup/aios-sentinel.slice/q-A3b";
        k.fail_on.insert(format!("cgroup_freeze {cgroup} on"));
        freeze(&mut k, &t, &src, "A3b", 200, false).unwrap_err();
        // Spec §6: the process is then neither frozen nor killed -- and not
        // left sitting in a cgroup nothing holds a record of either.
        for pid in [200u32, 201] {
            assert!(
                k.calls
                    .contains(&format!("cgroup_attach /user.slice/session-2.scope {pid}")),
                "pid {pid} was not put back: {:?}",
                k.calls
            );
        }
        assert!(k.calls.contains(&format!("cgroup_remove {cgroup}")));
        assert!(k.frozen.is_empty());
        assert!(!k.cgroups.contains_key(cgroup), "the cgroup was removed");
    }

    #[test]
    fn a_freeze_that_takes_nothing_fails_instead_of_freezing_an_empty_cgroup() {
        let (t, mut k, src) = setup();
        // Every process in the tree is already gone, so none has a cgroup.
        k.pid_cgroups.clear();
        let e = freeze(&mut k, &t, &src, "A3c", 200, false).unwrap_err();
        assert!(e.to_string().contains("200"), "error was {e}");
        assert!(k.frozen.is_empty(), "nothing was frozen");
        assert!(k
            .calls
            .contains(&"cgroup_remove /sys/fs/cgroup/aios-sentinel.slice/q-A3c".to_string()));
    }

    #[test]
    fn the_rescan_catches_a_process_that_forked_during_the_move() {
        let (t, mut k, base) = setup();
        for pid in [202u32, 203] {
            k.pid_cgroups
                .insert(pid, "/user.slice/session-2.scope".to_string());
        }
        // 202 is forked by 201 while the move is in progress, and 203 by 202
        // during the rescan itself: both are in /proc but neither is in the
        // table snapshot the first pass walked, and the second needs a second
        // round to be seen.
        let src = GrowingProc {
            base,
            extras: vec![p(202, 201), p(203, 202)],
            scans: std::cell::Cell::new(0),
        };
        let q = freeze(&mut k, &t, &src, "A7", 200, false).unwrap();
        let mut pids = q.pids.clone();
        pids.sort_unstable();
        assert_eq!(
            pids,
            vec![200, 201, 202, 203],
            "the rescan must run until a round adds nothing"
        );
        let ops = ops(&k);
        let freeze_at = ops.iter().position(|o| *o == "cgroup_freeze").unwrap();
        let last_attach = ops.iter().rposition(|o| *o == "cgroup_attach").unwrap();
        assert!(
            last_attach < freeze_at,
            "the late children are in before the freeze"
        );
    }

    #[test]
    fn the_rescan_does_not_take_a_process_outside_the_tree() {
        let (t, mut k, mut base) = setup();
        // A sibling under pid 1, not under the root being frozen.
        base.add(p(300, 1));
        k.pid_cgroups
            .insert(300, "/user.slice/session-2.scope".to_string());
        let q = freeze(&mut k, &t, &base, "A8", 200, false).unwrap();
        assert!(
            !q.pids.contains(&300),
            "an unrelated process must not be quarantined: {:?}",
            q.pids
        );
    }

    #[test]
    fn release_unfreezes_restores_cgroups_and_clears_the_map() {
        let (t, mut k, src) = setup();
        let q = freeze(&mut k, &t, &src, "A4", 200, false).unwrap();
        k.calls.clear();
        release(&mut k, &q).expect("release succeeds");
        assert!(!k.frozen.contains(&q.cgroup));
        assert!(!k.quarantined.contains(&q.cgroup_id));
        assert!(
            k.calls
                .contains(&"cgroup_attach /user.slice/session-2.scope 200".to_string()),
            "calls were {:?}",
            k.calls
        );
        assert!(k.calls.contains(&format!("cgroup_remove {}", q.cgroup)));
    }

    #[test]
    fn kill_quarantine_kills_an_existing_quarantine() {
        let (t, mut k, src) = setup();
        let q = freeze(&mut k, &t, &src, "A5", 200, false).unwrap();
        k.calls.clear();
        kill_quarantine(&mut k, &q).expect("kill succeeds");
        assert!(k.killed.contains(&q.cgroup));
    }

    #[test]
    fn the_registry_tracks_and_drops_quarantines() {
        let (t, mut k, src) = setup();
        let mut reg = Registry::default();
        let q = freeze(&mut k, &t, &src, "A6", 200, false).unwrap();
        reg.insert(q);
        assert_eq!(reg.list().len(), 1);
        assert!(reg.get("A6").is_some());
        let taken = reg.take("A6").expect("present");
        assert_eq!(taken.alert_id, "A6");
        assert!(reg.list().is_empty());
        assert!(reg.take("A6").is_none());
    }

    /// A `/proc` that reveals one more process on each scan, which is what a
    /// tree still forking during the move looks like from user space.
    struct GrowingProc {
        base: FakeProc,
        extras: Vec<Proc>,
        scans: std::cell::Cell<usize>,
    }

    impl GrowingProc {
        /// How many of `extras` the scans so far have exposed.
        fn visible(&self) -> usize {
            self.scans.get().min(self.extras.len())
        }
    }

    impl ProcSource for GrowingProc {
        fn read(&self, pid: u32) -> Option<Proc> {
            if let Some(p) = self.extras[..self.visible()].iter().find(|p| p.pid == pid) {
                return Some(p.clone());
            }
            self.base.read(pid)
        }
        fn pids(&self) -> Vec<u32> {
            self.scans.set(self.scans.get() + 1);
            let mut v = self.base.pids();
            v.extend(self.extras[..self.visible()].iter().map(|p| p.pid));
            v
        }
        fn has_env_ld(&self, pid: u32) -> bool {
            self.base.has_env_ld(pid)
        }
        fn has_stdio_socket(&self, pid: u32) -> bool {
            self.base.has_stdio_socket(pid)
        }
    }
}
