//! The process table and the alert-context ring (spec §7, amendment 9).

use std::collections::{HashMap, HashSet, VecDeque};

use crate::proc::{Proc, ProcSource};

/// Longest ancestor chain an alert carries; also the cycle guard.
pub const MAX_ANCESTORS: usize = 64;
/// Context events per alert (spec §7).
pub const MAX_CONTEXT: usize = 20;
/// How long a context event stays in the ring (spec §4: "about five minutes").
pub const CONTEXT_WINDOW_MS: u64 = 5 * 60 * 1000;
/// Hard cap on the ring, so a storm cannot grow it past the §13 budget.
pub const MAX_CONTEXT_RING: usize = 200_000;

#[derive(Debug, Clone)]
struct ContextEvent {
    pid: u32,
    at_ms: u64,
    json: serde_json::Value,
}

/// The live process table plus the recent-event ring.
///
/// `procs` holds live processes and *tombstones*: pids that have exited but
/// still have something alive below them. A tombstone keeps the chain
/// walkable, because the kernel's own reparenting would otherwise hand an
/// attacker a one-line bypass: fork, let the middle process exit, and the
/// orphan is a child of pid 1 with no `sshd` anywhere in its ancestry — past
/// every `parent` and `ancestors` rule (spec §4), and outside the tree a
/// `freeze` of the original process would take (spec §6). A tombstone is
/// dropped as soon as its last descendant goes, so the extra entries are
/// bounded by the number of live processes.
#[derive(Default)]
pub struct Table {
    /// Live processes and tombstones. Invariant: `exited` ⊆ keys of `procs`.
    procs: HashMap<u32, Proc>,
    /// Parent pid -> its children, so an exit does not have to scan the table.
    children: HashMap<u32, HashSet<u32>>,
    /// Tombstoned pids: present in `procs`, but gone from the machine.
    exited: HashSet<u32>,
    ring: VecDeque<ContextEvent>,
}

impl Table {
    /// Build the table from a full `/proc` scan (spec §4: at start).
    pub fn seed(&mut self, src: &dyn ProcSource) {
        for pid in src.pids() {
            if let Some(p) = src.read(pid) {
                self.insert(p);
            }
        }
    }

    /// How many processes are alive; tombstones do not count.
    pub fn len(&self) -> usize {
        self.procs.len().saturating_sub(self.exited.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The live process `pid`, or `None` once it has exited — a tombstone is
    /// an ancestry link, not a process anything may act on.
    pub fn get(&self, pid: u32) -> Option<&Proc> {
        if self.exited.contains(&pid) {
            return None;
        }
        self.procs.get(&pid)
    }

    /// `pid` whether it is alive or a tombstone — what an alert wants, since
    /// a record of what the process *was* is the point of the ancestor chain.
    /// Anything that acts on a process must use [`Table::get`] instead.
    pub fn get_any(&self, pid: u32) -> Option<&Proc> {
        self.procs.get(&pid)
    }

    pub fn insert(&mut self, p: Proc) {
        let (pid, ppid) = (p.pid, p.ppid);
        if let Some(old) = self.procs.get(&pid) {
            let old_ppid = old.ppid;
            if old_ppid != ppid {
                self.unlink(pid, old_ppid);
            }
        }
        // A pid that is being inserted is alive again: either it is new, or
        // the kernel reused a number we still held a tombstone for.
        self.exited.remove(&pid);
        self.children.entry(ppid).or_default().insert(pid);
        self.procs.insert(pid, p);
    }

    fn unlink(&mut self, pid: u32, ppid: u32) {
        if let Some(kids) = self.children.get_mut(&ppid) {
            kids.remove(&pid);
            if kids.is_empty() {
                self.children.remove(&ppid);
            }
        }
    }

    /// A fork: the child starts as a copy of the parent.
    pub fn on_fork(&mut self, parent: u32, child: u32) {
        let mut p = self.procs.get(&parent).cloned().unwrap_or_default();
        p.pid = child;
        p.ppid = parent;
        self.insert(p);
    }

    /// An exec: re-read the pid, because its image, argv and cgroup changed.
    /// `/proc` is also the authority on its parent, so this repairs a link
    /// that a missed or out-of-order fork left wrong.
    pub fn on_exec(&mut self, pid: u32, src: &dyn ProcSource) {
        if let Some(p) = src.read(pid) {
            self.insert(p);
        }
    }

    /// An exit: drop the pid, or keep it as a tombstone while anything below
    /// it is still running. Its context events age out of the ring on their
    /// own, so an alert raised moments later still has them.
    pub fn on_exit(&mut self, pid: u32) {
        if !self.procs.contains_key(&pid) {
            return;
        }
        self.exited.insert(pid);
        self.prune(pid);
    }

    /// Drop `pid` if it is a childless tombstone, then do the same to its
    /// parent, and so on up: the death of the last descendant clears the whole
    /// dead chain above it in one pass.
    fn prune(&mut self, pid: u32) {
        let mut cur = pid;
        for _ in 0..MAX_ANCESTORS {
            if !self.exited.contains(&cur) {
                break;
            }
            if self.children.get(&cur).is_some_and(|k| !k.is_empty()) {
                break;
            }
            let Some(p) = self.procs.remove(&cur) else {
                break;
            };
            self.exited.remove(&cur);
            self.children.remove(&cur);
            self.unlink(cur, p.ppid);
            if p.ppid == cur {
                break;
            }
            cur = p.ppid;
        }
    }

    /// The ancestors of `pid`, nearest first, excluding `pid` itself; stops at
    /// pid 1, at an unknown pid, at a cycle, or after [`MAX_ANCESTORS`].
    pub fn ancestors(&self, pid: u32) -> Vec<Proc> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut cur = pid;
        seen.insert(cur);
        while out.len() < MAX_ANCESTORS {
            let Some(p) = self.procs.get(&cur) else { break };
            let parent = p.ppid;
            if parent == 0 || !seen.insert(parent) {
                break;
            }
            let Some(pp) = self.procs.get(&parent) else {
                break;
            };
            out.push(pp.clone());
            if parent == 1 {
                break;
            }
            cur = parent;
        }
        out
    }

    /// `pid` and every live descendant of it (spec §6: what a freeze takes).
    /// The walk goes *through* tombstones but never reports one: a dead pid
    /// cannot be moved into a quarantine cgroup, while the live orphans below
    /// it must still be.
    pub fn descendants(&self, pid: u32) -> Vec<u32> {
        let mut out = Vec::new();
        let mut seen = HashSet::from([pid]);
        let mut queue = vec![pid];
        let mut i = 0;
        while i < queue.len() {
            let cur = queue[i];
            i += 1;
            if self.get(cur).is_some() {
                out.push(cur);
            }
            if let Some(kids) = self.children.get(&cur) {
                for &child in kids {
                    if seen.insert(child) {
                        queue.push(child);
                    }
                }
            }
        }
        out
    }

    /// Record one event for the alert context of `pid`'s tree.
    pub fn record_context(&mut self, pid: u32, json: serde_json::Value, now_ms: u64) {
        self.ring.push_back(ContextEvent {
            pid,
            at_ms: now_ms,
            json,
        });
        while self.ring.len() > MAX_CONTEXT_RING {
            self.ring.pop_front();
        }
        while let Some(front) = self.ring.front() {
            if now_ms.saturating_sub(front.at_ms) > CONTEXT_WINDOW_MS {
                self.ring.pop_front();
            } else {
                break;
            }
        }
    }

    /// The newest [`MAX_CONTEXT`] events belonging to `pid`'s tree — `pid`
    /// itself, its ancestors and its descendants — oldest first.
    pub fn context_for(&self, pid: u32, now_ms: u64) -> Vec<serde_json::Value> {
        let mut tree: HashSet<u32> = self.descendants(pid).into_iter().collect();
        tree.insert(pid);
        for a in self.ancestors(pid) {
            tree.insert(a.pid);
        }
        let mut out: Vec<serde_json::Value> = self
            .ring
            .iter()
            .filter(|e| {
                tree.contains(&e.pid) && now_ms.saturating_sub(e.at_ms) <= CONTEXT_WINDOW_MS
            })
            .map(|e| e.json.clone())
            .collect();
        if out.len() > MAX_CONTEXT {
            out.drain(..out.len() - MAX_CONTEXT);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc::{FakeProc, Proc};

    fn p(pid: u32, ppid: u32, exe: &str) -> Proc {
        Proc {
            pid,
            ppid,
            exe: exe.to_string(),
            argv: exe.to_string(),
            uid: 1000,
            unit: "session-2.scope".to_string(),
            cgroup_id: 77,
        }
    }

    fn seeded() -> (Table, FakeProc) {
        let mut src = FakeProc::default();
        src.add(p(1, 0, "/usr/lib/systemd/systemd"));
        src.add(p(100, 1, "/usr/bin/sshd"));
        src.add(p(200, 100, "/usr/bin/bash"));
        let mut t = Table::default();
        t.seed(&src);
        (t, src)
    }

    #[test]
    fn seed_reads_every_pid() {
        let (t, _) = seeded();
        assert_eq!(t.len(), 3);
        assert_eq!(t.get(200).unwrap().exe, "/usr/bin/bash");
    }

    #[test]
    fn ancestors_walk_up_to_pid_one() {
        let (t, _) = seeded();
        let exes: Vec<String> = t.ancestors(200).iter().map(|a| a.exe.clone()).collect();
        assert_eq!(
            exes,
            vec!["/usr/bin/sshd", "/usr/lib/systemd/systemd"],
            "the chain excludes the process itself and ends at pid 1"
        );
    }

    #[test]
    fn ancestors_terminate_on_a_cycle() {
        let mut t = Table::default();
        t.insert(p(5, 6, "/a"));
        t.insert(p(6, 5, "/b"));
        assert!(t.ancestors(5).len() <= MAX_ANCESTORS);
    }

    #[test]
    fn fork_inserts_the_child_with_the_parents_image() {
        let (mut t, _) = seeded();
        t.on_fork(200, 201);
        let c = t.get(201).expect("child present");
        assert_eq!(c.ppid, 200);
        assert_eq!(c.exe, "/usr/bin/bash", "a fork shares the parent's image");
    }

    #[test]
    fn exec_replaces_the_image_of_an_existing_pid() {
        let (mut t, mut src) = seeded();
        src.add(p(200, 100, "/usr/bin/python3"));
        t.on_exec(200, &src);
        assert_eq!(t.get(200).unwrap().exe, "/usr/bin/python3");
    }

    #[test]
    fn exit_removes_the_pid() {
        let (mut t, _) = seeded();
        t.on_exit(200);
        assert!(t.get(200).is_none());
    }

    #[test]
    fn descendants_include_the_whole_subtree() {
        let (mut t, _) = seeded();
        t.on_fork(200, 201);
        t.on_fork(201, 202);
        let mut d = t.descendants(200);
        d.sort_unstable();
        assert_eq!(d, vec![200, 201, 202]);
    }

    #[test]
    fn context_keeps_only_the_trees_newest_events() {
        let (mut t, _) = seeded();
        t.on_fork(200, 201);
        for i in 0..25u64 {
            t.record_context(200, serde_json::json!({"on": "connect", "n": i}), i);
        }
        t.record_context(201, serde_json::json!({"on": "exec"}), 30);
        // A sibling's events must not appear.
        t.record_context(999, serde_json::json!({"on": "open"}), 31);

        let ctx = t.context_for(200, 32);
        assert_eq!(ctx.len(), MAX_CONTEXT);
        assert_eq!(ctx.last().unwrap()["on"], "exec", "newest last");
        assert!(
            ctx.iter().all(|e| e["on"] != "open"),
            "unrelated events excluded: {ctx:?}"
        );
    }

    #[test]
    fn an_exiting_parent_stays_reachable_while_its_children_live() {
        let (mut t, _) = seeded();
        t.on_fork(200, 201);
        t.on_exit(200);
        assert!(t.get(200).is_none(), "the dead pid is not a live process");
        let mut d = t.descendants(100);
        d.sort_unstable();
        assert_eq!(d, vec![100, 201], "the orphan stays under sshd");
        let exes: Vec<String> = t.ancestors(201).iter().map(|a| a.exe.clone()).collect();
        assert_eq!(
            exes,
            vec!["/usr/bin/bash", "/usr/bin/sshd", "/usr/lib/systemd/systemd"],
            "the chain still reaches pid 1 through the dead parent"
        );
    }

    #[test]
    fn a_tombstone_goes_once_its_last_descendant_does() {
        let (mut t, _) = seeded();
        t.on_fork(200, 201);
        t.on_exit(200);
        t.on_exit(201);
        assert_eq!(t.len(), 2, "only pid 1 and sshd are left");
        assert!(t.ancestors(201).is_empty(), "nothing left to walk");
        assert_eq!(t.descendants(100), vec![100]);
    }

    #[test]
    fn a_double_fork_keeps_the_orphan_in_its_original_tree() {
        let (mut t, _) = seeded();
        t.on_fork(200, 201);
        t.on_fork(201, 202);
        t.on_exit(201);
        let mut d = t.descendants(200);
        d.sort_unstable();
        assert_eq!(
            d,
            vec![200, 202],
            "the middle pid is gone, the orphan is not"
        );
        let exes: Vec<String> = t.ancestors(202).iter().map(|a| a.exe.clone()).collect();
        assert!(
            exes.contains(&"/usr/bin/sshd".to_string()),
            "an `ancestors` rule still matches after the double fork: {exes:?}"
        );
    }

    #[test]
    fn tombstones_cascade_away_together() {
        let (mut t, _) = seeded();
        t.on_fork(200, 201);
        t.on_fork(201, 202);
        t.on_exit(200);
        t.on_exit(201);
        t.on_exit(202);
        assert_eq!(t.len(), 2);
        assert_eq!(t.descendants(100), vec![100]);
    }

    #[test]
    fn exec_relinks_a_pid_under_its_real_parent() {
        let (mut t, mut src) = seeded();
        t.on_fork(200, 201);
        // /proc disagrees with the fork event: 201's parent is really sshd.
        src.add(p(201, 100, "/usr/bin/python3"));
        t.on_exec(201, &src);
        assert_eq!(
            t.descendants(200),
            vec![200],
            "the stale child link is gone"
        );
        let mut d = t.descendants(100);
        d.sort_unstable();
        assert_eq!(d, vec![100, 200, 201]);
    }

    #[test]
    fn context_survives_the_death_of_a_middle_process() {
        let (mut t, _) = seeded();
        t.on_fork(200, 201);
        t.record_context(200, serde_json::json!({"on": "exec"}), 1);
        t.record_context(201, serde_json::json!({"on": "connect"}), 2);
        t.on_exit(200);
        let ctx = t.context_for(201, 3);
        assert_eq!(
            ctx.len(),
            2,
            "the dead parent's events are still the orphan's context: {ctx:?}"
        );
    }

    #[test]
    fn context_drops_events_older_than_the_window() {
        let mut t = Table::default();
        t.insert(p(10, 1, "/a"));
        t.record_context(10, serde_json::json!({"on": "connect"}), 0);
        t.record_context(
            10,
            serde_json::json!({"on": "listen"}),
            CONTEXT_WINDOW_MS + 1,
        );
        let ctx = t.context_for(10, CONTEXT_WINDOW_MS + 2);
        assert_eq!(ctx.len(), 1);
        assert_eq!(ctx[0]["on"], "listen");
    }
}
