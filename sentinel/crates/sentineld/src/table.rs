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
#[derive(Default)]
pub struct Table {
    procs: HashMap<u32, Proc>,
    ring: VecDeque<ContextEvent>,
}

impl Table {
    /// Build the table from a full `/proc` scan (spec §4: at start).
    pub fn seed(&mut self, src: &dyn ProcSource) {
        for pid in src.pids() {
            if let Some(p) = src.read(pid) {
                self.procs.insert(pid, p);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.procs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.procs.is_empty()
    }

    pub fn get(&self, pid: u32) -> Option<&Proc> {
        self.procs.get(&pid)
    }

    pub fn insert(&mut self, p: Proc) {
        self.procs.insert(p.pid, p);
    }

    /// A fork: the child starts as a copy of the parent.
    pub fn on_fork(&mut self, parent: u32, child: u32) {
        let mut p = self.procs.get(&parent).cloned().unwrap_or_default();
        p.pid = child;
        p.ppid = parent;
        self.procs.insert(child, p);
    }

    /// An exec: re-read the pid, because its image, argv and cgroup changed.
    pub fn on_exec(&mut self, pid: u32, src: &dyn ProcSource) {
        if let Some(p) = src.read(pid) {
            self.procs.insert(pid, p);
        }
    }

    /// An exit: drop the pid. Its context events age out of the ring on their
    /// own, so an alert raised moments later still has them.
    pub fn on_exit(&mut self, pid: u32) {
        self.procs.remove(&pid);
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
            let Some(pp) = self.procs.get(&parent) else { break };
            out.push(pp.clone());
            if parent == 1 {
                break;
            }
            cur = parent;
        }
        out
    }

    /// `pid` and every descendant of it (spec §6: what a freeze takes).
    pub fn descendants(&self, pid: u32) -> Vec<u32> {
        let mut out = vec![pid];
        let mut i = 0;
        while i < out.len() {
            let parent = out[i];
            for (child, p) in &self.procs {
                if p.ppid == parent && !out.contains(child) {
                    out.push(*child);
                }
            }
            i += 1;
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
    fn context_drops_events_older_than_the_window() {
        let mut t = Table::default();
        t.insert(p(10, 1, "/a"));
        t.record_context(10, serde_json::json!({"on": "connect"}), 0);
        t.record_context(10, serde_json::json!({"on": "listen"}), CONTEXT_WINDOW_MS + 1);
        let ctx = t.context_for(10, CONTEXT_WINDOW_MS + 2);
        assert_eq!(ctx.len(), 1);
        assert_eq!(ctx[0]["on"], "listen");
    }
}
