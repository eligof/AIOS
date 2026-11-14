//! The daemon state and the hot path: one raw event in, alerts and actions out.

use sentinel_common::event::{Action, EventKind};
use sentinel_common::wire::RawEvent;
use sentinel_rules::config::SentinelConfig;

use crate::action::{self, Registry};
use crate::alert::{Alert, ProcRef, Store};
use crate::engine::{Decision, Detectors, Outcome, Policy, RuleSet, StormBrake};
use crate::kernel::Kernel;
use crate::proc::ProcSource;
use crate::report::Sink;
use crate::resolve::{HomeBinds, Resolved};
use crate::table::Table;

/// Everything the daemon owns. The threads share one `Mutex<Daemon>`.
pub struct Daemon {
    pub rules: RuleSet,
    pub config: SentinelConfig,
    pub table: Table,
    pub procs: Box<dyn ProcSource>,
    pub sink: Box<dyn Sink>,
    pub store: Store,
    pub policy: Policy,
    pub binds: HomeBinds,
    pub quarantines: Registry,
    pub brake: StormBrake,
    pub detectors: Detectors,
    /// The last `DROPS` value seen, so only an increase alerts (spec §4).
    last_drops: u64,
    /// Alerts kept in memory for `WatchAlerts` subscribers (Task 17).
    pub recent: std::collections::VecDeque<Alert>,
    /// Set when the store is failing, for `Status` (spec §12).
    pub store_failing: Option<String>,
    /// The generation whose rules are loaded, for `Status` (spec §10.1).
    pub generation: String,
    /// The last `Status` built, so the varlink thread does not need a kernel.
    pub status: Option<crate::status::Status>,
    /// The last wall clock the hot path saw, for alerts raised off it.
    pub last_wall_ms: u64,
}

/// How many alerts stay in memory for watchers.
const RECENT_CAP: usize = 256;

impl Daemon {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rules: RuleSet,
        config: SentinelConfig,
        procs: Box<dyn ProcSource>,
        sink: Box<dyn Sink>,
        store: Store,
        policy: Policy,
        binds: HomeBinds,
    ) -> Daemon {
        let brake = StormBrake::new(config.storm_brake);
        let detectors = Detectors::new(&config.beacon, &config.dns_tunnel);
        Daemon {
            rules,
            config,
            table: Table::default(),
            procs,
            sink,
            store,
            policy,
            binds,
            quarantines: Registry::default(),
            brake,
            detectors,
            last_drops: 0,
            recent: std::collections::VecDeque::new(),
            store_failing: None,
            generation: String::new(),
            status: None,
            last_wall_ms: 0,
        }
    }

    /// The snapshot the read methods answer from.
    pub fn read_view(&self) -> crate::varlink::ReadView {
        crate::varlink::ReadView {
            status: self.status.clone(),
            alerts: self.store.read_all().unwrap_or_default(),
            quarantines: self
                .quarantines
                .list()
                .iter()
                .map(|q| {
                    serde_json::json!({
                        "id": q.alert_id,
                        "cgroup": q.cgroup,
                        "rootPid": q.root_pid,
                        "pids": q.pids,
                        "killed": q.killed,
                    })
                })
                .collect(),
            chain: self.store.verify().map_err(|e| e.to_string()),
        }
    }

    /// Validate and swap a generation's rules (spec §11.3). On success the
    /// change summary is returned and a critical alert records it; on failure
    /// the current rules stay and the errors come back.
    pub fn load_generation(
        &mut self,
        generation: &str,
        dir: &std::path::Path,
        kernel: std::sync::Arc<std::sync::Mutex<Box<dyn Kernel>>>,
    ) -> Result<Vec<String>, Vec<String>> {
        let loaded = sentinel_rules::load_dir(dir)
            .map_err(|errs| errs.iter().map(|e| e.to_string()).collect::<Vec<_>>())?;
        let next = crate::engine::RuleSet::compile(loaded)
            .map_err(|errs| errs.iter().map(|e| e.to_string()).collect::<Vec<_>>())?;

        let diff = sentinel_rules::diff::diff_rules(&self.rules.rules, &next.rules);
        let changes = diff.summary();

        {
            let mut k = kernel.lock().map_err(|_| vec!["kernel busy".to_string()])?;
            k.swap_rules(&next.tables)
                .map_err(|e| vec![e.to_string()])?;
        }
        self.rules = next;
        self.generation = generation.to_string();

        let now = self.last_wall_ms;
        let mut a = self.blank_alert("config-changed", "critical", "alerted");
        a.ts = Self::format_ts(now);
        a.message = format!("Sentinel configuration changed by {generation}");
        a.event = serde_json::json!({
            "on": "config",
            "generation": generation,
            "changes": changes,
        });
        self.raise(a);
        Ok(changes)
    }

    /// A DNS-tunnel hit. Host-level, so it names the domain, not a process
    /// (spec §5.4), and its action can only be alert — freezing a host-level
    /// detection has no process to freeze.
    pub fn raise_dns(&mut self, hit: crate::engine::DetectorHit, now_ms: u64) {
        let mut a = self.blank_alert(hit.rule_id, &hit.severity, "alerted");
        a.ts = Self::format_ts(now_ms);
        a.event = hit.event;
        self.raise(a);
    }

    /// Rebuild the `Status` snapshot the varlink thread serves (spec §10.1).
    ///
    /// Called from the heartbeat thread, which already holds the kernel each
    /// tick. Without it the snapshot would keep whatever values it was built
    /// with at start-up, and `sentinel status` would report a 0 ms heartbeat
    /// age and no drops however long the daemon had been running.
    pub fn refresh_status(&mut self, k: &dyn Kernel, dns_monitor: bool, lockdown_after_ns: u64) {
        let Some(prev) = self.status.clone() else {
            return;
        };
        let beat = k.heartbeat_value().unwrap_or(0);
        let now_ns = k.monotonic_ns();
        let counts = k.lockdown_counts().unwrap_or([0; crate::kernel::NHOOKS]);
        let (kernel_rules, user_rules) = self.rules.counts();
        self.status = Some(crate::status::Status {
            heartbeat_age_ms: crate::status::heartbeat_age_ms(now_ns, beat),
            lockdown_active: crate::status::lockdown_active(now_ns, beat, lockdown_after_ns),
            lockdown_counts: counts.to_vec(),
            kernel_rules,
            user_rules,
            audit_rules: self
                .rules
                .rules
                .iter()
                .filter(|r| r.mode.as_deref() == Some("audit"))
                .count(),
            generation: self.generation.clone(),
            drops: k.drops().unwrap_or(0),
            quarantines: self.quarantines.list().len(),
            dns_monitor,
            store_error: self.store_failing.clone(),
            ..prev
        });
    }

    /// The start-up `/proc` scan (spec §4).
    pub fn seed_table(&mut self) {
        let src = &*self.procs;
        self.table.seed(src);
    }

    /// RFC 3339 UTC with millisecond precision, from a wall-clock millisecond
    /// count. Written by hand because the dependency set has no date crate.
    fn format_ts(ms: u64) -> String {
        let secs = (ms / 1000) as i64;
        let millis = ms % 1000;
        // Days since the Unix epoch, converted with the civil-from-days
        // algorithm (Howard Hinnant's, public domain).
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            y,
            m,
            d,
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60,
            millis
        )
    }

    /// The process reference an alert carries. Reads tombstones too: an alert
    /// is a record of what was running, and the ancestor chain is worth more
    /// than the distinction between a live parent and one that just exited.
    fn proc_ref(&self, pid: u32) -> Option<ProcRef> {
        self.table.get_any(pid).map(|p| ProcRef {
            pid: p.pid,
            exe: p.exe.clone(),
            argv: p.argv.clone(),
            uid: p.uid,
            unit: p.unit.clone(),
        })
    }

    /// Store, remember and emit one alert. A store failure is recorded for
    /// `Status` but never stops the journal or the TTYs (spec §12).
    pub fn raise(&mut self, mut a: Alert) -> String {
        // Read the chain head before the append: that is what this record is
        // sealed onto, so the in-memory copy can mirror the on-disk one
        // without re-reading the log to find its predecessor.
        let prev = self.store.head().to_string();
        let mut recovered = None;
        match self.store.append(a.clone()) {
            Ok(hash) => {
                a.prev_hash = prev;
                a.hash = hash;
                recovered = self.store_failing.take();
            }
            Err(e) => {
                self.store_failing = Some(e.to_string());
            }
        }
        if let Some(was) = recovered {
            // Spec §12 asks for an alert once the store works again.
            let mut note = self.blank_alert("store-recovered", "critical", "alerted");
            note.ts = a.ts.clone();
            note.message = format!("the alert store is writable again (was: {was})");
            let _ = self.store.append(note);
        }
        self.sink.emit(&a);
        let id = a.id.clone();
        self.recent.push_back(a);
        while self.recent.len() > RECENT_CAP {
            self.recent.pop_front();
        }
        id
    }

    /// An alert that is not a rule hit: a lockdown report, a brake, an
    /// overflow, a configuration change.
    pub fn blank_alert(&self, rule: &str, severity: &str, outcome: &str) -> Alert {
        Alert {
            id: ulid::Ulid::generate().to_string(),
            ts: String::new(),
            rule: rule.to_string(),
            severity: severity.to_string(),
            action: "alert".to_string(),
            mode: "enforce".to_string(),
            outcome: outcome.to_string(),
            message: String::new(),
            process: None,
            ancestors: vec![],
            event: serde_json::json!({}),
            context: vec![],
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    /// Report an increase in the kernel's dropped-event counter (spec §4, §12).
    pub fn check_drops(&mut self, k: &mut dyn Kernel) {
        let Ok(now) = k.drops() else { return };
        if now <= self.last_drops {
            return;
        }
        let lost = now - self.last_drops;
        self.last_drops = now;
        let mut a = self.blank_alert("sensor-overflow", "high", "alerted");
        a.ts = Self::format_ts(k.wall_ms());
        a.message = format!("{lost} events dropped by a full ring buffer");
        a.event = serde_json::json!({"on": "sensor", "dropped": lost, "total": now});
        self.raise(a);
    }

    fn action_name(a: Action) -> &'static str {
        match a {
            Action::Alert => "alert",
            Action::Deny => "deny",
            Action::Freeze => "freeze",
            Action::Kill => "kill",
        }
    }

    /// The ancestor chain for an alert, taken from the chain the event
    /// resolved against so a tombstoned ancestor keeps its place in it.
    fn ancestor_refs(&self, r: &Resolved) -> Vec<ProcRef> {
        r.ancestor_pids
            .iter()
            .zip(&r.ancestors)
            .map(|(pid, exe)| {
                self.proc_ref(*pid).unwrap_or(ProcRef {
                    pid: *pid,
                    exe: exe.clone(),
                    argv: String::new(),
                    uid: 0,
                    unit: String::new(),
                })
            })
            .collect()
    }

    /// Build the alert for one decision on one resolved event.
    fn alert_for(&self, r: &Resolved, d: &Decision, outcome: Outcome, now_ms: u64) -> Alert {
        let severity = if outcome == Outcome::Failed {
            // A failed action is critical regardless of the rule (spec §6).
            "critical".to_string()
        } else {
            d.severity.clone()
        };
        Alert {
            id: ulid::Ulid::generate().to_string(),
            ts: Self::format_ts(now_ms),
            rule: d.rule_id.clone(),
            severity,
            action: Self::action_name(d.action).to_string(),
            mode: match d.mode {
                sentinel_common::event::Mode::Enforce => "enforce",
                sentinel_common::event::Mode::Audit => "audit",
            }
            .to_string(),
            outcome: outcome.as_str().to_string(),
            message: String::new(),
            process: self.proc_ref(r.pid),
            ancestors: self.ancestor_refs(r),
            event: r.detail.clone(),
            context: self.table.context_for(r.pid, now_ms),
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    /// The whole hot path for one raw event.
    pub fn on_event(&mut self, ev: &RawEvent, k: &mut dyn Kernel) {
        let now_ms = k.wall_ms();
        self.last_wall_ms = now_ms;

        // 1. Table upkeep. An event whose kind does not decode is dropped
        //    right here: `Resolved::from_raw` would refuse it anyway, and
        //    nothing below may run on a record we cannot read.
        let Some(kind) = EventKind::from_u8(ev.hdr.kind) else {
            return;
        };
        match kind {
            EventKind::Exec => {
                let src = &*self.procs;
                self.table.on_exec(ev.hdr.pid, src);
            }
            EventKind::Fork => {
                // SAFETY: the kernel wrote the proc_ variant for a fork.
                let p = unsafe { ev.payload.proc_ };
                self.table.on_fork(ev.hdr.pid, p.child_pid);
            }
            _ => {}
        }

        // 2. Resolve.
        let Some(r) = ({
            let src = &*self.procs;
            Resolved::from_raw(ev, &self.table, src, &self.binds)
        }) else {
            return;
        };

        // 3. Context ring.
        self.table.record_context(r.pid, r.detail.clone(), now_ms);

        // 4. Detectors.
        if r.kind == EventKind::Connect {
            if let Some((dest, port)) = r.net.clone() {
                if let Some(hit) = self.detectors.on_connect(&r.exe, &dest, port, now_ms) {
                    self.raise_detector(hit, &r, now_ms, k);
                }
            }
        }

        // 5. Decisions.
        let decisions = self.rules.decide(&r, &self.policy, now_ms);
        for d in decisions {
            self.apply(&r, d, now_ms, k);
        }

        // 6. An exit is processed last, so the alert above still saw the pid.
        if kind == EventKind::Exit {
            self.table.on_exit(ev.hdr.pid);
        }
    }

    /// Take the tree, under the brake, naming the quarantine after `id`.
    fn act(
        &mut self,
        id: &str,
        root_pid: u32,
        kill: bool,
        now_ms: u64,
        k: &mut dyn Kernel,
    ) -> (Outcome, String, Option<action::Quarantine>) {
        if self.brake.trip(now_ms) {
            if self.brake.just_engaged() {
                let mut a = self.blank_alert("storm-brake", "critical", "alerted");
                a.ts = Self::format_ts(now_ms);
                a.message = format!(
                    "storm brake engaged: more than {} automatic actions in a minute",
                    self.config.storm_brake
                );
                self.raise(a);
            }
            return (Outcome::Braked, String::new(), None);
        }
        let src = &*self.procs;
        match action::freeze(k, &self.table, src, id, root_pid, kill) {
            Ok(q) => (
                if kill {
                    Outcome::Killed
                } else {
                    Outcome::Frozen
                },
                String::new(),
                Some(q),
            ),
            Err(e) => (Outcome::Failed, e.to_string(), None),
        }
    }

    /// Run a decision's action, then store and emit its alert.
    fn apply(&mut self, r: &Resolved, d: Decision, now_ms: u64, k: &mut dyn Kernel) {
        let mut outcome = d.outcome;
        let mut message = String::new();
        let mut quarantine = None;
        // The alert id names the quarantine cgroup, so it is minted up front.
        let id = ulid::Ulid::generate().to_string();

        if d.acts() {
            let (o, m, q) = self.act(&id, r.pid, d.outcome == Outcome::Killed, now_ms, k);
            outcome = o;
            message = m;
            quarantine = q;
        }

        let mut a = self.alert_for(r, &d, outcome, now_ms);
        a.message = message;
        if quarantine.is_some() {
            // Keep the alert id and the cgroup name in step.
            a.id = id;
        }
        self.raise(a);
        if let Some(q) = quarantine {
            self.quarantines.insert(q);
        }
    }

    /// A detector hit becomes an alert the same way a rule hit does.
    fn raise_detector(
        &mut self,
        hit: crate::engine::DetectorHit,
        r: &Resolved,
        now_ms: u64,
        k: &mut dyn Kernel,
    ) {
        let mut outcome = match hit.action {
            Action::Alert => Outcome::Alerted,
            Action::Freeze => Outcome::Frozen,
            Action::Kill => Outcome::Killed,
            // `config::validate` rejects deny for a detector (§5.4).
            Action::Deny => Outcome::Alerted,
        };
        let mut message = String::new();
        let mut quarantine = None;
        let id = ulid::Ulid::generate().to_string();

        if matches!(outcome, Outcome::Frozen | Outcome::Killed) {
            if self.policy.is_protected_event(r) {
                outcome = Outcome::Suppressed;
            } else {
                let (o, m, q) = self.act(&id, r.pid, outcome == Outcome::Killed, now_ms, k);
                outcome = o;
                message = m;
                quarantine = q;
            }
        }

        let mut a = self.blank_alert(hit.rule_id, &hit.severity, outcome.as_str());
        a.ts = Self::format_ts(now_ms);
        a.action = Self::action_name(hit.action).to_string();
        a.message = message;
        a.event = hit.event;
        a.process = self.proc_ref(r.pid);
        a.ancestors = self.ancestor_refs(r);
        a.context = self.table.context_for(r.pid, now_ms);
        if quarantine.is_some() {
            a.id = id;
        }
        self.raise(a);
        if let Some(q) = quarantine {
            self.quarantines.insert(q);
        }
    }
}

/// `Daemon::format_ts`, for callers outside the type.
pub fn format_ts_pub(ms: u64) -> String {
    Daemon::format_ts(ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::FakeKernel;
    use crate::proc::{FakeProc, Proc};
    use crate::report::FakeSink;
    use sentinel_common::wire::{EventHeader, EventPayload, ExecPayload, NetPayload};

    const PACK: &str = r#"
[[rule]]
id = "ld-preload"
on = "exec"
severity = "medium"
action = "alert"
match = { env_ld = true }

[[rule]]
id = "reverse-shell"
on = "exec"
severity = "high"
action = "freeze"
match = { exe = ["/usr/bin/bash"], stdio_socket = true }
"#;

    fn p(pid: u32, ppid: u32, exe: &str) -> Proc {
        Proc {
            pid,
            ppid,
            exe: exe.to_string(),
            argv: format!("{exe} -i"),
            uid: 1000,
            unit: "session-2.scope".to_string(),
            cgroup_id: 77,
        }
    }

    /// A daemon over fakes, with the two-rule pack above.
    fn daemon(dir: &std::path::Path) -> (Daemon, Box<FakeKernel>) {
        let pack = dir.join("rules");
        std::fs::create_dir_all(&pack).unwrap();
        std::fs::write(pack.join("p.toml"), PACK).unwrap();
        let rules = sentinel_rules::load_dir(&pack).unwrap();
        let rs = crate::engine::RuleSet::compile(rules).unwrap();

        let mut src = FakeProc::default();
        src.add(p(1, 0, "/usr/lib/systemd/systemd"));
        src.add(p(200, 1, "/usr/bin/bash"));
        src.env_ld.insert(200);
        src.stdio_socket.insert(200);
        // 201 is the child some tests fork from 200. It has no /proc entry of
        // its own on purpose, so the table keeps the image it inherited.
        src.stdio_socket.insert(201);

        let mut k = FakeKernel::default();
        for pid in [1u32, 200, 201] {
            k.pid_cgroups
                .insert(pid, "/user.slice/session-2.scope".to_string());
        }

        let cfg = sentinel_rules::config::SentinelConfig::default();
        let mut d = Daemon::new(
            rs,
            cfg,
            Box::new(src),
            Box::new(FakeSink::default()),
            crate::alert::Store::open(&dir.join("alerts")).unwrap(),
            crate::engine::Policy::new(7, 9, vec![]),
            crate::resolve::HomeBinds::default(),
        );
        d.seed_table();
        (d, Box::new(k))
    }

    fn exec_event(pid: u32) -> RawEvent {
        let mut h: EventHeader = unsafe { std::mem::zeroed() };
        h.kind = EventKind::Exec as u8;
        h.pid = pid;
        h.ppid = 1;
        h.uid = 1000;
        h.matched_rule = -1;
        RawEvent {
            hdr: h,
            payload: EventPayload {
                exec: ExecPayload {
                    exe: [0; 256],
                    argv: [0; 256],
                    exe_len: 0,
                    argv_len: 0,
                    mnt_id: 0,
                },
            },
        }
    }

    #[test]
    fn timestamps_are_rfc3339_utc() {
        // Checked against `date -u -d @1763000571` -> 2025-11-13T02:22:51.
        assert_eq!(
            Daemon::format_ts(1_763_000_571_123),
            "2025-11-13T02:22:51.123Z"
        );
        // `date -u -d @1709164800` -> 2024-02-29T00:00:00 (a leap day).
        assert_eq!(
            Daemon::format_ts(1_709_164_800_000),
            "2024-02-29T00:00:00.000Z"
        );
        assert_eq!(Daemon::format_ts(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn an_alert_rule_stores_and_emits_one_alert() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, mut k) = daemon(dir.path());
        d.on_event(&exec_event(200), k.as_mut());

        let stored = d.store.read_all().unwrap();
        let ld = stored
            .iter()
            .find(|a| a.rule == "ld-preload")
            .expect("stored");
        assert_eq!(ld.outcome, "alerted");
        assert_eq!(ld.severity, "medium");
        assert_eq!(ld.process.as_ref().unwrap().exe, "/usr/bin/bash");
        assert_eq!(
            ld.ancestors.first().map(|a| a.exe.as_str()),
            Some("/usr/lib/systemd/systemd"),
            "the chain is carried into the alert"
        );
        assert!(!ld.id.is_empty(), "every alert gets an id");
    }

    #[test]
    fn a_stored_alert_mirrors_the_chain_it_was_sealed_onto() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, mut k) = daemon(dir.path());
        d.on_event(&exec_event(200), k.as_mut());
        let stored = d.store.read_all().unwrap();
        assert!(!stored.is_empty());
        for (i, a) in stored.iter().enumerate() {
            let kept = d
                .recent
                .iter()
                .find(|x| x.id == a.id)
                .expect("every stored alert is also in memory");
            assert_eq!(kept.hash, a.hash, "record {i}");
            assert_eq!(kept.prev_hash, a.prev_hash, "record {i}");
        }
    }

    #[test]
    fn a_freeze_rule_actually_freezes_and_records_the_quarantine() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, mut k) = daemon(dir.path());
        d.on_event(&exec_event(200), k.as_mut());

        let frozen = d
            .store
            .read_all()
            .unwrap()
            .into_iter()
            .find(|a| a.rule == "reverse-shell")
            .expect("reverse-shell alert");
        assert_eq!(frozen.outcome, "frozen");
        assert_eq!(d.quarantines.list().len(), 1);
        let q = d
            .quarantines
            .get(&frozen.id)
            .expect("registered by alert id");
        assert_eq!(q.root_pid, 200);
        assert!(k.frozen.contains(&q.cgroup));
        assert!(k.quarantined.contains(&q.cgroup_id));
    }

    #[test]
    fn a_failed_action_becomes_a_critical_alert_and_freezes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, mut k) = daemon(dir.path());
        // The cgroup name carries a generated id, so fail by prefix.
        k.fail_all_prefixed = Some("cgroup_freeze".to_string());

        d.on_event(&exec_event(200), k.as_mut());

        let stored = d.store.read_all().unwrap();
        let failed = stored
            .iter()
            .find(|a| a.rule == "reverse-shell")
            .expect("alert exists");
        assert_eq!(failed.outcome, "failed");
        assert!(
            failed.message.contains("cgroup_freeze"),
            "the error is named: {}",
            failed.message
        );
        assert_eq!(failed.severity, "critical", "a failed action is critical");
        assert!(d.quarantines.list().is_empty());
        assert!(k.frozen.is_empty(), "nothing is left frozen");
    }

    #[test]
    fn the_storm_brake_downgrades_later_freezes() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, mut k) = daemon(dir.path());
        d.brake = crate::engine::StormBrake::new(1);

        d.on_event(&exec_event(200), k.as_mut());
        d.on_event(&exec_event(200), k.as_mut());

        let outcomes: Vec<String> = d
            .store
            .read_all()
            .unwrap()
            .into_iter()
            .filter(|a| a.rule == "reverse-shell")
            .map(|a| a.outcome)
            .collect();
        assert_eq!(outcomes, vec!["frozen", "braked"]);
        assert!(
            d.store
                .read_all()
                .unwrap()
                .iter()
                .any(|a| a.rule == "storm-brake" && a.severity == "critical"),
            "engaging the brake is itself a critical alert"
        );
    }

    #[test]
    fn exit_removes_the_pid_from_the_table() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, mut k) = daemon(dir.path());
        let mut h: EventHeader = unsafe { std::mem::zeroed() };
        h.kind = EventKind::Exit as u8;
        h.pid = 200;
        h.matched_rule = -1;
        let ev = RawEvent {
            hdr: h,
            payload: EventPayload {
                proc_: sentinel_common::wire::ProcPayload {
                    child_pid: 200,
                    exit_code: 0,
                },
            },
        };
        d.on_event(&ev, k.as_mut());
        assert!(d.table.get(200).is_none());
    }

    #[test]
    fn an_exited_ancestor_still_appears_in_the_alert_chain() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, mut k) = daemon(dir.path());
        // 200 forks 201, then 200 exits: 201 is an orphan whose parent is a
        // tombstone. Its alert must still name what that parent was.
        d.table.on_fork(200, 201);
        d.table.on_exit(200);
        let mut ev = exec_event(201);
        ev.hdr.ppid = 200;
        d.on_event(&ev, k.as_mut());
        let a = d
            .store
            .read_all()
            .unwrap()
            .into_iter()
            .find(|a| a.rule == "reverse-shell")
            .expect("the orphan still matches");
        assert_eq!(
            a.ancestors.first().map(|x| x.exe.as_str()),
            Some("/usr/bin/bash"),
            "the dead parent is in the chain: {:?}",
            a.ancestors
        );
    }

    #[test]
    fn a_connect_feeds_the_beacon_detector() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, mut k) = daemon(dir.path());
        d.detectors = crate::engine::Detectors::new(
            &sentinel_rules::config::Beacon {
                min_connects: 3,
                max_cov: 0.2,
                allow: vec![],
                severity: "high".to_string(),
                action: "alert".to_string(),
            },
            &sentinel_rules::config::DnsTunnel::default(),
        );
        for i in 0..4u64 {
            let mut h: EventHeader = unsafe { std::mem::zeroed() };
            h.kind = EventKind::Connect as u8;
            h.pid = 200;
            h.matched_rule = -1;
            h.ts_ns = i * 5_000_000_000;
            let ev = RawEvent {
                hdr: h,
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
            k.advance_ms(5_000);
            d.on_event(&ev, k.as_mut());
        }
        assert!(
            d.store
                .read_all()
                .unwrap()
                .iter()
                .any(|a| a.rule == "beacon"),
            "a periodic connect raises a beacon alert"
        );
    }

    #[test]
    fn a_ring_drop_raises_one_sensor_overflow_alert() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, mut k) = daemon(dir.path());
        k.drops_value = 5;
        d.check_drops(k.as_mut());
        d.check_drops(k.as_mut());
        let overflows = d
            .store
            .read_all()
            .unwrap()
            .into_iter()
            .filter(|a| a.rule == "sensor-overflow")
            .count();
        assert_eq!(overflows, 1, "only an increase alerts");

        k.drops_value = 9;
        d.check_drops(k.as_mut());
        let overflows = d
            .store
            .read_all()
            .unwrap()
            .into_iter()
            .filter(|a| a.rule == "sensor-overflow")
            .count();
        assert_eq!(overflows, 2);
    }

    #[test]
    fn an_undecodable_event_is_dropped_without_an_alert() {
        let dir = tempfile::tempdir().unwrap();
        let (mut d, mut k) = daemon(dir.path());
        let mut ev = exec_event(200);
        ev.hdr.kind = 200;
        d.on_event(&ev, k.as_mut());
        assert!(
            d.store.read_all().unwrap().is_empty(),
            "an unknown kind must not be dispatched as an exec"
        );
    }
}
