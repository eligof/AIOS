//! Dispatch: which rules a resolved event hits, and what the outcome is
//! before any action runs (spec §5.3, §6).

use std::collections::{HashMap, VecDeque};

use globset::{Glob, GlobSet, GlobSetBuilder};
use ipnet::IpNet;
use sentinel_common::event::{Action, Mode};
use sentinel_common::wire::KVerdict;
use sentinel_detect::beacon::{Beacon, BeaconConfig};
use sentinel_detect::dns_tunnel::{DnsReason, DnsTunnel, DnsTunnelConfig};
use sentinel_rules::matcher::{compile_all, UserRule};
use sentinel_rules::model::Rule;
use sentinel_rules::validate::parse_duration_ms;
use sentinel_rules::window::WindowState;
use sentinel_rules::{compile::Tables, RuleError};

use crate::resolve::Resolved;

/// What happened, or would have happened (spec §6, §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Alerted,
    Denied,
    WouldDeny,
    Frozen,
    WouldFreeze,
    Killed,
    WouldKill,
    /// The target is never acted on (spec §6).
    Suppressed,
    /// The storm brake is engaged (spec §6, Task 11).
    Braked,
    /// The action itself failed (spec §6, §12).
    Failed,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Alerted => "alerted",
            Outcome::Denied => "denied",
            Outcome::WouldDeny => "would-deny",
            Outcome::Frozen => "frozen",
            Outcome::WouldFreeze => "would-freeze",
            Outcome::Killed => "killed",
            Outcome::WouldKill => "would-kill",
            Outcome::Suppressed => "suppressed",
            Outcome::Braked => "braked",
            Outcome::Failed => "failed",
        }
    }
}

/// One rule hit on one event, before any action has run.
#[derive(Debug, Clone)]
pub struct Decision {
    pub rule_index: u32,
    pub rule_id: String,
    pub desc: String,
    pub severity: String,
    pub action: Action,
    pub mode: Mode,
    pub outcome: Outcome,
}

impl Decision {
    /// Does the daemon still have to do something, or is this alert-only?
    pub fn acts(&self) -> bool {
        matches!(self.outcome, Outcome::Frozen | Outcome::Killed)
    }
}

/// Which processes are never frozen or killed (spec §6).
pub struct Policy {
    /// The daemon's own tgid.
    pub self_tgid: u32,
    /// `systemd-journald`'s pid, or 0 if it is not running.
    pub journald_pid: u32,
    never_act_on: GlobSet,
}

impl Policy {
    pub fn new(self_tgid: u32, journald_pid: u32, never_act_on: Vec<String>) -> Policy {
        let mut b = GlobSetBuilder::new();
        for g in &never_act_on {
            // Validated by `config::validate`; a bad glob here is a bug.
            if let Ok(glob) = Glob::new(g) {
                b.add(glob);
            }
        }
        Policy {
            self_tgid,
            journald_pid,
            never_act_on: b.build().unwrap_or_else(|_| GlobSet::empty()),
        }
    }

    /// PID 1, PID 2, the daemon, journald and `never_act_on` units.
    pub fn is_protected(&self, pid: u32, unit: &str) -> bool {
        pid <= 2
            || pid == self.self_tgid
            || (self.journald_pid != 0 && pid == self.journald_pid)
            || (!unit.is_empty() && self.never_act_on.is_match(unit))
    }

    /// The same, plus every process with no executable.
    ///
    /// Kernel threads are never acted on (spec §6) and `pid <= 2` does not
    /// cover them: a kworker is an ordinary pid whose `/proc/<pid>/exe` does
    /// not resolve, so `RealProc` admits it to the table with an empty `exe`
    /// and a rule not keyed on the executable would otherwise freeze it. An
    /// empty `exe` means a kernel thread or a process that died before the
    /// read — nothing that can be frozen either way, and nothing a user-space
    /// process can fake, because a deleted or memfd image still reports a path.
    pub fn is_protected_event(&self, r: &Resolved) -> bool {
        self.is_protected(r.pid, &r.unit) || r.exe.is_empty()
    }
}

fn action_from_u8(v: u8) -> Action {
    match v {
        1 => Action::Deny,
        2 => Action::Freeze,
        3 => Action::Kill,
        _ => Action::Alert,
    }
}

fn mode_from_u8(v: u8) -> Mode {
    if v == Mode::Audit as u8 {
        Mode::Audit
    } else {
        Mode::Enforce
    }
}

/// The compiled rule set, plus one window counter per windowed rule.
pub struct RuleSet {
    pub rules: Vec<Rule>,
    pub tables: Tables,
    pub user: Vec<UserRule>,
    windows: HashMap<u32, WindowState>,
}

impl RuleSet {
    /// Compile a loaded rule list. Fails with the same errors `aios plan` prints.
    pub fn compile(rules: Vec<Rule>) -> Result<RuleSet, Vec<RuleError>> {
        let (tables, user) = compile_all(&rules)?;
        let mut windows = HashMap::new();
        for u in &user {
            if let Some(w) = &u.window {
                // `within` was validated at load time.
                let ms = parse_duration_ms(&w.within).unwrap_or(60_000);
                windows.insert(u.index, WindowState::new(w.count, ms));
            }
        }
        Ok(RuleSet {
            rules,
            tables,
            user,
            windows,
        })
    }

    /// How many rules of each kind, for `Status` (spec §10.1).
    pub fn counts(&self) -> (usize, usize) {
        (self.tables.rules.len(), self.user.len())
    }

    /// The window key for a hit, per the rule's `by` (spec §5.1).
    fn window_key(by: &str, r: &Resolved) -> String {
        match by {
            "uid" => r.uid.to_string(),
            "unit" => r.unit.clone(),
            "dest" => r
                .net
                .as_ref()
                .map(|(a, p)| format!("{a}:{p}"))
                .unwrap_or_default(),
            // "exe" and anything else
            _ => r.exe.clone(),
        }
    }

    /// Build the outcome for one rule hit, applying audit mode and protection.
    fn outcome_for(action: Action, mode: Mode, protected: bool) -> Outcome {
        if mode == Mode::Audit {
            return match action {
                Action::Alert => Outcome::Alerted,
                Action::Deny => Outcome::WouldDeny,
                Action::Freeze => Outcome::WouldFreeze,
                Action::Kill => Outcome::WouldKill,
            };
        }
        match action {
            Action::Alert => Outcome::Alerted,
            // A user rule can never be `deny` (§5.3), so this arm is only
            // reached for a kernel rule, whose verdict the caller overrides.
            Action::Deny => Outcome::Denied,
            Action::Freeze | Action::Kill if protected => Outcome::Suppressed,
            Action::Freeze => Outcome::Frozen,
            Action::Kill => Outcome::Killed,
        }
    }

    fn decision(&self, idx: u32, action: Action, mode: Mode, outcome: Outcome) -> Decision {
        let r = &self.rules[idx as usize];
        Decision {
            rule_index: idx,
            rule_id: r.id.clone(),
            desc: r.desc.clone(),
            severity: r.severity.clone(),
            action,
            mode,
            outcome,
        }
    }

    /// Every rule this event hits: the kernel's own match first, then the user
    /// rules in source order.
    pub fn decide(&mut self, r: &Resolved, policy: &Policy, now_ms: u64) -> Vec<Decision> {
        let mut out = Vec::new();
        let protected = policy.is_protected_event(r);

        // 1. The kernel already decided this one (spec §5.3).
        //
        // `matched_rule` is a position in the kernel's own RULES map, which
        // holds only the kernel-evaluable rules -- not an index into the
        // source list. The compiled `KRule` carries the source index for
        // exactly this reason. An out-of-range position is a stale event from
        // before a `LoadGeneration` swap, and is dropped.
        if r.matched_rule >= 0 {
            if let Some(kr) = self.tables.rules.get(r.matched_rule as usize) {
                let (idx, action, mode) =
                    (kr.index, action_from_u8(kr.action), mode_from_u8(kr.mode));
                if (idx as usize) < self.rules.len() {
                    // The kernel's verdict wins over our own reading of the
                    // rule: it is what actually happened in the hook.
                    let outcome = match r.kverdict {
                        KVerdict::Denied => Outcome::Denied,
                        KVerdict::WouldDeny => Outcome::WouldDeny,
                        KVerdict::None => Self::outcome_for(action, mode, protected),
                    };
                    out.push(self.decision(idx, action, mode, outcome));
                }
            }
        }

        // 2. User-space rules.
        let view = r.as_event();
        let hits: Vec<(u32, Action, Mode, Option<String>)> = self
            .user
            .iter()
            .filter(|u| u.on == r.kind && u.matches(&view))
            .map(|u| {
                (
                    u.index,
                    u.action,
                    u.mode,
                    u.window.as_ref().map(|w| w.by.clone()),
                )
            })
            .collect();

        for (idx, action, mode, by) in hits {
            if let Some(by) = by {
                let key = Self::window_key(&by, r);
                let fired = self
                    .windows
                    .get_mut(&idx)
                    .map(|w| w.record(&key, now_ms))
                    .unwrap_or(true);
                if !fired {
                    continue;
                }
            }
            let outcome = Self::outcome_for(action, mode, protected);
            out.push(self.decision(idx, action, mode, outcome));
        }

        out
    }
}

/// The storm-brake window (spec §6: "within a minute").
pub const BRAKE_WINDOW_MS: u64 = 60_000;

/// Caps automatic freezes and kills (spec §6).
pub struct StormBrake {
    limit: u32,
    acts: VecDeque<u64>,
    engaged: bool,
    reported: bool,
}

impl StormBrake {
    pub fn new(limit: u32) -> StormBrake {
        StormBrake {
            limit,
            acts: VecDeque::new(),
            engaged: false,
            reported: false,
        }
    }

    /// Record one automatic act. Returns true when this one must be braked.
    pub fn trip(&mut self, now_ms: u64) -> bool {
        while let Some(&front) = self.acts.front() {
            if now_ms.saturating_sub(front) > BRAKE_WINDOW_MS {
                self.acts.pop_front();
            } else {
                break;
            }
        }
        if self.acts.len() as u32 >= self.limit {
            // Engaging for the first time in this window is itself a critical
            // alert (spec §6); `just_engaged` reports it exactly once.
            self.engaged = true;
            return true;
        }
        self.acts.push_back(now_ms);
        self.engaged = false;
        self.reported = false;
        false
    }

    pub fn engaged(&self) -> bool {
        self.engaged
    }

    /// True the first time the brake engages, false on every later brake.
    pub fn just_engaged(&mut self) -> bool {
        if self.engaged && !self.reported {
            self.reported = true;
            return true;
        }
        false
    }
}

/// A detector hit, shaped like a rule hit so the daemon handles both the same way.
#[derive(Debug, Clone)]
pub struct DetectorHit {
    pub rule_id: &'static str,
    pub severity: String,
    pub action: Action,
    pub event: serde_json::Value,
    /// The executable the hit is about, for the alert's process reference.
    pub exe: String,
}

/// The two built-in detectors plus their allow lists (spec §5.4).
pub struct Detectors {
    beacon: Beacon,
    dns: DnsTunnel,
    beacon_nets: Vec<IpNet>,
    beacon_exes: GlobSet,
    beacon_severity: String,
    beacon_action: Action,
    dns_severity: String,
    dns_action: Action,
}

impl Detectors {
    pub fn new(
        b: &sentinel_rules::config::Beacon,
        d: &sentinel_rules::config::DnsTunnel,
    ) -> Detectors {
        let mut nets = Vec::new();
        let mut exes = GlobSetBuilder::new();
        for a in &b.allow {
            // `config::validate` has already checked these are a CIDR or a
            // `/`-prefixed glob.
            if let Ok(n) = a.parse::<IpNet>() {
                nets.push(n);
            } else if let Ok(g) = Glob::new(a) {
                exes.add(g);
            }
        }
        Detectors {
            beacon: Beacon::new(BeaconConfig {
                min_connects: b.min_connects,
                max_cov: b.max_cov,
                ..BeaconConfig::default()
            }),
            dns: DnsTunnel::new(DnsTunnelConfig {
                label_len: d.label_len,
                entropy: d.entropy,
                unique_per_min: d.unique_per_min,
                ..DnsTunnelConfig::default()
            }),
            beacon_nets: nets,
            beacon_exes: exes.build().unwrap_or_else(|_| GlobSet::empty()),
            beacon_severity: b.severity.clone(),
            beacon_action: sentinel_rules::validate::parse_action(&b.action)
                .unwrap_or(Action::Alert),
            dns_severity: d.severity.clone(),
            dns_action: sentinel_rules::validate::parse_action(&d.action).unwrap_or(Action::Alert),
        }
    }

    /// Is this (executable, destination) never reported (spec §5.4 `allow`)?
    pub fn beacon_allowed(&self, exe: &str, dest: &str) -> bool {
        if self.beacon_exes.is_match(exe) {
            return true;
        }
        match dest.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
            Ok(ip) => self.beacon_nets.iter().any(|n| n.contains(&ip)),
            Err(_) => false,
        }
    }

    /// Feed one connect to the beacon detector.
    pub fn on_connect(
        &mut self,
        exe: &str,
        dest: &str,
        port: u16,
        now_ms: u64,
    ) -> Option<DetectorHit> {
        if self.beacon_allowed(exe, dest) {
            return None;
        }
        let hit = self.beacon.observe(exe, dest, port, now_ms)?;
        Some(DetectorHit {
            rule_id: "beacon",
            severity: self.beacon_severity.clone(),
            action: self.beacon_action,
            event: serde_json::json!({
                "on": "connect",
                "detector": "beacon",
                "dest": hit.dest,
                "port": hit.port,
                "count": hit.count,
                "cov": hit.cov,
            }),
            exe: hit.exe,
        })
    }

    /// Feed one resolved query name to the DNS-tunnel detector.
    pub fn on_dns(&mut self, qname: &str, now_ms: u64) -> Option<DetectorHit> {
        let hit = self.dns.observe(qname, now_ms)?;
        let reason = match &hit.reason {
            DnsReason::HighEntropy { label, bits } => serde_json::json!({
                "reason": "entropy", "label": label, "bits": bits
            }),
            DnsReason::HighRate { unique } => serde_json::json!({
                "reason": "rate", "unique": unique
            }),
        };
        let mut event = serde_json::json!({
            "on": "dns",
            "detector": "dns_tunnel",
            "domain": hit.domain,
        });
        if let (Some(dst), Some(src)) = (event.as_object_mut(), reason.as_object()) {
            for (k, v) in src {
                dst.insert(k.clone(), v.clone());
            }
        }
        Some(DetectorHit {
            rule_id: "dns-tunnel",
            severity: self.dns_severity.clone(),
            action: self.dns_action,
            // Host-level: the alert names the domain, not a process (§5.4).
            event,
            exe: String::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc::{FakeProc, Proc};
    use crate::resolve::{HomeBinds, Resolved};
    use crate::table::Table;
    use sentinel_common::event::EventKind;
    use sentinel_common::wire::{EventHeader, EventPayload, ExecPayload, RawEvent};

    const PACK: &str = r#"
[[rule]]
id = "exec-memfd"
on = "exec"
severity = "critical"
action = "deny"
match = { exe_memfd = true }

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
except = { ancestors = ["/usr/bin/sshd"] }

[[rule]]
id = "any-stdio"
on = "exec"
severity = "high"
action = "freeze"
match = { stdio_socket = true }

[[rule]]
id = "noisy"
on = "exec"
severity = "low"
action = "alert"
match = { exe = ["/usr/bin/noisy"] }
window = { count = 3, within = "60s", by = "exe" }

[[rule]]
id = "audited"
on = "exec"
severity = "medium"
action = "freeze"
mode = "audit"
match = { exe = ["/usr/bin/audited"] }
"#;

    /// A user rule first, then two kernel rules: the kernel reports a position
    /// in its own map, which is not the index of the source rule.
    const PACK_KERNEL_LAST: &str = r#"
[[rule]]
id = "u-first"
on = "exec"
severity = "low"
action = "alert"
match = { env_ld = true }

[[rule]]
id = "k-memfd"
on = "exec"
severity = "critical"
action = "deny"
match = { exe_memfd = true }

[[rule]]
id = "k-deleted"
on = "exec"
severity = "high"
action = "deny"
match = { exe_deleted = true }
"#;

    fn ruleset_from(pack: &str) -> RuleSet {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pack.toml"), pack).unwrap();
        let rules = sentinel_rules::load_dir(dir.path()).expect("pack is valid");
        RuleSet::compile(rules).expect("pack compiles")
    }

    fn ruleset() -> RuleSet {
        ruleset_from(PACK)
    }

    fn proc_at(pid: u32, ppid: u32, exe: &str, unit: &str) -> Proc {
        Proc {
            pid,
            ppid,
            exe: exe.to_string(),
            argv: exe.to_string(),
            uid: 1000,
            unit: unit.to_string(),
            cgroup_id: 77,
        }
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

    /// An exec event for `pid`, with the table and /proc wired to `exe`.
    fn exec_for(pid: u32, exe: &str, unit: &str, env_ld: bool, stdio: bool) -> (Resolved, Table) {
        let mut src = FakeProc::default();
        src.add(proc_at(1, 0, "/usr/lib/systemd/systemd", "init.scope"));
        src.add(proc_at(pid, 1, exe, unit));
        if env_ld {
            src.env_ld.insert(pid);
        }
        if stdio {
            src.stdio_socket.insert(pid);
        }
        let mut t = Table::default();
        t.seed(&src);
        let ev = exec_event(pid);
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default()).expect("a known kind");
        (r, t)
    }

    fn policy() -> Policy {
        Policy::new(7, 9, vec!["systemd-*.service".to_string()])
    }

    #[test]
    fn a_user_rule_hit_produces_a_decision_naming_the_rule() {
        let mut rs = ruleset();
        let (r, _) = exec_for(200, "/usr/bin/bash", "session-2.scope", true, false);
        let d = rs.decide(&r, &policy(), 0);
        let ids: Vec<&str> = d.iter().map(|x| x.rule_id.as_str()).collect();
        assert_eq!(ids, vec!["ld-preload"]);
        assert_eq!(d[0].action, Action::Alert);
        assert_eq!(d[0].outcome, Outcome::Alerted);
        assert_eq!(d[0].severity, "medium");
    }

    #[test]
    fn except_suppresses_a_rule() {
        let mut rs = ruleset();
        let mut src = FakeProc::default();
        src.add(proc_at(1, 0, "/usr/lib/systemd/systemd", "init.scope"));
        src.add(proc_at(100, 1, "/usr/bin/sshd", "sshd.service"));
        src.add(proc_at(200, 100, "/usr/bin/bash", "session-2.scope"));
        src.stdio_socket.insert(200);
        let mut t = Table::default();
        t.seed(&src);
        let ev = exec_event(200);
        let r = Resolved::from_raw(&ev, &t, &src, &HomeBinds::default()).expect("a known kind");
        let d = rs.decide(&r, &policy(), 0);
        assert!(
            d.iter().all(|x| x.rule_id != "reverse-shell"),
            "sshd ancestor must suppress it: {:?}",
            d.iter().map(|x| &x.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_kernel_matched_event_becomes_a_decision_with_the_kernel_verdict() {
        let mut rs = ruleset();
        let (mut r, _) = exec_for(200, "/usr/bin/x", "session-2.scope", false, false);
        // The kernel matched its first rule (exec-memfd) and denied it.
        r.matched_rule = 0;
        r.kverdict = KVerdict::Denied;
        let d = rs.decide(&r, &policy(), 0);
        assert_eq!(d[0].rule_id, "exec-memfd");
        assert_eq!(d[0].outcome, Outcome::Denied);
        assert_eq!(d[0].action, Action::Deny);
    }

    #[test]
    fn a_kernel_hit_is_named_by_its_source_rule_not_its_map_position() {
        let mut rs = ruleset_from(PACK_KERNEL_LAST);
        let (mut r, _) = exec_for(200, "/usr/bin/x", "session-2.scope", false, false);
        // The kernel reports position 1 in its own RULES map, which holds only
        // the two kernel rules: that is source rule 2, not source rule 1.
        r.matched_rule = 1;
        r.kverdict = KVerdict::Denied;
        // The divergence this guards against: position 1 of the kernel map is
        // source rule 2, while source rule 1 is a different rule entirely.
        assert_eq!(rs.tables.rules[1].index, 2);
        assert_eq!(rs.rules[1].id, "k-memfd");
        let d = rs.decide(&r, &policy(), 0);
        assert_eq!(d[0].rule_id, "k-deleted", "named the wrong source rule");
        assert_eq!(d[0].severity, "high");
    }

    #[test]
    fn an_out_of_range_kernel_index_is_dropped() {
        let mut rs = ruleset();
        let (mut r, _) = exec_for(200, "/usr/bin/x", "session-2.scope", false, false);
        // A stale index from before a LoadGeneration swap.
        r.matched_rule = 99;
        r.kverdict = KVerdict::Denied;
        assert!(rs.decide(&r, &policy(), 0).is_empty());
    }

    #[test]
    fn a_would_deny_verdict_reports_would_deny() {
        let mut rs = ruleset();
        let (mut r, _) = exec_for(200, "/usr/bin/x", "session-2.scope", false, false);
        r.matched_rule = 0;
        r.kverdict = KVerdict::WouldDeny;
        let d = rs.decide(&r, &policy(), 0);
        assert_eq!(d[0].outcome, Outcome::WouldDeny);
    }

    #[test]
    fn an_audit_rule_reports_what_it_would_have_done() {
        let mut rs = ruleset();
        let (r, _) = exec_for(200, "/usr/bin/audited", "session-2.scope", false, false);
        let d = rs.decide(&r, &policy(), 0);
        assert_eq!(d[0].rule_id, "audited");
        assert_eq!(d[0].outcome, Outcome::WouldFreeze);
        assert!(!d[0].acts(), "an audit rule never acts");
    }

    #[test]
    fn a_windowed_rule_fires_only_on_the_nth_event() {
        let mut rs = ruleset();
        let (r, _) = exec_for(200, "/usr/bin/noisy", "session-2.scope", false, false);
        assert!(rs.decide(&r, &policy(), 0).is_empty(), "1st");
        assert!(rs.decide(&r, &policy(), 1000).is_empty(), "2nd");
        let d = rs.decide(&r, &policy(), 2000);
        assert_eq!(d.len(), 1, "3rd fires");
        assert_eq!(d[0].rule_id, "noisy");
    }

    #[test]
    fn a_windowed_rule_forgets_events_outside_the_window() {
        let mut rs = ruleset();
        let (r, _) = exec_for(200, "/usr/bin/noisy", "session-2.scope", false, false);
        rs.decide(&r, &policy(), 0);
        rs.decide(&r, &policy(), 1000);
        // The first two fall outside a 60 s window by now.
        assert!(rs.decide(&r, &policy(), 200_000).is_empty());
    }

    #[test]
    fn protected_processes_are_suppressed_not_acted_on() {
        let mut rs = ruleset();
        // pid 1
        let (r1, _) = exec_for(1, "/usr/bin/bash", "init.scope", false, true);
        // the daemon itself (policy says tgid 7)
        let (r2, _) = exec_for(7, "/usr/bin/bash", "session-2.scope", false, true);
        // journald (policy says pid 9)
        let (r3, _) = exec_for(9, "/usr/bin/bash", "session-2.scope", false, true);
        // a never_act_on unit
        let (r4, _) = exec_for(300, "/usr/bin/bash", "systemd-logind.service", false, true);
        for r in [r1, r2, r3, r4] {
            let d = rs.decide(&r, &policy(), 0);
            let hit = d
                .iter()
                .find(|x| x.rule_id == "reverse-shell")
                .expect("rule hit");
            assert_eq!(
                hit.outcome,
                Outcome::Suppressed,
                "pid {} unit {}",
                r.pid,
                r.unit
            );
            assert!(!hit.acts());
        }
    }

    #[test]
    fn a_process_with_no_executable_is_protected() {
        let mut rs = ruleset();
        // What a kernel thread looks like: /proc/<pid>/exe does not resolve,
        // so `RealProc` reports an empty exe. Spec §6 never acts on those, and
        // pid <= 2 does not cover a kworker.
        let (r, _) = exec_for(420, "", "", false, true);
        assert!(
            !policy().is_protected(420, ""),
            "the pid and unit checks alone do not cover a kworker"
        );
        let d = rs.decide(&r, &policy(), 0);
        let hit = d
            .iter()
            .find(|x| x.rule_id == "any-stdio")
            .expect("rule hit");
        assert_eq!(hit.outcome, Outcome::Suppressed);
        assert!(!hit.acts());
    }

    #[test]
    fn an_alert_rule_on_a_protected_process_still_alerts() {
        let mut rs = ruleset();
        let (r, _) = exec_for(1, "/usr/bin/bash", "init.scope", true, false);
        let d = rs.decide(&r, &policy(), 0);
        let hit = d.iter().find(|x| x.rule_id == "ld-preload").unwrap();
        assert_eq!(
            hit.outcome,
            Outcome::Alerted,
            "protection only blocks freeze and kill, not alerting"
        );
    }

    #[test]
    fn kernel_threads_are_protected() {
        let p = policy();
        assert!(p.is_protected(2, ""), "kthreadd");
        assert!(p.is_protected(1, ""), "pid 1");
        assert!(!p.is_protected(4242, "session-2.scope"));
    }

    #[test]
    fn the_brake_engages_after_the_configured_count() {
        let mut b = StormBrake::new(2);
        assert!(!b.trip(0), "1st act allowed");
        assert!(!b.trip(100), "2nd act allowed");
        assert!(b.trip(200), "3rd act is braked");
        assert!(b.engaged(), "the brake reports itself engaged");
    }

    #[test]
    fn the_brake_reports_engaging_only_once() {
        let mut b = StormBrake::new(1);
        b.trip(0);
        assert!(b.trip(10) && b.just_engaged(), "first brake reports");
        assert!(b.trip(20) && !b.just_engaged(), "later brakes stay quiet");
    }

    #[test]
    fn the_brake_forgets_acts_older_than_a_minute() {
        let mut b = StormBrake::new(2);
        b.trip(0);
        b.trip(1_000);
        assert!(b.trip(2_000), "braked inside the minute");
        assert!(!b.trip(70_000), "the window has rolled past the old acts");
    }

    #[test]
    fn beacon_allow_list_skips_destinations_and_executables() {
        let d = Detectors::new(
            &sentinel_rules::config::Beacon {
                min_connects: 2,
                max_cov: 1.0,
                allow: vec!["9.9.9.9/32".to_string(), "/usr/bin/chronyd".to_string()],
                severity: "high".to_string(),
                action: "alert".to_string(),
            },
            &sentinel_rules::config::DnsTunnel::default(),
        );
        assert!(d.beacon_allowed("/usr/bin/curl", "9.9.9.9"), "CIDR match");
        assert!(d.beacon_allowed("/usr/bin/chronyd", "1.2.3.4"), "exe match");
        assert!(!d.beacon_allowed("/usr/bin/curl", "1.2.3.4"));
    }

    #[test]
    fn a_periodic_connect_fires_the_beacon_detector() {
        let mut d = Detectors::new(
            &sentinel_rules::config::Beacon {
                min_connects: 3,
                max_cov: 0.2,
                allow: vec![],
                severity: "high".to_string(),
                action: "alert".to_string(),
            },
            &sentinel_rules::config::DnsTunnel::default(),
        );
        let mut fired = None;
        for i in 0..4 {
            // The hit lands on the min_connects-th connect; the ones after it
            // return None because `refire_ms` holds the key quiet for an hour,
            // so keep the fire rather than the last answer.
            fired = fired.or(d.on_connect("/usr/bin/implant", "10.0.2.2", 443, i * 5_000));
        }
        let hit = fired.expect("a perfectly periodic connect is a beacon");
        assert_eq!(hit.rule_id, "beacon");
        assert_eq!(hit.severity, "high");
        assert_eq!(hit.action, Action::Alert);
        assert_eq!(hit.event["dest"], "10.0.2.2");
    }

    #[test]
    fn a_detector_action_of_freeze_is_carried_through() {
        let mut d = Detectors::new(
            &sentinel_rules::config::Beacon {
                min_connects: 2,
                max_cov: 0.5,
                allow: vec![],
                severity: "critical".to_string(),
                action: "freeze".to_string(),
            },
            &sentinel_rules::config::DnsTunnel::default(),
        );
        let mut fired = None;
        for i in 0..3 {
            fired = fired.or(d.on_connect("/usr/bin/implant", "10.0.2.2", 443, i * 5_000));
        }
        let hit = fired.expect("beacon fires");
        assert_eq!(hit.action, Action::Freeze);
        assert_eq!(hit.severity, "critical");
    }

    #[test]
    fn high_entropy_subdomains_fire_the_dns_detector() {
        let mut d = Detectors::new(
            &sentinel_rules::config::Beacon::default(),
            &sentinel_rules::config::DnsTunnel {
                label_len: 10,
                entropy: 3.0,
                unique_per_min: 1000,
                severity: "high".to_string(),
                action: "alert".to_string(),
            },
        );
        let hit = d
            .on_dns("a7f3k9x2m4q8w1e5r6t0y.example.com", 0)
            .expect("a high-entropy label is a tunnel");
        assert_eq!(hit.rule_id, "dns-tunnel");
        assert_eq!(hit.event["domain"], "example.com");
    }
}
