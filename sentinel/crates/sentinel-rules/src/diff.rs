//! Diff two rule sets and two configs for `aios plan` (§11.2).

use std::collections::BTreeMap;

use crate::config::SentinelConfig;
use crate::model::Rule;

#[derive(Debug, Default, PartialEq)]
pub struct RuleSetDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// (id, per-field change lines)
    pub changed: Vec<(String, Vec<String>)>,
}

impl RuleSetDiff {
    /// Human lines for the plan output.
    pub fn summary(&self) -> Vec<String> {
        let mut out = Vec::new();
        for id in &self.added {
            out.push(format!("+ {id}"));
        }
        for id in &self.removed {
            out.push(format!("- {id}"));
        }
        for (id, fields) in &self.changed {
            for f in fields {
                out.push(format!("{id}: {f}"));
            }
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

fn by_id(rules: &[Rule]) -> BTreeMap<&str, &Rule> {
    rules.iter().map(|r| (r.id.as_str(), r)).collect()
}

fn action_of(r: &Rule) -> &str {
    r.action.as_deref().unwrap_or("alert")
}
fn mode_of(r: &Rule) -> &str {
    r.mode.as_deref().unwrap_or("enforce")
}

/// The field-level changes between two rules of the same id.
pub fn rule_field_changes(old: &Rule, new: &Rule) -> Vec<String> {
    let mut c = Vec::new();
    if old.on != new.on {
        c.push(format!("on {} → {}", old.on, new.on));
    }
    if old.severity != new.severity {
        c.push(format!("severity {} → {}", old.severity, new.severity));
    }
    if action_of(old) != action_of(new) {
        c.push(format!("action {} → {}", action_of(old), action_of(new)));
    }
    if mode_of(old) != mode_of(new) {
        c.push(format!("mode {} → {}", mode_of(old), mode_of(new)));
    }
    if old.match_ != new.match_ {
        c.push("match changed".to_string());
    }
    if old.except != new.except {
        c.push("except changed".to_string());
    }
    if old.window != new.window {
        c.push("window changed".to_string());
    }
    c
}

pub fn diff_rules(old: &[Rule], new: &[Rule]) -> RuleSetDiff {
    let om = by_id(old);
    let nm = by_id(new);
    let mut d = RuleSetDiff::default();

    for id in nm.keys() {
        if !om.contains_key(id) {
            d.added.push(id.to_string());
        }
    }
    for id in om.keys() {
        if !nm.contains_key(id) {
            d.removed.push(id.to_string());
        }
    }
    for (id, nr) in &nm {
        if let Some(or) = om.get(id) {
            let fields = rule_field_changes(or, nr);
            if !fields.is_empty() {
                d.changed.push((id.to_string(), fields));
            }
        }
    }
    d.added.sort();
    d.removed.sort();
    d.changed.sort_by(|a, b| a.0.cmp(&b.0));
    d
}

/// Changed `[sentinel]` fields as `name old → new` lines.
pub fn diff_config(old: &SentinelConfig, new: &SentinelConfig) -> Vec<String> {
    let mut c = Vec::new();
    if old.enable != new.enable {
        c.push(format!("enable {} → {}", old.enable, new.enable));
    }
    if old.rules != new.rules {
        c.push(format!("rules {} → {}", old.rules, new.rules));
    }
    if old.lockdown_after != new.lockdown_after {
        c.push(format!(
            "lockdown_after {} → {}",
            old.lockdown_after, new.lockdown_after
        ));
    }
    if old.storm_brake != new.storm_brake {
        c.push(format!(
            "storm_brake {} → {}",
            old.storm_brake, new.storm_brake
        ));
    }
    if old.never_act_on != new.never_act_on {
        c.push("never_act_on changed".to_string());
    }
    if old.bpf_loaders != new.bpf_loaders {
        c.push("bpf_loaders changed".to_string());
    }
    if old.beacon != new.beacon {
        c.push("beacon changed".to_string());
    }
    if old.dns_tunnel != new.dns_tunnel {
        c.push("dns_tunnel changed".to_string());
    }
    c
}
