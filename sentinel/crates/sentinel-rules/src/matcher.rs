//! User-space rules: the kernel portion via `eval`, plus residual globs and
//! `managed_home`. `compile_all` returns the kernel tables and the user rules.

use globset::{Glob, GlobSet, GlobSetBuilder};
use sentinel_common::{eval, EventKind, Facts, KRule};

use crate::classify::{classify, Kind};
use crate::compile::{build_masks, Tables};
use crate::model::{Match, OneOrMany, Rule, Window};
use crate::validate::{parse_action, parse_mode, parse_on};
use crate::RuleError;

/// An event after `sentineld` has resolved paths, uid, unit and ancestors (§7).
pub struct ResolvedEvent<'a> {
    pub kind: EventKind,
    pub facts: Facts,
    pub exe: &'a str,
    pub argv: &'a str,
    pub parent_exe: &'a str,
    pub ancestors: &'a [String],
    pub unit: &'a str,
    pub path: &'a str,
    pub managed_home: bool,
}

/// The compiled residual (non-kernel) predicates of one `match`/`except`.
#[derive(Default)]
struct GlobPart {
    exe: Option<GlobSet>,
    argv: Option<GlobSet>,
    parent: Option<GlobSet>,
    ancestors: Option<GlobSet>,
    unit: Option<GlobSet>,
    path: Option<GlobSet>,
    managed_home: Option<bool>,
}

fn build_set(v: &OneOrMany<String>) -> GlobSet {
    let mut b = GlobSetBuilder::new();
    for g in v.to_vec() {
        // validated already; unwrap is safe
        b.add(Glob::new(&g).unwrap());
    }
    b.build().unwrap()
}

impl GlobPart {
    fn from(m: &Match) -> GlobPart {
        GlobPart {
            exe: m.exe.as_ref().map(build_set),
            argv: m.argv.as_ref().map(build_set),
            parent: m.parent.as_ref().map(build_set),
            ancestors: m.ancestors.as_ref().map(build_set),
            unit: m.unit.as_ref().map(build_set),
            path: m.path.as_ref().map(build_set),
            managed_home: m.managed_home,
        }
    }

    /// For `match`: every present predicate must hold (AND).
    fn all_hold(&self, ev: &ResolvedEvent) -> bool {
        if let Some(s) = &self.exe {
            if !s.is_match(ev.exe) {
                return false;
            }
        }
        if let Some(s) = &self.argv {
            if !s.is_match(ev.argv) {
                return false;
            }
        }
        if let Some(s) = &self.parent {
            if !s.is_match(ev.parent_exe) {
                return false;
            }
        }
        if let Some(s) = &self.ancestors {
            if !ev.ancestors.iter().any(|a| s.is_match(a)) {
                return false;
            }
        }
        if let Some(s) = &self.unit {
            if !s.is_match(ev.unit) {
                return false;
            }
        }
        if let Some(s) = &self.path {
            if !s.is_match(ev.path) {
                return false;
            }
        }
        self.managed_home != Some(true) || ev.managed_home
    }

    /// For `except`: any present predicate holding suppresses (OR).
    fn any_holds(&self, ev: &ResolvedEvent) -> bool {
        if self.exe.as_ref().is_some_and(|s| s.is_match(ev.exe)) {
            return true;
        }
        if self.argv.as_ref().is_some_and(|s| s.is_match(ev.argv)) {
            return true;
        }
        if self
            .parent
            .as_ref()
            .is_some_and(|s| s.is_match(ev.parent_exe))
        {
            return true;
        }
        if self
            .ancestors
            .as_ref()
            .is_some_and(|s| ev.ancestors.iter().any(|a| s.is_match(a)))
        {
            return true;
        }
        if self.unit.as_ref().is_some_and(|s| s.is_match(ev.unit)) {
            return true;
        }
        if self.path.as_ref().is_some_and(|s| s.is_match(ev.path)) {
            return true;
        }
        self.managed_home == Some(true) && ev.managed_home
    }

    fn is_empty(&self) -> bool {
        self.exe.is_none()
            && self.argv.is_none()
            && self.parent.is_none()
            && self.ancestors.is_none()
            && self.unit.is_none()
            && self.path.is_none()
            && self.managed_home.is_none()
    }
}

/// A compiled user-space rule.
pub struct UserRule {
    pub index: u32,
    pub on: EventKind,
    pub action: sentinel_common::Action,
    pub mode: sentinel_common::Mode,
    /// Kernel-evaluable portion (facts terms), run through the shared `eval`.
    pub kernel: KRule,
    match_glob: GlobPart,
    except_glob: GlobPart,
    pub window: Option<Window>,
}

impl UserRule {
    /// Does this rule match the resolved event (ignoring any `window`, which the
    /// caller applies with a `WindowState`)?
    pub fn matches(&self, ev: &ResolvedEvent) -> bool {
        if ev.kind != self.on {
            return false;
        }
        // kernel portion (facts, incl. kernel-side except via ex_any)
        if !eval(&self.kernel, &ev.facts) {
            return false;
        }
        // residual match globs: all must hold
        if !self.match_glob.all_hold(ev) {
            return false;
        }
        // residual except globs: any holding suppresses
        if !self.except_glob.is_empty() && self.except_glob.any_holds(ev) {
            return false;
        }
        true
    }
}

/// Compile the whole rule set: kernel `Tables` plus the user-space rules.
pub fn compile_all(rules: &[Rule]) -> Result<(Tables, Vec<UserRule>), Vec<RuleError>> {
    let mut t = Tables::default();
    let mut user = Vec::new();
    let mut errors = Vec::new();

    for (i, r) in rules.iter().enumerate() {
        let on = parse_on(&r.on).expect("validated");
        let action = r
            .action
            .as_deref()
            .and_then(parse_action)
            .unwrap_or(sentinel_common::Action::Alert);
        let mode = r
            .mode
            .as_deref()
            .and_then(parse_mode)
            .unwrap_or(sentinel_common::Mode::Enforce);

        let (all, any, ex) = match build_masks(&r.match_, &r.except, &mut t) {
            Ok(v) => v,
            Err(msg) => {
                errors.push(RuleError {
                    file: r.source.clone(),
                    rule: Some(r.id.clone()),
                    message: msg,
                });
                continue;
            }
        };
        let mut kr = KRule::empty(on, action, mode, i as u32);
        kr.all = all;
        kr.any = any;
        kr.ex_any = ex;

        match classify(&r.match_, &r.except, r.window.is_some()).0 {
            Kind::Kernel => t.rules.push(kr),
            Kind::User => user.push(UserRule {
                index: i as u32,
                on,
                action,
                mode,
                kernel: kr,
                match_glob: GlobPart::from(&r.match_),
                except_glob: GlobPart::from(&r.except),
                window: r.window.clone(),
            }),
        }
    }

    if errors.is_empty() {
        Ok((t, user))
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pack_has_ld_preload_as_a_user_rule() {
        let dir = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../manifest/sentinel/rules"
        ));
        let rules = crate::load_dir(dir).expect("default pack is valid");
        let (_tables, user) = compile_all(&rules).expect("default pack compiles");
        let ids: Vec<&str> = user
            .iter()
            .map(|u| rules[u.index as usize].id.as_str())
            .collect();
        assert!(ids.contains(&"ld-preload"), "user rules were {ids:?}");
        assert!(ids.contains(&"reverse-shell"), "user rules were {ids:?}");
    }
}
