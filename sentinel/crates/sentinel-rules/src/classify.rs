//! Split a rule into kernel-evaluable vs user-space (§5.3).

use crate::model::Match;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Kernel,
    User,
}

/// The user-space-only predicates, in the order we report them.
const USER_PREDS: &[&str] = &[
    "exe",
    "argv",
    "parent",
    "ancestors",
    "unit",
    "path",
    "managed_home",
];

/// First user-space-only predicate set in `m`, if any.
pub fn first_user_pred(m: &Match) -> Option<&'static str> {
    for name in USER_PREDS {
        let set = match *name {
            "exe" => m.exe.is_some(),
            "argv" => m.argv.is_some(),
            "parent" => m.parent.is_some(),
            "ancestors" => m.ancestors.is_some(),
            "unit" => m.unit.is_some(),
            "path" => m.path.is_some(),
            "managed_home" => m.managed_home.is_some(),
            _ => false,
        };
        if set {
            return Some(name);
        }
    }
    None
}

/// Classify a rule. A window, or any user-space predicate in `match` or
/// `except`, forces user space. Returns the first offending predicate too.
pub fn classify(match_: &Match, except: &Match, has_window: bool) -> (Kind, Option<&'static str>) {
    if has_window {
        return (Kind::User, Some("window"));
    }
    if let Some(p) = first_user_pred(match_).or_else(|| first_user_pred(except)) {
        return (Kind::User, Some(p));
    }
    (Kind::Kernel, None)
}
