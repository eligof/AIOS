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
    // Spec amendment 8: S2 cannot fill F_ENV_LD or F_STDIO_SOCKET in the
    // kernel (spec §17.7) — reading env and fd 0/1/2 socket-ness both need
    // user space — so both predicates are user-space-only, not kernel facts.
    if m.env_ld.is_some() {
        return Some("env_ld");
    }
    if m.stdio_socket.is_some() {
        return Some("stdio_socket");
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_ld_alone_is_a_user_rule() {
        let m = Match {
            env_ld: Some(true),
            ..Default::default()
        };
        let (kind, pred) = classify(&m, &Match::default(), false);
        assert_eq!(kind, Kind::User);
        assert_eq!(pred, Some("env_ld"));
    }

    #[test]
    fn stdio_socket_alone_is_a_user_rule() {
        let m = Match {
            stdio_socket: Some(true),
            ..Default::default()
        };
        let (kind, pred) = classify(&m, &Match::default(), false);
        assert_eq!(kind, Kind::User);
        assert_eq!(pred, Some("stdio_socket"));
    }

    #[test]
    fn memfd_alone_is_still_a_kernel_rule() {
        let m = Match {
            exe_memfd: Some(true),
            ..Default::default()
        };
        assert_eq!(classify(&m, &Match::default(), false).0, Kind::Kernel);
    }
}
