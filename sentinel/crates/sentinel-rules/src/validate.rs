//! Validate parsed rules. Every §5.1 error class, with file+id locations.

use globset::Glob;
use sentinel_common::EventKind;

use crate::classify::{classify, Kind};
use crate::model::{Match, PortSpec, Rule, UidItem};
use crate::RuleError;

/// Map the 8 valid `on` strings to an `EventKind` (the subset rules may fire on).
pub fn parse_on(s: &str) -> Option<EventKind> {
    Some(match s {
        "exec" => EventKind::Exec,
        "connect" => EventKind::Connect,
        "listen" => EventKind::Listen,
        "open" => EventKind::Open,
        "write_refused" => EventKind::WriteRefused,
        "memfd" => EventKind::Memfd,
        "ptrace" => EventKind::Ptrace,
        "module" => EventKind::Module,
        _ => return None,
    })
}

pub fn parse_severity(s: &str) -> Option<sentinel_common::Severity> {
    use sentinel_common::Severity::*;
    Some(match s {
        "info" => Info,
        "low" => Low,
        "medium" => Medium,
        "high" => High,
        "critical" => Critical,
        _ => return None,
    })
}

pub fn parse_action(s: &str) -> Option<sentinel_common::Action> {
    use sentinel_common::Action::*;
    Some(match s {
        "alert" => Alert,
        "deny" => Deny,
        "freeze" => Freeze,
        "kill" => Kill,
        _ => return None,
    })
}

pub fn parse_mode(s: &str) -> Option<sentinel_common::Mode> {
    use sentinel_common::Mode::*;
    Some(match s {
        "enforce" => Enforce,
        "audit" => Audit,
        _ => return None,
    })
}

/// Parse a duration like `"60s"`, `"5s"`, `"2m"` into milliseconds.
pub fn parse_duration_ms(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, unit) = s.split_at(
        s.find(|c: char| c.is_ascii_alphabetic())
            .ok_or_else(|| format!("{s:?} has no unit"))?,
    );
    let n: u64 = num.trim().parse().map_err(|_| format!("{s:?} has a bad number"))?;
    let mult = match unit {
        "ms" => 1,
        "s" => 1000,
        "m" => 60_000,
        "h" => 3_600_000,
        _ => return Err(format!("{s:?} has an unknown unit")),
    };
    Ok(n * mult)
}

fn id_ok(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn validate(rules: &[Rule]) -> Vec<RuleError> {
    let mut errors = Vec::new();
    let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();

    for r in rules {
        let err = |message: String| RuleError {
            file: r.source.clone(),
            rule: Some(r.id.clone()),
            message,
        };

        if !id_ok(&r.id) {
            errors.push(err(format!("id {:?} must match [a-z0-9-]+ and be non-empty", r.id)));
        }
        if let Some(_prev) = seen.insert(r.id.as_str(), 0) {
            errors.push(err(format!("duplicate rule id {:?}", r.id)));
        }

        let on = match parse_on(&r.on) {
            Some(k) => k,
            None => {
                errors.push(err(format!(
                    "unknown event {:?} (exec|connect|listen|open|write_refused|memfd|ptrace|module)",
                    r.on
                )));
                continue;
            }
        };
        if parse_severity(&r.severity).is_none() {
            errors.push(err(format!("unknown severity {:?}", r.severity)));
        }
        let action = match &r.action {
            Some(a) => match parse_action(a) {
                Some(x) => x,
                None => {
                    errors.push(err(format!("unknown action {:?}", a)));
                    sentinel_common::Action::Alert
                }
            },
            None => sentinel_common::Action::Alert,
        };
        if let Some(m) = &r.mode {
            if parse_mode(m).is_none() {
                errors.push(err(format!("unknown mode {:?}", m)));
            }
        }

        validate_match(&r.match_, on, false, &err, &mut errors);
        validate_match(&r.except, on, true, &err, &mut errors);

        if is_empty(&r.match_) {
            errors.push(err("match has no predicates (use any = true to match every event)".into()));
        }

        let (kind, offending) = classify(&r.match_, &r.except, r.window.is_some());
        if action == sentinel_common::Action::Deny && kind == Kind::User {
            errors.push(err(format!(
                "action \"deny\" must be decided in the kernel, but predicate {:?} needs user space",
                offending.unwrap_or("window")
            )));
        }

        if let Some(w) = &r.window {
            if w.count == 0 {
                errors.push(err("window.count must be >= 1".into()));
            }
            if let Err(m) = parse_duration_ms(&w.within) {
                errors.push(err(format!("window.within: {m}")));
            }
            if !matches!(w.by.as_str(), "exe" | "uid" | "unit" | "dest") {
                errors.push(err(format!("window.by {:?} must be exe|uid|unit|dest", w.by)));
            }
        }
    }
    errors
}

/// Is this match empty (no predicate at all)?
pub fn is_empty(m: &Match) -> bool {
    let Match {
        exe_memfd, exe_deleted, exe_outside_usr, stdio_socket, env_ld, exe_on, uid, dest, port,
        listen_scope, device, ptrace_target, any, managed_home, exe, argv, parent, ancestors, unit,
        path,
    } = m;
    exe_memfd.is_none() && exe_deleted.is_none() && exe_outside_usr.is_none() && stdio_socket.is_none()
        && env_ld.is_none() && exe_on.is_none() && uid.is_none() && dest.is_none() && port.is_none()
        && listen_scope.is_none() && device.is_none() && ptrace_target.is_none() && any.is_none()
        && managed_home.is_none() && exe.is_none() && argv.is_none() && parent.is_none()
        && ancestors.is_none() && unit.is_none() && path.is_none()
}

/// Which event kinds a predicate applies to; `None` = all 8.
fn applies_to(pred: &str) -> Option<&'static [EventKind]> {
    use EventKind::*;
    Some(match pred {
        "exe_memfd" | "exe_deleted" | "exe_outside_usr" | "stdio_socket" | "env_ld" | "exe_on"
        | "argv" => &[Exec],
        "dest" => &[Connect],
        "port" => &[Connect, Listen],
        "listen_scope" => &[Listen],
        "device" => &[Open],
        "ptrace_target" => &[Ptrace],
        "path" => &[Open, WriteRefused],
        "managed_home" => &[WriteRefused],
        // uid, exe, parent, ancestors, unit, any apply to all
        _ => return None,
    })
}

/// The lowercase `on` name for a kind, matching the TOML spelling.
fn on_name(k: EventKind) -> &'static str {
    use EventKind::*;
    match k {
        Exec => "exec",
        Connect => "connect",
        Listen => "listen",
        Open => "open",
        WriteRefused => "write_refused",
        Memfd => "memfd",
        Ptrace => "ptrace",
        Module => "module",
        _ => "?",
    }
}

fn check_applies(pred: &str, on: EventKind, except: bool, err: &dyn Fn(String) -> RuleError, out: &mut Vec<RuleError>) {
    if let Some(kinds) = applies_to(pred) {
        if !kinds.contains(&on) {
            let where_ = if except { "except" } else { "match" };
            out.push(err(format!(
                "{where_} predicate {pred:?} does not apply to on = {}",
                on_name(on)
            )));
        }
    }
}

fn check_globs(pred: &str, v: &crate::model::OneOrMany<String>, err: &dyn Fn(String) -> RuleError, out: &mut Vec<RuleError>) {
    for g in v.to_vec() {
        if Glob::new(&g).is_err() {
            out.push(err(format!("{pred}: glob {g:?} does not compile")));
        }
    }
}

fn validate_match(m: &Match, on: EventKind, except: bool, err: &dyn Fn(String) -> RuleError, out: &mut Vec<RuleError>) {
    // applicability for every set predicate
    macro_rules! appl {
        ($field:ident, $name:literal) => {
            if m.$field.is_some() {
                check_applies($name, on, except, err, out);
            }
        };
    }
    appl!(exe_memfd, "exe_memfd");
    appl!(exe_deleted, "exe_deleted");
    appl!(exe_outside_usr, "exe_outside_usr");
    appl!(stdio_socket, "stdio_socket");
    appl!(env_ld, "env_ld");
    appl!(exe_on, "exe_on");
    appl!(dest, "dest");
    appl!(port, "port");
    appl!(listen_scope, "listen_scope");
    appl!(device, "device");
    appl!(ptrace_target, "ptrace_target");
    appl!(managed_home, "managed_home");
    appl!(argv, "argv");
    appl!(path, "path");

    // value checks
    if let Some(v) = &m.exe {
        check_globs("exe", v, err, out);
    }
    for (name, opt) in [
        ("argv", &m.argv),
        ("parent", &m.parent),
        ("ancestors", &m.ancestors),
        ("unit", &m.unit),
        ("path", &m.path),
    ] {
        if let Some(v) = opt {
            check_globs(name, v, err, out);
        }
    }
    if let Some(v) = &m.dest {
        for c in v.to_vec() {
            if c.parse::<ipnet::IpNet>().is_err() {
                out.push(err(format!("dest: {c:?} is not a CIDR")));
            }
        }
    }
    if let Some(v) = &m.port {
        for p in v.to_vec() {
            match p {
                PortSpec::Num(n) => {
                    if !(1..=65535).contains(&n) {
                        out.push(err(format!("port: {n} out of range 1..=65535")));
                    }
                }
                PortSpec::Range(s) => {
                    if parse_port_range(&s).is_none() {
                        out.push(err(format!("port: range {s:?} is not start-end in 1..=65535")));
                    }
                }
            }
        }
    }
    if let Some(v) = &m.uid {
        let mut n = 0;
        for it in v.to_vec() {
            match it {
                UidItem::Num(x) => {
                    if !(0..=u32::MAX as i64).contains(&x) {
                        out.push(err(format!("uid: {x} out of range")));
                    }
                    n += 1;
                }
                UidItem::Kw(k) if k == "user" || k == "system" => {}
                UidItem::Kw(k) => out.push(err(format!("uid: {k:?} must be a number, \"user\" or \"system\""))),
            }
        }
        if n > sentinel_common::MAX_UID_LITERALS {
            out.push(err(format!("uid: at most {} literal uids", sentinel_common::MAX_UID_LITERALS)));
        }
    }
    if let Some(v) = &m.device {
        for d in v.to_vec() {
            if !matches!(d.as_str(), "camera" | "mic" | "input" | "uinput" | "hidraw") {
                out.push(err(format!("device: {d:?} is not camera|mic|input|uinput|hidraw")));
            }
        }
    }
    if let Some(s) = &m.listen_scope {
        if s != "non-loopback" {
            out.push(err(format!("listen_scope: {s:?} must be \"non-loopback\"")));
        }
    }
    if let Some(s) = &m.ptrace_target {
        if !matches!(s.as_str(), "other-uid" | "non-descendant" | "any") {
            out.push(err(format!("ptrace_target: {s:?} must be other-uid|non-descendant|any")));
        }
    }
}

/// Parse `"start-end"` into an inclusive port range.
pub fn parse_port_range(s: &str) -> Option<(u16, u16)> {
    let (a, b) = s.split_once('-')?;
    let a: u32 = a.trim().parse().ok()?;
    let b: u32 = b.trim().parse().ok()?;
    if (1..=65535).contains(&a) && (1..=65535).contains(&b) && a <= b {
        Some((a as u16, b as u16))
    } else {
        None
    }
}
