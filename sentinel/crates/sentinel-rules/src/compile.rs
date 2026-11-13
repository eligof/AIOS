//! Compile kernel-evaluable rules into `KRule`s and the side tables S2's maps
//! are built from. `build_masks` is shared with the user-rule matcher (Task 8).

use ipnet::IpNet;
use sentinel_common::{
    slot_bit, uid_literal_bit, Action, KRule, Mode, D_CAMERA, D_HIDRAW, D_INPUT, D_MIC, D_UINPUT,
    F_ENV_LD, F_DELETED, F_LISTEN_NON_LOOPBACK, F_MEMFD, F_OUTSIDE_USR, F_STDIO_SOCKET, G_DEST,
    G_DEVICE, G_FLAGS, G_MOUNT, G_PORT, G_PTRACE, G_UID, NGROUPS, P_ANY, P_NON_DESCENDANT,
    P_OTHER_UID, U_SYSTEM, U_USER, MAX_CIDRS, MAX_MOUNTS, MAX_PORT_SETS, MAX_RULES,
    MAX_UID_LITERALS,
};

use crate::classify::{classify, Kind};
use crate::model::{Match, OneOrMany, PortSpec, Rule, UidItem};
use crate::validate::{parse_on, parse_port_range};
use crate::RuleError;

/// The kernel-side tables. Indices are the bit positions in each group.
#[derive(Debug, Default, Clone)]
pub struct Tables {
    pub uid_lits: Vec<u32>,
    pub mounts: Vec<String>,
    pub cidrs: Vec<IpNet>,
    pub port_sets: Vec<Vec<(u16, u16)>>,
    /// Compiled kernel rules, in source order.
    pub rules: Vec<KRule>,
}

impl Tables {
    fn intern_uid(&mut self, uid: u32) -> Option<u32> {
        if let Some(i) = self.uid_lits.iter().position(|&x| x == uid) {
            return Some(uid_literal_bit(i));
        }
        if self.uid_lits.len() >= MAX_UID_LITERALS {
            return None;
        }
        self.uid_lits.push(uid);
        Some(uid_literal_bit(self.uid_lits.len() - 1))
    }
    fn intern_mount(&mut self, path: &str) -> Option<u32> {
        if let Some(i) = self.mounts.iter().position(|x| x == path) {
            return Some(slot_bit(i));
        }
        if self.mounts.len() >= MAX_MOUNTS {
            return None;
        }
        self.mounts.push(path.to_string());
        Some(slot_bit(self.mounts.len() - 1))
    }
    fn intern_cidr(&mut self, net: IpNet) -> Option<u32> {
        if let Some(i) = self.cidrs.iter().position(|x| *x == net) {
            return Some(slot_bit(i));
        }
        if self.cidrs.len() >= MAX_CIDRS {
            return None;
        }
        self.cidrs.push(net);
        Some(slot_bit(self.cidrs.len() - 1))
    }
    fn intern_portset(&mut self, set: Vec<(u16, u16)>) -> Option<u32> {
        if let Some(i) = self.port_sets.iter().position(|x| *x == set) {
            return Some(slot_bit(i));
        }
        if self.port_sets.len() >= MAX_PORT_SETS {
            return None;
        }
        self.port_sets.push(set);
        Some(slot_bit(self.port_sets.len() - 1))
    }
}

fn normalize_ports(v: &OneOrMany<PortSpec>) -> Vec<(u16, u16)> {
    let mut out: Vec<(u16, u16)> = Vec::new();
    for p in v.to_vec() {
        match p {
            PortSpec::Num(n) => out.push((n as u16, n as u16)),
            PortSpec::Range(s) => {
                if let Some(r) = parse_port_range(&s) {
                    out.push(r);
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn device_bit(d: &str) -> u32 {
    match d {
        "camera" => D_CAMERA,
        "mic" => D_MIC,
        "input" => D_INPUT,
        "uinput" => D_UINPUT,
        "hidraw" => D_HIDRAW,
        _ => 0,
    }
}

/// One mask per fact group.
pub type Masks = [u32; NGROUPS];

/// Translate a rule's kernel-evaluable predicates into masks. `except` bits go
/// entirely into `ex_any`. Returns `Err` when a table limit is hit.
pub fn build_masks(
    m: &Match,
    except: &Match,
    t: &mut Tables,
) -> Result<(Masks, Masks, Masks), String> {
    let mut all = [0u32; NGROUPS];
    let mut any = [0u32; NGROUPS];
    let mut ex = [0u32; NGROUPS];

    // match: positive constraints
    add_flags(m, &mut all);
    if let Some(v) = &m.exe_on {
        for p in v.to_vec() {
            any[G_MOUNT] |= t.intern_mount(&p).ok_or("too many exe_on mount points")?;
        }
    }
    if let Some(v) = &m.uid {
        any[G_UID] |= uid_bits(v, t)?;
    }
    if let Some(v) = &m.dest {
        for c in v.to_vec() {
            let net: IpNet = c.parse().map_err(|_| format!("bad CIDR {c:?}"))?;
            any[G_DEST] |= t.intern_cidr(net).ok_or("too many dest CIDRs")?;
        }
    }
    if let Some(v) = &m.port {
        all[G_PORT] |= t.intern_portset(normalize_ports(v)).ok_or("too many port sets")?;
    }
    if let Some(v) = &m.device {
        for d in v.to_vec() {
            any[G_DEVICE] |= device_bit(&d);
        }
    }
    if let Some(s) = &m.ptrace_target {
        all[G_PTRACE] |= ptrace_bit(s);
    }
    // `any = true` adds nothing.

    // except: OR everything into ex_any (reuses the same interned slots)
    add_flags(except, &mut ex);
    if let Some(v) = &except.exe_on {
        for p in v.to_vec() {
            ex[G_MOUNT] |= t.intern_mount(&p).ok_or("too many exe_on mount points")?;
        }
    }
    if let Some(v) = &except.uid {
        ex[G_UID] |= uid_bits(v, t)?;
    }
    if let Some(v) = &except.dest {
        for c in v.to_vec() {
            let net: IpNet = c.parse().map_err(|_| format!("bad CIDR {c:?}"))?;
            ex[G_DEST] |= t.intern_cidr(net).ok_or("too many dest CIDRs")?;
        }
    }
    if let Some(v) = &except.port {
        ex[G_PORT] |= t.intern_portset(normalize_ports(v)).ok_or("too many port sets")?;
    }
    if let Some(v) = &except.device {
        for d in v.to_vec() {
            ex[G_DEVICE] |= device_bit(&d);
        }
    }
    if let Some(s) = &except.ptrace_target {
        ex[G_PTRACE] |= ptrace_bit(s);
    }

    Ok((all, any, ex))
}

fn add_flags(m: &Match, out: &mut [u32; NGROUPS]) {
    if m.exe_memfd == Some(true) {
        out[G_FLAGS] |= F_MEMFD;
    }
    if m.exe_deleted == Some(true) {
        out[G_FLAGS] |= F_DELETED;
    }
    if m.exe_outside_usr == Some(true) {
        out[G_FLAGS] |= F_OUTSIDE_USR;
    }
    if m.stdio_socket == Some(true) {
        out[G_FLAGS] |= F_STDIO_SOCKET;
    }
    if m.env_ld == Some(true) {
        out[G_FLAGS] |= F_ENV_LD;
    }
    if m.listen_scope.as_deref() == Some("non-loopback") {
        out[G_FLAGS] |= F_LISTEN_NON_LOOPBACK;
    }
}

fn uid_bits(v: &OneOrMany<UidItem>, t: &mut Tables) -> Result<u32, String> {
    let mut bits = 0u32;
    for it in v.to_vec() {
        bits |= match it {
            UidItem::Kw(k) if k == "user" => U_USER,
            UidItem::Kw(k) if k == "system" => U_SYSTEM,
            UidItem::Kw(k) => return Err(format!("bad uid keyword {k:?}")),
            UidItem::Num(n) => t.intern_uid(n as u32).ok_or("too many literal uids")?,
        };
    }
    Ok(bits)
}

fn ptrace_bit(s: &str) -> u32 {
    match s {
        "other-uid" => P_OTHER_UID,
        "non-descendant" => P_NON_DESCENDANT,
        "any" => P_ANY,
        _ => 0,
    }
}

/// Compile only the kernel rules, returning the populated tables.
pub fn compile_kernel(rules: &[Rule]) -> Result<Tables, Vec<RuleError>> {
    let mut t = Tables::default();
    let mut errors = Vec::new();

    for (i, r) in rules.iter().enumerate() {
        let (kind, _) = classify(&r.match_, &r.except, r.window.is_some());
        if kind != Kind::Kernel {
            continue;
        }
        let on = parse_on(&r.on).expect("validated");
        let action = r
            .action
            .as_deref()
            .and_then(crate::validate::parse_action)
            .unwrap_or(Action::Alert);
        let mode = r
            .mode
            .as_deref()
            .and_then(crate::validate::parse_mode)
            .unwrap_or(Mode::Enforce);

        match build_masks(&r.match_, &r.except, &mut t) {
            Ok((all, any, ex)) => {
                let mut kr = KRule::empty(on, action, mode, i as u32);
                kr.all = all;
                kr.any = any;
                kr.ex_any = ex;
                t.rules.push(kr);
            }
            Err(msg) => errors.push(RuleError {
                file: r.source.clone(),
                rule: Some(r.id.clone()),
                message: msg,
            }),
        }
    }

    if t.rules.len() > MAX_RULES {
        errors.push(RuleError {
            file: String::new(),
            rule: None,
            message: format!("{} kernel rules exceed the limit of {MAX_RULES}", t.rules.len()),
        });
    }
    if errors.is_empty() {
        Ok(t)
    } else {
        Err(errors)
    }
}
