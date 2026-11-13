mod common;
use sentinel_common::{eval, Facts, EventKind};
use sentinel_common::{G_FLAGS, G_MOUNT, G_UID, G_DEST, F_MEMFD, U_USER, slot_bit};
use sentinel_rules::compile::compile_kernel;
use sentinel_rules::model::parse;

fn rules(raw: &str) -> Vec<sentinel_rules::model::Rule> {
    let mut rs = parse(raw).unwrap().rules;
    for r in &mut rs { r.source = "t.toml".into(); }
    rs
}

#[test]
fn memfd_rule_compiles_to_a_flags_bit() {
    let t = compile_kernel(&rules(common::SAMPLE)).unwrap();
    // SAMPLE has one kernel rule (exec-memfd); reverse-shell is user-space.
    assert_eq!(t.rules.len(), 1);
    let kr = &t.rules[0];
    assert_eq!(kr.on, EventKind::Exec as u8);
    assert_eq!(kr.all[G_FLAGS], F_MEMFD);
    // a memfd exec matches; a plain exec does not
    let mut f = Facts::new();
    assert!(!eval(kr, &f));
    f.set(G_FLAGS, F_MEMFD);
    assert!(eval(kr, &f));
}

#[test]
fn exe_on_list_and_uid_and_dest_use_any() {
    let raw = r#"
[[rule]]
id="exec-shm"
on="exec"
severity="high"
action="deny"
match={ exe_on=["/dev/shm","/tmp"] }

[[rule]]
id="user-beacon"
on="connect"
severity="medium"
match={ uid="user", dest=["10.0.0.0/8","192.168.0.0/16"] }
"#;
    let t = compile_kernel(&rules(raw)).unwrap();
    assert_eq!(t.mounts.len(), 2);
    assert_eq!(t.cidrs.len(), 2);
    // exec-shm: any over the two mount slots
    let shm = &t.rules[0];
    assert_eq!(shm.any[G_MOUNT], slot_bit(0) | slot_bit(1));
    // user-beacon: uid and dest both land in any (uid -> any[UID], per the mapping)
    let bc = &t.rules[1];
    assert_eq!(bc.any[G_UID], U_USER);
    assert_eq!(bc.any[G_DEST], slot_bit(0) | slot_bit(1));
}

#[test]
fn slots_are_deduplicated_across_rules() {
    let raw = r#"
[[rule]]
id="a"
on="connect"
severity="low"
match={ dest=["10.0.0.0/8"] }
[[rule]]
id="b"
on="connect"
severity="low"
match={ dest=["10.0.0.0/8"] }
"#;
    let t = compile_kernel(&rules(raw)).unwrap();
    assert_eq!(t.cidrs.len(), 1, "same CIDR shares one slot");
    assert_eq!(t.rules[0].any[G_DEST], t.rules[1].any[G_DEST]);
}

#[test]
fn too_many_rules_is_an_error() {
    let mut raw = String::new();
    for i in 0..65 {
        raw.push_str(&format!("[[rule]]\nid=\"r{i}\"\non=\"exec\"\nseverity=\"low\"\nmatch={{any=true}}\n"));
    }
    assert!(compile_kernel(&rules(&raw)).is_err());
}
