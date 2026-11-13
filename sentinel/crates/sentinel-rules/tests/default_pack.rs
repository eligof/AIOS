use sentinel_rules::{load_dir, matcher::compile_all};
use std::path::Path;

fn pack_dir() -> std::path::PathBuf {
    // tests run with CWD = crate dir; the repo root is three levels up.
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../manifest/sentinel/rules")
}

#[test]
fn default_pack_loads_validates_and_compiles() {
    let rules = load_dir(&pack_dir()).expect("default pack validates");
    assert_eq!(rules.len(), 14, "the §5.5 table has 14 rules");

    let (tables, user) = compile_all(&rules).expect("default pack compiles");
    // 8 kernel rules, 6 user-space rules (exe/ancestors/managed_home, plus
    // env_ld and stdio_socket per spec amendment 8: S2 cannot fill either
    // fact in the kernel, so `ld-preload` (env_ld) is now a user rule too).
    assert_eq!(tables.rules.len(), 8, "kernel rules");
    assert_eq!(user.len(), 6, "user-space rules");
    assert!(tables.rules.len() <= sentinel_common::MAX_RULES);
    assert!(tables.cidrs.len() <= sentinel_common::MAX_CIDRS);

    // spot checks: the amendment predicates are present and classified right
    assert!(rules
        .iter()
        .any(|r| r.id == "module-load" && r.match_.any == Some(true)));
    assert!(user
        .iter()
        .any(|u| rules[u.index as usize].id == "persistence-write"));
    assert!(user
        .iter()
        .any(|u| rules[u.index as usize].id == "reverse-shell"));
}
