mod common;
use sentinel_rules::model::parse;

#[test]
fn parses_the_sample_file() {
    let rf = parse(common::SAMPLE).expect("sample parses");
    assert_eq!(rf.rules.len(), 2);
    assert_eq!(rf.rules[0].id, "exec-memfd");
    assert_eq!(rf.rules[0].on, "exec");
    assert_eq!(rf.rules[0].match_.exe_memfd, Some(true));
    // list and scalar both land in OneOrMany
    let exe = rf.rules[1].match_.exe.as_ref().unwrap().to_vec();
    assert_eq!(
        exe,
        vec!["/usr/bin/bash".to_string(), "/usr/bin/sh".to_string()]
    );
}

#[test]
fn unknown_predicate_key_is_a_parse_error() {
    let bad = r#"
[[rule]]
id = "x"
on = "exec"
severity = "low"
match = { exe_memfdx = true }
"#;
    assert!(parse(bad).is_err());
}

#[test]
fn scalar_predicate_value_is_accepted() {
    let one = r#"
[[rule]]
id = "cam"
on = "open"
severity = "low"
match = { device = "camera" }
"#;
    let rf = parse(one).unwrap();
    assert_eq!(
        rf.rules[0].match_.device.as_ref().unwrap().to_vec(),
        vec!["camera".to_string()]
    );
}

use sentinel_rules::validate::validate;

fn load(raw: &str) -> Vec<sentinel_rules::RuleError> {
    let mut rules = parse(raw).unwrap().rules;
    for r in &mut rules {
        r.source = "t.toml".into();
    }
    validate(&rules)
}

fn msgs(raw: &str) -> String {
    load(raw)
        .iter()
        .map(|e| e.message.clone())
        .collect::<Vec<_>>()
        .join(" | ")
}

#[test]
fn the_sample_is_valid() {
    assert!(load(common::SAMPLE).is_empty());
}

#[test]
fn bad_id_rejected() {
    let e = msgs(
        r#"[[rule]]
id="Bad_ID"
on="exec"
severity="low"
match={any=true}"#,
    );
    assert!(e.contains("[a-z0-9-]"), "{e}");
}

#[test]
fn duplicate_ids_rejected() {
    let e = msgs(
        r#"[[rule]]
id="dup"
on="exec"
severity="low"
match={any=true}
[[rule]]
id="dup"
on="exec"
severity="low"
match={any=true}"#,
    );
    assert!(e.contains("duplicate"), "{e}");
}

#[test]
fn unknown_on_rejected() {
    assert!(msgs(
        r#"[[rule]]
id="x"
on="nope"
severity="low"
match={any=true}"#
    )
    .contains("event"));
}

#[test]
fn predicate_wrong_event_rejected() {
    // `device` only applies to `open`.
    let e = msgs(
        r#"[[rule]]
id="x"
on="exec"
severity="low"
match={device="camera"}"#,
    );
    assert!(e.contains("device") && e.contains("exec"), "{e}");
}

#[test]
fn empty_match_rejected() {
    let e = msgs(
        r#"[[rule]]
id="x"
on="exec"
severity="low"
match={}"#,
    );
    assert!(e.contains("no predicates"), "{e}");
}

#[test]
fn deny_on_userspace_rule_names_predicate() {
    let e = msgs(
        r#"[[rule]]
id="x"
on="exec"
severity="high"
action="deny"
match={exe=["/usr/bin/bash"]}"#,
    );
    assert!(e.contains("deny") && e.contains("exe"), "{e}");
}

#[test]
fn bad_cidr_and_port_rejected() {
    assert!(msgs(
        r#"[[rule]]
id="x"
on="connect"
severity="low"
match={dest=["999.0.0.0/8"]}"#
    )
    .contains("dest"));
    assert!(msgs(
        r#"[[rule]]
id="y"
on="connect"
severity="low"
match={port=[70000]}"#
    )
    .contains("port"));
}

#[test]
fn bad_glob_rejected() {
    assert!(msgs(
        r#"[[rule]]
id="x"
on="exec"
severity="low"
match={exe=["/usr/bin/[["]}"#
    )
    .contains("glob"));
}
