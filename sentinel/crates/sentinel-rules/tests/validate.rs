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
    assert_eq!(exe, vec!["/usr/bin/bash".to_string(), "/usr/bin/sh".to_string()]);
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
    assert_eq!(rf.rules[0].match_.device.as_ref().unwrap().to_vec(), vec!["camera".to_string()]);
}
