use sentinel_rules::config::SentinelConfig;
use sentinel_rules::diff::{diff_config, diff_rules};
use sentinel_rules::model::parse;

fn rules(raw: &str) -> Vec<sentinel_rules::model::Rule> {
    parse(raw).unwrap().rules
}

#[test]
fn added_removed_and_changed_rules() {
    let old = rules(
        r#"
[[rule]]
id="keep"
on="exec"
severity="low"
action="freeze"
match={any=true}
[[rule]]
id="gone"
on="exec"
severity="low"
match={any=true}
"#,
    );
    let new = rules(
        r#"
[[rule]]
id="keep"
on="exec"
severity="low"
action="kill"
match={any=true}
[[rule]]
id="added"
on="exec"
severity="low"
match={any=true}
"#,
    );
    let d = diff_rules(&old, &new);
    assert_eq!(d.added, vec!["added".to_string()]);
    assert_eq!(d.removed, vec!["gone".to_string()]);
    assert_eq!(d.changed.len(), 1);
    assert_eq!(d.changed[0].0, "keep");
    let line = d.summary().join("\n");
    assert!(line.contains("keep: action freeze → kill"), "{line}");
    assert!(line.contains("+ added"));
    assert!(line.contains("- gone"));
}

#[test]
fn config_change_is_reported() {
    let old = SentinelConfig::default();
    let new = SentinelConfig {
        lockdown_after: "10s".into(),
        ..SentinelConfig::default()
    };
    let lines = diff_config(&old, &new);
    assert!(lines
        .iter()
        .any(|l| l.contains("lockdown_after") && l.contains("5s") && l.contains("10s")));
    assert!(diff_config(&old, &old).is_empty());
}
