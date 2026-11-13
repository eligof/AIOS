mod common;
use sentinel_common::{Facts, EventKind, G_FLAGS, F_STDIO_SOCKET};
use sentinel_rules::matcher::{compile_all, ResolvedEvent};
use sentinel_rules::window::WindowState;
use sentinel_rules::model::parse;

fn rules(raw: &str) -> Vec<sentinel_rules::model::Rule> {
    let mut rs = parse(raw).unwrap().rules;
    for r in &mut rs { r.source = "t.toml".into(); }
    rs
}

fn ev<'a>(kind: EventKind, facts: Facts, exe: &'a str, ancestors: &'a [String]) -> ResolvedEvent<'a> {
    ResolvedEvent { kind, facts, exe, argv: "", parent_exe: "", ancestors, unit: "", path: "", managed_home: false }
}

#[test]
fn reverse_shell_matches_exe_and_facts_but_except_suppresses() {
    let (_tables, user) = compile_all(&rules(common::SAMPLE)).unwrap();
    // one user rule: reverse-shell
    let r = user.iter().find(|u| u.index == 1).unwrap();

    let mut f = Facts::new();
    f.set(G_FLAGS, F_STDIO_SOCKET);
    let anc = vec!["/usr/bin/login".to_string()];
    // bash with a socket stdio, not under sshd => matches
    assert!(r.matches(&ev(EventKind::Exec, f, "/usr/bin/bash", &anc)));

    // same, but an sshd ancestor => except suppresses
    let anc2 = vec!["/usr/bin/sshd".to_string()];
    assert!(!r.matches(&ev(EventKind::Exec, f, "/usr/bin/bash", &anc2)));

    // wrong exe => no match even with the socket
    assert!(!r.matches(&ev(EventKind::Exec, f, "/usr/bin/cat", &anc)));

    // right exe, no socket => kernel portion fails
    assert!(!r.matches(&ev(EventKind::Exec, Facts::new(), "/usr/bin/bash", &anc)));
}

#[test]
fn window_fires_on_the_nth_event_within_the_span() {
    // 3 within 60s, keyed by exe
    let mut w = WindowState::new(3, 60_000);
    assert!(!w.record("a", 0));
    assert!(!w.record("a", 10_000));
    assert!(w.record("a", 20_000)); // 3rd within 60s
    // a different key is independent
    assert!(!w.record("b", 20_000));
}

#[test]
fn window_forgets_events_older_than_the_span() {
    let mut w = WindowState::new(2, 10_000);
    assert!(!w.record("a", 0));
    assert!(!w.record("a", 100_000)); // first is now stale; only 1 in window
    assert!(w.record("a", 105_000));  // 2 within 10s
}
