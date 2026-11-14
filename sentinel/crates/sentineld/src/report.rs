//! Where an alert goes besides the store: the journal and the TTYs (spec §9).

use std::io::Write;

use crate::alert::Alert;

/// syslog priority from a severity name (spec §9).
pub fn priority(severity: &str) -> u8 {
    match severity {
        "critical" => 2,
        "high" => 3,
        "medium" => 4,
        "low" => 5,
        _ => 6,
    }
}

/// Which severities are broadcast to the TTYs (spec §9).
pub fn broadcasts(severity: &str) -> bool {
    matches!(severity, "high" | "critical")
}

/// Encode journald native-protocol fields. A value with a newline in it uses
/// the length-prefixed binary framing; everything else is `KEY=value\n`.
pub fn encode_fields(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in fields {
        if v.contains('\n') {
            out.extend_from_slice(k.as_bytes());
            out.push(b'\n');
            out.extend_from_slice(&(v.len() as u64).to_le_bytes());
            out.extend_from_slice(v.as_bytes());
            out.push(b'\n');
        } else {
            out.extend_from_slice(k.as_bytes());
            out.push(b'=');
            out.extend_from_slice(v.as_bytes());
            out.push(b'\n');
        }
    }
    out
}

/// The one-line form used for the journal MESSAGE and the TTY broadcast.
pub fn summary(a: &Alert) -> String {
    match &a.process {
        Some(p) => format!(
            "sentinel: {} [{}] {} — pid {} {} (uid {})",
            a.rule, a.severity, a.outcome, p.pid, p.exe, p.uid
        ),
        None => {
            let tail = if a.message.is_empty() {
                String::new()
            } else {
                format!(" — {}", a.message)
            };
            format!("sentinel: {} [{}] {}{tail}", a.rule, a.severity, a.outcome)
        }
    }
}

/// Where alerts are reported, besides the store.
pub trait Sink: Send {
    fn emit(&mut self, a: &Alert);
}

/// The real sink: journald over its native socket, plus the TTYs.
pub struct SystemSink {
    journal: Option<std::os::unix::net::UnixDatagram>,
}

impl Default for SystemSink {
    fn default() -> SystemSink {
        SystemSink::new()
    }
}

impl SystemSink {
    pub fn new() -> SystemSink {
        let journal = std::os::unix::net::UnixDatagram::unbound()
            .ok()
            .filter(|s| s.connect("/run/systemd/journal/socket").is_ok());
        SystemSink { journal }
    }

    /// Every TTY an alert is broadcast to (amendment 10).
    fn ttys() -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir("/dev/pts") {
            for ent in rd.flatten() {
                let name = ent.file_name().to_string_lossy().into_owned();
                if name.chars().all(|c| c.is_ascii_digit()) {
                    out.push(format!("/dev/pts/{name}"));
                }
            }
        }
        for n in 1..=12 {
            let p = format!("/dev/tty{n}");
            if std::path::Path::new(&p).exists() {
                out.push(p);
            }
        }
        out.sort();
        out
    }
}

impl Sink for SystemSink {
    fn emit(&mut self, a: &Alert) {
        let prio = priority(&a.severity).to_string();
        let msg = summary(a);
        let payload = encode_fields(&[
            ("MESSAGE", &msg),
            ("PRIORITY", &prio),
            ("SYSLOG_IDENTIFIER", "sentineld"),
            ("AIOS_SENTINEL_ALERT", &a.id),
            ("AIOS_SENTINEL_RULE", &a.rule),
            ("AIOS_SENTINEL_OUTCOME", &a.outcome),
        ]);
        if let Some(s) = &self.journal {
            // A failed journal write must never take the daemon down; the
            // store and the TTYs still have the alert (spec §12).
            let _ = s.send(&payload);
        }
        if broadcasts(&a.severity) {
            let line = format!("\r\n{msg}\r\n");
            for t in Self::ttys() {
                // O_NONBLOCK on both the open and the write: a terminal whose
                // reader is gone, or whose output is stopped, would otherwise
                // block this thread inside the event loop and start costing
                // ring-buffer drops (spec §13). A broadcast is best effort.
                use std::os::unix::fs::OpenOptionsExt;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&t)
                {
                    let _ = f.write_all(line.as_bytes());
                }
            }
        }
    }
}

/// A sink that records instead of writing, for tests.
#[derive(Default)]
pub struct FakeSink {
    pub journal: Vec<String>,
    pub tty: Vec<String>,
}

impl Sink for FakeSink {
    fn emit(&mut self, a: &Alert) {
        let msg = summary(a);
        self.journal.push(msg.clone());
        if broadcasts(&a.severity) {
            self.tty.push(msg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_follows_severity() {
        assert_eq!(priority("critical"), 2);
        assert_eq!(priority("high"), 3);
        assert_eq!(priority("medium"), 4);
        assert_eq!(priority("low"), 5);
        assert_eq!(priority("info"), 6);
        assert_eq!(priority("nonsense"), 6, "unknown severities are info");
    }

    #[test]
    fn plain_fields_are_key_equals_value_lines() {
        let out = encode_fields(&[("PRIORITY", "3"), ("SYSLOG_IDENTIFIER", "sentineld")]);
        assert_eq!(out, b"PRIORITY=3\nSYSLOG_IDENTIFIER=sentineld\n");
    }

    #[test]
    fn a_multiline_value_uses_the_binary_framing() {
        let out = encode_fields(&[("MESSAGE", "one\ntwo")]);
        let mut want = Vec::new();
        want.extend_from_slice(b"MESSAGE\n");
        want.extend_from_slice(&7u64.to_le_bytes());
        want.extend_from_slice(b"one\ntwo");
        want.push(b'\n');
        assert_eq!(out, want);
    }

    #[test]
    fn broadcast_covers_high_and_critical_only() {
        assert!(broadcasts("critical"));
        assert!(broadcasts("high"));
        assert!(!broadcasts("medium"));
        assert!(!broadcasts("low"));
    }

    fn alert_at(id: &str, rule: &str, severity: &str, outcome: &str) -> crate::alert::Alert {
        crate::alert::Alert {
            id: id.to_string(),
            ts: "2026-11-12T16:42:51.123Z".to_string(),
            rule: rule.to_string(),
            severity: severity.to_string(),
            action: "freeze".to_string(),
            mode: "enforce".to_string(),
            outcome: outcome.to_string(),
            message: String::new(),
            process: None,
            ancestors: vec![],
            event: serde_json::json!({"on": "exec"}),
            context: vec![],
            prev_hash: crate::alert::GENESIS.to_string(),
            hash: "abc".to_string(),
        }
    }

    #[test]
    fn the_fake_sink_records_what_it_was_given() {
        let mut s = FakeSink::default();
        let a = alert_at("A1", "reverse-shell", "high", "frozen");
        s.emit(&a);
        assert_eq!(s.journal.len(), 1);
        assert_eq!(s.tty.len(), 1, "high severity reaches the TTYs");
        assert!(
            s.tty[0].contains("reverse-shell"),
            "message was {}",
            s.tty[0]
        );
        assert!(s.tty[0].contains("frozen"));
    }

    #[test]
    fn the_fake_sink_skips_the_tty_for_a_low_alert() {
        let mut s = FakeSink::default();
        let a = alert_at("A2", "camera-open", "low", "alerted");
        s.emit(&a);
        assert_eq!(s.journal.len(), 1);
        assert!(s.tty.is_empty());
    }

    #[test]
    fn the_one_line_summary_names_rule_outcome_and_process() {
        let mut a = alert_at("A3", "exec-memfd", "critical", "denied");
        a.action = "deny".to_string();
        a.process = Some(crate::alert::ProcRef {
            pid: 4242,
            exe: "/usr/bin/x".to_string(),
            argv: String::new(),
            uid: 1000,
            unit: String::new(),
        });
        let line = summary(&a);
        assert!(line.contains("exec-memfd"));
        assert!(line.contains("denied"));
        assert!(line.contains("4242"));
        assert!(line.contains("/usr/bin/x"));
    }

    #[test]
    fn a_summary_without_a_process_carries_the_message() {
        let mut a = alert_at("A4", "lockdown-gap", "critical", "alerted");
        a.message = "lockdown engaged 1200 ms after boot".to_string();
        let line = summary(&a);
        assert!(line.contains("lockdown-gap"));
        assert!(
            line.contains("lockdown engaged"),
            "a host-level alert has only its message to say what happened: {line}"
        );
    }
}
