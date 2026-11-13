//! Shared fixtures for sentinel-rules tests.
#![allow(dead_code)]

/// A valid two-rule file covering a kernel rule and a user-space rule.
pub const SAMPLE: &str = r#"
[[rule]]
id       = "exec-memfd"
desc     = "Fileless execution from a memfd"
on       = "exec"
severity = "critical"
action   = "deny"
match    = { exe_memfd = true }

[[rule]]
id       = "reverse-shell"
on       = "exec"
severity = "high"
action   = "freeze"
match    = { exe = ["/usr/bin/bash", "/usr/bin/sh"], stdio_socket = true }
except   = { ancestors = ["/usr/bin/sshd"] }
"#;
