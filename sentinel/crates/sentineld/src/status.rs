//! The `Status` snapshot, `/run/aios-sentinel/state` and systemd readiness
//! (spec §10.1, §11.5, §12).

use std::path::Path;

use serde::Serialize;

/// Where the health check reads the daemon's own verdict (spec §11.5).
pub const STATE_PATH: &str = "/run/aios-sentinel/state";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Health {
    Ok,
    Degraded,
}

impl Health {
    pub fn as_str(self) -> &'static str {
        match self {
            Health::Ok => "ok",
            Health::Degraded => "degraded",
        }
    }
}

/// The `Status` reply (spec §10.1). Field names are camelCase, as varlink
/// interfaces conventionally use.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub version: String,
    pub health: Health,
    pub programs: Vec<String>,
    pub heartbeat_age_ms: u64,
    pub lockdown_active: bool,
    pub lockdown_counts: Vec<u64>,
    pub kernel_rules: usize,
    pub user_rules: usize,
    pub audit_rules: usize,
    pub generation: String,
    pub drops: u64,
    pub quarantines: usize,
    pub dns_monitor: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store_error: Option<String>,
}

/// Write `ok` or `degraded` where `aios-health.sh` looks (spec §11.5).
pub fn write_state(path: &Path, h: Health) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, h.as_str())
}

/// Milliseconds since the last heartbeat. A heartbeat at or after `now`
/// reads as 0, never as an enormous gap from wrapping.
pub fn heartbeat_age_ms(now_ns: u64, beat_ns: u64) -> u64 {
    now_ns.saturating_sub(beat_ns) / 1_000_000
}

/// The same test the kernel hooks make (spec §8.3). A heartbeat of 0 means
/// "not started", and there is no lockdown before the first one.
pub fn lockdown_active(now_ns: u64, beat_ns: u64, after_ns: u64) -> bool {
    beat_ns != 0 && now_ns.saturating_sub(beat_ns) > after_ns
}

/// The `sd_notify` readiness datagram.
pub fn ready_payload() -> Vec<u8> {
    b"READY=1\n".to_vec()
}

/// `NOTIFY_SOCKET` as a connectable address: a leading `@` means the abstract
/// namespace, which is a leading NUL on the wire. Kept as its own function
/// because the two cases need different send calls — a path holding an
/// interior NUL cannot go through `send_to`, which converts it to a C string.
pub fn notify_addr(raw: &str) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    Some(match raw.strip_prefix('@') {
        Some(rest) => format!("\0{rest}"),
        None => raw.to_string(),
    })
}

/// Tell systemd the unit is ready (`Type=notify`, spec §11.4). Silent when
/// `NOTIFY_SOCKET` is unset, which is the case outside systemd.
pub fn notify_ready() {
    let Ok(raw) = std::env::var("NOTIFY_SOCKET") else {
        return;
    };
    if raw.is_empty() {
        return;
    }
    let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() else {
        return;
    };
    let payload = ready_payload();
    match raw.strip_prefix('@') {
        Some(name) => {
            // An abstract socket is addressed by name, not by path.
            use std::os::linux::net::SocketAddrExt;
            if let Ok(addr) = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()) {
                let _ = sock.send_to_addr(&payload, &addr);
            }
        }
        None => {
            let _ = sock.send_to(&payload, &raw);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_state_file_holds_ok_or_degraded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        write_state(&path, Health::Ok).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "ok");
        write_state(&path, Health::Degraded).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "degraded");
    }

    #[test]
    fn the_state_file_directory_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/run/state");
        write_state(&path, Health::Ok).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn heartbeat_age_is_the_gap_in_milliseconds() {
        assert_eq!(heartbeat_age_ms(5_000_000_000, 3_000_000_000), 2_000);
        assert_eq!(
            heartbeat_age_ms(1_000, 9_000),
            0,
            "a heartbeat from the future reads as fresh, never as a huge gap"
        );
    }

    #[test]
    fn lockdown_is_active_only_past_the_threshold() {
        // 5 s threshold, 2 s gap.
        assert!(!lockdown_active(
            7_000_000_000,
            5_000_000_000,
            5_000_000_000
        ));
        // 6 s gap.
        assert!(lockdown_active(
            11_000_000_000,
            5_000_000_000,
            5_000_000_000
        ));
        // Never started.
        assert!(!lockdown_active(11_000_000_000, 0, 5_000_000_000));
    }

    #[test]
    fn status_serialises_every_field_the_spec_names() {
        let s = Status {
            version: "0.1.0".to_string(),
            health: Health::Degraded,
            programs: vec!["exec".to_string(), "connect".to_string()],
            heartbeat_age_ms: 400,
            lockdown_active: false,
            lockdown_counts: vec![0, 0, 0, 0, 0, 0, 0, 3],
            kernel_rules: 4,
            user_rules: 6,
            audit_rules: 1,
            generation: "gen-7".to_string(),
            drops: 0,
            quarantines: 2,
            dns_monitor: false,
            store_error: Some("disk full".to_string()),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["health"], "degraded");
        assert_eq!(v["programs"][0], "exec");
        assert_eq!(v["lockdownCounts"][7], 3);
        assert_eq!(v["kernelRules"], 4);
        assert_eq!(v["userRules"], 6);
        assert_eq!(v["auditRules"], 1);
        assert_eq!(v["heartbeatAgeMs"], 400);
        assert_eq!(v["dnsMonitor"], false);
        assert_eq!(v["storeError"], "disk full");
    }

    #[test]
    fn notify_payload_is_the_systemd_ready_line() {
        assert_eq!(ready_payload(), b"READY=1\n".to_vec());
    }

    #[test]
    fn an_abstract_notify_socket_is_translated() {
        assert_eq!(notify_addr("@/run/x"), Some("\0/run/x".to_string()));
        assert_eq!(notify_addr("/run/x"), Some("/run/x".to_string()));
        assert_eq!(notify_addr(""), None);
    }
}
