//! The `io.aios.Sentinel` varlink service: framing, access control and the
//! read-only methods (spec §10.1, amendment 7).

use crate::alert::Alert;

/// The interface name every method and error is prefixed with.
pub const INTERFACE: &str = "io.aios.Sentinel";
/// The socket the CLI and the Cockpit connect to (spec §10.1).
pub const SOCKET_PATH: &str = "/run/aios-sentinel/io.aios.Sentinel";

/// Split a read buffer into complete NUL-terminated frames plus the remainder.
pub fn split_frames(buf: &[u8]) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut frames = Vec::new();
    let mut start = 0;
    for (i, b) in buf.iter().enumerate() {
        if *b == 0 {
            frames.push(buf[start..i].to_vec());
            start = i + 1;
        }
    }
    (frames, buf[start..].to_vec())
}

/// `{"parameters": …}` plus the NUL, with `continues` on a streaming reply.
pub fn encode_reply(parameters: &serde_json::Value, continues: bool) -> Vec<u8> {
    let mut v = serde_json::json!({ "parameters": parameters });
    if continues {
        v["continues"] = true.into();
    }
    let mut out = serde_json::to_vec(&v).unwrap_or_default();
    out.push(0);
    out
}

/// `{"error": "io.aios.Sentinel.<name>", "parameters": …}` plus the NUL.
pub fn encode_error(name: &str, parameters: serde_json::Value) -> Vec<u8> {
    let v = serde_json::json!({
        "error": format!("{INTERFACE}.{name}"),
        "parameters": parameters,
    });
    let mut out = serde_json::to_vec(&v).unwrap_or_default();
    out.push(0);
    out
}

/// The method name without the interface prefix, or `None` for another interface.
pub fn short_method(full: &str) -> Option<&str> {
    full.strip_prefix(INTERFACE)
        .and_then(|r| r.strip_prefix('.'))
        .filter(|m| !m.is_empty() && !m.contains('.'))
}

/// The connected peer, from `SO_PEERCRED` (spec §10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    pub gid: u32,
    pub wheel: bool,
}

impl Peer {
    /// Root and `wheel` may read.
    pub fn may_read(&self) -> bool {
        self.uid == 0 || self.wheel
    }
    /// Only root may change anything.
    pub fn may_write(&self) -> bool {
        self.uid == 0
    }
}

/// The gid of the `wheel` line of an `/etc/group` text.
pub fn wheel_gid(group_file: &str) -> Option<u32> {
    for l in group_file.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() >= 3 && f[0] == "wheel" {
            return f[2].parse().ok();
        }
    }
    None
}

/// The member names on the `wheel` line.
pub fn wheel_members(group_file: &str) -> Vec<String> {
    group_file
        .lines()
        .find(|l| l.starts_with("wheel:"))
        .and_then(|l| l.split(':').nth(3))
        .map(|m| {
            m.split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// The login name of `uid`, from an `/etc/passwd` text.
fn passwd_name(passwd_file: &str, uid: u32) -> Option<String> {
    for l in passwd_file.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() >= 3 && f[2].parse::<u32>().ok() == Some(uid) {
            return Some(f[0].to_string());
        }
    }
    None
}

/// Is `(uid, gid)` in `wheel`, by primary group or by secondary membership?
pub fn in_wheel(group_file: &str, passwd_file: &str, uid: u32, gid: u32) -> bool {
    let Some(g) = wheel_gid(group_file) else {
        return false;
    };
    if gid == g {
        return true;
    }
    passwd_name(passwd_file, uid).is_some_and(|n| wheel_members(group_file).contains(&n))
}

/// Read `SO_PEERCRED` off a connected stream and decide `wheel` membership.
pub fn peer_of(stream: &std::os::unix::net::UnixStream) -> std::io::Result<Peer> {
    use std::os::fd::AsRawFd;
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred and len are valid out-pointers of the documented types.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let (uid, gid) = (cred.uid as u32, cred.gid as u32);
    let group_file = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let passwd_file = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    Ok(Peer {
        uid,
        gid,
        wheel: in_wheel(&group_file, &passwd_file, uid, gid),
    })
}

/// A read-only snapshot the dispatcher works from, so the methods are pure
/// and testable without a daemon.
pub struct ReadView {
    pub status: Option<crate::status::Status>,
    pub alerts: Vec<Alert>,
    pub quarantines: Vec<serde_json::Value>,
    /// `Ok(record count)` or `Err(message)`.
    pub chain: Result<usize, String>,
}

impl Default for ReadView {
    fn default() -> ReadView {
        ReadView {
            status: None,
            alerts: Vec::new(),
            quarantines: Vec::new(),
            chain: Ok(0),
        }
    }
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "info" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 0,
    }
}

/// Handle one read-only method. Returns the encoded reply or error.
pub fn dispatch_read(method: &str, params: &serde_json::Value, v: &ReadView) -> Vec<u8> {
    match method {
        "Status" => match &v.status {
            Some(s) => encode_reply(
                &serde_json::json!({ "status": serde_json::to_value(s).unwrap_or_default() }),
                false,
            ),
            None => encode_error("NotReady", serde_json::json!({})),
        },
        "ListAlerts" => {
            let min = params
                .get("minSeverity")
                .and_then(|s| s.as_str())
                .map(severity_rank)
                .unwrap_or(0);
            let since = params.get("since").and_then(|s| s.as_str()).unwrap_or("");
            let mut out: Vec<&Alert> = v
                .alerts
                .iter()
                .filter(|a| severity_rank(&a.severity) >= min)
                .filter(|a| since.is_empty() || a.ts.as_str() >= since)
                .collect();
            if let Some(limit) = params.get("limit").and_then(|l| l.as_u64()) {
                let limit = limit as usize;
                if out.len() > limit {
                    // Keep the newest.
                    out.drain(..out.len() - limit);
                }
            }
            encode_reply(&serde_json::json!({ "alerts": out }), false)
        }
        "GetAlert" => {
            let id = params.get("id").and_then(|i| i.as_str()).unwrap_or("");
            match v.alerts.iter().find(|a| a.id == id) {
                Some(a) => encode_reply(&serde_json::json!({ "alert": a }), false),
                None => encode_error("NoSuchAlert", serde_json::json!({ "id": id })),
            }
        }
        "ListQuarantine" => {
            encode_reply(&serde_json::json!({ "quarantines": v.quarantines }), false)
        }
        "VerifyChain" => match &v.chain {
            Ok(n) => encode_reply(&serde_json::json!({"ok": true, "records": n}), false),
            Err(e) => encode_reply(&serde_json::json!({"ok": false, "error": e}), false),
        },
        other => encode_error("MethodNotFound", serde_json::json!({ "method": other })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_split_on_nul() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(br#"{"method":"A"}"#);
        buf.push(0);
        buf.extend_from_slice(br#"{"method":"B"}"#);
        buf.push(0);
        buf.extend_from_slice(br#"{"method":"partial"#);
        let (frames, rest) = split_frames(&buf);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], br#"{"method":"A"}"#);
        assert_eq!(rest, br#"{"method":"partial"#);
    }

    #[test]
    fn a_reply_is_nul_terminated_json() {
        let out = encode_reply(&serde_json::json!({"ok": true}), false);
        assert_eq!(out.last(), Some(&0u8));
        let text = std::str::from_utf8(&out[..out.len() - 1]).unwrap();
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["parameters"]["ok"], true);
        assert!(v.get("continues").is_none());
    }

    #[test]
    fn a_streaming_reply_sets_continues() {
        let out = encode_reply(&serde_json::json!({}), true);
        let text = std::str::from_utf8(&out[..out.len() - 1]).unwrap();
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["continues"], true);
    }

    #[test]
    fn an_error_names_the_interface() {
        let out = encode_error("PermissionDenied", serde_json::json!({"method": "Release"}));
        let text = std::str::from_utf8(&out[..out.len() - 1]).unwrap();
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["error"], "io.aios.Sentinel.PermissionDenied");
        assert_eq!(v["parameters"]["method"], "Release");
    }

    #[test]
    fn the_method_name_is_stripped_of_the_interface_prefix() {
        assert_eq!(short_method("io.aios.Sentinel.Status"), Some("Status"));
        assert_eq!(short_method("org.varlink.service.GetInfo"), None);
        assert_eq!(short_method("Status"), None);
    }

    #[test]
    fn access_follows_peer_credentials() {
        let root = Peer {
            uid: 0,
            gid: 0,
            wheel: false,
        };
        let wheel = Peer {
            uid: 1000,
            gid: 998,
            wheel: true,
        };
        let user = Peer {
            uid: 1000,
            gid: 1000,
            wheel: false,
        };
        assert!(root.may_read() && root.may_write());
        assert!(wheel.may_read() && !wheel.may_write());
        assert!(!user.may_read() && !user.may_write());
    }

    #[test]
    fn wheel_membership_is_read_from_the_group_file() {
        let text = "root:x:0:\nwheel:x:998:alice,bob\nusers:x:100:\n";
        assert_eq!(wheel_gid(text), Some(998));
        assert!(wheel_members(text).contains(&"alice".to_string()));
        assert!(wheel_members(text).contains(&"bob".to_string()));
        assert_eq!(wheel_gid("root:x:0:\n"), None);
    }

    #[test]
    fn wheel_covers_both_primary_and_secondary_membership() {
        let group = "root:x:0:\nwheel:x:998:alice\nusers:x:100:\n";
        let passwd = "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n\
                      bob:x:1001:1001::/home/bob:/bin/bash\n";
        // Primary group is wheel.
        assert!(in_wheel(group, passwd, 1001, 998));
        // A secondary member, with a primary group of their own.
        assert!(in_wheel(group, passwd, 1000, 1000));
        // Neither.
        assert!(!in_wheel(group, passwd, 1001, 1001));
        // No wheel group at all.
        assert!(!in_wheel("root:x:0:\n", passwd, 1000, 1000));
    }

    #[test]
    fn an_unknown_method_is_an_interface_error() {
        let out = dispatch_read("Nonsense", &serde_json::json!({}), &ReadView::default());
        let v = decode(&out);
        assert_eq!(v["error"], "io.aios.Sentinel.MethodNotFound");
    }

    fn decode(out: &[u8]) -> serde_json::Value {
        serde_json::from_slice(&out[..out.len() - 1]).unwrap()
    }

    fn view_with_alerts() -> ReadView {
        let a = |id: &str, sev: &str, ts: &str| crate::alert::Alert {
            id: id.to_string(),
            ts: ts.to_string(),
            rule: "r".to_string(),
            severity: sev.to_string(),
            action: "alert".to_string(),
            mode: "enforce".to_string(),
            outcome: "alerted".to_string(),
            message: String::new(),
            process: None,
            ancestors: vec![],
            event: serde_json::json!({}),
            context: vec![],
            prev_hash: crate::alert::GENESIS.to_string(),
            hash: String::new(),
        };
        ReadView {
            alerts: vec![
                a("A1", "low", "2026-11-12T10:00:00.000Z"),
                a("A2", "high", "2026-11-12T11:00:00.000Z"),
                a("A3", "critical", "2026-11-12T12:00:00.000Z"),
            ],
            ..ReadView::default()
        }
    }

    #[test]
    fn list_alerts_filters_by_severity() {
        let out = dispatch_read(
            "ListAlerts",
            &serde_json::json!({"minSeverity": "high"}),
            &view_with_alerts(),
        );
        let v = decode(&out);
        let ids: Vec<&str> = v["parameters"]["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["A2", "A3"]);
    }

    #[test]
    fn list_alerts_honours_since_and_limit() {
        let out = dispatch_read(
            "ListAlerts",
            &serde_json::json!({"since": "2026-11-12T10:30:00.000Z"}),
            &view_with_alerts(),
        );
        assert_eq!(
            decode(&out)["parameters"]["alerts"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        let out = dispatch_read(
            "ListAlerts",
            &serde_json::json!({"limit": 1}),
            &view_with_alerts(),
        );
        let v = decode(&out);
        let arr = v["parameters"]["alerts"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], "A3", "a limit keeps the newest");
    }

    #[test]
    fn get_alert_finds_one_or_errors() {
        let out = dispatch_read(
            "GetAlert",
            &serde_json::json!({"id": "A2"}),
            &view_with_alerts(),
        );
        assert_eq!(decode(&out)["parameters"]["alert"]["id"], "A2");

        let out = dispatch_read(
            "GetAlert",
            &serde_json::json!({"id": "ZZ"}),
            &view_with_alerts(),
        );
        assert_eq!(decode(&out)["error"], "io.aios.Sentinel.NoSuchAlert");
    }

    #[test]
    fn verify_chain_reports_the_count() {
        let v = ReadView {
            chain: Ok(12),
            ..ReadView::default()
        };
        let out = dispatch_read("VerifyChain", &serde_json::json!({}), &v);
        let r = decode(&out);
        assert_eq!(r["parameters"]["ok"], true);
        assert_eq!(r["parameters"]["records"], 12);

        let v = ReadView {
            chain: Err("record 3 hash mismatch".to_string()),
            ..ReadView::default()
        };
        let out = dispatch_read("VerifyChain", &serde_json::json!({}), &v);
        let r = decode(&out);
        assert_eq!(r["parameters"]["ok"], false);
        assert_eq!(r["parameters"]["error"], "record 3 hash mismatch");
    }
}
