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

/// One parsed call.
#[derive(Debug, Clone)]
pub struct Call {
    pub method: String,
    pub parameters: serde_json::Value,
    pub more: bool,
}

impl Call {
    pub fn parse(frame: &[u8]) -> Option<Call> {
        let v: serde_json::Value = serde_json::from_slice(frame).ok()?;
        Some(Call {
            method: v.get("method")?.as_str()?.to_string(),
            parameters: v
                .get("parameters")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
            more: v.get("more").and_then(|m| m.as_bool()).unwrap_or(false),
        })
    }
}

/// Methods that change something, and so need root (spec §10.1).
pub fn requires_root(method: &str) -> bool {
    matches!(method, "Release" | "Kill" | "LoadGeneration")
}

/// `Some(error frame)` when the peer may not call this method.
pub fn check_access(method: &str, peer: &Peer) -> Option<Vec<u8>> {
    let allowed = if requires_root(method) {
        peer.may_write()
    } else {
        peer.may_read()
    };
    if allowed {
        None
    } else {
        Some(encode_error(
            "PermissionDenied",
            serde_json::json!({ "method": method, "uid": peer.uid }),
        ))
    }
}

/// One `WatchAlerts` stream item. Always `continues`, because the stream only
/// ends when the client disconnects.
pub fn encode_watch_item(a: &Alert) -> Vec<u8> {
    encode_reply(&serde_json::json!({ "alert": a }), true)
}

/// `WatchAlerts` requires `more: true`; returns the error frame when it is absent.
pub fn dispatch_watch_precheck(more: bool) -> Option<Vec<u8>> {
    if more {
        None
    } else {
        Some(encode_error("ExpectedMore", serde_json::json!({})))
    }
}

/// The reply for `LoadGeneration`: the change summary, or the validation errors.
pub fn load_generation_result(r: Result<Vec<String>, Vec<String>>) -> Vec<u8> {
    match r {
        Ok(changes) => encode_reply(&serde_json::json!({"ok": true, "changes": changes}), false),
        Err(errors) => encode_error("InvalidRules", serde_json::json!({ "errors": errors })),
    }
}

/// The reply for `Release` and `Kill`.
pub fn quarantine_result(r: Result<(), String>, id: &str) -> Vec<u8> {
    match r {
        Ok(()) => encode_reply(&serde_json::json!({"ok": true, "id": id}), false),
        Err(e) => encode_error("ActionFailed", serde_json::json!({"id": id, "error": e})),
    }
}

/// The reply when `Release` or `Kill` names a quarantine that is not there.
pub fn no_such_quarantine(id: &str) -> Vec<u8> {
    encode_error("NoSuchQuarantine", serde_json::json!({ "id": id }))
}

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

/// Largest run of bytes a client may send without completing a frame. A
/// `wheel` peer that opens the socket and writes without ever sending a NUL
/// would otherwise grow this buffer without limit (spec §13).
const MAX_PENDING: usize = 1 << 20;

/// What a connection thread needs to answer a call. The daemon is behind the
/// same mutex every other thread uses.
pub struct Service {
    pub daemon: Arc<Mutex<crate::daemon::Daemon>>,
    /// Hands each watcher a clone of every new alert.
    pub watchers: Arc<Mutex<Vec<Sender<Alert>>>>,
    /// The kernel handle, for `Release` and `Kill`.
    pub kernel: Arc<Mutex<Box<dyn crate::kernel::Kernel>>>,
    /// Where the rendered rule files live, for `LoadGeneration`.
    pub rules_dir: std::path::PathBuf,
}

/// Send one alert to every `WatchAlerts` subscriber, dropping the ones whose
/// client has gone. Without the drop, every disconnected watcher would stay in
/// the list for the life of the daemon.
pub fn fan_out(watchers: &Arc<Mutex<Vec<Sender<Alert>>>>, a: &Alert) {
    if let Ok(mut w) = watchers.lock() {
        w.retain(|tx| tx.send(a.clone()).is_ok());
    }
}

/// Bind the socket, replacing a stale one from a previous instance. Mode 0660
/// with the `wheel` group, so a `wheel` member can reach it at all (§10.1);
/// the `SO_PEERCRED` check is still what decides what they may call.
pub fn bind(path: &std::path::Path) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // A leftover socket file from a killed instance would make bind fail.
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    set_socket_group(path);
    Ok(l)
}

/// Give the socket away to the `wheel` group. Best effort: it needs root, and
/// a host with no `wheel` group leaves the socket root-only, which fails
/// closed — `sentinel` run by root still works.
fn set_socket_group(path: &std::path::Path) {
    let group_file = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let Some(gid) = wheel_gid(&group_file) else {
        return;
    };
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
        return;
    };
    // SAFETY: `c` is a NUL-terminated path that exists; -1 leaves the owner.
    unsafe {
        libc::chown(c.as_ptr(), u32::MAX, gid);
    }
}

/// Serve one connection until the peer goes away.
pub fn serve_conn(mut stream: UnixStream, svc: Arc<Service>) {
    let Ok(peer) = peer_of(&stream) else { return };
    let mut pending: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        pending.extend_from_slice(&buf[..n]);
        let (frames, rest) = split_frames(&pending);
        pending = rest;
        if pending.len() > MAX_PENDING {
            let _ = stream.write_all(&encode_error(
                "InvalidParameter",
                serde_json::json!({"error": "frame too long"}),
            ));
            return;
        }
        for frame in frames {
            let Some(call) = Call::parse(&frame) else {
                let _ = stream.write_all(&encode_error(
                    "InvalidParameter",
                    serde_json::json!({"frame": String::from_utf8_lossy(&frame)}),
                ));
                continue;
            };
            let Some(method) = short_method(&call.method).map(|m| m.to_string()) else {
                let _ = stream.write_all(&encode_error(
                    "InterfaceNotFound",
                    serde_json::json!({"method": call.method}),
                ));
                continue;
            };
            if let Some(denied) = check_access(&method, &peer) {
                let _ = stream.write_all(&denied);
                continue;
            }
            if method == "WatchAlerts" {
                if let Some(e) = dispatch_watch_precheck(call.more) {
                    let _ = stream.write_all(&e);
                    continue;
                }
                stream_alerts(&mut stream, &svc);
                return;
            }
            let reply = handle(&method, &call.parameters, &svc);
            if stream.write_all(&reply).is_err() {
                return;
            }
        }
    }
}

/// Register a watcher and forward alerts until the write fails.
fn stream_alerts(stream: &mut UnixStream, svc: &Arc<Service>) {
    let (tx, rx): (Sender<Alert>, Receiver<Alert>) = channel();
    if let Ok(mut w) = svc.watchers.lock() {
        w.push(tx);
    }
    while let Ok(a) = rx.recv() {
        if stream.write_all(&encode_watch_item(&a)).is_err() {
            return;
        }
    }
}

/// Answer one non-streaming method against the live daemon.
fn handle(method: &str, params: &serde_json::Value, svc: &Arc<Service>) -> Vec<u8> {
    use crate::action;

    let mut d = match svc.daemon.lock() {
        Ok(d) => d,
        Err(_) => return encode_error("Internal", serde_json::json!({"error": "state poisoned"})),
    };

    match method {
        "Release" | "Kill" => {
            let id = params.get("id").and_then(|i| i.as_str()).unwrap_or("");
            let Some(q) = d.quarantines.take(id) else {
                return no_such_quarantine(id);
            };
            let mut k = match svc.kernel.lock() {
                Ok(k) => k,
                Err(_) => {
                    d.quarantines.insert(q);
                    return encode_error("Internal", serde_json::json!({"error": "kernel busy"}));
                }
            };
            let r = if method == "Release" {
                action::release(k.as_mut(), &q)
            } else {
                action::kill_quarantine(k.as_mut(), &q)
            };
            match r {
                Ok(()) => {
                    if method == "Kill" {
                        // A killed quarantine stays listed until its cgroup is
                        // gone, so put it back with the flag set.
                        let mut q = q;
                        q.killed = true;
                        d.quarantines.insert(q);
                    }
                    quarantine_result(Ok(()), id)
                }
                Err(e) => {
                    d.quarantines.insert(q);
                    quarantine_result(Err(e.to_string()), id)
                }
            }
        }
        "LoadGeneration" => {
            let generation = params
                .get("gen")
                .and_then(|g| g.as_str())
                .unwrap_or("")
                .to_string();
            let dir = params
                .get("dir")
                .and_then(|p| p.as_str())
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| svc.rules_dir.clone());
            load_generation_result(d.load_generation(&generation, &dir, svc.kernel.clone()))
        }
        other => {
            let view = d.read_view();
            dispatch_read(other, params, &view)
        }
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
    fn a_non_root_peer_is_refused_a_write_method() {
        let wheel = Peer {
            uid: 1000,
            gid: 998,
            wheel: true,
        };
        assert!(requires_root("Release"));
        assert!(requires_root("Kill"));
        assert!(requires_root("LoadGeneration"));
        assert!(!requires_root("Status"));
        assert!(!wheel.may_write());
        let out = check_access("Release", &wheel).expect("refused");
        assert_eq!(decode(&out)["error"], "io.aios.Sentinel.PermissionDenied");
        assert!(check_access("Status", &wheel).is_none(), "but may read");
    }

    #[test]
    fn a_peer_with_no_access_is_refused_everything() {
        let user = Peer {
            uid: 1000,
            gid: 1000,
            wheel: false,
        };
        let out = check_access("Status", &user).expect("an error is produced");
        assert_eq!(decode(&out)["error"], "io.aios.Sentinel.PermissionDenied");
        assert!(check_access(
            "Status",
            &Peer {
                uid: 0,
                gid: 0,
                wheel: false
            }
        )
        .is_none());
    }

    #[test]
    fn load_generation_rejects_an_invalid_rule_set_and_keeps_the_old_one() {
        let out = load_generation_result(Err(vec![
            "default.toml: rule x: unknown predicate `nope`".to_string(),
        ]));
        let v = decode(&out);
        assert_eq!(v["error"], "io.aios.Sentinel.InvalidRules");
        assert!(
            v["parameters"]["errors"][0]
                .as_str()
                .unwrap()
                .contains("unknown predicate"),
            "the validation error is returned verbatim: {v}"
        );
    }

    #[test]
    fn load_generation_reports_the_diff_on_success() {
        let out = load_generation_result(Ok(vec![
            "reverse-shell: action freeze -> kill".to_string(),
            "+ exec-shm".to_string(),
        ]));
        let v = decode(&out);
        assert_eq!(v["parameters"]["ok"], true);
        assert_eq!(v["parameters"]["changes"][1], "+ exec-shm");
    }

    fn an_alert(id: &str) -> Alert {
        Alert {
            id: id.to_string(),
            ts: String::new(),
            rule: "r".to_string(),
            severity: "high".to_string(),
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
        }
    }

    #[test]
    fn watch_alerts_streams_each_alert_with_continues() {
        let out = encode_watch_item(&an_alert("A1"));
        let v = decode(&out);
        assert_eq!(v["continues"], true, "a stream item always continues");
        assert_eq!(v["parameters"]["alert"]["id"], "A1");
    }

    #[test]
    fn watch_alerts_without_more_is_an_error() {
        let out = dispatch_watch_precheck(false);
        assert_eq!(
            decode(&out.unwrap())["error"],
            "io.aios.Sentinel.ExpectedMore",
            "WatchAlerts only makes sense with more: true"
        );
        assert!(dispatch_watch_precheck(true).is_none());
    }

    #[test]
    fn fan_out_drops_a_watcher_that_went_away() {
        let (live_tx, live_rx) = std::sync::mpsc::channel();
        let (dead_tx, dead_rx) = std::sync::mpsc::channel();
        drop(dead_rx);
        let watchers = std::sync::Arc::new(std::sync::Mutex::new(vec![live_tx, dead_tx]));
        fan_out(&watchers, &an_alert("A9"));
        assert_eq!(live_rx.recv().unwrap().id, "A9");
        assert_eq!(
            watchers.lock().unwrap().len(),
            1,
            "a disconnected watcher is not kept forever"
        );
    }

    #[test]
    fn a_call_is_parsed_into_method_parameters_and_more() {
        let c = Call::parse(
            br#"{"method":"io.aios.Sentinel.GetAlert","parameters":{"id":"A1"},"more":true}"#,
        )
        .expect("parses");
        assert_eq!(c.method, "io.aios.Sentinel.GetAlert");
        assert_eq!(c.parameters["id"], "A1");
        assert!(c.more);

        assert!(Call::parse(b"not json").is_none());
    }

    #[test]
    fn a_call_without_parameters_defaults_to_an_empty_object() {
        let c = Call::parse(br#"{"method":"io.aios.Sentinel.Status"}"#).unwrap();
        assert!(c.parameters.is_object());
        assert!(!c.more);
    }

    #[test]
    fn the_socket_is_group_readable_so_wheel_can_reach_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/io.aios.Sentinel");
        let l = bind(&path).expect("binds");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "0660 plus the wheel group, not root-only");
        // Binding again over a leftover socket must work: a killed instance
        // leaves the file behind and systemd restarts us.
        drop(l);
        assert!(bind(&path).is_ok());
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
