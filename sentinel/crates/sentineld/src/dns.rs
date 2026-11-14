//! The systemd-resolved query monitor (spec §4 `dns`, §12).

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

/// Where resolved listens for monitor subscribers.
pub const MONITOR_SOCKET: &str = "/run/systemd/resolve/io.systemd.Resolve.Monitor";
/// Retry interval when resolved is not there (spec §12).
pub const RETRY: std::time::Duration = std::time::Duration::from_secs(30);

/// The subscribe call, NUL-terminated.
pub fn subscribe_call() -> Vec<u8> {
    let v = serde_json::json!({
        "method": "io.systemd.Resolve.Monitor.SubscribeQueryResults",
        "parameters": {},
        "more": true,
    });
    let mut out = serde_json::to_vec(&v).unwrap_or_default();
    out.push(0);
    out
}

/// The distinct query names in one monitor reply.
pub fn query_names(reply: &serde_json::Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let Some(q) = reply
        .get("parameters")
        .and_then(|p| p.get("question"))
        .and_then(|q| q.as_array())
    else {
        return out;
    };
    for item in q {
        if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
            let name = name.to_string();
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

/// Subscribe to resolved and feed every query name to the DNS-tunnel
/// detector. Reconnects every [`RETRY`] while resolved is unavailable.
///
/// Sets `connected` so `Status` can report the monitor's state (spec §12).
pub fn run(
    daemon: Arc<Mutex<crate::daemon::Daemon>>,
    kernel: Arc<Mutex<Box<dyn crate::kernel::Kernel>>>,
    connected: Arc<std::sync::atomic::AtomicBool>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;
    while !stop.load(Ordering::Relaxed) {
        let Ok(mut sock) = std::os::unix::net::UnixStream::connect(MONITOR_SOCKET) else {
            connected.store(false, Ordering::Relaxed);
            std::thread::sleep(RETRY);
            continue;
        };
        if sock.write_all(&subscribe_call()).is_err() {
            connected.store(false, Ordering::Relaxed);
            std::thread::sleep(RETRY);
            continue;
        }
        connected.store(true, Ordering::Relaxed);

        let mut pending: Vec<u8> = Vec::new();
        let mut buf = [0u8; 8192];
        while !stop.load(Ordering::Relaxed) {
            let n = match sock.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            pending.extend_from_slice(&buf[..n]);
            let (frames, rest) = crate::varlink::split_frames(&pending);
            pending = rest;
            for frame in frames {
                let Ok(v) = serde_json::from_slice::<serde_json::Value>(&frame) else {
                    continue;
                };
                for name in query_names(&v) {
                    // Daemon before kernel, the one lock order every thread
                    // uses; taking the clock first would deadlock against the
                    // drain and the varlink methods.
                    if let Ok(mut d) = daemon.lock() {
                        let now = kernel.lock().map(|k| k.wall_ms()).unwrap_or(0);
                        if let Some(hit) = d.detectors.on_dns(&name, now) {
                            d.raise_dns(hit, now);
                        }
                    }
                }
            }
        }
        connected.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_subscribe_call_asks_for_a_stream() {
        let call = subscribe_call();
        let v: serde_json::Value = serde_json::from_slice(&call[..call.len() - 1]).unwrap();
        assert_eq!(
            v["method"],
            "io.systemd.Resolve.Monitor.SubscribeQueryResults"
        );
        assert_eq!(v["more"], true);
    }

    #[test]
    fn query_names_are_lifted_out_of_a_monitor_reply() {
        let reply = serde_json::json!({
            "parameters": {
                "question": [
                    {"type": "A", "name": "a7f3k9x2m4q8w1e5r6t0y.example.com"},
                    {"type": "AAAA", "name": "a7f3k9x2m4q8w1e5r6t0y.example.com"}
                ]
            },
            "continues": true
        });
        assert_eq!(
            query_names(&reply),
            vec!["a7f3k9x2m4q8w1e5r6t0y.example.com".to_string()],
            "a repeated name is reported once per reply"
        );
    }

    #[test]
    fn a_reply_without_a_question_yields_nothing() {
        assert!(query_names(&serde_json::json!({"parameters": {}})).is_empty());
        assert!(query_names(&serde_json::json!({})).is_empty());
    }
}
