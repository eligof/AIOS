//! A varlink client for `io.aios.Sentinel` (spec §10.2).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use anyhow::{bail, Result};

pub const INTERFACE: &str = "io.aios.Sentinel";
pub const SOCKET_PATH: &str = "/run/aios-sentinel/io.aios.Sentinel";

/// One call, NUL-terminated.
pub fn encode_call(method: &str, parameters: serde_json::Value, more: bool) -> Vec<u8> {
    let mut v = serde_json::json!({
        "method": format!("{INTERFACE}.{method}"),
        "parameters": parameters,
    });
    if more {
        v["more"] = true.into();
    }
    let mut out = serde_json::to_vec(&v).unwrap_or_default();
    out.push(0);
    out
}

/// A readable message for an error reply, or `None` if it is not an error.
pub fn reply_error(v: &serde_json::Value) -> Option<String> {
    let name = v.get("error")?.as_str()?;
    let short = name.rsplit('.').next().unwrap_or(name);
    let params = v.get("parameters").cloned().unwrap_or_default();
    let detail = match short {
        "PermissionDenied" => {
            " — this command changes something, so it needs root: re-run it with run0".to_string()
        }
        "NoSuchAlert" => format!(
            " — no alert with id {}",
            params.get("id").and_then(|i| i.as_str()).unwrap_or("?")
        ),
        "NoSuchQuarantine" => format!(
            " — no quarantine with id {}",
            params.get("id").and_then(|i| i.as_str()).unwrap_or("?")
        ),
        "InvalidRules" => {
            let errs = params
                .get("errors")
                .and_then(|e| e.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|e| e.as_str())
                        .collect::<Vec<_>>()
                        .join("\n  ")
                })
                .unwrap_or_default();
            format!(":\n  {errs}")
        }
        _ => {
            let p = params.to_string();
            if p == "{}" {
                String::new()
            } else {
                format!(" {p}")
            }
        }
    };
    Some(format!("{short}{detail}"))
}

/// `1h`, `30m`, `2d`, or a timestamp passed through unchanged.
pub fn since_to_ts(spec: &str, now_ms: u64) -> Option<String> {
    if spec.contains('T') && spec.ends_with('Z') {
        return Some(spec.to_string());
    }
    let (num, unit) = spec.split_at(spec.len().checked_sub(1)?);
    let n: u64 = num.parse().ok()?;
    let ms = match unit {
        "s" => n * 1000,
        "m" => n * 60_000,
        "h" => n * 3_600_000,
        "d" => n * 86_400_000,
        _ => return None,
    };
    Some(format_ts(now_ms.saturating_sub(ms)))
}

/// The same RFC 3339 rendering the daemon uses.
pub fn format_ts(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let millis = ms % 1000;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        millis
    )
}

/// One line of `sentinel alerts`.
pub fn alert_line(a: &serde_json::Value) -> String {
    let s = |k: &str| a.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let time = s("ts")
        .split('T')
        .nth(1)
        .unwrap_or("")
        .trim_end_matches('Z');
    let time = time.split('.').next().unwrap_or(time);
    let who = match a.get("process") {
        Some(p) if p.is_object() => format!(
            "pid {} {}",
            p.get("pid").and_then(|v| v.as_u64()).unwrap_or(0),
            p.get("exe").and_then(|v| v.as_str()).unwrap_or("")
        ),
        _ => s("message").to_string(),
    };
    format!(
        "{:<26}  {:<8}  {:<18}  {:<8}  {:<12}  {}",
        s("id"),
        time,
        s("rule"),
        s("severity"),
        s("outcome"),
        who
    )
}

/// A connected client.
pub struct Client {
    sock: UnixStream,
    pending: Vec<u8>,
}

impl Client {
    pub fn connect(path: &str) -> Result<Client> {
        let sock = UnixStream::connect(path).map_err(|e| {
            anyhow::anyhow!(
                "cannot reach sentineld at {path}: {e}\n\
                 Is aios-sentinel.service running, and are you root or in the wheel group?"
            )
        })?;
        Ok(Client {
            sock,
            pending: Vec::new(),
        })
    }

    /// One call, one reply.
    pub fn call(
        &mut self,
        method: &str,
        parameters: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.sock
            .write_all(&encode_call(method, parameters, false))?;
        let v = self.read_frame()?;
        if let Some(e) = reply_error(&v) {
            bail!("{e}");
        }
        Ok(v.get("parameters").cloned().unwrap_or_default())
    }

    /// A streaming call: `f` is invoked per reply until the peer closes.
    pub fn call_more(
        &mut self,
        method: &str,
        parameters: serde_json::Value,
        mut f: impl FnMut(&serde_json::Value),
    ) -> Result<()> {
        self.sock
            .write_all(&encode_call(method, parameters, true))?;
        loop {
            let v = match self.read_frame() {
                Ok(v) => v,
                Err(_) => return Ok(()),
            };
            if let Some(e) = reply_error(&v) {
                bail!("{e}");
            }
            if let Some(p) = v.get("parameters") {
                f(p);
            }
            if v.get("continues").and_then(|c| c.as_bool()) != Some(true) {
                return Ok(());
            }
        }
    }

    fn read_frame(&mut self) -> Result<serde_json::Value> {
        let mut buf = [0u8; 8192];
        loop {
            if let Some(i) = self.pending.iter().position(|b| *b == 0) {
                let frame: Vec<u8> = self.pending.drain(..=i).collect();
                return Ok(serde_json::from_slice(&frame[..frame.len() - 1])?);
            }
            let n = self.sock.read(&mut buf)?;
            if n == 0 {
                bail!("sentineld closed the connection");
            }
            self.pending.extend_from_slice(&buf[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_is_nul_terminated_and_names_the_interface() {
        let out = encode_call("Status", serde_json::json!({}), false);
        assert_eq!(out.last(), Some(&0u8));
        let v: serde_json::Value = serde_json::from_slice(&out[..out.len() - 1]).unwrap();
        assert_eq!(v["method"], "io.aios.Sentinel.Status");
        assert!(v.get("more").is_none());

        let out = encode_call("WatchAlerts", serde_json::json!({}), true);
        let v: serde_json::Value = serde_json::from_slice(&out[..out.len() - 1]).unwrap();
        assert_eq!(v["more"], true);
    }

    #[test]
    fn an_error_reply_becomes_a_readable_message() {
        let v = serde_json::json!({
            "error": "io.aios.Sentinel.PermissionDenied",
            "parameters": {"method": "Release", "uid": 1000}
        });
        let e = reply_error(&v).expect("an error");
        assert!(e.contains("PermissionDenied"), "{e}");
        assert!(e.contains("run0"), "the hint names run0: {e}");

        let v = serde_json::json!({
            "error": "io.aios.Sentinel.NoSuchAlert",
            "parameters": {"id": "A9"}
        });
        let e = reply_error(&v).unwrap();
        assert!(e.contains("NoSuchAlert") && e.contains("A9"), "{e}");

        assert!(reply_error(&serde_json::json!({"parameters": {}})).is_none());
    }

    #[test]
    fn relative_times_become_timestamps() {
        // `date -u -d @1794571200` is 2026-11-13T12:00:00.
        let now = 1_794_571_200_000u64;
        assert_eq!(
            since_to_ts("1h", now),
            Some("2026-11-13T11:00:00.000Z".to_string())
        );
        assert_eq!(
            since_to_ts("30m", now),
            Some("2026-11-13T11:30:00.000Z".to_string())
        );
        assert_eq!(
            since_to_ts("2d", now),
            Some("2026-11-11T12:00:00.000Z".to_string())
        );
        assert_eq!(since_to_ts("nonsense", now), None);
        // An explicit timestamp passes through.
        assert_eq!(
            since_to_ts("2026-11-01T00:00:00.000Z", now),
            Some("2026-11-01T00:00:00.000Z".to_string())
        );
    }

    #[test]
    fn the_client_renders_the_same_timestamps_as_the_daemon() {
        // Both sides format by hand, so one shared case is checked against
        // `date -u -d @1763000571` -> 2025-11-13T02:22:51.
        assert_eq!(format_ts(1_763_000_571_123), "2025-11-13T02:22:51.123Z");
    }

    #[test]
    fn the_alert_table_line_is_aligned_and_complete() {
        let a = serde_json::json!({
            "id": "01JCZZ", "ts": "2026-11-12T16:42:51.123Z", "rule": "reverse-shell",
            "severity": "high", "outcome": "frozen",
            "process": {"pid": 4242, "exe": "/usr/bin/bash"}
        });
        let line = alert_line(&a);
        for want in [
            "01JCZZ",
            "16:42:51",
            "reverse-shell",
            "high",
            "frozen",
            "4242",
            "/usr/bin/bash",
        ] {
            assert!(line.contains(want), "{want:?} missing from {line:?}");
        }
    }

    #[test]
    fn an_alert_without_a_process_still_renders() {
        let a = serde_json::json!({
            "id": "01JD00", "ts": "2026-11-12T16:00:00.000Z", "rule": "lockdown-gap",
            "severity": "critical", "outcome": "alerted",
            "message": "lockdown was active for 20.0 s"
        });
        let line = alert_line(&a);
        assert!(line.contains("lockdown-gap"));
        assert!(
            line.contains("lockdown was active"),
            "the message stands in: {line}"
        );
    }
}
