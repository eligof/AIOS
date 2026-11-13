//! The alert record, its canonical form and the SHA-256 chain (spec §9).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The `prev_hash` of the first record of a fresh store (spec §9).
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One process as it appears in an alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcRef {
    pub pid: u32,
    pub exe: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub argv: String,
    pub uid: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub unit: String,
}

/// An alert record (spec §9). The declaration order here does not matter: the
/// hash is taken over the canonical form, which sorts keys.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub ts: String,
    pub rule: String,
    pub severity: String,
    pub action: String,
    pub mode: String,
    pub outcome: String,
    /// Free text for alerts that are not a rule hit: the lockdown gap, an
    /// action failure, a sensor overflow, a configuration change.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestors: Vec<ProcRef>,
    pub event: serde_json::Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<serde_json::Value>,
    pub prev_hash: String,
    pub hash: String,
}

/// Serialise `v` with sorted object keys and no whitespace.
///
/// `serde_json`'s map preserves insertion order unless the `preserve_order`
/// feature is on (it is not), so re-walking the value and sorting at each
/// object is what guarantees the ordering the spec asks for, independent of
/// how the value was built.
pub fn canonical(v: &serde_json::Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

// Recursion here is unbounded by construction. That's fine: `event` and
// `context` are built by the daemon from fixed-shape eBPF payloads, not
// parsed from untrusted input, and `serde_json`'s own deserialiser enforces
// a recursion limit (default 128) when a stored record is parsed back into
// a `Value` in Task 4's `verify` walk. Do not add a depth guard here.
fn write_canonical(v: &serde_json::Value, out: &mut String) {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(*k).expect("String key serialises"));
                out.push(':');
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, it) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(it, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

impl Alert {
    /// SHA-256, hex, over the canonical record with `hash` removed (spec §9).
    pub fn compute_hash(&self) -> String {
        // `serde_json::to_value` only fails when a `Serialize` impl errors,
        // which in practice means a non-finite f64 or a non-string map key.
        // `Alert` has no raw float fields, and `serde_json::Value` cannot
        // hold a non-finite number by construction (`Number::from_f64`
        // returns `None` for NaN/Infinity), so this cannot panic today. If
        // you add an `f64` field (e.g. a confidence score) to `Alert` or
        // `ProcRef`, you are reintroducing this panic path — route it
        // through a finite check or `Number::from_f64` first.
        let mut v = serde_json::to_value(self).expect("Alert serialises");
        if let Some(map) = v.as_object_mut() {
            map.remove("hash");
        }
        let mut h = Sha256::new();
        h.update(canonical(&v).as_bytes());
        format!("{:x}", h.finalize())
    }

    /// Chain this record onto `prev` and fill `hash`.
    pub fn seal(&mut self, prev: &str) {
        self.prev_hash = prev.to_string();
        self.hash = self.compute_hash();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn sample() -> Alert {
        Alert {
            id: "01JCZZZZZZZZZZZZZZZZZZZZZZ".to_string(),
            ts: "2026-11-12T16:42:51.123Z".to_string(),
            rule: "reverse-shell".to_string(),
            severity: "high".to_string(),
            action: "freeze".to_string(),
            mode: "enforce".to_string(),
            outcome: "frozen".to_string(),
            message: String::new(),
            process: Some(ProcRef {
                pid: 4242,
                exe: "/usr/bin/bash".to_string(),
                argv: "bash -i".to_string(),
                uid: 1000,
                unit: "session-2.scope".to_string(),
            }),
            ancestors: vec![ProcRef {
                pid: 1,
                exe: "/usr/lib/systemd/systemd".to_string(),
                argv: String::new(),
                uid: 0,
                unit: "init.scope".to_string(),
            }],
            event: serde_json::json!({"on": "exec", "stdio_socket": true}),
            context: vec![],
            prev_hash: GENESIS.to_string(),
            hash: String::new(),
        }
    }

    #[test]
    fn canonical_json_sorts_keys_and_drops_whitespace() {
        let v = serde_json::json!({"b": 1, "a": {"d": 2, "c": [3, 4]}});
        assert_eq!(canonical(&v), r#"{"a":{"c":[3,4],"d":2},"b":1}"#);
    }

    #[test]
    fn genesis_is_sixty_four_zeros() {
        assert_eq!(GENESIS.len(), 64);
        assert!(GENESIS.chars().all(|c| c == '0'));
    }

    #[test]
    fn hash_is_stable_and_excludes_the_hash_field() {
        let mut a = sample();
        let h1 = a.compute_hash();
        // A stale `hash` field must not change the result.
        a.hash = "deadbeef".to_string();
        assert_eq!(a.compute_hash(), h1);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn hash_changes_when_prev_hash_changes() {
        let a = sample();
        let mut b = sample();
        b.prev_hash = "11".repeat(32);
        assert_ne!(a.compute_hash(), b.compute_hash());
    }

    #[test]
    fn sealing_links_a_chain() {
        let mut a = sample();
        a.seal(GENESIS);
        let mut b = sample();
        b.id = "01JCZZZZZZZZZZZZZZZZZZZZA0".to_string();
        b.seal(&a.hash);
        assert_eq!(b.prev_hash, a.hash);
        assert_eq!(b.hash, b.compute_hash());
    }

    // This is the property `sentinel verify` (Task 4) relies on: a record
    // written to disk, read back, and rehashed must match the hash it was
    // sealed with — even though the omitted-when-empty fields (`message`,
    // `context`) are missing from the JSON on the wire and have to be
    // restored by `#[serde(default)]` on deserialisation.
    #[test]
    fn hash_survives_a_json_round_trip_with_omitted_empty_fields() {
        let mut a = sample();
        a.message = String::new();
        a.context = vec![];
        a.seal(GENESIS);

        let line = serde_json::to_string(&a).expect("Alert serialises");
        // Prove the omission actually happens, so this test cannot pass
        // vacuously if `skip_serializing_if` is later removed.
        assert!(!line.contains("\"message\""), "line: {line}");
        assert!(!line.contains("\"context\""), "line: {line}");

        let restored: Alert = serde_json::from_str(&line).expect("Alert deserialises");
        assert_eq!(restored.message, "");
        assert_eq!(restored.context, Vec::<serde_json::Value>::new());
        assert_eq!(restored.compute_hash(), a.hash);
    }

    // `exe`/`argv`/`message` come straight from observed process data (a
    // reverse shell's argv, for instance), so they can contain quotes,
    // backslashes, newlines and non-ASCII. Nothing but serde_json's own
    // escaping protects the canonical form from breaking on that; this pins
    // that escaping is in fact happening and stays stable across a round
    // trip.
    #[test]
    fn hash_is_stable_across_a_round_trip_of_tricky_characters() {
        let mut a = sample();
        a.message = "quote \" backslash \\ newline \n emoji \u{1F600} end".to_string();
        if let Some(p) = a.process.as_mut() {
            p.argv = "sh -c \"echo \\\"hi\\\"\"\nbash".to_string();
        }
        a.seal(GENESIS);

        // The canonical form must still be valid, parseable JSON.
        let v = serde_json::to_value(&a).expect("Alert serialises");
        let reparsed: serde_json::Value =
            serde_json::from_str(&canonical(&v)).expect("canonical output is valid JSON");
        assert_eq!(
            reparsed["message"],
            serde_json::Value::String(a.message.clone())
        );

        let line = serde_json::to_string(&a).expect("Alert serialises");
        let restored: Alert = serde_json::from_str(&line).expect("Alert deserialises");
        assert_eq!(restored.message, a.message);
        assert_eq!(restored.compute_hash(), a.hash);
    }
}
