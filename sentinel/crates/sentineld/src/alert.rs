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
                out.push_str(&serde_json::Value::String((*k).clone()).to_string());
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
}
