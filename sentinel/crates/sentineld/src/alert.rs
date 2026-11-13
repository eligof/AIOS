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

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// Rotation threshold (spec §9).
pub const ROTATE_AT: u64 = 64 * 1024 * 1024;

/// A store error. The daemon downgrades these to "alerts still reach the
/// journal and the TTY" rather than exiting (spec §12).
#[derive(Debug)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

fn err<T>(msg: impl Into<String>) -> Result<T, StoreError> {
    Err(StoreError(msg.into()))
}

/// The hash-chained alert log (spec §9).
pub struct Store {
    dir: PathBuf,
    live: PathBuf,
    last: String,
    /// Bytes after which the live file rotates. Public so tests can shrink it.
    pub rotate_at: u64,
}

impl Store {
    /// Open (creating the directory if needed) and recover the chain head.
    pub fn open(dir: &Path) -> Result<Store, StoreError> {
        if let Err(e) = std::fs::create_dir_all(dir) {
            return err(format!("cannot create {}: {e}", dir.display()));
        }
        let live = dir.join("alerts.jsonl");
        let mut s = Store {
            dir: dir.to_path_buf(),
            live,
            last: GENESIS.to_string(),
            rotate_at: ROTATE_AT,
        };
        s.last = match s.read_all()?.last() {
            Some(a) => a.hash.clone(),
            None => GENESIS.to_string(),
        };
        Ok(s)
    }

    /// The hash the next record will chain from.
    pub fn last_hash(&self) -> String {
        self.last.clone()
    }

    /// The rotated files, oldest first, then the live file.
    fn files(&self) -> Result<Vec<PathBuf>, StoreError> {
        let mut rotated: Vec<(u32, PathBuf)> = Vec::new();
        let rd = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) => return err(format!("cannot read {}: {e}", self.dir.display())),
        };
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().into_owned();
            if let Some(n) = name
                .strip_prefix("alerts.")
                .and_then(|r| r.strip_suffix(".jsonl"))
                .and_then(|n| n.parse::<u32>().ok())
            {
                rotated.push((n, ent.path()));
            }
        }
        rotated.sort_by_key(|(n, _)| *n);
        let mut out: Vec<PathBuf> = rotated.into_iter().map(|(_, p)| p).collect();
        if self.live.exists() {
            out.push(self.live.clone());
        }
        Ok(out)
    }

    /// Every record, oldest first, across rotated files.
    pub fn read_all(&self) -> Result<Vec<Alert>, StoreError> {
        let mut out = Vec::new();
        for p in self.files()? {
            let f = match File::open(&p) {
                Ok(f) => f,
                Err(e) => return err(format!("cannot read {}: {e}", p.display())),
            };
            for (i, line) in BufReader::new(f).lines().enumerate() {
                let line = match line {
                    Ok(l) => l,
                    Err(e) => return err(format!("{}: line {}: {e}", p.display(), i + 1)),
                };
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<Alert>(&line) {
                    Ok(a) => out.push(a),
                    Err(e) => return err(format!("{}: line {}: {e}", p.display(), i + 1)),
                }
            }
        }
        Ok(out)
    }

    /// Seal `a` onto the chain, write it, rotate if the live file is now over
    /// the threshold. Returns the record's hash.
    pub fn append(&mut self, mut a: Alert) -> Result<String, StoreError> {
        a.seal(&self.last);
        let line = match serde_json::to_string(&a) {
            Ok(l) => l,
            Err(e) => return err(format!("cannot serialise alert {}: {e}", a.id)),
        };
        let mut f = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.live)
        {
            Ok(f) => f,
            Err(e) => return err(format!("cannot open {}: {e}", self.live.display())),
        };
        if let Err(e) = writeln!(f, "{line}").and_then(|()| f.sync_data()) {
            return err(format!("cannot write {}: {e}", self.live.display()));
        }
        self.last = a.hash.clone();
        let size = f.metadata().map(|m| m.len()).unwrap_or(0);
        if size >= self.rotate_at {
            self.rotate()?;
        }
        Ok(a.hash)
    }

    /// Rename the live file to the next free `alerts.<n>.jsonl`. The next
    /// record keeps chaining from `self.last`, so the chain spans the rename.
    fn rotate(&mut self) -> Result<(), StoreError> {
        let mut n = 1u32;
        while self.dir.join(format!("alerts.{n}.jsonl")).exists() {
            n += 1;
        }
        let to = self.dir.join(format!("alerts.{n}.jsonl"));
        if let Err(e) = std::fs::rename(&self.live, &to) {
            return err(format!("cannot rotate to {}: {e}", to.display()));
        }
        Ok(())
    }

    /// Walk the whole chain. Returns the number of records, or an error naming
    /// the index of the first bad one.
    pub fn verify(&self) -> Result<usize, StoreError> {
        let all = self.read_all()?;
        let mut prev = GENESIS.to_string();
        for (i, a) in all.iter().enumerate() {
            if a.prev_hash != prev {
                return err(format!(
                    "record {i} ({}) chains from {}, expected {prev}",
                    a.id, a.prev_hash
                ));
            }
            if a.hash != a.compute_hash() {
                return err(format!("record {i} ({}) hash mismatch", a.id));
            }
            prev = a.hash.clone();
        }
        Ok(all.len())
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

    fn store_alert(id: &str) -> Alert {
        let mut a = sample();
        a.id = id.to_string();
        a
    }

    #[test]
    fn append_chains_each_record_to_the_last() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open(dir.path()).unwrap();
        let h1 = s.append(store_alert("a1")).unwrap();
        let h2 = s.append(store_alert("a2")).unwrap();
        assert_ne!(h1, h2);
        let read = s.read_all().unwrap();
        assert_eq!(read.len(), 2);
        assert_eq!(read[0].prev_hash, GENESIS);
        assert_eq!(read[1].prev_hash, read[0].hash);
        assert_eq!(read[1].hash, h2);
    }

    #[test]
    fn a_fresh_store_verifies_and_reports_the_count() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open(dir.path()).unwrap();
        for i in 0..5 {
            s.append(store_alert(&format!("a{i}"))).unwrap();
        }
        assert_eq!(s.verify().unwrap(), 5);
    }

    #[test]
    fn a_tampered_record_fails_verification_at_its_index() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut s = Store::open(dir.path()).unwrap();
            for i in 0..3 {
                s.append(store_alert(&format!("a{i}"))).unwrap();
            }
        }
        // Rewrite record 1's severity, keeping its stored hash.
        let path = dir.path().join("alerts.jsonl");
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
        lines[1] = lines[1].replace(r#""severity":"high""#, r#""severity":"low""#);
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let s = Store::open(dir.path()).unwrap();
        let err = s.verify().unwrap_err();
        assert!(
            err.to_string().contains("record 1"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rotation_renames_the_live_file_and_keeps_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open(dir.path()).unwrap();
        // A tiny limit, so every record rotates.
        s.rotate_at = 1;
        let h1 = s.append(store_alert("a1")).unwrap();
        let h2 = s.append(store_alert("a2")).unwrap();
        assert!(dir.path().join("alerts.1.jsonl").exists());
        let all = s.read_all().unwrap();
        assert_eq!(all.len(), 2, "read_all must span rotated files");
        assert_eq!(all[0].hash, h1);
        assert_eq!(all[1].prev_hash, h1);
        assert_eq!(all[1].hash, h2);
        assert_eq!(s.verify().unwrap(), 2);
    }

    #[test]
    fn reopening_resumes_the_chain_from_the_last_record() {
        let dir = tempfile::tempdir().unwrap();
        let h1 = {
            let mut s = Store::open(dir.path()).unwrap();
            s.append(store_alert("a1")).unwrap()
        };
        let mut s = Store::open(dir.path()).unwrap();
        assert_eq!(s.last_hash(), h1);
        s.append(store_alert("a2")).unwrap();
        assert_eq!(s.verify().unwrap(), 2);
    }
}
