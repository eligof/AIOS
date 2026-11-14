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
                // A bare `String` key can only fail to serialise if its
                // `Serialize` impl errors, which (as in `compute_hash`
                // below) means a non-finite f64 or a non-string map key —
                // neither applies to a `&String`, so this cannot panic.
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
#[derive(Debug)]
pub struct Store {
    dir: PathBuf,
    live: PathBuf,
    last: String,
    /// Bytes after which the live file rotates. Public so tests can shrink it.
    pub rotate_at: u64,
    /// Set by `open` when it dropped an incomplete final record left by a
    /// crash mid-append — a torn write that was never sealed onto the chain
    /// (spec §12: a store problem degrades the store, it does not stop
    /// alerting). `None` means the live file's tail was intact.
    pub recovered_tail: Option<String>,
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
            recovered_tail: None,
        };
        s.last = s.recover_last_hash()?;
        Ok(s)
    }

    /// The hash the next record will chain from.
    pub fn last_hash(&self) -> String {
        self.last.clone()
    }

    /// Recover the chain head without reading the whole log: only the live
    /// file, or — when it is missing or has nothing usable — the newest
    /// rotated file. This bounds the cost of `open` to one file (at most
    /// `rotate_at` bytes) rather than the store's total history, which can
    /// span an unbounded number of rotated files (spec §13's RSS budget;
    /// the daemon's unit also orders `Before=sysinit.target`, so `open`'s
    /// latency matters). `read_all` and `verify` remain the operations that
    /// walk the full chain; this one deliberately does not.
    fn recover_last_hash(&mut self) -> Result<String, StoreError> {
        if self.live.exists() {
            let live = self.live.clone();
            if let Some(h) = self.recover_from_file(&live, true)? {
                return Ok(h);
            }
        }
        if let Some((_, path)) = self.rotated()?.into_iter().next_back() {
            if let Some(h) = self.recover_from_file(&path, false)? {
                return Ok(h);
            }
        }
        Ok(GENESIS.to_string())
    }

    /// Read `path` looking only for its last record's hash. A parse failure
    /// on any line other than the final one, or any parse failure at all
    /// when `tolerate_torn_tail` is false (a rotated file: it was only
    /// renamed into place after a complete, synced write, so it should
    /// never have a torn tail), is tampering or corruption — a hard error.
    ///
    /// A parse failure on the FINAL line when `tolerate_torn_tail` is true
    /// (the live file) is instead treated as a crash mid-append: that
    /// record was never completed, so nothing was ever chained from it —
    /// dropping it leaves the chain intact. The file is truncated back to
    /// the end of the last complete line and `recovered_tail` is set so a
    /// later task can surface this in `Status` and as an alert.
    fn recover_from_file(
        &mut self,
        path: &Path,
        tolerate_torn_tail: bool,
    ) -> Result<Option<String>, StoreError> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => return err(format!("cannot read {}: {e}", path.display())),
        };
        // Byte ranges of each non-empty line, found by scanning for `\n`
        // directly rather than `read_to_string` + `BufRead::lines`, so a
        // crash that tears a multi-byte UTF-8 character mid-write is still
        // just a bad final line rather than a whole-file read failure.
        let mut lines: Vec<(usize, &[u8])> = Vec::new();
        let mut start = 0usize;
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'\n' {
                let line = &bytes[start..i];
                if !line.iter().all(u8::is_ascii_whitespace) {
                    lines.push((start, line));
                }
                start = i + 1;
            }
        }
        if start < bytes.len() {
            let line = &bytes[start..];
            if !line.iter().all(u8::is_ascii_whitespace) {
                lines.push((start, line));
            }
        }

        let last_index = lines.len().saturating_sub(1);
        let mut last_hash: Option<String> = None;
        for (i, &(line_start, line)) in lines.iter().enumerate() {
            match serde_json::from_slice::<Alert>(line) {
                Ok(a) => last_hash = Some(a.hash),
                Err(e) => {
                    if tolerate_torn_tail && i == last_index {
                        let f = match OpenOptions::new().write(true).open(path) {
                            Ok(f) => f,
                            Err(e) => {
                                return err(format!(
                                    "cannot open {} to drop a torn final record: {e}",
                                    path.display()
                                ));
                            }
                        };
                        if let Err(e) = f.set_len(line_start as u64) {
                            return err(format!("cannot truncate {}: {e}", path.display()));
                        }
                        self.recovered_tail = Some(format!(
                            "{}: dropped an incomplete final record (line {}): {e}",
                            path.display(),
                            i + 1
                        ));
                        return Ok(last_hash);
                    }
                    return err(format!("{}: line {}: {e}", path.display(), i + 1));
                }
            }
        }
        Ok(last_hash)
    }

    /// Parsed `alerts.<n>.jsonl` entries in this directory, sorted by `n`
    /// ascending. Directory-iteration errors are surfaced rather than
    /// silently skipped (`flatten`-ing them would make `verify` miss a
    /// whole file and misreport a real I/O problem as a broken chain).
    fn rotated(&self) -> Result<Vec<(u32, PathBuf)>, StoreError> {
        let mut rotated: Vec<(u32, PathBuf)> = Vec::new();
        let rd = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) => return err(format!("cannot read {}: {e}", self.dir.display())),
        };
        for ent in rd {
            let ent = match ent {
                Ok(ent) => ent,
                Err(e) => {
                    return err(format!(
                        "cannot read an entry in {}: {e}",
                        self.dir.display()
                    ));
                }
            };
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
        Ok(rotated)
    }

    /// The rotated files, oldest first, then the live file.
    fn files(&self) -> Result<Vec<PathBuf>, StoreError> {
        let mut out: Vec<PathBuf> = self.rotated()?.into_iter().map(|(_, p)| p).collect();
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

    /// The chain head: the hash of the most recent record, or [`GENESIS`] for
    /// an empty store. This is what the next `append` will seal onto, so a
    /// caller mirroring records in memory can read it before appending
    /// instead of re-reading the whole log to find the predecessor.
    pub fn head(&self) -> &str {
        &self.last
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
        // Propagated rather than defaulted to 0: defaulting would make
        // `size >= rotate_at` silently and permanently false after one
        // failed `fstat`, disabling rotation forever with no error for
        // `Status` to report.
        let size = match f.metadata() {
            Ok(m) => m.len(),
            Err(e) => return err(format!("cannot stat {}: {e}", self.live.display())),
        };
        if size >= self.rotate_at {
            self.rotate()?;
        }
        Ok(a.hash)
    }

    /// Rename the live file to the next free `alerts.<n>.jsonl`, `n` one
    /// past the HIGHEST EXISTING rotated file — not the first free slot.
    /// A rotated file can be missing (an admin's cleanup, a partial
    /// restore) without that being tamper evidence; reusing the gap would
    /// make a later `verify` misreport that ordinary deletion as a broken
    /// hash chain instead of just a shorter one. The next record keeps
    /// chaining from `self.last`, so the chain spans the rename.
    fn rotate(&mut self) -> Result<(), StoreError> {
        let next = self
            .rotated()?
            .into_iter()
            .map(|(n, _)| n)
            .max()
            .unwrap_or(0)
            + 1;
        let to = self.dir.join(format!("alerts.{next}.jsonl"));
        if let Err(e) = std::fs::rename(&self.live, &to) {
            return err(format!(
                "cannot rotate {} to {}: {e}",
                self.live.display(),
                to.display()
            ));
        }
        Ok(())
    }

    /// Walk the whole chain. Returns the number of records, or an error
    /// naming the index of the first bad one.
    ///
    /// Blind spot: deleting a whole suffix of trailing records (complete
    /// records, including the very last one — not a partial line) leaves
    /// no surviving record to show a broken link, so `verify` reports the
    /// shorter chain as intact. Deleting, inserting, or reordering a
    /// record anywhere else breaks a hash or a `prev_hash` link and is
    /// caught. A hash chain alone cannot close this gap; the mitigation
    /// here is operational, not cryptographic: the journal and TTY mirror
    /// (spec §12) hold an independent copy of each alert as it is raised,
    /// and the store directory is meant to be writable only by `sentineld`
    /// itself, which keeps other writers from truncating it in the first
    /// place.
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

    // Review finding 1: `rotate` must number past the HIGHEST existing
    // rotated file, not just find the first free slot. A missing rotated
    // file (an admin's cleanup, a partial restore) is not tamper evidence;
    // reusing its number would make a later `verify` misreport that
    // ordinary deletion as a broken hash chain.
    #[test]
    fn rotate_numbers_past_the_highest_existing_even_with_a_gap() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open(dir.path()).unwrap();
        s.rotate_at = 1;
        for i in 0..5 {
            s.append(store_alert(&format!("a{i}"))).unwrap();
        }
        for n in 1..=5 {
            assert!(dir.path().join(format!("alerts.{n}.jsonl")).exists());
        }

        // Simulate an admin deleting a middle rotated file.
        std::fs::remove_file(dir.path().join("alerts.2.jsonl")).unwrap();

        s.append(store_alert("a5")).unwrap();
        assert!(
            dir.path().join("alerts.6.jsonl").exists(),
            "must number past the highest existing file (5), not reuse the gap left at 2"
        );
        assert!(!dir.path().join("alerts.2.jsonl").exists());
    }

    // Review finding 2: a crash that tears the live file's final write in
    // half must not wedge `open` — the daemon would otherwise exit, be
    // restarted by systemd, and fail to open again forever.
    #[test]
    fn a_torn_final_line_in_the_live_file_is_recovered_and_flagged() {
        let dir = tempfile::tempdir().unwrap();
        let h1 = {
            let mut s = Store::open(dir.path()).unwrap();
            let h1 = s.append(store_alert("a1")).unwrap();
            s.append(store_alert("a2")).unwrap();
            h1
        };
        // Simulate a crash mid-write: chop the last line's closing bytes.
        let path = dir.path().join("alerts.jsonl");
        let text = std::fs::read_to_string(&path).unwrap();
        let torn_len = text.trim_end_matches('\n').len() - 10;
        std::fs::write(&path, &text.as_bytes()[..torn_len]).unwrap();

        let s = Store::open(dir.path()).unwrap();
        assert!(
            s.recovered_tail.is_some(),
            "a torn final line must be flagged, not silently accepted"
        );
        assert_eq!(
            s.last_hash(),
            h1,
            "the head must fall back to the last COMPLETE record"
        );

        let repaired = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            repaired.lines().count(),
            1,
            "the torn record must actually be dropped from the file on disk"
        );
        assert_eq!(s.verify().unwrap(), 1);
    }

    // Review finding 2: tolerance is for the FINAL line only. A parse
    // failure earlier in the live file is corruption or tampering, not a
    // torn write, and must still be a hard error even though the file has
    // a valid-looking last line after it.
    #[test]
    fn a_torn_line_in_the_middle_of_the_live_file_still_hard_errors() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut s = Store::open(dir.path()).unwrap();
            for i in 0..3 {
                s.append(store_alert(&format!("a{i}"))).unwrap();
            }
        }
        let path = dir.path().join("alerts.jsonl");
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
        // Corrupt the middle line only; the third line stays intact.
        let cut = lines[1].len() - 10;
        lines[1].truncate(cut);
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let err = Store::open(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("line 2"),
            "unexpected error: {err}"
        );
    }

    // Review finding 2: a rotated file was only renamed into place after a
    // complete, synced write, so it should never have a torn tail. Even a
    // bad FINAL line there is corruption, not a crash-torn write, and must
    // still be a hard error.
    #[test]
    fn a_torn_line_in_a_rotated_file_still_hard_errors() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut s = Store::open(dir.path()).unwrap();
            s.rotate_at = 1;
            s.append(store_alert("a1")).unwrap();
        }
        assert!(dir.path().join("alerts.1.jsonl").exists());
        assert!(!dir.path().join("alerts.jsonl").exists());

        let path = dir.path().join("alerts.1.jsonl");
        let text = std::fs::read_to_string(&path).unwrap();
        let torn_len = text.trim_end_matches('\n').len() - 10;
        std::fs::write(&path, &text.as_bytes()[..torn_len]).unwrap();

        let err = Store::open(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("line 1"),
            "unexpected error: {err}"
        );
    }

    // Review finding 4: `open` must recover the head from the newest
    // ROTATED file when the live file does not exist yet — the state right
    // after a rotation and before the next append — without reading the
    // rest of the store's history.
    #[test]
    fn reopening_right_after_a_rotation_recovers_the_head_from_the_rotated_file() {
        let dir = tempfile::tempdir().unwrap();
        let h1 = {
            let mut s = Store::open(dir.path()).unwrap();
            s.rotate_at = 1;
            s.append(store_alert("a1")).unwrap()
        };
        assert!(!dir.path().join("alerts.jsonl").exists());
        assert!(dir.path().join("alerts.1.jsonl").exists());

        let mut s = Store::open(dir.path()).unwrap();
        assert_eq!(s.last_hash(), h1);
        s.append(store_alert("a2")).unwrap();
        assert_eq!(s.verify().unwrap(), 2);
    }

    // Review finding 5(a): the existing tamper test only ever reaches
    // `verify`'s hash-mismatch branch (it edits a field in place). Deleting
    // a whole middle record instead must trip the `prev_hash` chain-link
    // branch, at the index of the record that now chains from the wrong
    // predecessor.
    #[test]
    fn a_deleted_middle_record_fails_verification_on_the_chain_link() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut s = Store::open(dir.path()).unwrap();
            for i in 0..3 {
                s.append(store_alert(&format!("a{i}"))).unwrap();
            }
        }
        let path = dir.path().join("alerts.jsonl");
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
        lines.remove(1); // Delete record 1 (a1) outright, not just a field.
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let s = Store::open(dir.path()).unwrap();
        let err = s.verify().unwrap_err();
        assert!(
            err.to_string().contains("record 1"),
            "unexpected error: {err}"
        );
        assert!(
            err.to_string().contains("chains from"),
            "expected the prev_hash chain-link branch, got: {err}"
        );
    }
}
