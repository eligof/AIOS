use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// The LUKS UUID from `rd.luks.name=<uuid>=aios`. `None` if absent, conflicting, or not a
/// canonical UUID (8-4-4-4-12 hex digits): it becomes a `/dev/disk/by-uuid/` path.
pub fn luks_uuid_from_cmdline(cmdline: &str) -> Option<String> {
    let mut found: Option<&str> = None;
    for value in cmdline
        .split_whitespace()
        .filter_map(|t| t.strip_prefix("rd.luks.name="))
    {
        if let Some((uuid, "aios")) = value.split_once('=') {
            if !is_canonical_uuid(uuid) || found.is_some_and(|prev| prev != uuid) {
                return None;
            }
            found = Some(uuid);
        }
    }
    found.map(str::to_string)
}

/// 8-4-4-4-12 hex digits (either case), as `RenderCtx` requires.
fn is_canonical_uuid(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, len)| g.len() == len && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn epoch_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Whole days since 1970-01-01 (UTC). Times before the epoch count as 0.
pub fn days_since_epoch(t: SystemTime) -> u64 {
    epoch_secs(t) / 86_400
}

/// `YYYY-MM-DDTHH:MM:SSZ`.
pub fn rfc3339_utc(t: SystemTime) -> String {
    let secs = epoch_secs(t);
    let (y, m, d) = civil_from_days(secs / 86_400);
    let rem = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

/// Lowercase hex sha256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// An efivarfs string variable: 4 attribute bytes, then UTF-16LE up to the first NUL.
/// `None` when malformed or empty.
pub fn parse_efivar_utf16(bytes: &[u8]) -> Option<String> {
    let data = bytes.get(4..)?;
    if data.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|&unit| unit != 0)
        .collect();
    let text = String::from_utf16(&units).ok()?;
    (!text.is_empty()).then_some(text)
}

/// Free bytes from `df --output=avail -B1 <dir>`: the last non-empty line.
pub fn parse_df_avail(stdout: &str) -> Option<u64> {
    stdout
        .lines()
        .map(str::trim)
        .rev()
        .find(|l| !l.is_empty())?
        .parse()
        .ok()
}

/// `NetworkManager` -> `NetworkManager.service`. Names with a type suffix are kept.
pub fn unit_file_name(name: &str) -> String {
    if name.contains('.') {
        name.to_string()
    } else {
        format!("{name}.service")
    }
}
