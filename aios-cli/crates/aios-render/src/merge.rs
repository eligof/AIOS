use crate::{GroupEntry, GshadowEntry, PasswdEntry, ShadowEntry, UserDb, UserDbError};
use aios_manifest::Manifest;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

/// uids and gids AIOS owns. Anything outside (system accounts, `nobody`) is kept as
/// packages created it.
pub const MANAGED_IDS: RangeInclusive<u32> = 1000..=59999;

/// Password field of a locked account.
const LOCKED: &str = "!*";

/// Shadow fields 3 to 9, all empty.
const NO_AGING: &str = "::::::";

/// Merge the manifest's users into the account files of a generation (spec §4.3 step 6).
///
/// - Entries with an unmanaged id are kept in file order; managed ones are dropped.
/// - Declared users and their primary groups (gid = uid) are appended in name order.
/// - Supplementary memberships of dropped and declared users are rebuilt from the manifest.
/// - root is locked (`!*`), and gets a shadow entry if it has none.
/// - Supplementary memberships and gshadow admins of dropped and declared users are rebuilt.
///
/// Fails closed on a declared uid outside [`MANAGED_IDS`] or used twice, a shell that isn't an
/// absolute path without `:`, whitespace or control characters, an invalid hash, a database
/// without root, a root whose uid isn't 0, or another kept account with uid 0.
///
/// `hashes` maps each declared user to the hash from `secrets/passwd/<user>`, trailing newline
/// already trimmed. `today_days` (days since the epoch) becomes `lastchg` only when a hash
/// changes, so planning on a later day renders identical files.
pub fn merge_users(
    m: &Manifest,
    db: &UserDb,
    hashes: &BTreeMap<String, String>,
    today_days: u64,
) -> Result<UserDb, UserDbError> {
    let mut uids = BTreeSet::new();
    for (name, user) in &m.users {
        if !MANAGED_IDS.contains(&user.uid) {
            return Err(UserDbError::InvalidUid {
                user: name.clone(),
                uid: user.uid,
            });
        }
        if !uids.insert(user.uid) {
            return Err(UserDbError::DuplicateUid(user.uid));
        }
        if !valid_shell(&user.shell) {
            return Err(UserDbError::InvalidShell(name.clone()));
        }
    }
    let declared: BTreeSet<&str> = m.users.keys().map(String::as_str).collect();

    let mut removed: BTreeSet<&str> = BTreeSet::new();
    let mut kept: BTreeSet<&str> = BTreeSet::new();
    let mut passwd = Vec::new();
    for entry in &db.passwd {
        if MANAGED_IDS.contains(&entry.uid) {
            removed.insert(&entry.name);
        } else if declared.contains(entry.name.as_str()) {
            return Err(UserDbError::NameConflict(entry.name.clone()));
        } else {
            kept.insert(&entry.name);
            passwd.push(entry.clone());
        }
    }
    if !kept.contains("root") {
        return Err(UserDbError::MissingRoot);
    }
    for entry in &passwd {
        match (entry.name == "root", entry.uid == 0) {
            (true, false) => return Err(UserDbError::RootNotUidZero),
            (false, true) => return Err(UserDbError::ExtraUidZero(entry.name.clone())),
            _ => {}
        }
    }
    for (name, user) in &m.users {
        passwd.push(PasswdEntry {
            name: name.clone(),
            uid: user.uid,
            gid: user.uid,
            gecos: String::new(),
            home: format!("/home/{name}"),
            shell: user.shell.clone(),
        });
    }

    let mut group = Vec::new();
    for entry in &db.group {
        if MANAGED_IDS.contains(&entry.gid) {
            continue;
        }
        if declared.contains(entry.name.as_str()) {
            return Err(UserDbError::NameConflict(entry.name.clone()));
        }
        group.push(entry.clone());
    }
    for (name, user) in &m.users {
        group.push(GroupEntry {
            name: name.clone(),
            gid: user.uid,
            members: Vec::new(),
        });
    }
    for entry in &mut group {
        entry.members.retain(|member| {
            !removed.contains(member.as_str()) && !declared.contains(member.as_str())
        });
    }
    for (name, user) in &m.users {
        for wanted in &user.groups {
            let entry = group
                .iter_mut()
                .find(|g| g.name == *wanted)
                .ok_or_else(|| UserDbError::MissingGroup {
                    user: name.clone(),
                    group: wanted.clone(),
                })?;
            if !entry.members.contains(name) {
                entry.members.push(name.clone());
            }
        }
    }

    let mut shadow = Vec::new();
    for entry in &db.shadow {
        if !kept.contains(entry.name.as_str()) {
            continue;
        }
        let mut entry = entry.clone();
        if entry.name == "root" {
            entry.hash = LOCKED.to_string();
        }
        shadow.push(entry);
    }
    if !shadow.iter().any(|s| s.name == "root") {
        shadow.insert(
            0,
            ShadowEntry {
                name: "root".to_string(),
                hash: LOCKED.to_string(),
                rest: NO_AGING.to_string(),
            },
        );
    }
    for name in m.users.keys() {
        let hash = hashes
            .get(name)
            .ok_or_else(|| UserDbError::MissingHash(name.clone()))?;
        if !valid_hash(hash) {
            return Err(UserDbError::InvalidHash(name.clone()));
        }
        let rest = match db.shadow.iter().find(|s| s.name == *name) {
            Some(old) if old.hash == *hash => old.rest.clone(),
            _ => format!("{today_days}:0:99999:7:::"),
        };
        shadow.push(ShadowEntry {
            name: name.clone(),
            hash: hash.clone(),
            rest,
        });
    }

    let gshadow = group
        .iter()
        .map(|g| {
            let old = db.gshadow.iter().find(|s| s.name == g.name);
            GshadowEntry {
                name: g.name.clone(),
                password: old.map_or_else(|| LOCKED.to_string(), |o| o.password.clone()),
                admins: old
                    .map(|o| {
                        o.admins
                            .iter()
                            .filter(|a| {
                                !removed.contains(a.as_str()) && !declared.contains(a.as_str())
                            })
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default(),
                members: g.members.clone(),
            }
        })
        .collect();

    Ok(UserDb {
        passwd,
        group,
        shadow,
        gshadow,
    })
}

/// Absolute, and no `:`, whitespace or control characters that would break `/etc/passwd`.
fn valid_shell(shell: &str) -> bool {
    shell.starts_with('/')
        && !shell
            .chars()
            .any(|c| c == ':' || c.is_whitespace() || c.is_control())
}

/// Non-empty, no surrounding whitespace, no `:` and no control characters.
fn valid_hash(hash: &str) -> bool {
    !hash.is_empty() && hash.trim() == hash && !hash.chars().any(|c| c == ':' || c.is_control())
}
