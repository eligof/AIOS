use crate::{GroupEntry, GshadowEntry, PasswdEntry, ShadowEntry, UserDb, UserDbError};
use aios_manifest::Manifest;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

/// uids and gids AIOS owns. Anything outside (system accounts, `nobody`) is kept as
/// packages created it.
pub const MANAGED_IDS: RangeInclusive<u32> = 1000..=59999;

/// Password field of a locked account.
const LOCKED: &str = "!*";

/// Merge the manifest's users into the account files of a generation (spec §4.3 step 6).
///
/// - Entries with an unmanaged id are kept in file order; managed ones are dropped.
/// - Declared users and their primary groups (gid = uid) are appended in name order.
/// - Supplementary memberships of dropped and declared users are rebuilt from the manifest.
/// - root is locked (`!*`).
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
    for name in m.users.keys() {
        let hash = hashes
            .get(name)
            .ok_or_else(|| UserDbError::MissingHash(name.clone()))?;
        if hash.is_empty() || hash.contains(':') || hash.contains('\n') {
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
                admins: old.map(|o| o.admins.clone()).unwrap_or_default(),
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
