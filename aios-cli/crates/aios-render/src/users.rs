use std::fmt;

/// One `/etc/passwd` line. The password field is always rendered as `x`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home: String,
    pub shell: String,
}

/// One `/etc/group` line. The password field is always rendered as `x`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

/// One `/etc/shadow` line. `rest` is fields 3 to 9 verbatim
/// (`lastchg:min:max:warn:inactive:expire:reserved`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowEntry {
    pub name: String,
    pub hash: String,
    pub rest: String,
}

/// One `/etc/gshadow` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GshadowEntry {
    pub name: String,
    pub password: String,
    pub admins: Vec<String>,
    pub members: Vec<String>,
}

/// The four account databases, each in file order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserDb {
    pub passwd: Vec<PasswdEntry>,
    pub group: Vec<GroupEntry>,
    pub shadow: Vec<ShadowEntry>,
    pub gshadow: Vec<GshadowEntry>,
}

/// Rendered contents of `/etc/passwd`, `/etc/group`, `/etc/shadow` and `/etc/gshadow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserFiles {
    pub passwd: String,
    pub group: String,
    pub shadow: String,
    pub gshadow: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserDbError {
    /// Wrong field count, empty name or non-numeric id. `file` is `passwd`, `group`,
    /// `shadow` or `gshadow`; `line` is 1-based.
    Malformed { file: &'static str, line: usize },
    /// A declared user lists a group that does not exist after merging.
    MissingGroup { user: String, group: String },
    /// A declared user's name is taken by a system account or group.
    NameConflict(String),
    /// No password hash was supplied for a declared user.
    MissingHash(String),
    /// The hash is empty or contains `:` or a newline.
    InvalidHash(String),
}

impl fmt::Display for UserDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserDbError::Malformed { file, line } => {
                write!(f, "/etc/{file}:{line}: malformed entry")
            }
            UserDbError::MissingGroup { user, group } => {
                write!(f, "user {user:?}: group {group:?} does not exist")
            }
            UserDbError::NameConflict(name) => write!(
                f,
                "user {name:?}: name is already used by a system account or group"
            ),
            UserDbError::MissingHash(name) => write!(
                f,
                "user {name:?}: no password hash (run `aios passwd {name}`)"
            ),
            UserDbError::InvalidHash(name) => write!(
                f,
                "user {name:?}: password hash is empty or contains ':' or a newline"
            ),
        }
    }
}

impl std::error::Error for UserDbError {}

impl UserDb {
    /// Parse the four files. Empty lines are skipped (but still counted for line numbers).
    pub fn parse(
        passwd: &str,
        group: &str,
        shadow: &str,
        gshadow: &str,
    ) -> Result<UserDb, UserDbError> {
        Ok(UserDb {
            passwd: parse_lines(passwd, "passwd", parse_passwd)?,
            group: parse_lines(group, "group", parse_group)?,
            shadow: parse_lines(shadow, "shadow", parse_shadow)?,
            gshadow: parse_lines(gshadow, "gshadow", parse_gshadow)?,
        })
    }

    /// One line per entry, each ending in a newline.
    pub fn render(&self) -> UserFiles {
        UserFiles {
            passwd: self
                .passwd
                .iter()
                .map(|e| {
                    format!(
                        "{}:x:{}:{}:{}:{}:{}\n",
                        e.name, e.uid, e.gid, e.gecos, e.home, e.shell
                    )
                })
                .collect(),
            group: self
                .group
                .iter()
                .map(|e| format!("{}:x:{}:{}\n", e.name, e.gid, e.members.join(",")))
                .collect(),
            shadow: self
                .shadow
                .iter()
                .map(|e| format!("{}:{}:{}\n", e.name, e.hash, e.rest))
                .collect(),
            gshadow: self
                .gshadow
                .iter()
                .map(|e| {
                    format!(
                        "{}:{}:{}:{}\n",
                        e.name,
                        e.password,
                        e.admins.join(","),
                        e.members.join(",")
                    )
                })
                .collect(),
        }
    }
}

fn parse_lines<T>(
    text: &str,
    file: &'static str,
    parse: fn(&[&str]) -> Option<T>,
) -> Result<Vec<T>, UserDbError> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        let entry = parse(&fields).ok_or(UserDbError::Malformed { file, line: i + 1 })?;
        out.push(entry);
    }
    Ok(out)
}

fn parse_passwd(fields: &[&str]) -> Option<PasswdEntry> {
    let [name, _password, uid, gid, gecos, home, shell] = fields else {
        return None;
    };
    Some(PasswdEntry {
        name: non_empty(name)?,
        uid: uid.parse().ok()?,
        gid: gid.parse().ok()?,
        gecos: gecos.to_string(),
        home: home.to_string(),
        shell: shell.to_string(),
    })
}

fn parse_group(fields: &[&str]) -> Option<GroupEntry> {
    let [name, _password, gid, members] = fields else {
        return None;
    };
    Some(GroupEntry {
        name: non_empty(name)?,
        gid: gid.parse().ok()?,
        members: split_list(members),
    })
}

fn parse_shadow(fields: &[&str]) -> Option<ShadowEntry> {
    let [name, hash, rest @ ..] = fields else {
        return None;
    };
    Some(ShadowEntry {
        name: non_empty(name)?,
        hash: hash.to_string(),
        rest: rest.join(":"),
    })
}

fn parse_gshadow(fields: &[&str]) -> Option<GshadowEntry> {
    let [name, password, admins, members] = fields else {
        return None;
    };
    Some(GshadowEntry {
        name: non_empty(name)?,
        password: password.to_string(),
        admins: split_list(admins),
        members: split_list(members),
    })
}

fn non_empty(name: &str) -> Option<String> {
    (!name.is_empty()).then(|| name.to_string())
}

fn split_list(list: &str) -> Vec<String> {
    list.split(',')
        .filter(|m| !m.is_empty())
        .map(str::to_string)
        .collect()
}
