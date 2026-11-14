//! The raw TOML model. Enum-ish fields stay strings; `validate` (Task 6)
//! resolves and checks them.

use serde::Deserialize;

/// The whole rule file: a list of `[[rule]]` tables.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

/// One rule as written in TOML.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub desc: String,
    pub on: String,
    pub severity: String,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default, rename = "match")]
    pub match_: Match,
    #[serde(default)]
    pub except: Match,
    #[serde(default)]
    pub window: Option<Window>,
    /// Source file name, filled by `load_dir`; not from TOML.
    #[serde(skip)]
    pub source: String,
}

/// Every predicate, all optional. `deny_unknown_fields` rejects typos.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    // kernel-evaluable flags (§5.2)
    pub exe_memfd: Option<bool>,
    pub exe_deleted: Option<bool>,
    pub exe_outside_usr: Option<bool>,
    pub stdio_socket: Option<bool>,
    pub env_ld: Option<bool>,
    pub exe_on: Option<OneOrMany<String>>,
    pub uid: Option<OneOrMany<UidItem>>,
    pub dest: Option<OneOrMany<String>>,
    pub port: Option<OneOrMany<PortSpec>>,
    pub listen_scope: Option<String>,
    pub device: Option<OneOrMany<String>>,
    pub ptrace_target: Option<String>,
    pub any: Option<bool>,
    // user-space only (§5.2) and the managed-home amendment (Task 14)
    pub managed_home: Option<bool>,
    pub exe: Option<OneOrMany<String>>,
    pub argv: Option<OneOrMany<String>>,
    pub parent: Option<OneOrMany<String>>,
    pub ancestors: Option<OneOrMany<String>>,
    pub unit: Option<OneOrMany<String>>,
    pub path: Option<OneOrMany<String>>,
}

/// Optional sliding-window qualifier (§5.1). Having one makes a rule user-space.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub count: u32,
    pub within: String,
    pub by: String,
}

/// A scalar or a list of `T`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T: Clone> OneOrMany<T> {
    pub fn to_vec(&self) -> Vec<T> {
        match self {
            OneOrMany::One(x) => vec![x.clone()],
            OneOrMany::Many(v) => v.clone(),
        }
    }
}

/// A `uid` list item: a keyword (`"user"`/`"system"`) or a numeric uid.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum UidItem {
    Num(i64),
    Kw(String),
}

/// A `port` list item: a number or a `"start-end"` range.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    Num(i64),
    Range(String),
}

/// Parse rule-file text. Unknown keys and type errors fail here.
pub fn parse(raw: &str) -> Result<RuleFile, String> {
    toml::from_str(raw).map_err(|e| e.message().to_string())
}
