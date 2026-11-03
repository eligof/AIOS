use aios_manifest::Manifest;

/// One read-only bind mount of a manifest-managed path into a home directory (spec §4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeBind {
    pub user: String,
    pub uid: u32,
    /// Mount point: `/home/<user>/<rel>`, no trailing slash.
    pub target: String,
    /// The generation's copy of the source: `/etc/aios/home/<user>/<rel>`, no trailing slash.
    pub bind_source: String,
    /// Source relative to the manifest repo, trailing slash trimmed.
    pub repo_source: String,
    /// The manifest key ends with `/`.
    pub is_dir: bool,
}

/// Every `[users.<u>.home]` entry, ordered by user name, then by key.
pub fn home_binds(m: &Manifest) -> Vec<HomeBind> {
    m.users
        .iter()
        .flat_map(|(user, u)| {
            u.home.iter().map(move |(key, source)| {
                let rel = key.trim_end_matches('/');
                HomeBind {
                    user: user.clone(),
                    uid: u.uid,
                    target: format!("/home/{user}/{rel}"),
                    bind_source: format!("/etc/aios/home/{user}/{rel}"),
                    repo_source: source.trim_end_matches('/').to_string(),
                    is_dir: key.ends_with('/'),
                }
            })
        })
        .collect()
}
