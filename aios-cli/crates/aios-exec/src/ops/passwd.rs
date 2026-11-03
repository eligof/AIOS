use crate::{run_ok, Cmd, CommandRunner, ExecError, Layout};
use std::fs::{self, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// `aios passwd <user>`: hash `password` with `mkpasswd -m yescrypt` (password on stdin)
/// and store it in `secrets/passwd/<user>` (0600, directories 0700). Takes effect at the
/// next apply. Returns the file written.
pub fn passwd(
    runner: &dyn CommandRunner,
    layout: &Layout,
    user: &str,
    password: &str,
) -> Result<PathBuf, ExecError> {
    if !valid_user_name(user) {
        return Err(ExecError(format!("invalid user name {user:?}")));
    }
    if password.is_empty() || password.contains('\n') {
        return Err(ExecError::new("the password must be one non-empty line"));
    }
    let cmd = Cmd::new("mkpasswd")
        .args(["-m", "yescrypt", "-s"])
        .stdin(format!("{password}\n"));
    let hash = run_ok(runner, &cmd)?.stdout_text();
    let hash = hash.trim_end_matches('\n');
    if !hash.starts_with("$y$") || hash.contains(':') || hash.contains('\n') {
        return Err(ExecError(format!("`{cmd}` printed an unexpected hash")));
    }
    let dir = layout.secrets.join("passwd");
    for d in [&layout.secrets, &dir] {
        private_dir(d)?;
    }
    let path = dir.join(user);
    let tmp = dir.join(format!(".{user}.tmp"));
    let io = |p: &Path, e: std::io::Error| ExecError::io(p, e);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| io(&tmp, e))?;
    file.write_all(format!("{hash}\n").as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| io(&tmp, e))?;
    fs::set_permissions(&tmp, Permissions::from_mode(0o600)).map_err(|e| io(&tmp, e))?;
    fs::rename(&tmp, &path).map_err(|e| io(&path, e))?;
    Ok(path)
}

fn private_dir(dir: &Path) -> Result<(), ExecError> {
    fs::create_dir_all(dir).map_err(|e| ExecError::io(dir, e))?;
    fs::set_permissions(dir, Permissions::from_mode(0o700)).map_err(|e| ExecError::io(dir, e))
}

/// Same rule as manifest validation: `[a-z_][a-z0-9_-]*`, at most 32 characters.
fn valid_user_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c == '_')
        && name.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}
