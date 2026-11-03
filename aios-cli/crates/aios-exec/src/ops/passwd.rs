use crate::sys::O_NOFOLLOW;
use crate::trust::check_dir;
use crate::{run_ok, Cmd, CommandRunner, ExecError, Layout};
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// `aios passwd <user>`: hash `password` with `mkpasswd -m yescrypt` (password on stdin)
/// and store it in `secrets/passwd/<user>` (0600). Both directories must be real
/// directories owned by `trusted_uid` (0 in production) and are made 0700; the hash goes
/// to a fresh temp file (never through a symlink) renamed into place. Takes effect at the
/// next apply. Returns the file written.
pub fn passwd(
    runner: &dyn CommandRunner,
    layout: &Layout,
    user: &str,
    password: &str,
    trusted_uid: u32,
) -> Result<PathBuf, ExecError> {
    if !valid_user_name(user) {
        return Err(ExecError(format!("invalid user name {user:?}")));
    }
    if password.is_empty() || password.contains(['\n', '\r', '\0']) {
        return Err(ExecError::new(
            "the password must be one non-empty line without NUL bytes",
        ));
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
        private_dir(d, trusted_uid)?;
    }
    let path = dir.join(user);
    let tmp = dir.join(format!(".{user}.tmp"));
    // Left over from an interrupted run.
    match fs::remove_file(&tmp) {
        Err(e) if e.kind() != ErrorKind::NotFound => return Err(ExecError::io(&tmp, e)),
        _ => {}
    }
    let written = write_new(&tmp, &format!("{hash}\n"))
        .and_then(|()| fs::rename(&tmp, &path).map_err(|e| ExecError::io(&path, e)));
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    // Make the rename itself durable.
    File::open(&dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| ExecError::io(&dir, e))?;
    Ok(path)
}

/// Create `dir` (0700) if it is missing, check it (`check_dir`), then make it 0700.
fn private_dir(dir: &Path, uid: u32) -> Result<(), ExecError> {
    match DirBuilder::new().recursive(true).mode(0o700).create(dir) {
        // `recursive` follows a symlink at `dir`; `check_dir` refuses it.
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(ExecError::io(dir, e)),
    }
    check_dir(dir, "secrets directory", uid)?;
    fs::set_permissions(dir, Permissions::from_mode(0o700)).map_err(|e| ExecError::io(dir, e))
}

/// Write `content` to a new file at `path` (0600, synced). Fails if anything, even a
/// symlink, is already there.
fn write_new(path: &Path, content: &str) -> Result<(), ExecError> {
    let io = |e: std::io::Error| ExecError::io(path, e);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(io)?;
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(io)?;
    file.write_all(content.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(io)
}

/// Same rule as manifest validation: `[a-z_][a-z0-9_-]*`, at most 32 characters.
fn valid_user_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c == '_')
        && name.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}
