use crate::ExecError;
use std::cell::RefCell;
use std::fmt;
use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// One command line. `stdin`, when set, is written to the child's standard input. It is
/// never part of `Display` or `Debug`, because it may hold a password.
#[derive(Clone, PartialEq, Eq)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
    /// Variables the child gets on top of the clean environment [`RealRunner`] gives
    /// every command, set in this order (a later one wins). Not part of `argv`.
    pub env: Vec<(String, String)>,
    pub stdin: Option<Vec<u8>>,
    /// The child talks to the user: it inherits all three standard streams (nothing is
    /// captured), except that `stdin` bytes, if any, still go through a pipe.
    pub interactive: bool,
}

impl Cmd {
    pub fn new(program: impl Into<String>) -> Cmd {
        Cmd {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            stdin: None,
            interactive: false,
        }
    }

    /// Set the variable `key` to `value` in the child's environment.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Cmd {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Cmd {
        self.args.push(arg.into());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Cmd
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// A path argument (AIOS paths are ASCII; others are converted lossily).
    pub fn arg_path(self, path: impl AsRef<Path>) -> Cmd {
        self.arg(path.as_ref().display().to_string())
    }

    pub fn stdin(mut self, bytes: impl Into<Vec<u8>>) -> Cmd {
        self.stdin = Some(bytes.into());
        self
    }

    /// For a tool that must prompt the user (`systemd-cryptenroll` asking for the PIN):
    /// see [`Cmd::interactive`](Cmd#structfield.interactive).
    pub fn interactive(mut self) -> Cmd {
        self.interactive = true;
        self
    }

    /// The program followed by its arguments.
    pub fn argv(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.program.as_str()).chain(self.args.iter().map(String::as_str))
    }
}

impl fmt::Display for Cmd {
    /// Shell-like: the env as `KEY=value` prefixes, then argv. Words outside
    /// `[A-Za-z0-9@%+=:,./_-]` are single-quoted. Words with a control or other
    /// unprintable character are written escaped in double quotes (`"a\nb"`), so a
    /// command can never forge a second log line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let words: Vec<String> = self
            .env
            .iter()
            .map(|(key, value)| format!("{}={}", quote(key), quote(value)))
            .chain(self.argv().map(quote))
            .collect();
        f.write_str(&words.join(" "))
    }
}

impl fmt::Debug for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Redacted(usize);
        impl fmt::Debug for Redacted {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "<{} bytes redacted>", self.0)
            }
        }
        f.debug_struct("Cmd")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("env", &self.env)
            .field("stdin", &self.stdin.as_ref().map(|b| Redacted(b.len())))
            .field("interactive", &self.interactive)
            .finish()
    }
}

/// `c` is shown escaped by `escape_debug` for a reason other than quoting.
fn unprintable(c: char) -> bool {
    !matches!(c, '\'' | '"' | '\\') && c.escape_debug().nth(1).is_some()
}

fn quote(word: &str) -> String {
    let safe = !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@%+=:,./_-".contains(&b));
    if safe {
        word.to_string()
    } else if word.chars().any(unprintable) {
        format!("{word:?}")
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// What a finished command produced.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Output {
    /// The exit status; -1 when the child was killed by a signal.
    pub status: i32,
    /// The signal that killed the child, if one did.
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Output {
    /// Exit status 0 with this standard output.
    pub fn ok(stdout: impl Into<Vec<u8>>) -> Output {
        Output {
            stdout: stdout.into(),
            ..Output::default()
        }
    }

    /// A non-zero exit status with this standard error.
    pub fn failed(status: i32, stderr: impl Into<Vec<u8>>) -> Output {
        Output {
            status,
            stderr: stderr.into(),
            ..Output::default()
        }
    }

    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// Inode number of every btrfs subvolume's root directory (`BTRFS_FIRST_FREE_OBJECTID`).
/// A plain directory on btrfs never has it.
pub const SUBVOLUME_ROOT_INO: u64 = 256;

/// Every system command aios runs goes through this trait, and so do the few file system
/// checks and effects that tests cannot get from a tempdir (a subvolume's inode number).
pub trait CommandRunner {
    /// Run `cmd` to completion. `Err` only when it could not be started: a non-zero exit is
    /// an `Ok` carrying that status.
    fn run(&self, cmd: &Cmd) -> Result<Output, ExecError>;

    /// `meta` (from `symlink_metadata`) is the root directory of a btrfs subvolume: a
    /// directory with inode [`SUBVOLUME_ROOT_INO`]. Tests can't make that inode, so
    /// [`FakeRunner::emulate_subvolumes`] counts every directory instead.
    fn is_subvolume_root(&self, meta: &fs::Metadata) -> bool;

    /// fsync the directory `dir`, so the renames and deletes made in it so far are on disk
    /// before anything that depends on them. A barrier whose order matters, so the fake
    /// records it (as the call `fsync DIR`).
    fn sync_dir(&self, dir: &Path) -> Result<(), ExecError>;
}

fn subvolume_root_inode(meta: &fs::Metadata) -> bool {
    meta.is_dir() && meta.ino() == SUBVOLUME_ROOT_INO
}

/// `File::open(dir)?.sync_all()`.
fn fsync_dir(dir: &Path) -> Result<(), ExecError> {
    fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| ExecError::io(dir, format!("fsync: {e}")))
}

/// Run `cmd` and turn a non-zero exit into an error naming the command and the last
/// lines of its output (see [`status_error`]).
pub fn run_ok(runner: &dyn CommandRunner, cmd: &Cmd) -> Result<Output, ExecError> {
    let out = runner.run(cmd)?;
    if out.status == 0 && out.signal.is_none() {
        Ok(out)
    } else {
        Err(status_error(cmd, &out))
    }
}

/// Longest line of command output an error message quotes, in characters.
const TAIL_LINE_MAX: usize = 300;

/// The error `run_ok` reports for a command that failed with `out`: how it ended, then
/// the last three non-empty lines of standard error (of standard output when standard
/// error is empty), each escaped and cut to `TAIL_LINE_MAX` characters.
pub fn status_error(cmd: &Cmd, out: &Output) -> ExecError {
    let how = match out.signal {
        Some(signal) => format!("killed by signal {signal}"),
        None => format!("exited with status {}", out.status),
    };
    let tail = Some(tail(&out.stderr))
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| tail(&out.stdout));
    if tail.is_empty() {
        ExecError(format!("`{cmd}` {how}"))
    } else {
        ExecError(format!("`{cmd}` {how}: {tail}"))
    }
}

fn tail(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let lines: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(escape_line)
        .collect();
    lines[lines.len().saturating_sub(3)..].join("; ")
}

fn escape_line(line: &str) -> String {
    let mut escaped = String::new();
    for c in line.chars() {
        if unprintable(c) {
            escaped.extend(c.escape_debug());
        } else {
            escaped.push(c);
        }
    }
    match escaped.char_indices().nth(TAIL_LINE_MAX) {
        Some((cut, _)) => format!("{}…", &escaped[..cut]),
        None => escaped,
    }
}

/// Runs commands with `std::process::Command`. The child gets a clean environment
/// (`PATH=/usr/bin`, `LC_ALL=C`, and `TERM` if set) plus the command's
/// [`env`](Cmd#structfield.env), and `/dev/null` as standard input
/// unless the command supplies bytes; stdout and stderr are captured. An
/// [`interactive`](Cmd::interactive) command instead inherits all three streams.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealRunner;

impl CommandRunner for RealRunner {
    fn run(&self, cmd: &Cmd) -> Result<Output, ExecError> {
        let fail = |e: std::io::Error| ExecError(format!("cannot run `{cmd}`: {e}"));
        let mut command = Command::new(&cmd.program);
        command
            .args(&cmd.args)
            .env_clear()
            .env("PATH", "/usr/bin")
            .env("LC_ALL", "C");
        if let Some(term) = std::env::var_os("TERM") {
            command.env("TERM", term);
        }
        command.envs(cmd.env.iter().map(|(k, v)| (k, v)));
        let stream = || {
            if cmd.interactive {
                Stdio::inherit()
            } else {
                Stdio::piped()
            }
        };
        let stdin = match (&cmd.stdin, cmd.interactive) {
            (Some(_), _) => Stdio::piped(),
            (None, true) => Stdio::inherit(),
            (None, false) => Stdio::null(),
        };
        let mut child = command
            .stdin(stdin)
            .stdout(stream())
            .stderr(stream())
            .spawn()
            .map_err(fail)?;
        let pipe = child.stdin.take();
        // Feed stdin from its own thread while this one drains stdout and stderr, so a
        // child that writes before it has read all of its input cannot deadlock us.
        let (out, fed) = std::thread::scope(|scope| {
            let feeder = pipe.zip(cmd.stdin.as_deref()).map(|(mut pipe, bytes)| {
                scope.spawn(move || match pipe.write_all(bytes) {
                    // A child that exits without reading its input is judged by its status.
                    Err(e) if e.kind() == ErrorKind::BrokenPipe => Ok(()),
                    result => result,
                })
            });
            let out = child.wait_with_output();
            let fed = feeder.map_or(Ok(()), |f| {
                f.join()
                    .unwrap_or_else(|_| Err(std::io::Error::other("stdin writer panicked")))
            });
            (out, fed)
        });
        let out = out.map_err(fail)?;
        fed.map_err(fail)?;
        Ok(Output {
            status: out.status.code().unwrap_or(-1),
            signal: out.status.signal(),
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }

    fn is_subvolume_root(&self, meta: &fs::Metadata) -> bool {
        subvolume_root_inode(meta)
    }

    fn sync_dir(&self, dir: &Path) -> Result<(), ExecError> {
        fsync_dir(dir)
    }
}

/// What [`FakeRunner::on_success`] runs, given the argv.
pub type Effect = fn(&[&str]);

/// Test double: records every command and answers from a script. Unscripted commands
/// succeed with empty output. [`CommandRunner::sync_dir`] is recorded and scripted as the
/// command `fsync DIR`; it syncs nothing.
#[derive(Debug, Default)]
pub struct FakeRunner {
    calls: RefCell<Vec<Cmd>>,
    script: Vec<(Vec<String>, Output)>,
    /// See `on_success`.
    effects: Vec<(Vec<String>, Effect)>,
    #[cfg(feature = "test-hooks")]
    call_log: Option<PathBuf>,
    emulate_subvolumes: bool,
    /// See `emulate_top_mounts`.
    top: Option<PathBuf>,
    /// Emulated top-level mounts: each mount point, now a symlink to `top`.
    top_mounts: RefCell<Vec<PathBuf>>,
}

/// `AIOS_FAKE_RUNNER` file format.
#[cfg(feature = "test-hooks")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Script {
    #[serde(default)]
    respond: Vec<Scripted>,
    #[serde(default)]
    fail_on: Vec<Vec<String>>,
    /// `emulate_top_mounts` with this top level.
    #[serde(default)]
    emulate_top: Option<PathBuf>,
    /// `emulate_subvolumes`.
    #[serde(default)]
    emulate_subvolumes: bool,
}

#[cfg(feature = "test-hooks")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Scripted {
    argv: Vec<String>,
    #[serde(default)]
    status: i32,
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    stderr: String,
}

impl FakeRunner {
    pub fn new() -> FakeRunner {
        FakeRunner::default()
    }

    /// Answer every command whose argv starts with `prefix` (whole words). The longest
    /// matching prefix wins; between equal lengths, the later entry wins.
    pub fn respond(&mut self, prefix: &[&str], output: Output) -> &mut FakeRunner {
        let prefix = prefix.iter().map(|w| w.to_string()).collect();
        self.script.push((prefix, output));
        self
    }

    /// Commands starting with `prefix` exit 1 with `injected failure` on stderr.
    pub fn fail_on(&mut self, prefix: &[&str]) -> &mut FakeRunner {
        self.respond(prefix, Output::failed(1, "injected failure"))
    }

    /// After each successful command whose argv starts with `prefix`, call `effect` with
    /// the argv: a side effect the real command has, a check of the state at that moment,
    /// or a panic.
    pub fn on_success(&mut self, prefix: &[&str], effect: Effect) -> &mut FakeRunner {
        let prefix = prefix.iter().map(|w| w.to_string()).collect();
        self.effects.push((prefix, effect));
        self
    }

    /// Treat plain directories as subvolumes: every directory counts as a subvolume root
    /// ([`CommandRunner::is_subvolume_root`]), a successful `btrfs subvolume create DST` or
    /// `snapshot SRC DST` creates the directory DST (empty; an existing DST is an error), and
    /// `delete --recursive PATH` removes PATH. Like btrfs-progs, which resolves PATH with
    /// realpath(3), the delete follows a symlink at PATH and removes its target.
    pub fn emulate_subvolumes(&mut self) -> &mut FakeRunner {
        self.emulate_subvolumes = true;
        self
    }

    /// Emulate mounting the btrfs top level elsewhere than `top` (where readers mount it):
    /// a successful `mount -t btrfs -o subvolid=5[,...] DEVICE DIR` with DIR other than
    /// `top` replaces the empty directory DIR with a symlink to `top`, so `DIR/NAME` is
    /// `top`'s entry itself, as on a mount (not a symlink to it). `umount DIR` puts the
    /// empty directory back. Mounting at `top` itself changes nothing.
    pub fn emulate_top_mounts(&mut self, top: impl Into<PathBuf>) -> &mut FakeRunner {
        self.top = Some(top.into());
        self
    }

    /// Every command run so far, in `Display` form.
    pub fn calls(&self) -> Vec<String> {
        self.calls.borrow().iter().map(Cmd::to_string).collect()
    }

    /// Every command run so far, including any stdin.
    pub fn commands(&self) -> Vec<Cmd> {
        self.calls.borrow().clone()
    }

    /// Load a script (`{"respond": [{"argv": [..], "status": 0, "stdout": "", "stderr": ""}],
    /// "fail_on": [[..]], "emulate_top": "<top>", "emulate_subvolumes": false}`, every key
    /// optional) and append each call to `<path>.calls`, one line per call
    /// (never through a symlink). Only with the `test-hooks` feature: the `aios` CLI tests
    /// drive the binary with it.
    #[cfg(feature = "test-hooks")]
    pub fn from_json_file(path: &Path) -> Result<FakeRunner, ExecError> {
        let text = fs::read_to_string(path).map_err(|e| ExecError::io(path, e))?;
        let script: Script = serde_json::from_str(&text).map_err(|e| ExecError::io(path, e))?;
        let mut fake = FakeRunner::new();
        for entry in script.respond {
            let argv: Vec<&str> = entry.argv.iter().map(String::as_str).collect();
            fake.respond(
                &argv,
                Output {
                    status: entry.status,
                    stdout: entry.stdout.into_bytes(),
                    stderr: entry.stderr.into_bytes(),
                    ..Output::default()
                },
            );
        }
        for prefix in &script.fail_on {
            let argv: Vec<&str> = prefix.iter().map(String::as_str).collect();
            fake.fail_on(&argv);
        }
        if let Some(top) = script.emulate_top {
            fake.emulate_top_mounts(top);
        }
        if script.emulate_subvolumes {
            fake.emulate_subvolumes();
        }
        let mut log = path.as_os_str().to_owned();
        log.push(".calls");
        fake.call_log = Some(PathBuf::from(log));
        Ok(fake)
    }

    fn emulate(&self, argv: &[&str]) -> Result<(), ExecError> {
        match argv {
            ["btrfs", "subvolume", "create", dst] | ["btrfs", "subvolume", "snapshot", _, dst] => {
                fs::create_dir(dst).map_err(|e| ExecError::io(Path::new(dst), e))
            }
            ["btrfs", "subvolume", "delete", "--recursive", path] if Path::new(path).exists() => {
                let real = fs::canonicalize(path).map_err(|e| ExecError::io(Path::new(path), e))?;
                fs::remove_dir_all(&real).map_err(|e| ExecError::io(&real, e))
            }
            _ => Ok(()),
        }
    }

    fn emulate_top_mount(&self, top: &Path, argv: &[&str]) -> Result<(), ExecError> {
        let io = |p: &Path, e: std::io::Error| ExecError::io(p, e);
        match argv {
            ["mount", "-t", "btrfs", "-o", options, _device, dir]
                if options.split(',').any(|o| o == "subvolid=5") && Path::new(dir) != top =>
            {
                let dir = Path::new(dir);
                fs::remove_dir(dir).map_err(|e| io(dir, e))?;
                std::os::unix::fs::symlink(top, dir).map_err(|e| io(dir, e))?;
                self.top_mounts.borrow_mut().push(dir.to_path_buf());
            }
            ["umount", dir] => {
                let mut mounts = self.top_mounts.borrow_mut();
                if let Some(at) = mounts.iter().rposition(|d| d == Path::new(dir)) {
                    let dir = mounts.remove(at);
                    fs::remove_file(&dir).map_err(|e| io(&dir, e))?;
                    fs::create_dir(&dir).map_err(|e| io(&dir, e))?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl CommandRunner for FakeRunner {
    fn run(&self, cmd: &Cmd) -> Result<Output, ExecError> {
        self.calls.borrow_mut().push(cmd.clone());
        #[cfg(feature = "test-hooks")]
        if let Some(log) = &self.call_log {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .custom_flags(crate::sys::O_NOFOLLOW)
                .open(log)
                .map_err(|e| ExecError::io(log, e))?;
            writeln!(file, "{cmd}").map_err(|e| ExecError::io(log, e))?;
        }
        let argv: Vec<&str> = cmd.argv().collect();
        let matches = |prefix: &Vec<String>| {
            prefix.len() <= argv.len() && prefix.iter().zip(&argv).all(|(p, a)| p == a)
        };
        let output = self
            .script
            .iter()
            .filter(|(prefix, _)| matches(prefix))
            .max_by_key(|(prefix, _)| prefix.len())
            .map(|(_, out)| out.clone())
            .unwrap_or_default();
        if output.status == 0 && self.emulate_subvolumes {
            self.emulate(&argv)?;
        }
        if let (0, Some(top)) = (output.status, &self.top) {
            self.emulate_top_mount(top, &argv)?;
        }
        if output.status == 0 {
            for (_, effect) in self.effects.iter().filter(|(prefix, _)| matches(prefix)) {
                effect(&argv);
            }
        }
        Ok(output)
    }

    fn is_subvolume_root(&self, meta: &fs::Metadata) -> bool {
        if self.emulate_subvolumes {
            meta.is_dir()
        } else {
            subvolume_root_inode(meta)
        }
    }

    fn sync_dir(&self, dir: &Path) -> Result<(), ExecError> {
        let out = self.run(&Cmd::new("fsync").arg_path(dir))?;
        if out.status == 0 {
            Ok(())
        } else {
            let detail = out.stderr_text();
            Err(ExecError::io(dir, format!("fsync: {}", detail.trim())))
        }
    }
}
