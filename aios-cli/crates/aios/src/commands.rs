use crate::cli::{Command, EnrollCommand, GenCommand};
use crate::context::Context;
use crate::failure::Failure;
use aios_exec::{apply, ops, ApplyCtx, Mode};
use aios_gen::GenId;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub fn run(command: Command) -> Result<(), Failure> {
    let cx = Context::new()?;
    cx.require_root()?;
    if command.needs_private_mounts() {
        cx.private_mounts()?;
    }
    match command {
        Command::Plan => plan(&cx),
        Command::Apply { yes, upgrade } => apply_cmd(&cx, yes, upgrade),
        Command::Status => status(&cx),
        Command::Gen {
            command: GenCommand::List,
        } => gen_list(&cx),
        Command::Rollback { gen, force } => rollback(&cx, gen, force),
        Command::Gc { keep } => gc(&cx, keep),
        Command::Passwd { user } => passwd(&cx, &user),
        Command::Secureboot {
            command: EnrollCommand::Enroll,
        } => {
            let _lock = cx.lock(true)?;
            println!("{}", ops::secureboot_enroll(cx.runner())?);
            Ok(())
        }
        Command::Tpm {
            command: EnrollCommand::Enroll,
        } => {
            let _lock = cx.lock(true)?;
            println!("{}", ops::tpm_enroll(cx.runner(), &cx.layout)?);
            Ok(())
        }
        Command::Bootstrap {
            target,
            esp,
            manifest,
            luks_uuid,
        } => bootstrap(cx, &target, esp, &manifest, luks_uuid),
    }
}

fn plan(cx: &Context) -> Result<(), Failure> {
    let _lock = cx.lock(false)?;
    let manifest = cx.load_manifest()?;
    let facts = cx.facts(None)?;
    let plan = ops::plan(
        cx.runner(),
        &cx.layout,
        &manifest,
        &facts,
        SystemTime::now(),
    )?;
    print!("{plan}");
    Ok(())
}

/// Show the plan, confirm and build. "no changes" ends here unless `upgrade`: then the
/// same manifest is built again, which upgrades every package (`pacman -Syu`).
fn apply_cmd(cx: &Context, yes: bool, upgrade: bool) -> Result<(), Failure> {
    let _lock = cx.lock(true)?;
    let manifest = cx.load_manifest()?;
    let facts = cx.facts(None)?;
    let booted = cx.booted()?;
    let plan = ops::plan(
        cx.runner(),
        &cx.layout,
        &manifest,
        &facts,
        SystemTime::now(),
    )?;
    print!("{plan}");
    if plan.is_empty() {
        if !upgrade {
            return Ok(());
        }
        println!("upgrading: no manifest changes");
    }
    if !yes && !confirm()? {
        return Err(Failure::op("aios: aborted"));
    }
    let outcome = apply(&ApplyCtx {
        runner: cx.runner(),
        layout: &cx.layout,
        manifest: &manifest,
        facts: &facts,
        now: SystemTime::now(),
        mode: Mode::Apply { booted },
        trusted_uid: cx.trusted_uid(),
    })?;
    note(&outcome.notices);
    warn(&outcome.warnings);
    if outcome.warnings.is_empty() {
        println!("reboot to activate gen-{}", outcome.gen);
    } else {
        println!(
            "gen-{} is installed; check the warnings above, then reboot to activate it",
            outcome.gen
        );
    }
    Ok(())
}

/// Notices of a build (spec §4.3 step 5): information, not problems.
fn note(notices: &[String]) {
    for notice in notices {
        eprintln!("aios: note: {notice}");
    }
}

/// Warnings of a build that succeeded (spec §4.3 step 5, §7).
fn warn(warnings: &[String]) {
    for warning in warnings {
        eprintln!("aios: warning: {warning}");
    }
}

/// `Proceed? [y/N]` on stdout; anything but y/yes declines.
fn confirm() -> Result<bool, Failure> {
    print!("Proceed? [y/N] ");
    io::stdout().flush().ok();
    let mut answer = String::new();
    io::stdin()
        .lock()
        .read_line(&mut answer)
        .map_err(|e| Failure::op(format!("aios: reading the answer: {e}")))?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn status(cx: &Context) -> Result<(), Failure> {
    let _lock = cx.lock(false)?;
    print!("{}", ops::status(cx.runner(), &cx.layout)?);
    Ok(())
}

fn gen_list(cx: &Context) -> Result<(), Failure> {
    let _lock = cx.lock(false)?;
    let rows = ops::gen_list(cx.runner(), &cx.layout)?;
    print!("{}", ops::render_gen_list(&rows));
    Ok(())
}

fn rollback(cx: &Context, gen: u32, force: bool) -> Result<(), Failure> {
    let _lock = cx.lock(true)?;
    let gen = GenId::new(gen).ok_or_else(|| Failure::op("aios: generation out of range"))?;
    let entry = ops::rollback(cx.runner(), &cx.layout, gen, force)?;
    println!("gen-{gen} boots next ({entry}); reboot to activate it");
    Ok(())
}

fn gc(cx: &Context, keep: usize) -> Result<(), Failure> {
    let _lock = cx.lock(true)?;
    let deleted = ops::gc(cx.runner(), &cx.layout, keep)?;
    if deleted.is_empty() {
        println!("nothing to delete");
    } else {
        let names: Vec<String> = deleted.iter().map(|g| format!("gen-{g}")).collect();
        println!("deleted {}", names.join(" "));
    }
    Ok(())
}

fn passwd(cx: &Context, user: &str) -> Result<(), Failure> {
    let _lock = cx.lock(true)?;
    let password = read_password(cx, user)?;
    let path = ops::passwd(cx.runner(), &cx.layout, user, &password, cx.trusted_uid())?;
    println!("wrote {}; run `aios apply` to use it", path.display());
    Ok(())
}

/// Prompt twice on the terminal. Under `AIOS_FAKE_RUNNER`, `AIOS_TEST_PASSWORD` instead.
fn read_password(cx: &Context, user: &str) -> Result<String, Failure> {
    if let Some(password) = cx.test_password() {
        return password;
    }
    let prompt = |text: String| {
        rpassword::prompt_password(text)
            .map_err(|e| Failure::op(format!("aios: reading the password: {e}")))
    };
    let first = prompt(format!("New password for {user}: "))?;
    let second = prompt("Retype the password: ".to_string())?;
    if first != second {
        return Err(Failure::op("aios: the passwords do not match"));
    }
    Ok(first)
}

/// Installer only: everything lives below the target's subvolumes. `manifest` is loaded
/// as given; its directory is the manifest repo.
fn bootstrap(
    mut cx: Context,
    target: &Path,
    esp: PathBuf,
    manifest: &Path,
    luks_uuid: String,
) -> Result<(), Failure> {
    let config = manifest
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .ok_or_else(|| {
            Failure::op(
                "aios: --manifest must be a path to a file in the manifest repo, such as \
                 <target>/@persist/aios/config/manifest.toml",
            )
        })?;
    let l = &mut cx.layout;
    l.top = target.to_path_buf();
    l.esp = esp;
    l.config = config.to_path_buf();
    l.persist = target.join("@persist");
    l.secrets = l.persist.join("aios/secrets");
    l.home = target.join("@home");
    l.log = target.join("@log");
    let _lock = cx.lock(true)?;
    let manifest = cx.load_manifest_at(manifest)?;
    let facts = cx.facts(Some(luks_uuid))?;
    let outcome = apply(&ApplyCtx {
        runner: cx.runner(),
        layout: &cx.layout,
        manifest: &manifest,
        facts: &facts,
        now: SystemTime::now(),
        mode: Mode::Bootstrap,
        trusted_uid: cx.trusted_uid(),
    })?;
    note(&outcome.notices);
    warn(&outcome.warnings);
    println!("gen-{} built in {}", outcome.gen, target.display());
    Ok(())
}
