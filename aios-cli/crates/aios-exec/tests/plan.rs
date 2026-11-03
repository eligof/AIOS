mod common;

use aios_exec::ops::plan;
use aios_exec::{etcfs, read_hashes, DirProbe, FakeRunner, Output};
use aios_plan::{desired_etc, Inputs};
use common::{facts, now, write, Fixture, BOOTED, MANIFEST};

/// Make `@etc-gen-0007` exactly what this manifest renders for gen-7, and the running
/// system's packages and units match it.
fn synced() -> Fixture {
    let mut fx = Fixture::booted();
    let snapshot = fx.layout.subvol("@etc-gen-0007");
    write(
        &snapshot.join("passwd"),
        "root:x:0:0::/root:/usr/bin/bash\n",
        0o644,
    );
    write(
        &snapshot.join("group"),
        "root:x:0:root\nwheel:x:998:\n",
        0o644,
    );
    let ctx = facts().render_ctx(BOOTED).unwrap();
    let hashes = read_hashes(&fx.layout, &fx.manifest).unwrap();
    let inputs = Inputs {
        manifest: &fx.manifest,
        repo_root: &fx.layout.config,
        ctx: &ctx,
        hashes: &hashes,
        today_days: aios_exec::days_since_epoch(now()),
    };
    let quiet = FakeRunner::new();
    let probe = DirProbe::new(&snapshot, &quiet, None);
    for (path, entry) in desired_etc(&inputs, &probe).unwrap() {
        etcfs::write(&snapshot, &path, &entry).unwrap();
    }
    let packages = fx.manifest.package_set().join("\n");
    fx.runner
        .respond(&["pacman", "-Qqe"], Output::ok(packages))
        .respond(&["systemctl", "is-enabled"], Output::ok("enabled\n"))
        .respond(
            &["systemctl", "is-enabled", "--", "bluetooth.service"],
            Output {
                status: 1,
                stdout: b"disabled\n".to_vec(),
                stderr: Vec::new(),
                signal: None,
            },
        )
        .respond(
            &["systemctl", "is-enabled", "--", "sshd.socket"],
            Output {
                status: 1,
                stdout: b"masked\n".to_vec(),
                stderr: Vec::new(),
                signal: None,
            },
        );
    fx
}

fn run_plan(fx: &Fixture) -> Result<aios_plan::Plan, aios_exec::ExecError> {
    plan(&fx.runner, &fx.layout, &fx.manifest, &fx.facts, now())
}

#[test]
fn a_generation_built_from_this_manifest_has_no_changes() {
    let fx = synced();
    let p = run_plan(&fx).unwrap();
    assert!(p.is_empty(), "unexpected plan:\n{p}");
    assert_eq!(p.to_string(), "no changes\n");
}

#[test]
fn plan_mounts_read_only_and_asks_the_running_system() {
    let fx = synced();
    run_plan(&fx).unwrap();
    assert_eq!(
        fx.calls(),
        fx.expand(
            "
            mount -t btrfs -o subvolid=5,ro /dev/mapper/aios {top}
            pacman -Qqe
            systemctl is-enabled -- NetworkManager.service
            systemctl is-enabled -- bluetooth.service
            systemctl is-enabled -- fwupd-refresh.timer
            systemctl is-enabled -- sshd.socket
            umount {top}
            "
        )
    );
}

#[test]
fn a_new_package_shows_up() {
    let mut fx = synced();
    fx.set_manifest(&MANIFEST.replace("\"zsh\", \"git\"", "\"zsh\", \"git\", \"tree\""));
    let p = run_plan(&fx).unwrap();
    assert_eq!(p.packages_add, ["tree"]);
    assert!(p.etc_changes.is_empty());
    assert!(p.to_string().starts_with("packages:\n  + tree\n"));
}

#[test]
fn plan_needs_the_booted_generation() {
    let fx = synced();
    write(&fx.layout.proc_cmdline, "quiet\n", 0o644);
    let err = run_plan(&fx).unwrap_err();
    assert_eq!(
        err.to_string(),
        "cannot tell the booted generation: no single aios.gen= on the kernel cmdline"
    );
    assert!(fx.calls().is_empty());
}

#[test]
fn a_missing_snapshot_still_unmounts() {
    let fx = synced();
    std::fs::remove_dir_all(fx.layout.subvol("@etc-gen-0007")).unwrap();
    let err = run_plan(&fx).unwrap_err();
    assert!(
        err.to_string().ends_with("@etc-gen-0007 is missing"),
        "{err}"
    );
    assert_eq!(fx.calls().last().unwrap(), "umount {top}");
}
