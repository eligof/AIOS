mod common;

use aios_exec::{check_trusted_dirs, Output, Step};
use common::{mkdir, Fixture, CLEANUP_MOUNTED};
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[test]
fn mounts_the_top_level_and_records_head_of_a_clean_repo() {
    let fx = Fixture::booted();
    let outcome = fx.run().unwrap();
    assert_eq!(outcome.manifest_commit, "3f9c2a1");
    assert_eq!(
        fx.calls()[..4],
        fx.expand(
            "
            mount -t btrfs -o subvolid=5 /dev/mapper/aios {top}
            mount --make-rprivate {top}
            {git} status --porcelain
            {git} rev-parse --short HEAD
            "
        )
    );
    assert!(!fx.calls().iter().any(|c| c.contains(" commit ")));
    assert_eq!(
        fx.runner.calls()[2],
        format!(
            "GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_ATTR_NOSYSTEM=1 \
             GIT_CEILING_DIRECTORIES={} git -C {} \
             --attr-source=4b825dc642cb6eb9a060e54bf8d69288fbee4904 \
             -c core.attributesFile=/dev/null -c core.hooksPath=/dev/null \
             -c core.fsmonitor=false -c commit.gpgsign=false status --porcelain",
            fx.dir.path().display(),
            fx.layout.config.display()
        )
    );
}

/// No system or global config, no system attributes, no repo found above the manifest
/// repo (env), no work tree or global attributes file (options): only the repo's
/// root-owned `.git/config` and the `-c` options can name a filter, diff or merge driver.
/// Every git call, the commit included.
#[test]
fn every_git_call_ignores_outside_config_and_work_tree_attributes() {
    let mut fx = Fixture::booted();
    fx.runner.respond(
        &common::git(&fx.layout.config, &["status"]),
        Output::ok(" M manifest.toml\n"),
    );
    fx.run().unwrap();
    let ceiling = fx.dir.path().display().to_string();
    let env: Vec<(String, String)> = [
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_ATTR_NOSYSTEM", "1"),
        ("GIT_CEILING_DIRECTORIES", ceiling.as_str()),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let gits: Vec<_> = fx
        .runner
        .commands()
        .into_iter()
        .filter(|c| c.program == "git")
        .collect();
    let subcommands: Vec<&str> = gits
        .iter()
        .map(|c| {
            c.args
                .iter()
                .find(|a| ["status", "add", "commit", "rev-parse"].contains(&a.as_str()))
                .unwrap()
                .as_str()
        })
        .collect();
    assert_eq!(subcommands, ["status", "add", "commit", "rev-parse"]);
    for git in &gits {
        assert_eq!(git.env, env, "{git}");
        assert_eq!(git.args[2..11], common::GIT_OPTIONS, "{git}");
    }
}

#[test]
fn a_dirty_repo_is_committed_for_the_new_generation() {
    let mut fx = Fixture::booted();
    fx.runner.respond(
        &common::git(&fx.layout.config, &["status"]),
        Output::ok(" M manifest.toml\n?? files/new.conf\n"),
    );
    fx.run().unwrap();
    assert_eq!(
        fx.calls()[2..6],
        fx.expand(
            "
            {git} status --porcelain
            {git} add -A
            {git} -c user.name=aios -c user.email=aios@localhost commit --no-verify -m 'aios: manifest for gen-0008'
            {git} rev-parse --short HEAD
            "
        )
    );
}

#[test]
fn the_new_id_follows_every_generation_subvolume() {
    let mut fx = Fixture::booted();
    mkdir(&fx.layout.subvol("@etc-gen-0011"));
    fx.runner.respond(
        &common::git(&fx.layout.config, &["status"]),
        Output::ok(" M manifest.toml\n"),
    );
    // The fixture's prebuilt UKIs are named for gen-0008, so this run fails later on;
    // only the commit message matters here.
    let _ = fx.run();
    assert!(fx
        .calls()
        .iter()
        .any(|c| c.ends_with("commit --no-verify -m 'aios: manifest for gen-0012'")));
}

#[test]
fn snapshots_the_booted_generation_and_blank() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    assert_eq!(
        fx.calls()[5..8],
        fx.expand(
            "
            btrfs subvolume snapshot {top}/@usr-gen-0007 {top}/@usr-cand
            btrfs subvolume snapshot {top}/@etc-gen-0007 {top}/@etc-cand
            btrfs subvolume snapshot {top}/@blank {top}/@root-cand
            "
        )
    );
}

#[test]
fn stale_candidates_are_deleted_first() {
    let fx = Fixture::booted();
    mkdir(&fx.layout.subvol("@usr-cand/var"));
    mkdir(&fx.layout.subvol("@root-cand"));
    fx.run().unwrap();
    assert_eq!(
        fx.calls()[4..10],
        fx.expand(
            "
            mountpoint -q {cand}
            btrfs subvolume show {top}/@usr-cand
            btrfs subvolume delete --recursive {top}/@usr-cand
            btrfs subvolume show {top}/@root-cand
            btrfs subvolume delete --recursive {top}/@root-cand
            btrfs subvolume snapshot {top}/@usr-gen-0007 {top}/@usr-cand
            "
        )
    );
}

#[test]
fn assembles_the_candidate_root() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    assert_eq!(
        fx.calls()[8..14],
        fx.expand(
            "
            mount --bind {top}/@root-cand {cand}
            mount --bind {top}/@usr-cand {cand}/usr
            mount --bind {top}/@etc-cand {cand}/etc
            mount --bind {persist}/var/cache/pacman/pkg {cand}/var/cache/pacman/pkg
            mount --bind {log} {cand}/var/log
            mount --bind {persist}/aios/repo {cand}/persist/aios/repo
            "
        )
    );
    let l = &fx.layout;
    for dir in [l.pkg_cache(), l.repo(), l.cand.join("persist/aios/repo")] {
        assert!(dir.is_dir(), "{} not created", dir.display());
    }
}

#[test]
fn a_failed_mount_needs_no_cleanup() {
    let mut fx = Fixture::booted();
    fx.runner.fail_on(&["mount", "-t", "btrfs"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::MountTop);
    assert_eq!(
        err.to_string(),
        format!(
            "aios: step mount-top failed: `mount -t btrfs -o subvolid=5 /dev/mapper/aios {}` \
             exited with status 1: injected failure",
            fx.layout.top.display()
        )
    );
    assert_eq!(fx.calls().len(), 1);
}

#[test]
fn a_failed_make_rprivate_unmounts_the_top_level() {
    let mut fx = Fixture::booted();
    fx.runner.fail_on(&["mount", "--make-rprivate"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::MountTop);
    assert_eq!(
        fx.calls_after("mount --make-rprivate"),
        fx.expand("umount {top}")
    );
}

#[test]
fn a_candidate_root_left_mounted_is_unmounted_before_anything_is_deleted() {
    let mut fx = Fixture::booted();
    mkdir(&fx.layout.subvol("@root-cand"));
    fx.runner.respond(&["mountpoint"], Output::ok(""));
    fx.run().unwrap();
    assert_eq!(
        fx.calls_after("{git}")[1..5],
        fx.expand(
            "
            mountpoint -q {cand}
            umount -R {cand}
            btrfs subvolume show {top}/@root-cand
            btrfs subvolume delete --recursive {top}/@root-cand
            "
        )
    );
}

#[test]
fn a_candidate_root_that_stays_mounted_keeps_the_stale_candidates() {
    let mut fx = Fixture::booted();
    mkdir(&fx.layout.subvol("@root-cand"));
    fx.runner
        .respond(&["mountpoint"], Output::ok(""))
        .fail_on(&["umount", "-R"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::PrepareCandidate);
    assert_eq!(
        fx.calls_after("mountpoint"),
        fx.expand("umount -R {cand}\numount -R {cand}\numount {top}")
    );
    assert!(fx.layout.subvol("@root-cand").is_dir());
}

#[test]
fn a_mountpoint_check_that_cannot_tell_fails() {
    let mut fx = Fixture::booted();
    fx.runner
        .respond(&["mountpoint"], Output::failed(1, "permission denied"));
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::PrepareCandidate);
    assert_eq!(
        err.detail,
        format!(
            "`mountpoint -q {}` exited with status 1: permission denied",
            fx.layout.cand.display()
        )
    );
}

#[test]
fn after_a_mountpoint_check_that_cannot_tell_cleanup_unmounts_before_deleting() {
    let mut fx = Fixture::booted();
    mkdir(&fx.layout.subvol("@root-cand"));
    fx.runner
        .respond(&["mountpoint"], Output::failed(1, "permission denied"))
        .fail_on(&["umount", "-R"]);
    fx.run().unwrap_err();
    assert_eq!(
        fx.calls_after("mountpoint"),
        fx.expand("umount -R {cand}\numount {top}")
    );
    assert!(
        fx.layout.subvol("@root-cand").is_dir(),
        "maybe still mounted"
    );
}

#[test]
fn no_candidate_root_directory_means_nothing_is_mounted_there() {
    let fx = Fixture::fresh();
    fs::remove_dir_all(&fx.layout.cand).unwrap();
    // The build stops later on (the candidate tree holds nothing), but no mountpoint
    // check ran: with no directory, nothing can be mounted there.
    let _ = fx.run();
    assert!(!fx.calls().iter().any(|c| c.starts_with("mountpoint")));
}

#[test]
fn invalid_machine_facts_fail_validation() {
    let mut fx = Fixture::booted();
    fx.facts.luks_uuid = "not-a-uuid".to_string();
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Validate);
    assert_eq!(err.detail, "invalid LUKS UUID \"not-a-uuid\"");
    assert_eq!(fx.calls()[2..], fx.expand("umount {top}"));
}

#[test]
fn a_group_writable_manifest_repo_fails_validation() {
    let fx = Fixture::booted();
    fs::set_permissions(&fx.layout.config, fs::Permissions::from_mode(0o775)).unwrap();
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Validate);
    assert_eq!(
        err.to_string(),
        format!(
            "aios: step validate failed: manifest repo {} must be root-owned and not \
             group/world-writable",
            fx.layout.config.display()
        )
    );
    assert_eq!(fx.calls()[2..], fx.expand("umount {top}"));
}

#[test]
fn trusted_dirs_need_the_right_owner_and_private_secrets() {
    let fx = Fixture::booted();
    assert!(check_trusted_dirs(&fx.layout, fx.trusted_uid).is_ok());
    let err = check_trusted_dirs(&fx.layout, fx.trusted_uid + 1).unwrap_err();
    assert!(err.to_string().starts_with("manifest repo "), "{err}");
    fs::set_permissions(&fx.layout.secrets, fs::Permissions::from_mode(0o707)).unwrap();
    let err = check_trusted_dirs(&fx.layout, fx.trusted_uid).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "secrets directory {} must be root-owned and not group/world-writable",
            fx.layout.secrets.display()
        )
    );
}

#[test]
fn a_failed_commit_unmounts_the_top_level() {
    let mut fx = Fixture::booted();
    fx.runner.fail_on(&["git"]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::CommitManifest);
    assert_eq!(fx.calls_after("{git}"), fx.expand("umount {top}"));
}

#[test]
fn a_missing_booted_generation_fails_before_any_snapshot() {
    let fx = Fixture::booted();
    std::fs::remove_dir(fx.layout.subvol("@etc-gen-0007")).unwrap();
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::PrepareCandidate);
    assert_eq!(
        err.detail,
        format!("{} is missing", fx.layout.subvol("@etc-gen-0007").display())
    );
    assert!(!fx.calls().iter().any(|c| c.contains("snapshot")));
}

#[test]
fn a_failed_snapshot_deletes_the_candidates_made_so_far() {
    let mut fx = Fixture::booted();
    let etc = fx.layout.subvol("@etc-gen-0007").display().to_string();
    fx.runner.fail_on(&["btrfs", "subvolume", "snapshot", &etc]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::PrepareCandidate);
    assert_eq!(
        fx.calls_after("btrfs subvolume snapshot {top}/@etc-gen-0007"),
        fx.expand(
            "
            btrfs subvolume show {top}/@usr-cand
            btrfs subvolume delete --recursive {top}/@usr-cand
            umount {top}
            "
        )
    );
    fx.assert_no_candidates();
}

#[test]
fn a_failed_bind_unmounts_and_deletes_everything() {
    let mut fx = Fixture::booted();
    let etc = fx.layout.cand.join("etc").display().to_string();
    let source = fx.layout.subvol("@etc-cand").display().to_string();
    fx.runner.fail_on(&["mount", "--bind", &source, &etc]);
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Assemble);
    assert_eq!(
        fx.calls_after("mount --bind {top}/@etc-cand"),
        fx.expand(CLEANUP_MOUNTED)
    );
    fx.assert_no_candidates();
}
