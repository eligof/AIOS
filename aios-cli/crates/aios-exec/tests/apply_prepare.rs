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
        fx.calls()[..3],
        fx.expand(
            "
            mount -t btrfs -o subvolid=5 /dev/mapper/aios {top}
            git -C {config} status --porcelain
            git -C {config} rev-parse --short HEAD
            "
        )
    );
    assert!(!fx.calls().iter().any(|c| c.contains(" commit ")));
}

#[test]
fn a_dirty_repo_is_committed_for_the_new_generation() {
    let mut fx = Fixture::booted();
    fx.runner.respond(
        &[
            "git",
            "-C",
            &fx.layout.config.display().to_string(),
            "status",
        ],
        Output::ok(" M manifest.toml\n?? files/new.conf\n"),
    );
    fx.run().unwrap();
    assert_eq!(
        fx.calls()[1..5],
        fx.expand(
            "
            git -C {config} status --porcelain
            git -C {config} add -A
            git -C {config} -c user.name=aios -c user.email=aios@localhost commit -m 'aios: manifest for gen-0008'
            git -C {config} rev-parse --short HEAD
            "
        )
    );
}

#[test]
fn the_new_id_follows_every_generation_subvolume() {
    let mut fx = Fixture::booted();
    mkdir(&fx.layout.subvol("@etc-gen-0011"));
    fx.runner.respond(
        &[
            "git",
            "-C",
            &fx.layout.config.display().to_string(),
            "status",
        ],
        Output::ok(" M manifest.toml\n"),
    );
    // The fixture's prebuilt UKIs are named for gen-0008, so this run fails later on;
    // only the commit message matters here.
    let _ = fx.run();
    assert!(fx
        .calls()
        .iter()
        .any(|c| c.ends_with("commit -m 'aios: manifest for gen-0012'")));
}

#[test]
fn snapshots_the_booted_generation_and_blank() {
    let fx = Fixture::booted();
    fx.run().unwrap();
    assert_eq!(
        fx.calls()[3..6],
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
        fx.calls()[3..8],
        fx.expand(
            "
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
        fx.calls()[6..12],
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
fn invalid_machine_facts_fail_validation() {
    let mut fx = Fixture::booted();
    fx.facts.luks_uuid = "not-a-uuid".to_string();
    let err = fx.run().unwrap_err();
    assert_eq!(err.step, Step::Validate);
    assert_eq!(err.detail, "invalid LUKS UUID \"not-a-uuid\"");
    assert_eq!(fx.calls()[1..], fx.expand("umount {top}"));
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
    assert_eq!(fx.calls()[1..], fx.expand("umount {top}"));
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
    assert_eq!(fx.calls_after("git"), fx.expand("umount {top}"));
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
