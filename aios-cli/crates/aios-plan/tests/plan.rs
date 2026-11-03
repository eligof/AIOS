mod common;

use aios_plan::{
    build_plan, ChangeKind, EtcChange, Plan, PlanError, ProbeError, UnitChange, UnitState,
};
use common::{fixture, fixture_with, text_file, FakeProbe, MANIFEST};
use std::collections::BTreeMap;

fn change(path: &str, kind: ChangeKind) -> EtcChange {
    EtcChange {
        path: path.to_string(),
        kind,
    }
}

fn unit(name: &str, from: UnitState, to: UnitState) -> UnitChange {
    UnitChange {
        unit: name.to_string(),
        from,
        to,
    }
}

#[test]
fn probe_with_only_root_adds_everything_else() {
    let fx = fixture_with(&MANIFEST.replace("groups = [\"wheel\"]", "groups = []"));
    let plan = build_plan(&fx.inputs(), &FakeProbe::root_only()).unwrap();
    assert_eq!(plan.packages_add, fx.manifest.package_set());
    assert!(plan.packages_remove.is_empty());
    assert_eq!(plan.etc_changes.len(), 19);
    for c in &plan.etc_changes {
        let want = if c.path == "/etc/passwd" {
            ChangeKind::Modify
        } else {
            ChangeKind::Add
        };
        assert_eq!(c.kind, want, "{}", c.path);
    }
    assert!(plan.etc_changes.windows(2).all(|w| w[0].path < w[1].path));
    assert_eq!(
        plan.unit_changes,
        [
            unit(
                "NetworkManager.service",
                UnitState::NotFound,
                UnitState::Enabled
            ),
            unit(
                "fwupd-refresh.timer",
                UnitState::NotFound,
                UnitState::Enabled
            ),
            unit("sshd.socket", UnitState::NotFound, UnitState::Masked),
        ]
    );
}

#[test]
fn synced_probe_has_no_changes() {
    let fx = fixture();
    let plan = build_plan(&fx.inputs(), &FakeProbe::synced(&fx)).unwrap();
    assert!(plan.is_empty(), "unexpected plan:\n{plan}");
    assert_eq!(plan.to_string(), "no changes\n");
}

#[test]
fn synced_probe_stays_clean_on_a_later_day() {
    let fx = fixture();
    let probe = FakeProbe::synced(&fx);
    let mut inputs = fx.inputs();
    inputs.today_days += 30;
    assert!(build_plan(&inputs, &probe).unwrap().is_empty());
}

#[test]
fn content_change_is_modify() {
    let fx = fixture();
    let mut probe = FakeProbe::synced(&fx);
    probe.etc.insert(
        "/etc/nftables.conf".to_string(),
        text_file("old ruleset\n", 0o600),
    );
    let plan = build_plan(&fx.inputs(), &probe).unwrap();
    assert_eq!(
        plan.etc_changes,
        [change("/etc/nftables.conf", ChangeKind::Modify)]
    );
}

#[test]
fn mode_change_is_modify() {
    let fx = fixture();
    let mut probe = FakeProbe::synced(&fx);
    probe.etc.insert(
        "/etc/nftables.conf".to_string(),
        text_file("flush ruleset\n", 0o644),
    );
    let plan = build_plan(&fx.inputs(), &probe).unwrap();
    assert_eq!(
        plan.etc_changes,
        [change("/etc/nftables.conf", ChangeKind::Modify)]
    );
}

#[test]
fn dropped_file_is_removed_via_managed_files() {
    let probe = FakeProbe::synced(&fixture());
    let fx = fixture_with(&MANIFEST.replace(
        "\"/etc/pacman.d/hooks/90-mkinitcpio-install.hook\" = { symlink = \"/dev/null\" }\n",
        "",
    ));
    let plan = build_plan(&fx.inputs(), &probe).unwrap();
    assert_eq!(
        plan.etc_changes,
        [
            change("/etc/aios/managed-files", ChangeKind::Modify),
            change(
                "/etc/pacman.d/hooks/90-mkinitcpio-install.hook",
                ChangeKind::Remove
            ),
        ]
    );
}

#[test]
fn package_differences_are_sorted() {
    let fx = fixture();
    let mut probe = FakeProbe::synced(&fx);
    probe.packages.remove("zsh");
    probe.packages.insert("vim".to_string());
    probe.packages.insert("nano".to_string());
    let plan = build_plan(&fx.inputs(), &probe).unwrap();
    assert_eq!(plan.packages_add, ["zsh"]);
    assert_eq!(plan.packages_remove, ["nano", "vim"]);
    assert!(plan.etc_changes.is_empty());
}

#[test]
fn unit_changes_sorted_with_service_suffix_and_static_as_enabled() {
    let fx = fixture();
    let mut probe = FakeProbe::synced(&fx);
    probe.units = BTreeMap::from([
        ("NetworkManager.service".to_string(), UnitState::Disabled),
        ("fwupd-refresh.timer".to_string(), UnitState::Static),
        ("bluetooth.service".to_string(), UnitState::Enabled),
        ("sshd.socket".to_string(), UnitState::Disabled),
    ]);
    let plan = build_plan(&fx.inputs(), &probe).unwrap();
    assert_eq!(
        plan.unit_changes,
        [
            unit(
                "NetworkManager.service",
                UnitState::Disabled,
                UnitState::Enabled
            ),
            unit("bluetooth.service", UnitState::Enabled, UnitState::Disabled),
            unit("sshd.socket", UnitState::Disabled, UnitState::Masked),
        ]
    );
}

#[test]
fn disable_is_satisfied_by_static_or_missing_units() {
    let fx = fixture();
    let mut probe = FakeProbe::synced(&fx);
    probe
        .units
        .insert("bluetooth.service".to_string(), UnitState::Static);
    assert!(build_plan(&fx.inputs(), &probe)
        .unwrap()
        .unit_changes
        .is_empty());
    probe.units.remove("bluetooth.service");
    assert!(build_plan(&fx.inputs(), &probe)
        .unwrap()
        .unit_changes
        .is_empty());
}

#[test]
fn mask_beats_disable_beats_enable() {
    let probe = FakeProbe::synced(&fixture());
    let fx = fixture_with(&MANIFEST.replace(
        "disable = [\"bluetooth\"]",
        "disable = [\"bluetooth\", \"NetworkManager\", \"sshd.socket\"]",
    ));
    let plan = build_plan(&fx.inputs(), &probe).unwrap();
    assert_eq!(
        plan.unit_changes,
        [unit(
            "NetworkManager.service",
            UnitState::Enabled,
            UnitState::Disabled
        )]
    );
}

#[test]
fn lockdown_none_warns_without_dirtying_the_plan() {
    let fx = fixture_with(&MANIFEST.replace("lockdown = \"integrity\"", "lockdown = \"none\""));
    let plan = build_plan(&fx.inputs(), &FakeProbe::synced(&fx)).unwrap();
    assert!(plan.is_empty());
    assert_eq!(
        plan.warnings,
        ["kernel.lockdown = \"none\": unsigned kernel modules can be loaded"]
    );
    assert_eq!(
        plan.to_string(),
        "no changes\nwarning: kernel.lockdown = \"none\": unsigned kernel modules can be loaded\n"
    );
}

#[test]
fn switching_lockdown_modifies_the_kernel_cmdline() {
    let probe = FakeProbe::synced(&fixture());
    let fx = fixture_with(&MANIFEST.replace("lockdown = \"integrity\"", "lockdown = \"none\""));
    let plan = build_plan(&fx.inputs(), &probe).unwrap();
    assert_eq!(
        plan.etc_changes,
        [change("/etc/kernel/cmdline", ChangeKind::Modify)]
    );
}

#[test]
fn display_lists_every_section_in_order() {
    let plan = Plan {
        packages_add: vec!["tree".to_string()],
        packages_remove: vec!["nano".to_string()],
        etc_changes: vec![
            change("/etc/fstab", ChangeKind::Modify),
            change("/etc/issue", ChangeKind::Add),
            change("/etc/old.conf", ChangeKind::Remove),
        ],
        unit_changes: vec![unit("sshd.service", UnitState::Enabled, UnitState::Masked)],
        warnings: vec!["something to know".to_string()],
    };
    assert_eq!(
        plan.to_string(),
        "packages:
  + tree
  - nano
/etc:
  ~ /etc/fstab
  + /etc/issue
  - /etc/old.conf
services:
  sshd.service: enabled -> masked
warning: something to know
"
    );
}

#[test]
fn display_omits_empty_sections() {
    let plan = Plan {
        unit_changes: vec![unit("a.service", UnitState::NotFound, UnitState::Enabled)],
        ..Plan::default()
    };
    assert!(!plan.is_empty());
    assert_eq!(
        plan.to_string(),
        "services:\n  a.service: not-found -> enabled\n"
    );
}

#[test]
fn probe_errors_propagate() {
    let fx = fixture();
    let probe = FakeProbe {
        fail: Some("pacman exited 1".to_string()),
        ..FakeProbe::default()
    };
    assert_eq!(
        build_plan(&fx.inputs(), &probe).unwrap_err(),
        PlanError::Probe(ProbeError("pacman exited 1".to_string()))
    );
}
