use aios_exec::{Step, StepError};

#[test]
fn step_names_are_kebab_case() {
    let names = [
        (Step::Lock, "lock"),
        (Step::Validate, "validate"),
        (Step::CommitManifest, "commit-manifest"),
        (Step::MountTop, "mount-top"),
        (Step::PrepareCandidate, "prepare-candidate"),
        (Step::Assemble, "assemble"),
        (Step::Packages, "packages"),
        (Step::Keyring, "keyring"),
        (Step::RenderEtc, "render-etc"),
        (Step::Services, "services"),
        (Step::Uki, "uki"),
        (Step::Sign, "sign"),
        (Step::EspSpace, "esp-space"),
        (Step::Finalize, "finalize"),
        (Step::Cleanup, "cleanup"),
    ];
    for (step, name) in names {
        assert_eq!(step.name(), name);
        assert_eq!(step.to_string(), name);
    }
}

#[test]
fn step_error_names_the_step() {
    let err = StepError {
        step: Step::Packages,
        detail: "`pacman -Syu` exited with status 1".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "aios: step packages failed: `pacman -Syu` exited with status 1"
    );
}
