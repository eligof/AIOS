use std::fmt;

/// The named steps of `aios apply` / `aios bootstrap` (spec §4.3), in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Lock,
    Validate,
    CommitManifest,
    MountTop,
    PrepareCandidate,
    Assemble,
    Packages,
    Keyring,
    RenderEtc,
    Services,
    Uki,
    Sign,
    EspSpace,
    Finalize,
    Cleanup,
}

impl Step {
    pub fn name(self) -> &'static str {
        match self {
            Step::Lock => "lock",
            Step::Validate => "validate",
            Step::CommitManifest => "commit-manifest",
            Step::MountTop => "mount-top",
            Step::PrepareCandidate => "prepare-candidate",
            Step::Assemble => "assemble",
            Step::Packages => "packages",
            Step::Keyring => "keyring",
            Step::RenderEtc => "render-etc",
            Step::Services => "services",
            Step::Uki => "uki",
            Step::Sign => "sign",
            Step::EspSpace => "esp-space",
            Step::Finalize => "finalize",
            Step::Cleanup => "cleanup",
        }
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The step that failed and why (spec §7: `aios: step <name> failed: <detail>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepError {
    pub step: Step,
    pub detail: String,
}

impl fmt::Display for StepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "aios: step {} failed: {}", self.step, self.detail)
    }
}

impl std::error::Error for StepError {}
