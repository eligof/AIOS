use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "aios",
    version,
    about = "Change an AIOS system through its manifest: plan, apply, roll back"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show what `aios apply` would change compared with the booted generation
    Plan,
    /// Build the next generation from the manifest (also a full system upgrade)
    Apply {
        /// Do not ask for confirmation
        #[arg(long)]
        yes: bool,
        /// Build a new generation even if the manifest has no changes: a full
        /// `pacman -Syu` with the same manifest
        #[arg(long)]
        upgrade: bool,
    },
    /// Show the booted, default and bad generations and runtime changes to /etc
    Status,
    /// Inspect generations
    Gen {
        #[command(subcommand)]
        command: GenCommand,
    },
    /// Boot generation N at the next reboot (no snapshot is touched)
    Rollback {
        /// Generation number, e.g. 7 or 0007
        #[arg(value_parser = clap::value_parser!(u32).range(1..=9999))]
        gen: u32,
    },
    /// Delete old generations
    Gc {
        /// Number of newest generations to keep
        #[arg(long, default_value_t = 5)]
        keep: usize,
    },
    /// Set a user's password hash (used from the next apply)
    Passwd {
        /// User declared in the manifest
        user: String,
    },
    /// Secure Boot key management
    Secureboot {
        #[command(subcommand)]
        command: EnrollCommand,
    },
    /// TPM2 unlock of the LUKS volume
    Tpm {
        #[command(subcommand)]
        command: EnrollCommand,
    },
    /// Installer only: build gen-1 in a mounted btrfs top level
    Bootstrap {
        /// Mount point of the new filesystem's top level (subvolid=5)
        #[arg(long)]
        target: PathBuf,
        /// Mount point of the new ESP
        #[arg(long)]
        esp: PathBuf,
        /// The manifest file, normally <target>/@persist/aios/config/manifest.toml; its
        /// directory is the manifest repo
        #[arg(long)]
        manifest: PathBuf,
        /// UUID of the LUKS2 partition (`cryptsetup luksUUID <partition>`)
        #[arg(long)]
        luks_uuid: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum GenCommand {
    /// List generations: id, created, manifest commit, boot state, kernels
    List,
}

#[derive(Debug, Subcommand)]
pub enum EnrollCommand {
    /// Enroll (see `aios <command> enroll --help`)
    Enroll,
}
