# Security Policy

AIOS is a security-focused operating system project (impermanent btrfs root,
signed generations, Secure Boot + TPM2, and the Sentinel host IDS). Reports of
vulnerabilities — in the project's own code or in how it configures the system —
are welcome.

## Reporting a vulnerability

Please report privately, not through a public issue:

1. Go to the repository's **Security** tab.
2. Choose **Report a vulnerability** (GitHub private vulnerability reporting).

This opens a private advisory visible only to the maintainer. Include, where you
can: the affected component (e.g. `aios-cli`, `sentinel`, the installer, a
packaged unit), the version or commit, steps to reproduce, and the impact.

If you cannot use GitHub's private reporting, open a minimal public issue that
says only that you have found a security problem and asks for a private channel —
do not include details in it.

## Scope

In scope: the Rust crates (`aios-cli`, `sentinel`), the installer and initrd
scripts, the packaged systemd units and their hardening, the manifest-driven
generation model, and the Sentinel rules and detectors.

Out of scope for this repository: upstream Arch/CachyOS packages, the Linux
kernel itself, and hardware or firmware issues (report those to their vendors).

## Handling

Reports are triaged on a best-effort basis by a single maintainer. There is no
paid bounty. A fix lands on a branch, is verified through `make check` (and,
where the issue touches the ISO or runtime, `make e2e`), and ships in a new
signed generation.
