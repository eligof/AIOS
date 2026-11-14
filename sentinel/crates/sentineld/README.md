# sentineld: what S4 inherits

The daemon (spec §6–§10, §12–§13). S4 packages it and wires it into the
manifest; this is the interface it should package against.

## Binaries

- `sentineld` — the daemon. Flags: `--config` (default
  `/etc/aios/sentinel/sentinel.toml`), `--rules`
  (`/etc/aios/sentinel/rules.d`), `--alerts` (`/var/log/aios/sentinel`),
  `--socket` (`/run/aios-sentinel/io.aios.Sentinel`), `--state`
  (`/run/aios-sentinel/state`), `--home-binds` (a file of manifest-managed
  home targets, one per line), `--no-enforce` and `--no-selfguard` (both
  default to on; the VM scenarios use the opt-outs).
- `sentinel` — the CLI. `sentinel rules check <dir>` runs offline and needs
  no daemon; everything else is a varlink client.

## What the unit must provide (spec §11.4)

`Type=notify` (the daemon sends `READY=1` once programs are attached and the
first heartbeat is written), `DefaultDependencies=no`, `After=local-fs.target`,
`Before=sysinit.target network-pre.target`, `Wants=network-pre.target`,
`RefuseManualStop=yes`, `Restart=always`, `RestartSec=1`,
`OOMScoreAdjust=-1000`, `WantedBy=sysinit.target`, `LogsDirectory=aios/sentinel`
(mode 0700).

The unit must also ensure bpffs is mounted on `/sys/fs/bpf` before the daemon
starts. Without it the daemon exits, because there is nowhere to pin; the error
says so.

## What the health check reads (spec §11.5)

`/run/aios-sentinel/state` contains exactly `ok` or `degraded`, written once
the daemon is ready. `degraded` means the LSM programs did not attach: observe
only, no deny, no self-guard, no lockdown. The health check counts degraded as
failed.

## Exit codes (spec §12)

The daemon exits non-zero, having pinned nothing, when: the config is invalid,
the rules are invalid, the kernel object fails to load, BTF is missing, or
bpffs is not mounted. A clean exit (0) also happens when `enable = false`.
systemd restarts it; the health check fails the generation.

## `LoadGeneration` (spec §11.3)

`aios apply` calls it over varlink as root:

    {"method":"io.aios.Sentinel.LoadGeneration",
     "parameters":{"gen":"gen-7","dir":"/etc/aios/sentinel/rules.d"}}

Reply on success: `{"parameters":{"ok":true,"changes":["reverse-shell: action freeze -> kill"]}}`,
and the daemon raises a critical `config-changed` alert. On failure:
`{"error":"io.aios.Sentinel.InvalidRules","parameters":{"errors":[…]}}` and the
current rules stay loaded. If the socket is not there, `aios apply` warns and
the rules take effect at the next boot.

## Access (spec §10.1)

The socket is mode 0660, group `wheel` (chowned at bind; a host with no `wheel`
group leaves it root-only, which fails closed). `SO_PEERCRED` decides what a
peer may call: root and `wheel` may read, only root may `Release`, `Kill` or
`LoadGeneration`. A refused call returns `io.aios.Sentinel.PermissionDenied`,
and the CLI turns that into advice to re-run under `run0`.

## The alert record (spec §9)

`/var/log/aios/sentinel/alerts.jsonl`, one JSON object per line, rotating at
64 MiB to `alerts.<n>.jsonl` (1 is oldest). `hash` is SHA-256 over the record
without `hash`, canonical JSON (sorted keys, no whitespace); the first record
chains from 64 zeros. `sentinel verify` walks the whole chain.

## Pins (spec §8.1)

`/sys/fs/bpf/aios-sentinel/maps/<MAP>` and
`/sys/fs/bpf/aios-sentinel/links/<program>`. bpffs is a tmpfs, so a reboot
starts with nothing loaded and nothing enforced until the daemon first starts.
A restart that finds a complete pin set re-opens those maps instead of
attaching again, so it leaves no observation gap; only `memfd` is re-attached,
because a perf-event link cannot be pinned.

## Tests

`make check` covers the unit tests (162 in `sentineld`, 6 in `sentinel`).
`make sentinel-vmtest` runs 26 scenarios; `daemon`, `freeze` and
`lockdown_report` are S3's.

## Exec resolution

An exec event's executable comes from the kernel's read of `bprm->filename`
(`ExecPayload::exe`), not from `/proc/<pid>/exe`: the hook runs at
`bprm_check_security`, before the new image is installed, so a user-space read
returns the caller's old image. `resolve` prefers the kernel's path whenever it
is absolute and falls back to the process table otherwise. argv, `env_ld` and
`stdio_socket` still come from `/proc`, so they are only available while the
process lives. Spec amendment 13 records it; the `freeze` scenario is keyed on
`exe` and is the regression test.
