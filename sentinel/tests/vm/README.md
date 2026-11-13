# Sentinel VM tests

Each scenario in `scenarios/` boots a throwaway VM, loads the real eBPF object
with `ebpf-loadtest`, provokes the behaviour under test and asserts on the
event stream (or on enforcement results).

## Requirements

- KVM: `/dev/kvm` must be accessible to your user (world-rw here, so no root needed).
- virtme-ng, fetched on demand via `uvx --from virtme-ng vng`.
- `busybox` on `PATH` (`build/hosttools/root/usr/bin` is appended by the harness and the Makefile).
- A built toolchain for the object (`make tools`: bpf-linker, clang).

## How it works

- The VM runs the **host kernel** (`vng --run $(uname -r)`) with `--user root`;
  the host filesystem is shared at identical absolute paths.
- `ebpf-loadtest` is built on the host **before** boot (`cargo build -p ebpf-loadtest`).
- Each scenario boots its own VM once and runs `scenarios/<name>.sh` inside it.
- `lib.sh` provides the assertion helpers (`assert_contains`).

## Running

```sh
cd sentinel
cargo run -p xtask -- vmtest <scenario>   # one scenario, e.g. exec
cargo run -p xtask -- vmtest all          # whole suite, fail-fast, prints a summary
make sentinel-vmtest                      # same as `all`, from the repo root
```

`all` runs `selftest` and `maps` first, then the rest alphabetically; it stops at
the first failure, prints PASS/FAIL/SKIP per scenario and exits non-zero on failure.
`make sentinel-vmtest` needs KVM and is **not** part of `make check` (nor CI).

## Scenarios

| Scenario | Asserts |
|---|---|
| `selftest` | The object loads and attaches ("loaded object with ..."). |
| `maps` | All expected BPF maps are found (CONFIG, none MISSING). |
| `bpf` | A socket-filter `BPF_PROG_LOAD` surfaces as a Bpf event. |
| `connect` | Non-loopback `connect()` attempts emit Connect events; loopback does not. |
| `deny` | In enforce mode, memfd exec and exec from `/tmp` are denied. |
| `exe_on` | `exe_on` rules: exec from `/dev/shm` is denied, from `/tmp` only audited. |
| `exec` | Exec events carry `flags_memfd` true for memfd exec and false for a normal one. |
| `guard_bpf` | With `--selfguard`, a kprobe `BPF_PROG_LOAD` gets EPERM; a socket filter is allowed. |
| `guard_files` | With `--selfguard`, writing or removing a guarded file gets EPERM and the file survives. |
| `guard_kill` | With `--selfguard`, a signal to the daemon from another process is denied and the daemon lives. |
| `guard_ptrace` | With `--selfguard`, `PTRACE_ATTACH` on the daemon is denied and the daemon lives. |
| `heartbeat` | Heartbeat lockdown self-test passes (`heartbeat-lockdown: PASS`). |
| `listen` | Non-loopback `listen()` emits a Listen event; loopback does not. |
| `lockdown` | After the heartbeat stops, non-loopback connect and non-`/usr` exec are denied; before, they work. |
| `memfd` | `memfd_create` emits a Memfd event with the memfd name. |
| `module` | A module load attempt emits a Module event with a module name. |
| `open` | Opening camera and input device nodes emits Open events; a regular file does not. |
| `proctree` | Fork and Exit events are emitted, with an exit matching a fork's child pid. |
| `ptrace` | `PTRACE_ATTACH` of an unrelated pid emits a Ptrace event; attaching to own child does not. |
| `quarantine` | A process in the quarantine cgroup gets EPERM on connect; its parent does not. |
| `rules` | An exec event's `matched_rule` resolves to the `exec-memfd` rule. |
| `signal` | A signal to the daemon is reported; one to an unrelated pid is not. |
| `write_refused` | A refused write (EROFS) on a read-only mount emits a WriteRefused event with the path. |
