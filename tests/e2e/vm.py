"""QEMU + swtpm for the AIOS end-to-end test (spec §9).

The VM boots OVMF's Secure Boot firmware with a fresh copy of the variable store (Setup
Mode), a swtpm TPM 2.0, a 20 GiB virtio disk (/dev/vda in the guest) and the ISO as a
CD-ROM. The install config reaches the guest as the fw_cfg file opt/aios/install.conf, and
the serial console is a unix socket the harness connects to. Nothing here needs root.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .serial import Serial

REPO = Path(__file__).resolve().parents[2]
OVMF_DIR = Path("/usr/share/edk2/x64")
FW_CFG_NAME = "opt/aios/install.conf"
# Longest unix socket path (sockaddr_un.sun_path is 108 bytes with the NUL).
UNIX_PATH_MAX = 107
# The installer's config keys, in its order (installer/lib/config.sh).
INSTALL_KEYS = (
    "DISK",
    "HOSTNAME",
    "USERNAME",
    "USER_PASSWORD",
    "LUKS_PASSPHRASE",
    "TIMEZONE",
    "WIPE",
    "EXTRA_CMDLINE",
)
# The unattended install the e2e test runs.
E2E_INSTALL = {
    "DISK": "/dev/vda",
    "HOSTNAME": "aios-e2e",
    "USERNAME": "tester",
    "USER_PASSWORD": "e2e-user-pass",
    "LUKS_PASSPHRASE": "e2e-luks-passphrase",
    "TIMEZONE": "UTC",
    "WIPE": "yes",
    "EXTRA_CMDLINE": "console=ttyS0,115200",
}


@dataclass(frozen=True)
class VmConfig:
    """Where the VM's files live and how big it is."""

    workdir: Path
    iso: Path | None
    ovmf_code: Path = OVMF_DIR / "OVMF_CODE.secboot.4m.fd"
    ovmf_vars: Path = OVMF_DIR / "OVMF_VARS.4m.fd"
    memory: str = "4G"
    cpus: int = 4
    disk_size: str = "20G"
    qemu: str = "qemu-system-x86_64"
    swtpm: str = "swtpm"
    kvm: Path = Path("/dev/kvm")

    @property
    def disk(self) -> Path:
        return self.workdir / "disk.qcow2"

    @property
    def vars(self) -> Path:
        return self.workdir / "OVMF_VARS.4m.fd"

    @property
    def serial_socket(self) -> Path:
        return self.workdir / "serial.sock"

    @property
    def tpm_dir(self) -> Path:
        return self.workdir / "tpm"

    @property
    def tpm_socket(self) -> Path:
        return self.tpm_dir / "swtpm.sock"

    @property
    def install_conf(self) -> Path:
        return self.workdir / "install.conf"

    @property
    def transcript(self) -> Path:
        return self.workdir / "serial.log"


def _opt(path: Path) -> str:
    """A path for a QEMU -opt value: a comma would start the next option."""
    text = str(path)
    if "," in text:
        raise ValueError(f"QEMU option paths may not contain ',': {text}")
    return text


def qemu_argv(cfg: VmConfig) -> list[str]:
    """The QEMU command line (spec §9)."""
    argv = [
        cfg.qemu,
        "-name", "aios-e2e",
        "-enable-kvm",
        "-machine", "q35,smm=on",
        "-cpu", "host",
        "-smp", str(cfg.cpus),
        "-m", cfg.memory,
        # OVMF's Secure Boot build needs SMM and a secure flash for its variable store.
        "-global", "driver=cfi.pflash01,property=secure,value=on",
        "-global", "ICH9-LPC.disable_s3=1",
        "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={_opt(cfg.ovmf_code)}",
        "-drive", f"if=pflash,format=raw,unit=1,file={_opt(cfg.vars)}",
        "-chardev", f"socket,id=chrtpm,path={_opt(cfg.tpm_socket)}",
        "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
        "-device", "tpm-tis,tpmdev=tpm0",
        "-drive", f"if=none,id=disk0,format=qcow2,file={_opt(cfg.disk)}",
        "-device", "virtio-blk-pci,drive=disk0,bootindex=0",
    ]
    if cfg.iso is not None:
        argv += [
            "-drive", f"if=none,id=cd0,media=cdrom,readonly=on,format=raw,file={_opt(cfg.iso)}",
            "-device", "ide-cd,drive=cd0,bootindex=1",
        ]
    argv += [
        # No option ROM: OVMF would refuse the unsigned iPXE ROM once keys are enrolled.
        "-netdev", "user,id=net0",
        "-device", "virtio-net-pci,netdev=net0,romfile=",
        "-device", "virtio-rng-pci",
        "-fw_cfg", f"name={FW_CFG_NAME},file={_opt(cfg.install_conf)}",
        # wait=on: QEMU starts the guest only once the harness is connected.
        "-chardev", f"socket,id=serial0,path={_opt(cfg.serial_socket)},server=on,wait=on",
        "-serial", "chardev:serial0",
        "-nographic",
        "-monitor", "none",
        "-parallel", "none",
    ]
    return argv


def swtpm_argv(cfg: VmConfig) -> list[str]:
    """swtpm as a TPM 2.0 socket device; it exits when QEMU disconnects."""
    return [
        cfg.swtpm, "socket", "--tpm2",
        "--tpmstate", f"dir={cfg.tpm_dir}",
        "--ctrl", f"type=unixio,path={cfg.tpm_socket}",
        "--terminate",
        "--log", f"file={cfg.workdir / 'swtpm.log'},level=1",
    ]


def render_install_conf(values: dict[str, str]) -> str:
    """KEY=value lines for the installer's whitelist parser."""
    unknown = set(values) - set(INSTALL_KEYS)
    if unknown:
        raise ValueError(f"unknown install keys: {sorted(unknown)}")
    lines = []
    for key in INSTALL_KEYS:
        if key not in values:
            continue
        value = values[key]
        if any(c in value for c in "\n\r\0"):
            raise ValueError(f"{key} holds a line break or NUL")
        lines.append(f"{key}={value}\n")
    return "".join(lines)


def find_iso(out_dir: Path) -> Path | None:
    """The newest out/aios-*.iso, or None."""
    isos = sorted(out_dir.glob("aios-*.iso"), key=lambda p: p.stat().st_mtime)
    return isos[-1] if isos else None


def missing_requirements(
    cfg: VmConfig, which: Callable[[str], str | None] = shutil.which
) -> list[str]:
    """Why the e2e test cannot run here (empty when it can)."""
    missing = []
    for tool, package in ((cfg.qemu, "qemu-system-x86"), ("qemu-img", "qemu-img"), (cfg.swtpm, "swtpm")):
        if which(tool) is None:
            missing.append(f"{tool} is not installed (pacman -S {package})")
    for firmware in (cfg.ovmf_code, cfg.ovmf_vars):
        if not firmware.is_file():
            missing.append(f"{firmware} is missing (pacman -S edk2-ovmf)")
    if not os.access(cfg.kvm, os.R_OK | os.W_OK):
        missing.append(f"{cfg.kvm} is not readable and writable")
    if cfg.iso is None or not cfg.iso.is_file():
        missing.append("no out/aios-*.iso: build it first (make iso)")
    if max(len(os.fsencode(p)) for p in (cfg.serial_socket, cfg.tpm_socket)) > UNIX_PATH_MAX:
        missing.append(f"{cfg.workdir} is too long for unix socket paths: set AIOS_E2E_DIR to a shorter one")
    return missing


def default_config() -> VmConfig:
    """The e2e VM: build/e2e/ (or $AIOS_E2E_DIR) and the newest out/aios-*.iso (or
    $AIOS_E2E_ISO)."""
    workdir = Path(os.environ.get("AIOS_E2E_DIR", REPO / "build" / "e2e"))
    iso_env = os.environ.get("AIOS_E2E_ISO")
    iso = Path(iso_env) if iso_env else find_iso(REPO / "out")
    return VmConfig(workdir=workdir, iso=iso)


def _wait_for(path: Path, timeout: float, what: str) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() > deadline:
            raise TimeoutError(f"{what} did not create {path} within {timeout:.0f}s")
        time.sleep(0.1)


class Vm:
    """A fresh VM: prepare() creates the disk, the variable store and the config, start()
    runs swtpm and QEMU and connects to the serial console."""

    def __init__(self, cfg: VmConfig):
        self.cfg = cfg
        self.qemu: subprocess.Popen | None = None
        self.swtpm: subprocess.Popen | None = None
        self.serial: Serial | None = None

    def prepare(self, install: dict[str, str]) -> None:
        cfg = self.cfg
        cfg.workdir.mkdir(parents=True, exist_ok=True)
        for old in (cfg.disk, cfg.vars, cfg.serial_socket, cfg.install_conf, cfg.transcript):
            old.unlink(missing_ok=True)
        shutil.rmtree(cfg.tpm_dir, ignore_errors=True)
        cfg.tpm_dir.mkdir()
        subprocess.run(
            ["qemu-img", "create", "-q", "-f", "qcow2", str(cfg.disk), cfg.disk_size], check=True
        )
        shutil.copyfile(cfg.ovmf_vars, cfg.vars)
        cfg.install_conf.write_text(render_install_conf(install))

    def start(self) -> Serial:
        cfg = self.cfg
        with open(cfg.workdir / "swtpm.out", "ab") as out:
            self.swtpm = subprocess.Popen(swtpm_argv(cfg), stdin=subprocess.DEVNULL, stdout=out, stderr=out)
        _wait_for(cfg.tpm_socket, 10, "swtpm")
        with open(cfg.workdir / "qemu.out", "ab") as out:
            self.qemu = subprocess.Popen(qemu_argv(cfg), stdin=subprocess.DEVNULL, stdout=out, stderr=out)
        self.serial = Serial.connect(cfg.serial_socket, transcript=cfg.transcript, timeout=30)
        return self.serial

    def stop(self) -> None:
        if self.serial is not None:
            self.serial.close()
        for proc in (self.qemu, self.swtpm):
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

    def __enter__(self) -> Vm:
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


if __name__ == "__main__":
    # `make e2e` runs this first, so a missing tool fails loudly instead of skipping.
    problems = missing_requirements(default_config())
    for problem in problems:
        print(f"make e2e: {problem}", file=sys.stderr)
    sys.exit(1 if problems else 0)
