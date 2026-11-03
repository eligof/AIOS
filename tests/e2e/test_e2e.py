"""The AIOS end-to-end test (spec §1 assertions (a)-(g), §9): install the ISO unattended into a
QEMU VM with OVMF Secure Boot firmware and swtpm, then drive gen-1, gen-2, a rollback and a
failing gen-3 over the serial console. Skipped unless out/aios-*.iso and the VM tools exist.
Run it with `make e2e` (about an hour; it downloads the packages). The transcript of
everything the VM printed is build/e2e/serial.log.

The steps share one VM and run in order; after a failure the rest xfail.
"""

from __future__ import annotations

import re
import shutil

import pytest

from .serial import Serial, Shell, choose_boot_entry, expect_unless, login_root_shell, unlock_luks
from .vm import E2E_INSTALL, Vm, default_config, missing_requirements

USER = E2E_INSTALL["USERNAME"]
HOST = E2E_INSTALL["HOSTNAME"]
PASSWORD = E2E_INSTALL["USER_PASSWORD"]
LUKS = E2E_INSTALL["LUKS_PASSPHRASE"]

# The ISO's serial-console boot entry: its title, and its position in the systemd-boot menu
# (a unit test checks both against iso/efiboot/loader/entries).
ISO_SERIAL_TITLE = "AIOS install medium (x86_64, UEFI, serial console)"
ISO_SERIAL_KEY = "2"

MANIFEST = "/persist/aios/config/manifest.toml"
# (d): add tree to the package list. (f): the test-only cmdline flag that fails aios-health.
ADD_TREE = f"sed -i 's/^  \"pacman-contrib\",$/  \"pacman-contrib\", \"tree\",/' {MANIFEST}"
ADD_FAIL_HEALTH = (
    f"sed -i 's/^extra_cmdline = \\[\"console=ttyS0,115200\"\\]/"
    f"extra_cmdline = [\"console=ttyS0,115200\", \"aios.test.fail_health=1\"]/' {MANIFEST}"
)

# How aios-install says it failed: die's error line, or the exit trap's line for a command
# that failed under set -e (installer/lib/common.sh, cleanup.sh). The whole line.
INSTALL_FAILURE = r"aios-install: (?:error: |step \d+ \([^)\n]*\) failed)[^\n]*\n"

INSTALL_TIMEOUT = 90 * 60
BOOT_TIMEOUT = 10 * 60
APPLY_TIMEOUT = 60 * 60

CONFIG = default_config()

pytestmark = [
    pytest.mark.incremental,
    pytest.mark.skipif(
        bool(missing_requirements(CONFIG)),
        reason="; ".join(missing_requirements(CONFIG)) or "ready",
    ),
]


def expect_install(serial: Serial, pattern: str, timeout: float) -> re.Match[str]:
    """Wait for aios-install to print `pattern`; fail at once when it reports a failure,
    instead of after the timeout."""
    return expect_unless(serial, pattern, INSTALL_FAILURE, timeout)


class Machine:
    """The VM plus the root shell of the current boot."""

    def __init__(self, vm: Vm, serial: Serial):
        self.vm = vm
        self.serial = serial
        self.shell: Shell | None = None

    def boot(self) -> Shell:
        """From power-on or reboot: unlock LUKS, log in, return the root shell."""
        unlock_luks(self.serial, LUKS, BOOT_TIMEOUT)
        self.shell = login_root_shell(self.serial, USER, PASSWORD, HOST, BOOT_TIMEOUT)
        return self.shell

    def reboot(self) -> Shell:
        assert self.shell is not None
        self.shell.send_only("systemctl reboot")
        return self.boot()

    def gen(self) -> int:
        """The booted generation, from aios.gen= on the kernel cmdline."""
        assert self.shell is not None
        out = self.shell.check("tr ' ' '\\n' </proc/cmdline | sed -n 's/^aios\\.gen=//p'")
        return int(out)

    def as_user(self, cmd: str) -> str:
        """Run `cmd` as the test user. runuser keeps root's $HOME, so use absolute paths."""
        assert self.shell is not None
        return self.shell.check(f"runuser -u {USER} -- sh -c '{cmd}'")


@pytest.fixture(scope="module")
def machine(request: pytest.FixtureRequest):
    vm = Vm(CONFIG)
    vm.prepare(E2E_INSTALL)
    serial = vm.start()
    yield Machine(vm, serial)
    vm.stop()
    if not request.config.getoption("--keep-vm"):
        CONFIG.disk.unlink(missing_ok=True)
        shutil.rmtree(CONFIG.tpm_dir, ignore_errors=True)


def test_01_unattended_install_from_the_iso(machine: Machine) -> None:
    """The serial boot entry, then aios-install from the fw_cfg config, then the reboot."""
    serial = machine.serial
    choose_boot_entry(serial, ISO_SERIAL_TITLE, ISO_SERIAL_KEY, BOOT_TIMEOUT)
    expect_install(serial, r"aios-install: step 1/13: preflight", BOOT_TIMEOUT)
    expect_install(serial, r"gen-0001 built in /mnt/aios-top", INSTALL_TIMEOUT)
    expect_install(serial, r"aios-install: installation complete", 10 * 60)
    expect_install(serial, r"aios-install: rebooting into AIOS", 60)


def test_02_gen1_boots_with_secure_boot_and_plan_is_clean(machine: Machine) -> None:
    """(c) aios plan reports no changes on a fresh install. Also: gen-1 is booted, healthy,
    and Secure Boot is on with the installer's keys."""
    shell = machine.boot()

    assert machine.gen() == 1
    assert shell.check("systemctl is-active aios-health.service") == "active"
    assert "enabled (user)" in shell.check("bootctl status 2>/dev/null | grep -i 'secure boot'")
    plan = shell.run("aios plan", 300)
    assert plan.rc == 0, plan.output
    assert "no changes" in plan.output


def test_03_runtime_state_is_ephemeral_and_declared_state_persists(machine: Machine) -> None:
    """(a) runtime writes to /etc, /var/tmp and /root vanish at reboot, /usr is read-only;
    (b) /persist and /home survive; (g, part 1) plant a symlink where ~/.ssh/authorized_keys
    is bind-mounted, by moving the protected ~/.ssh away (spec §4.4)."""
    shell = machine.shell
    assert shell is not None
    shell.check("echo e2e | tee /etc/aios-e2e /var/tmp/aios-e2e /root/aios-e2e /persist/aios-e2e")
    machine.as_user(f"echo e2e > /home/{USER}/aios-e2e")
    erofs = shell.run("touch /usr/aios-e2e")
    assert erofs.rc != 0
    assert "Read-only file system" in erofs.output
    machine.as_user(
        f"cd /home/{USER} && mv .ssh .ssh-moved && mkdir -m 0700 .ssh"
        " && ln -s /etc/nftables.conf .ssh/authorized_keys"
    )

    shell = machine.reboot()

    assert machine.gen() == 1
    for gone in ("/etc/aios-e2e", "/var/tmp/aios-e2e", "/root/aios-e2e"):
        assert shell.run(f"test -e {gone}").rc == 1, f"{gone} survived the reboot"
    assert shell.check("cat /persist/aios-e2e") == "e2e"
    assert shell.check(f"cat /home/{USER}/aios-e2e") == "e2e"


def test_04_a_planted_symlink_does_not_redirect_the_home_bind(machine: Machine) -> None:
    """(g) findmnt shows no mount on /etc/nftables.conf, nftables loaded the real ruleset,
    and nothing is mounted at the symlink path."""
    shell = machine.shell
    assert shell is not None

    assert shell.run("findmnt -n /etc/nftables.conf").rc == 1
    assert shell.run(f"findmnt -rno TARGET | grep -Fx /home/{USER}/.ssh/authorized_keys").rc == 1
    assert shell.check("systemctl is-active nftables.service") == "active"
    assert "policy drop" in shell.check("nft list chain inet filter input")
    # The managed file is intact (sha256sum: base has no cmp).
    assert shell.check("sha256sum </etc/nftables.conf") == shell.check(
        "sha256sum </persist/aios/config/files/nftables.conf"
    )


def test_05_apply_builds_gen2_with_a_new_package(machine: Machine) -> None:
    """(d) after adding tree to the manifest, aios apply --yes + reboot boots gen-2 with tree."""
    shell = machine.shell
    assert shell is not None
    shell.check(ADD_TREE)
    assert "reboot to activate gen-0002" in shell.check("aios apply --yes", APPLY_TIMEOUT)

    shell = machine.reboot()

    assert machine.gen() == 2
    shell.check("command -v tree")


def test_06_rollback_boots_gen1_without_the_package(machine: Machine) -> None:
    """(e) aios rollback 1 + reboot boots gen-1, where tree does not exist."""
    shell = machine.shell
    assert shell is not None
    shell.check("aios rollback 1")

    shell = machine.reboot()

    assert machine.gen() == 1
    assert shell.run("command -v tree").rc == 1


def test_07_a_failing_generation_falls_back_after_three_boots(machine: Machine) -> None:
    """(f) gen-3 with aios.test.fail_health=1 fails its health check on each of 3 boots; the
    next boot is the previous good generation (gen-2, the newest blessed one)."""
    shell = machine.shell
    assert shell is not None
    shell.check(ADD_FAIL_HEALTH)
    assert "reboot to activate gen-0003" in shell.check("aios apply --yes", APPLY_TIMEOUT)

    for attempt in range(1, 4):
        shell = machine.reboot()
        assert machine.gen() == 3, f"boot {attempt} after the apply"
        assert shell.run("systemctl is-failed aios-health.service").output == "failed"

    shell = machine.reboot()

    assert machine.gen() == 2
    assert shell.check("systemctl is-active aios-health.service") == "active"
