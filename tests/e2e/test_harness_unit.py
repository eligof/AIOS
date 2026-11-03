"""Unit tests of the e2e harness (spec §9): no VM, no root. A thread plays the guest's serial
console on a unix socket. Part of `make check` (make e2e-unit)."""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable

import pytest

from .serial import (
    Serial,
    SerialClosed,
    SerialTimeout,
    Shell,
    choose_boot_entry,
    login_root_shell,
    parse_result,
    strip_ansi,
    unlock_luks,
    wrap_command,
)
from .vm import (
    E2E_INSTALL,
    FW_CFG_NAME,
    REPO,
    Vm,
    VmConfig,
    find_iso,
    missing_requirements,
    qemu_argv,
    render_install_conf,
    swtpm_argv,
)

SENTINEL_LINE = re.compile(
    r"printf '__AIOS_E2E_BEGIN_%s__\\n' (\d+); \{ (.*) ; \} 2>&1; "
    r"printf '__AIOS_E2E_END_%s_%s__\\n' \1 \"\$\?\"$"
)


class FakeConsole:
    """The guest side of the serial socket. Sends `banner` (a list of byte chunks, with
    `gap` seconds between them), then answers each line the harness sends (terminated by
    CR) with on_line(line), and records everything it received."""

    def __init__(
        self,
        path: Path,
        banner: list[bytes] = (),
        on_line: Callable[[str], bytes] | None = None,
        gap: float = 0.0,
        close_after_banner: bool = False,
    ):
        self.path = path
        self.banner = list(banner)
        self.on_line = on_line or (lambda line: b"")
        self.gap = gap
        self.close_after_banner = close_after_banner
        self.received = b""
        self.lines: list[str] = []
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(str(path))
        self._server.listen(1)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        conn, _ = self._server.accept()
        with conn:
            for i, chunk in enumerate(self.banner):
                if i:
                    time.sleep(self.gap)
                conn.sendall(chunk)
            if self.close_after_banner:
                return
            buffer = b""
            conn.settimeout(5)
            while True:
                try:
                    data = conn.recv(4096)
                except (TimeoutError, OSError):
                    return
                if not data:
                    return
                self.received += data
                buffer += data
                while b"\r" in buffer:
                    line, buffer = buffer.split(b"\r", 1)
                    text = line.decode()
                    self.lines.append(text)
                    reply = self.on_line(text)
                    if reply:
                        conn.sendall(reply)

    def join(self) -> None:
        self._thread.join(timeout=10)
        self._server.close()


def shell_replies(results: dict[str, tuple[int, str]]) -> Callable[[str], bytes]:
    """on_line for a fake root shell: answers sentinel lines from `results` (command ->
    (status, output)); other lines get no answer."""

    def reply(line: str) -> bytes:
        match = SENTINEL_LINE.match(line)
        if not match:
            return b""
        n, cmd = match.group(1), match.group(2)
        rc, out = results.get(cmd, (127, f"bash: {cmd}: command not found\n"))
        return f"__AIOS_E2E_BEGIN_{n}__\r\n{out}__AIOS_E2E_END_{n}_{rc}__\r\n".encode()

    return reply


@pytest.fixture
def sock_path(tmp_path: Path) -> Path:
    return tmp_path / "serial.sock"


def connect(path: Path, **kw) -> Serial:
    return Serial.connect(path, timeout=5, **kw)


def option(argv: list[str], flag: str) -> list[str]:
    """Every value that follows `flag` in argv."""
    return [argv[i + 1] for i, a in enumerate(argv) if a == flag]


# --- vm.py -----------------------------------------------------------------------------


def test_qemu_argv_has_kvm_secure_boot_tpm_disk_cdrom_fw_cfg_and_serial(tmp_path: Path) -> None:
    cfg = VmConfig(workdir=tmp_path, iso=Path("/out/aios-2026.11.03-x86_64.iso"))

    argv = qemu_argv(cfg, install=True)

    assert argv[0] == "qemu-system-x86_64"
    assert "-enable-kvm" in argv and "-nographic" in argv
    assert option(argv, "-cpu") == ["host"]
    assert option(argv, "-m") == ["4G"]
    assert option(argv, "-machine") == ["q35,smm=on"]
    assert "driver=cfi.pflash01,property=secure,value=on" in option(argv, "-global")
    assert option(argv, "-drive")[:2] == [
        "if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd",
        f"if=pflash,format=raw,unit=1,file={tmp_path}/OVMF_VARS.4m.fd",
    ]
    assert f"socket,id=chrtpm,path={tmp_path}/tpm/swtpm.sock" in option(argv, "-chardev")
    assert option(argv, "-tpmdev") == ["emulator,id=tpm0,chardev=chrtpm"]
    devices = option(argv, "-device")
    assert "tpm-tis,tpmdev=tpm0" in devices
    assert "virtio-blk-pci,drive=disk0,bootindex=0" in devices
    assert "ide-cd,drive=cd0,bootindex=1" in devices
    assert f"if=none,id=disk0,format=qcow2,file={tmp_path}/disk.qcow2" in option(argv, "-drive")
    assert option(argv, "-fw_cfg") == [f"name={FW_CFG_NAME},file={tmp_path}/install.conf"]
    assert FW_CFG_NAME == "opt/aios/install.conf"
    assert f"socket,id=serial0,path={tmp_path}/serial.sock,server=on,wait=on" in option(argv, "-chardev")
    assert option(argv, "-serial") == ["chardev:serial0"]
    assert option(argv, "-monitor") == ["none"]


def test_qemu_argv_refuses_commas_and_an_install_boot_without_the_iso(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="may not contain ','"):
        qemu_argv(VmConfig(workdir=tmp_path / "a,b", iso=None), install=False)
    with pytest.raises(ValueError, match="needs the ISO"):
        qemu_argv(VmConfig(workdir=tmp_path, iso=None), install=True)


def test_the_boots_after_the_install_have_no_iso_or_install_config_and_the_same_state(tmp_path: Path) -> None:
    # The ISO's aios-install-auto.service installs whenever the fw_cfg config is there, so a
    # later boot with it would wipe the disk and install again.
    cfg = VmConfig(workdir=tmp_path, iso=Path("/out/aios.iso"))

    install, later = qemu_argv(cfg, install=True), qemu_argv(cfg, install=False)

    assert "-no-reboot" in install  # the installer's reboot ends QEMU; the harness restarts it
    assert "-no-reboot" not in later  # reboots of the installed system stay guest reboots
    assert "-fw_cfg" not in later
    assert not any("cdrom" in a or "cd0" in a for a in later)
    for argv in (install, later):
        assert option(argv, "-cpu") == ["host"]
        assert f"if=pflash,format=raw,unit=1,file={tmp_path}/OVMF_VARS.4m.fd" in option(argv, "-drive")
        assert f"if=none,id=disk0,format=qcow2,file={tmp_path}/disk.qcow2" in option(argv, "-drive")
        assert f"socket,id=chrtpm,path={tmp_path}/tpm/swtpm.sock" in option(argv, "-chardev")
        assert "virtio-blk-pci,drive=disk0,bootindex=0" in option(argv, "-device")
    # The install boot only adds: -no-reboot, the CD-ROM (-drive + -device) and -fw_cfg.
    assert len(install) - len(later) == 1 + 4 + 2


# Stand-ins for swtpm and QEMU: they make their sockets the way the real ones do, record each
# start, and the QEMU one prints the console of an install boot (which ends with the reboot,
# as -no-reboot makes it) or of a boot from the disk.
FAKE_SWTPM = """
import socket, sys
args = sys.argv[1:]
path = args[args.index("--ctrl") + 1].split("path=", 1)[1]
state = args[args.index("--tpmstate") + 1].split("dir=", 1)[1]
with open(f"{state}/starts", "a") as f:
    f.write("swtpm\\n")
server = socket.socket(socket.AF_UNIX)
server.bind(path)
server.listen(1)
conn, _ = server.accept()
conn.recv(1)  # --terminate: exit once QEMU disconnects
"""
FAKE_QEMU = """
import json, os, socket, sys
argv = sys.argv
chardevs = [argv[i + 1] for i, a in enumerate(argv) if a == "-chardev"]
def path(name):
    spec = next(c for c in chardevs if f"id={name}," in c)
    return dict(kv.split("=", 1) for kv in spec.split(",")[1:])["path"]
with open(os.path.join(os.path.dirname(path("serial0")), "qemu-starts.jsonl"), "a") as f:
    f.write(json.dumps(argv) + "\\n")
tpm = socket.socket(socket.AF_UNIX)
tpm.connect(path("chrtpm"))
server = socket.socket(socket.AF_UNIX)
server.bind(path("serial0"))
server.listen(1)
conn, _ = server.accept()
if "-no-reboot" in argv:
    conn.sendall(b"aios-install: rebooting into AIOS\\r\\nreboot: Restarting system\\r\\n")
else:
    conn.sendall(b"Please enter passphrase for disk aios: ")
    conn.recv(1)
"""


def test_the_vm_installs_from_the_iso_then_powers_on_from_the_disk_with_its_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()

    def script(name: str, text: str) -> str:
        path = bin_dir / name
        path.write_text(text)
        path.chmod(0o755)
        return str(path)

    script("qemu-img", '#!/bin/sh\n: > "$5"\n')  # qemu-img create -q -f qcow2 FILE SIZE
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    (tmp_path / "VARS.fd").write_bytes(b"empty variable store")
    cfg = VmConfig(
        workdir=tmp_path / "vm",
        iso=tmp_path / "aios.iso",
        ovmf_code=tmp_path / "CODE.fd",
        ovmf_vars=tmp_path / "VARS.fd",
        qemu=script("qemu", f"#!{sys.executable}\n{FAKE_QEMU}"),
        swtpm=script("swtpm", f"#!{sys.executable}\n{FAKE_SWTPM}"),
    )
    vm = Vm(cfg)
    vm.prepare(E2E_INSTALL)
    cfg.vars.write_bytes(b"keys the installer enrolled")  # the firmware's writes
    machine = Machine(vm)

    with vm:
        vm.start(install=True)
        install_console = machine.serial
        expect_install(machine.serial, r"aios-install: rebooting into AIOS", 5)
        machine.restart_from_disk()
        machine.serial.expect(r"Please enter passphrase", 5)
        assert machine.serial is not install_console

    assert vm.qemu.poll() is not None and vm.swtpm.poll() is not None
    starts = [json.loads(line) for line in (cfg.workdir / "qemu-starts.jsonl").read_text().splitlines()]
    assert starts == [qemu_argv(cfg, install=True), qemu_argv(cfg, install=False)]
    assert cfg.vars.read_bytes() == b"keys the installer enrolled"
    assert (cfg.tpm_dir / "starts").read_text() == "swtpm\nswtpm\n"
    transcript = cfg.transcript.read_text()
    assert transcript.index("rebooting into AIOS") < transcript.index("Please enter passphrase")


def test_swtpm_is_a_tpm2_socket_that_exits_with_qemu(tmp_path: Path) -> None:
    argv = swtpm_argv(VmConfig(workdir=tmp_path, iso=None))

    assert argv[:3] == ["swtpm", "socket", "--tpm2"]
    assert option(argv, "--tpmstate") == [f"dir={tmp_path}/tpm"]
    assert option(argv, "--ctrl") == [f"type=unixio,path={tmp_path}/tpm/swtpm.sock"]
    assert "--terminate" in argv


def test_the_install_config_is_rendered_in_order_and_checked() -> None:
    text = render_install_conf(E2E_INSTALL)

    assert text.splitlines()[0] == "DISK=/dev/vda"
    assert "EXTRA_CMDLINE=console=ttyS0,115200\n" in text
    assert "WIPE=yes\n" in text
    with pytest.raises(ValueError, match="unknown install keys"):
        render_install_conf({"ROOT_PASSWORD": "x"})
    with pytest.raises(ValueError, match="line break"):
        render_install_conf({"HOSTNAME": "a\nWIPE=yes"})


def test_the_e2e_config_passes_the_installers_own_parser(tmp_path: Path) -> None:
    conf = tmp_path / "install.conf"
    conf.write_text(render_install_conf(E2E_INSTALL))
    (tmp_path / "zoneinfo").mkdir()
    (tmp_path / "zoneinfo" / "UTC").write_text("")
    lib = REPO / "installer" / "lib"
    script = 'for f in common config; do . "$1/$f.sh"; done; parse_config "$2" && validate_config 1'

    proc = subprocess.run(
        ["bash", "-c", script, "_", str(lib), str(conf)],
        env={**os.environ, "AIOS_ZONEINFO": str(tmp_path / "zoneinfo"), "AIOS_PASSWD_FILE": "/dev/null"},
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 0, proc.stderr


def test_missing_requirements_name_each_missing_piece(tmp_path: Path) -> None:
    code, vars_ = tmp_path / "CODE.fd", tmp_path / "VARS.fd"
    iso = tmp_path / "aios.iso"
    kvm = tmp_path / "kvm"
    for f in (code, vars_, iso, kvm):
        f.write_text("")
    cfg = VmConfig(workdir=tmp_path, iso=iso, ovmf_code=code, ovmf_vars=vars_, kvm=kvm)

    assert missing_requirements(cfg, which=lambda tool: f"/usr/bin/{tool}") == []
    missing = missing_requirements(
        VmConfig(workdir=tmp_path, iso=None, ovmf_code=tmp_path / "none.fd", ovmf_vars=vars_, kvm=tmp_path / "nokvm"),
        which=lambda tool: None if tool == "swtpm" else f"/usr/bin/{tool}",
    )
    assert missing == [
        "swtpm is not installed (pacman -S swtpm)",
        f"{tmp_path}/none.fd is missing (pacman -S edk2-ovmf)",
        f"{tmp_path}/nokvm is not readable and writable",
        "no out/aios-*.iso: build it first (make iso)",
    ]


def test_a_workdir_too_long_for_unix_sockets_is_reported(tmp_path: Path) -> None:
    deep = tmp_path / ("d" * 100)
    cfg = VmConfig(workdir=deep, iso=None)

    assert missing_requirements(cfg, which=lambda tool: tool)[-1] == (
        f"{deep} is too long for unix socket paths: set AIOS_E2E_DIR to a shorter one"
    )


def test_find_iso_takes_the_newest(tmp_path: Path) -> None:
    assert find_iso(tmp_path) is None
    old, new = tmp_path / "aios-2026.10.01-x86_64.iso", tmp_path / "aios-2026.11.03-x86_64.iso"
    old.write_text("")
    new.write_text("")
    os.utime(old, (1, 1))
    (tmp_path / "other.iso").write_text("")

    assert find_iso(tmp_path) == new


# --- serial.py -------------------------------------------------------------------------


def test_strip_ansi_keeps_only_the_text() -> None:
    raw = "\x1b]0;title\x07\x1b[1;36mtester@aios-e2e\x1b[0m \x1b(B\x1b7~\x1b8 %\r\n\x1b[?25lok\x1bc\tx"

    assert strip_ansi(raw) == "tester@aios-e2e ~ %\nok\tx"


def test_escapes_and_utf8_split_across_reads_are_reassembled(sock_path: Path) -> None:
    console = FakeConsole(sock_path, [b"Please enter \x1b[1", b";31mpass\xf0\x9f", b"\x94\x90phrase\x1b", b"[0m for disk aios:"])
    serial = connect(sock_path)

    serial.expect(r"for disk aios:", 5)

    assert serial.text == "Please enter pass\U0001f510phrase for disk aios:"
    serial.close()
    console.join()


def test_expect_matches_across_chunks_and_moves_past_each_match(sock_path: Path) -> None:
    console = FakeConsole(sock_path, [b"aios-e2e lo", b"gin: \n", b"aios-e2e login: \n"], gap=0.05)
    serial = connect(sock_path)

    first = serial.expect(r"login: ", 5)
    second = serial.expect(r"login: ", 5)

    assert first.start() < second.start()
    with pytest.raises(SerialTimeout):
        serial.expect(r"login: ", 0.3)
    serial.close()
    console.join()


def test_a_timeout_is_prompt_and_shows_the_last_output(sock_path: Path) -> None:
    console = FakeConsole(sock_path, [b"Booting AIOS\r\nsomething else\r\n"])
    serial = connect(sock_path)

    started = time.monotonic()
    with pytest.raises(SerialTimeout) as err:
        serial.expect(r"login: ", 0.5)

    assert time.monotonic() - started < 3
    assert "something else" in str(err.value)
    serial.close()
    console.join()


def test_a_closed_console_raises_serial_closed(sock_path: Path) -> None:
    console = FakeConsole(sock_path, [b"Power down.\r\n"], close_after_banner=True)
    serial = connect(sock_path)

    with pytest.raises(SerialClosed, match="Power down"):
        serial.expect(r"login: ", 5)
    console.join()


def test_the_last_output_before_the_console_closes_can_still_be_matched(sock_path: Path) -> None:
    console = FakeConsole(sock_path, [b"aios-install: rebooting into AIOS\r\n"], close_after_banner=True)
    serial = connect(sock_path)
    console.join()  # the output and the close are both waiting when the harness reads

    serial.expect(r"rebooting into AIOS", 5)
    with pytest.raises(SerialClosed, match="rebooting into AIOS"):
        serial.expect(r"login: ", 5)
    serial.close()


def test_a_reset_connection_raises_serial_closed() -> None:
    guest, peer = socket.socketpair()
    serial = Serial(guest)
    serial.send("typed but never read\r")
    # Closing with unread input makes the kernel report ECONNRESET to the harness.
    peer.close()

    with pytest.raises(SerialClosed, match="closed"):
        serial.expect(r"login: ", 5)
    serial.close()


def test_sending_to_a_closed_console_raises_serial_closed() -> None:
    guest, peer = socket.socketpair()
    serial = Serial(guest)
    peer.close()

    with pytest.raises(SerialClosed, match="closed"):
        serial.send("root\r")
    serial.close()


def test_a_large_send_completes_while_the_console_is_busy_printing(sock_path: Path) -> None:
    # The console prints 1 MB before it reads anything: the harness must read while it
    # writes, or both sides wait for the other to drain its socket.
    console = FakeConsole(sock_path, [b"y" * 1_000_000 + b"\r\nEND\r\n"])
    serial = connect(sock_path)
    payload = "x" * 1_000_000

    serial.sendline(payload)
    serial.expect(r"END", 5)
    serial.close()
    console.join()

    assert console.received == payload.encode() + b"\r"
    assert serial.text.startswith("y" * 1000)


class CountingPattern:
    """A pattern that counts how often expect searches with it."""

    def __init__(self, pattern: str):
        self._rx = re.compile(pattern)
        self.pattern = pattern
        self.searches = 0

    def search(self, text: str, pos: int = 0) -> re.Match[str] | None:
        self.searches += 1
        return self._rx.search(text, pos)


def test_expect_searches_again_only_when_new_output_arrived(sock_path: Path) -> None:
    console = FakeConsole(sock_path, [b"Booting\r\n", b"aios-e2e login: "], gap=1.2)
    serial = connect(sock_path)
    pattern = CountingPattern(r"login: ")

    serial.expect(pattern, 5)  # type: ignore[arg-type]

    # Once before any output, at most once per chunk: not every 0.5 s of silence.
    assert pattern.searches <= 3
    serial.close()
    console.join()


def test_many_small_reads_cost_linear_time_and_keep_the_text_in_order() -> None:
    # A 115200-baud console arrives in small reads; an hour of install output is MBs.
    # Copying the whole text on each read (str +=) took 8 s here; a chunk list takes 0.1 s.
    guest, peer = socket.socketpair()
    serial = Serial(guest)
    lines = [f"line {i:05} {'x' * 87}\r\n".encode() for i in range(30000)]

    started = time.monotonic()
    for line in lines:
        serial._feed(line)
    text = serial.text

    assert time.monotonic() - started < 2
    assert text == b"".join(lines).decode().replace("\r", "")
    assert serial.tail(5) == "xxxx\n"
    serial.close()
    peer.close()


def test_read_until_closed_returns_once_qemu_closes_the_console(sock_path: Path) -> None:
    console = FakeConsole(sock_path, [b"reboot: Restarting system\r\n"], close_after_banner=True)
    serial = connect(sock_path)

    serial.read_until_closed(5)

    assert serial.text.endswith("Restarting system\n")
    serial.close()
    console.join()


def test_read_until_closed_times_out_while_the_console_stays_open(sock_path: Path) -> None:
    console = FakeConsole(sock_path, [b"still running\r\n"])
    serial = connect(sock_path)

    with pytest.raises(SerialTimeout, match="still running"):
        serial.read_until_closed(0.5)
    serial.close()
    console.join()


def test_the_transcript_keeps_the_raw_bytes(sock_path: Path, tmp_path: Path) -> None:
    raw = b"\x1b[2J\x1b[HAIOS\r\n"
    console = FakeConsole(sock_path, [raw])
    serial = connect(sock_path, transcript=tmp_path / "serial.log")

    serial.expect(r"AIOS", 5)
    serial.close()
    console.join()

    assert (tmp_path / "serial.log").read_bytes() == raw


def test_wrap_and_parse_the_sentinel_protocol() -> None:
    line = wrap_command("cat /etc/hostname", 7)
    assert line == (
        "printf '__AIOS_E2E_BEGIN_%s__\\n' 7; { cat /etc/hostname ; } 2>&1; "
        "printf '__AIOS_E2E_END_%s_%s__\\n' 7 \"$?\""
    )
    echoed = line + "\n"
    assert parse_result(echoed, 7) is None
    assert parse_result(echoed + "__AIOS_E2E_BEGIN_7__\naios-e2e\n__AIOS_E2E_END_7_0__\n", 7) == (0, "aios-e2e")
    assert parse_result("__AIOS_E2E_BEGIN_8__\n__AIOS_E2E_END_8_1__\n", 8) == (1, "")
    assert parse_result("__AIOS_E2E_BEGIN_9__\nhalf", 9) is None
    with pytest.raises(ValueError):
        wrap_command("echo a\necho b", 1)


def test_shell_runs_numbered_commands_and_returns_status_and_output(sock_path: Path) -> None:
    console = FakeConsole(
        sock_path,
        on_line=shell_replies({
            "cat /etc/hostname": (0, "aios-e2e\r\n"),
            "touch /usr/x": (1, "touch: cannot touch '/usr/x': Read-only file system\r\n"),
        }),
    )
    shell = Shell(connect(sock_path))

    assert shell.check("cat /etc/hostname") == "aios-e2e"
    result = shell.run("touch /usr/x")
    assert (result.rc, result.output) == (1, "touch: cannot touch '/usr/x': Read-only file system")
    with pytest.raises(AssertionError, match="exited 127"):
        shell.check("tree")
    assert [SENTINEL_LINE.match(l).group(1) for l in console.lines] == ["1", "2", "3"]
    shell.serial.close()
    console.join()


def test_boot_menu_luks_and_login_are_answered_in_order(sock_path: Path) -> None:
    # dmesg -n 1: kernel messages on the console would land inside command output.
    setup = "stty -echo; dmesg -n 1; PS1=; PS2=; export SYSTEMD_PAGER= SYSTEMD_COLORS=0 PAGER=cat"
    # Each answer the harness types gets the next prompt as the reply.
    script = iter([
        b"\x1b[0m\xf0\x9f\x94\x90 Please enter passphrase or recovery key for disk aios: ",  # "2" + Enter
        b"\r\naios-e2e login: ",  # after the passphrase
        b"Password: ",  # after the user name
        b"\x1b[36mtester@aios-e2e\x1b[39m ~ % ",  # after the password: zsh
        b"",  # after exec bash
        b"==== AUTHENTICATING FOR org.freedesktop.systemd1.manage-units ====\r\nPassword: ",
        b"==== AUTHENTICATION COMPLETE ====\r\n",  # after the password for run0
    ])
    replies = shell_replies({setup: (0, "")})

    def on_line(line: str) -> bytes:
        return replies(line) if SENTINEL_LINE.match(line) else next(script)

    console = FakeConsole(sock_path, [b"  AIOS install medium (x86_64, UEFI, serial console)\r\n"], on_line=on_line)
    serial = connect(sock_path)

    choose_boot_entry(serial, "AIOS install medium (x86_64, UEFI, serial console)", "2", 5)
    unlock_luks(serial, "e2e-luks-passphrase", 5)
    shell = login_root_shell(serial, "tester", "e2e-user-pass", "aios-e2e", 5)

    assert console.lines[:7] == [
        "2",
        "e2e-luks-passphrase",
        "tester",
        "e2e-user-pass",
        "exec bash --norc --noprofile --noediting",
        "run0 bash --norc --noprofile --noediting",
        "e2e-user-pass",
    ]
    assert shell.count == 1
    serial.close()
    console.join()


# --- test_e2e.py: its helpers, the boot menu position and the manifest edits -------------

from .serial import SerialFailure  # noqa: E402
from .test_e2e import (  # noqa: E402
    ADD_FAIL_HEALTH,
    ADD_TREE,
    ISO_SERIAL_KEY,
    ISO_SERIAL_TITLE,
    MANIFEST,
    Machine,
    expect_install,
    has_option,
    should_delete_vm,
)

GEN1_BUILT = r"gen-0001 built in /mnt/aios-top"


def test_a_mount_option_is_matched_as_a_whole_element_of_findmnts_options() -> None:
    assert has_option("ro,nosuid,nodev,relatime\n", "ro")
    assert has_option("rw,relatime,ro", "ro")
    assert not has_option("rw,relatime,errors=remount-ro", "ro")
    assert not has_option("rw,nosuid,nodev,relatime", "ro")
    # Two lines (stacked mounts) are not one bind.
    assert not has_option("ro,relatime\nrw,relatime", "ro")


def test_the_vm_disk_is_deleted_only_after_a_passing_run_without_keep_vm() -> None:
    assert should_delete_vm(keep_vm=False, failures=0)
    assert not should_delete_vm(keep_vm=True, failures=0)
    # A failed run keeps the disk and the TPM state to inspect what went wrong.
    assert not should_delete_vm(keep_vm=False, failures=1)
    assert not should_delete_vm(keep_vm=True, failures=3)


def test_the_install_wait_fails_at_once_on_an_error_line_and_quotes_all_of_it(sock_path: Path) -> None:
    console = FakeConsole(
        sock_path,
        [
            b"aios-install: step 1/13: preflight\r\n",
            b"aios-install: error: /dev/vda is 10 GiB",  # the rest of the line comes later
            b"; AIOS needs at least 20 GiB\r\n",
        ],
        gap=0.2,
    )
    serial = connect(sock_path)

    started = time.monotonic()
    with pytest.raises(SerialFailure) as err:
        expect_install(serial, GEN1_BUILT, 60)

    assert time.monotonic() - started < 5
    assert str(err.value).startswith(
        "aios-install: error: /dev/vda is 10 GiB; AIOS needs at least 20 GiB (while waiting for"
    )
    serial.close()
    console.join()


def test_the_install_wait_fails_on_the_exit_traps_line_for_a_failed_command(sock_path: Path) -> None:
    # A command that fails under set -e gets no "error:" line, only the trap's (cleanup.sh).
    console = FakeConsole(
        sock_path, [b"aios-install: step 5/13: bootstrap\r\naios-install: step 5 (bootstrap) failed (exit 1)\r\n"]
    )
    serial = connect(sock_path)

    with pytest.raises(SerialFailure, match=r"^aios-install: step 5 \(bootstrap\) failed \(exit 1\) "):
        expect_install(serial, GEN1_BUILT, 5)
    serial.close()
    console.join()


def test_the_install_wait_returns_on_progress_and_the_next_wait_sees_a_later_error(sock_path: Path) -> None:
    console = FakeConsole(
        sock_path,
        [b"aios-install: step 5/13: bootstrap\r\ngen-0001 built in /mnt/aios-top\r\naios-install: error: sbctl failed\r\n"],
    )
    serial = connect(sock_path)

    assert expect_install(serial, GEN1_BUILT, 5).group(0) == "gen-0001 built in /mnt/aios-top"
    with pytest.raises(SerialFailure, match="^aios-install: error: sbctl failed "):
        expect_install(serial, r"aios-install: installation complete", 5)
    serial.close()
    console.join()


def test_the_serial_entry_is_the_second_in_the_iso_boot_menu() -> None:
    entries = REPO / "iso" / "efiboot" / "loader" / "entries"
    keys = {}
    for entry in entries.glob("*.conf"):
        text = entry.read_text()
        keys[re.search(r"^sort-key\s+(\S+)", text, re.M).group(1)] = re.search(
            r"^title\s+(.*)$", text, re.M
        ).group(1)
    titles = [keys[k] for k in sorted(keys)]

    assert titles[int(ISO_SERIAL_KEY) - 1].replace("%ARCH%", "x86_64") == ISO_SERIAL_TITLE


def test_the_manifest_edits_apply_once_to_the_installed_manifest(tmp_path: Path) -> None:
    template = (REPO / "manifest" / "manifest.toml").read_text()
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(
        template.replace("@HOSTNAME@", "aios-e2e")
        .replace("@USERNAME@", "tester")
        .replace("@TIMEZONE@", "UTC")
        .replace("@EXTRA_CMDLINE@", '"console=ttyS0,115200"')
    )

    for edit, expected in (
        (ADD_TREE, '"tree",'),
        (ADD_FAIL_HEALTH, '"aios.test.fail_health=1"]'),
    ):
        cmd = edit.replace(MANIFEST, str(manifest))
        subprocess.run(["sh", "-c", cmd], check=True)
        assert manifest.read_text().count(expected) == 1, cmd
