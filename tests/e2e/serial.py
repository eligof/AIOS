"""Expect-style driving of the VM's serial console over QEMU's unix socket (spec §9).

`Serial` keeps two views of what the guest printed: the raw bytes in a transcript file,
and `text`, decoded and stripped of terminal escape sequences and carriage returns, which
`expect` searches. It reads the console while it writes to it, so a guest that is busy
printing can't block the harness. `Shell` runs one command at a time with a sentinel
protocol:

    printf '__AIOS_E2E_BEGIN_%s__\\n' 7; { CMD ; } 2>&1; printf '__AIOS_E2E_END_%s_%s__\\n' 7 "$?"

The typed line itself only ever holds `%s`, so an echoed command can never look like a
result. The login helpers get from a LUKS prompt to a root bash with echo off.
"""

from __future__ import annotations

import codecs
import re
import select
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

# OSC (title etc.), CSI (colors, cursor), charset designation, then any other 2-byte escape.
_ESCAPE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[()*+][0-9A-Za-z]|\x1b[0-~]")
# An escape sequence cut off at the end of a chunk.
_PARTIAL = re.compile(r"\x1b(?:\][^\x07\x1b]*|\[[0-?]*[ -/]*|[()*+])?$")
# Control characters except tab and newline (this drops CR and stray ESC).
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
# Once output arrives, keep reading until it pauses for _QUIET seconds (for at most _BATCH):
# QEMU's UART writes the console out a byte at a time, and expect searches once per batch.
_QUIET = 0.02
_BATCH = 0.25


def strip_ansi(text: str) -> str:
    """Text without escape sequences, carriage returns or other control characters."""
    return _CONTROL.sub("", _ESCAPE.sub("", text))


class SerialTimeout(AssertionError):
    """The expected text did not appear in time."""


class SerialClosed(AssertionError):
    """QEMU closed the serial socket (the VM is gone)."""


class Serial:
    """One connection to the guest's serial console."""

    def __init__(
        self,
        sock: socket.socket,
        transcript: Path | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._sock = sock
        self._sock.setblocking(False)
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._partial = ""
        self._clock = clock
        self._log = open(transcript, "ab") if transcript else None
        # `text` is _joined plus the chunks read since it was last asked for: appending to
        # one str would copy all of it on every read.
        self._joined = ""
        self._chunks: list[str] = []
        self.pos = 0

    @classmethod
    def connect(cls, path: Path, transcript: Path | None = None, timeout: float = 30.0) -> Serial:
        """Connect to QEMU's serial socket, retrying until it exists."""
        deadline = time.monotonic() + timeout
        while True:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.connect(str(path))
                return cls(sock, transcript)
            except (FileNotFoundError, ConnectionRefusedError):
                sock.close()
                if time.monotonic() > deadline:
                    raise SerialTimeout(f"no serial console at {path} after {timeout:.0f}s") from None
                time.sleep(0.1)

    @property
    def text(self) -> str:
        """Everything the guest printed so far, decoded, without escapes or CRs."""
        if self._chunks:
            self._joined = "".join([self._joined, *self._chunks])
            self._chunks.clear()
        return self._joined

    def _feed(self, data: bytes) -> None:
        if self._log:
            self._log.write(data)
            self._log.flush()
        chunk = self._partial + self._decoder.decode(data)
        partial = _PARTIAL.search(chunk)
        cut = partial.start() if partial else len(chunk)
        self._partial = chunk[cut:]
        text = strip_ansi(chunk[:cut])
        if text:
            self._chunks.append(text)

    def _closed(self, err: OSError | None = None) -> SerialClosed:
        why = f" ({err.strerror})" if err else ""
        return SerialClosed(f"the serial console closed{why}; last output:\n{self.tail()}")

    def _recv(self) -> None:
        """Read what the socket holds; select said it is readable."""
        try:
            data = self._sock.recv(65536)
        except BlockingIOError:
            return
        except (BrokenPipeError, ConnectionResetError) as err:
            raise self._closed(err) from err
        if not data:
            raise self._closed()
        self._feed(data)

    def _read(self, timeout: float) -> bool:
        """Wait up to `timeout` for output, then read until it pauses. True if any came."""
        ready, _, _ = select.select([self._sock], [], [], max(0.0, timeout))
        if not ready:
            return False
        batch_end = time.monotonic() + _BATCH
        while ready:
            self._recv()
            wait = min(_QUIET, batch_end - time.monotonic())
            if wait <= 0:
                break
            ready, _, _ = select.select([self._sock], [], [], wait)
        return True

    def expect(self, pattern: str | re.Pattern[str], timeout: float) -> re.Match[str]:
        """Wait for `pattern` in the text after the previous match, and move past it."""
        rx = re.compile(pattern) if isinstance(pattern, str) else pattern
        deadline = self._clock() + timeout
        fresh = True
        while True:
            if fresh:
                match = rx.search(self.text, self.pos)
                if match:
                    self.pos = match.end()
                    return match
            left = deadline - self._clock()
            if left <= 0:
                raise SerialTimeout(
                    f"no {rx.pattern!r} within {timeout:.0f}s; last output:\n{self.tail()}"
                )
            fresh = self._read(min(left, 0.5))

    def tail(self, chars: int = 3000) -> str:
        return self.text[-chars:]

    def send(self, text: str, timeout: float = 60.0) -> None:
        """Type `text`, reading the console while the socket is full: a guest that is busy
        printing takes input only once its output is read."""
        data = memoryview(text.encode())
        deadline = self._clock() + timeout
        while data:
            left = deadline - self._clock()
            if left <= 0:
                raise SerialTimeout(
                    f"the console took no input for {timeout:.0f}s; last output:\n{self.tail()}"
                )
            readable, writable, _ = select.select([self._sock], [self._sock], [], min(left, 0.5))
            if writable:
                try:
                    data = data[self._sock.send(data):]
                except BlockingIOError:
                    pass
                except (BrokenPipeError, ConnectionResetError) as err:
                    raise self._closed(err) from err
            if readable:
                self._recv()

    def sendline(self, text: str) -> None:
        self.send(text + "\r")

    def close(self) -> None:
        self._sock.close()
        if self._log:
            self._log.close()
            self._log = None


def wrap_command(cmd: str, n: int) -> str:
    """The line that runs `cmd` as command number `n` of the sentinel protocol."""
    if any(c in cmd for c in "\n\r"):
        raise ValueError("a command must be one line")
    return (
        f"printf '__AIOS_E2E_BEGIN_%s__\\n' {n}; {{ {cmd} ; }} 2>&1; "
        f"printf '__AIOS_E2E_END_%s_%s__\\n' {n} \"$?\""
    )


def result_pattern(n: int) -> re.Pattern[str]:
    return re.compile(rf"__AIOS_E2E_BEGIN_{n}__\n(.*?)__AIOS_E2E_END_{n}_(\d+)__", re.S)


def parse_result(text: str, n: int) -> tuple[int, str] | None:
    """(exit status, output) of command `n` in `text`, or None if it has not finished."""
    match = result_pattern(n).search(text)
    if not match:
        return None
    return int(match.group(2)), match.group(1).rstrip("\n")


@dataclass(frozen=True)
class Result:
    rc: int
    output: str


class Shell:
    """A shell on the serial console that runs commands with the sentinel protocol."""

    def __init__(self, serial: Serial):
        self.serial = serial
        self.count = 0

    def run(self, cmd: str, timeout: float = 120) -> Result:
        self.count += 1
        self.serial.sendline(wrap_command(cmd, self.count))
        match = self.serial.expect(result_pattern(self.count), timeout)
        return Result(int(match.group(2)), match.group(1).rstrip("\n"))

    def check(self, cmd: str, timeout: float = 120) -> str:
        """Run `cmd`; it must exit 0. Returns its output."""
        result = self.run(cmd, timeout)
        if result.rc != 0:
            raise AssertionError(f"`{cmd}` exited {result.rc}:\n{result.output}")
        return result.output

    def send_only(self, cmd: str) -> None:
        """Type `cmd` without waiting for a result (reboot)."""
        self.serial.sendline(cmd)


def choose_boot_entry(serial: Serial, title: str, key: str, timeout: float) -> None:
    """In the systemd-boot menu, wait for the entry `title`, then select entry `key` and boot."""
    serial.expect(re.escape(title), timeout)
    time.sleep(0.5)
    serial.send(key)
    time.sleep(0.5)
    serial.send("\r")


def unlock_luks(serial: Serial, passphrase: str, timeout: float) -> None:
    """Answer systemd-cryptsetup's prompt in the initrd. With the recovery key enrolled it
    reads "Please enter passphrase or recovery key for disk aios:"."""
    serial.expect(r"Please enter [a-z ]+ for disk ", timeout)
    time.sleep(0.5)
    serial.sendline(passphrase)


def login_root_shell(serial: Serial, user: str, password: str, hostname: str, timeout: float) -> Shell:
    """Log in as `user` on the getty, then `run0` a root bash with echo and prompts off.
    The root account itself is locked (spec §4.3 step 6), so root goes through polkit."""
    serial.expect(rf"{re.escape(hostname)} login: ", timeout)
    serial.sendline(user)
    serial.expect(r"Password: ", 60)
    serial.sendline(password)
    serial.expect(rf"{re.escape(user)}@{re.escape(hostname)}", 60)
    serial.sendline("exec bash --norc --noprofile --noediting")
    serial.sendline("run0 bash --norc --noprofile --noediting")
    serial.expect(r"Password: ", 60)
    serial.sendline(password)
    serial.expect(r"AUTHENTICATION COMPLETE", 60)
    shell = Shell(serial)
    # dmesg -n 1: kernel messages on the console would land inside command output.
    shell.check("stty -echo; dmesg -n 1; PS1=; PS2=; export SYSTEMD_PAGER= SYSTEMD_COLORS=0 PAGER=cat", 60)
    return shell
