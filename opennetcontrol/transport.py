"""Device sessions: SSH (paramiko, pinned host keys) and an in-process simulator session."""
from __future__ import annotations

import base64
import hashlib
import logging
import re
import socket
import time

import paramiko

from .models import DriverError
from . import validation

log = logging.getLogger("opennetcontrol.transport")

MAX_OUTPUT = 8 * 1024 * 1024        # a device (or an attacker impersonating one) must not be able to exhaust collector memory/CPU
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[=>]|\r")


class HostKeyMismatch(DriverError):
    pass


class _PinPolicy(paramiko.MissingHostKeyPolicy):
    """Trust-on-first-use, then pin. A changed key is a hard failure (possible MITM)."""

    def __init__(self, pinned: str | None):
        self.pinned = pinned
        self.seen: str | None = None

    def missing_host_key(self, client, hostname, key):
        fp = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        self.seen = fp
        if self.pinned and self.pinned != fp:
            raise HostKeyMismatch(f"host key mismatch for {hostname}: expected {self.pinned}, got {fp}")


class SSHSession:
    def __init__(self, address, port, username, secret, prompt_re, pinned_key=None, timeout=10, allow_loopback=False):
        validation.check_target_address(address, allow_loopback)
        self.prompt_re = re.compile(prompt_re)
        self.timeout = timeout
        self.policy = _PinPolicy(pinned_key)
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(self.policy)
        try:
            self.client.connect(address, port=port, username=username, password=secret, timeout=timeout,
                                banner_timeout=timeout, auth_timeout=timeout, look_for_keys=False, allow_agent=False)
        except HostKeyMismatch:
            raise
        except (paramiko.SSHException, OSError, socket.timeout) as e:
            raise DriverError(f"ssh connect failed: {type(e).__name__}: {str(e)[:120]}")
        self.host_key = self.policy.seen
        self.chan = self.client.invoke_shell(width=250, height=500)
        self.chan.settimeout(self.timeout)
        self._read_until_prompt()

    def _read_until_prompt(self) -> str:
        buf, end = "", time.time() + self.timeout
        while time.time() < end:
            try:
                data = self.chan.recv(65535)
            except socket.timeout:
                break
            if not data:
                raise DriverError("connection closed by device")
            buf += ANSI.sub("", data.decode("utf-8", "replace"))
            if len(buf) > MAX_OUTPUT:
                raise DriverError("device output exceeds the 8 MiB safety limit")
            # only the tail can hold the prompt: inspecting the whole buffer on every chunk is quadratic
            if self.prompt_re.search(buf[-1024:].rstrip("\n").split("\n")[-1]):
                return buf
        raise DriverError("timeout waiting for device prompt")

    def run(self, cmd: str) -> str:
        if "\n" in cmd or "\r" in cmd:
            raise DriverError("refusing multi-line command")
        self.chan.send(cmd + "\n")
        out = self._read_until_prompt()
        lines = out.split("\n")
        if lines and cmd.strip() in lines[0]:
            lines = lines[1:]
        return "\n".join(lines[:-1]).strip("\n")

    def close(self):
        try:
            self.client.close()
        except Exception:
            log.debug("ssh close failed", exc_info=True)

    def __enter__(self): return self
    def __exit__(self, *a): self.close()


class SimSession:
    host_key = None

    def __init__(self, sim):
        if not sim.reachable or sim.reloaded:
            raise DriverError("device unreachable (simulated)")
        self.sim = sim

    def run(self, cmd: str) -> str:
        if "\n" in cmd or "\r" in cmd:
            raise DriverError("refusing multi-line command")
        try:
            return self.sim.execute(cmd)
        except ConnectionError as e:
            raise DriverError(str(e))

    def close(self): pass
    def __enter__(self): return self
    def __exit__(self, *a): self.close()
