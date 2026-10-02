"""Run simulated devices behind real SSH servers (paramiko) so the SSH transport can be exercised.

    python lab/ssh_lab.py            # starts every simulator on 127.0.0.1:2201+
"""
from __future__ import annotations

import logging
import secrets
import socket
import sys
import threading
import os

import paramiko

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from opennetcontrol.lab import build_lab, LAB  # noqa: E402

HOST_KEY = paramiko.RSAKey.generate(2048)


class _Server(paramiko.ServerInterface):
    def __init__(self, user, password):
        self.user, self.password = user, password

    def check_auth_password(self, u, p):
        return paramiko.AUTH_SUCCESSFUL if (u, p) == (self.user, self.password) else paramiko.AUTH_FAILED

    def get_allowed_auths(self, u): return "password"
    def check_channel_request(self, kind, chanid): return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_shell_request(self, ch): return True
    def check_channel_pty_request(self, *a): return True


def _serve(sim, client, user, password, hostkey):
    t = paramiko.Transport(client)
    t.add_server_key(hostkey)
    try:
        t.start_server(server=_Server(user, password))
        ch = t.accept(20)
        if ch is None:
            return
        ch.sendall(sim.prompt())
        buf = ""
        while True:
            d = ch.recv(1024)
            if not d:
                break
            for c in d.decode("utf-8", "replace"):
                if c in "\r\n":
                    line, buf = buf, ""
                    ch.sendall("\r\n")
                    try:
                        out = sim.execute(line) if line.strip() else ""
                    except ConnectionError:
                        ch.close(); return
                    if out:
                        ch.sendall(out.replace("\n", "\r\n") + "\r\n")
                    ch.sendall(sim.prompt())
                else:
                    buf += c
    except Exception:
        log.debug("lab session ended with error", exc_info=True)
    finally:
        t.close()


log = logging.getLogger("lab.ssh")
# No fixed default credential: generated per process (or supply ONC_LAB_PASSWORD). Tests import ssh_lab.PASSWORD.
PASSWORD = os.environ.get("ONC_LAB_PASSWORD") or secrets.token_urlsafe(16)


def start(sim, port, user="admin", password=None, hostkey=None, bind="127.0.0.1"):
    password = password or PASSWORD
    sock = socket.socket(); sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, port)); sock.listen(20)

    def loop():
        while True:
            try:
                c, _ = sock.accept()
            except OSError:
                return
            threading.Thread(target=_serve, args=(sim, c, user, password, hostkey or HOST_KEY), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return sock


if __name__ == "__main__":
    build_lab()
    for n, name in enumerate(LAB):
        start(LAB[name], 2201 + n)
        print(f"{name:14s} {LAB[name].platform:20s} ssh admin@127.0.0.1 -p {2201+n}  (password: {PASSWORD})")
    threading.Event().wait()
