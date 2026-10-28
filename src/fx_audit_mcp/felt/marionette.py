#!/usr/bin/env python3
"""Minimal Marionette client: just enough to drive the Felt sign-in form.

Deliberately not `marionette_driver`. That package lives in the Firefox tree
and pulls mozrunner/mozprofile with it; this needs four commands, and the wire
protocol is small enough that a self-contained implementation is cheaper to
carry than the dependency.

Protocol: length-prefixed JSON over TCP -- `<len>:<json>` where the payload is
`[type, msgid, name, params]`. The server sends a handshake object first.
"""

from __future__ import annotations

import contextlib
import json
import socket
import time


class Marionette:
    def __init__(self, port: int, host: str = "127.0.0.1", timeout: float = 60.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.sock: socket.socket | None = None
        self._msgid = 0
        self._buf = b""

    # -- wire ------------------------------------------------------------

    def _recv_packet(self) -> dict:
        assert self.sock
        while b":" not in self._buf:
            chunk = self.sock.recv(8192)
            if not chunk:
                raise ConnectionError("marionette closed the connection")
            self._buf += chunk
        length, _, rest = self._buf.partition(b":")
        n = int(length)
        while len(rest) < n:
            chunk = self.sock.recv(8192)
            if not chunk:
                raise ConnectionError("marionette closed mid-packet")
            rest += chunk
        self._buf = rest[n:]
        return json.loads(rest[:n])

    def _send(self, name: str, params: dict | None = None) -> object:
        assert self.sock
        self._msgid += 1
        payload = json.dumps([0, self._msgid, name, params or {}]).encode()
        self.sock.sendall(str(len(payload)).encode() + b":" + payload)
        while True:
            pkt = self._recv_packet()
            # Responses are [1, msgid, error, result]
            if isinstance(pkt, list) and len(pkt) == 4 and pkt[1] == self._msgid:
                _, _, err, result = pkt
                if err:
                    raise RuntimeError(f"{name} failed: {err}")
                return result

    # -- session ---------------------------------------------------------

    def connect(self, attempts: int = 30) -> dict:
        last: Exception | None = None
        for _ in range(attempts):
            try:
                s = socket.create_connection(
                    (self.host, self.port), timeout=self.timeout
                )
                s.settimeout(self.timeout)
                self.sock = s
                return self._recv_packet()
            except OSError as exc:  # not listening yet
                last = exc
                time.sleep(1)
        raise ConnectionError(f"could not reach marionette on {self.port}: {last}")

    def new_session(self) -> object:
        return self._send("WebDriver:NewSession", {"strictFileInteractability": False})

    def set_context(self, context: str) -> None:
        self._send("Marionette:SetContext", {"value": context})

    def execute_script(self, script: str, args: list | None = None) -> object:
        return self._send(
            "WebDriver:ExecuteScript", {"script": script, "args": args or []}
        )

    def get_page_source(self) -> object:
        return self._send("WebDriver:GetPageSource")

    def close(self) -> None:
        if self.sock:
            with contextlib.suppress(Exception):
                self._send("Marionette:Quit", {"flags": ["eForceQuit"]})
            self.sock.close()
            self.sock = None
