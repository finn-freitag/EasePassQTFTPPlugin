#!/usr/bin/env python3
"""Test servers for core/tests/servers.rs (and for trying the plugin by hand).

    servers.py <directory to serve>

Starts, on 127.0.0.1 with free ports:
  - an FTP server and an FTPS server (pyftpdlib; FTPS needs encrypted control and data)
  - four SFTP servers (asyncssh) that differ in host key type and offered algorithms
Prints one line of JSON with ports and host key fingerprints, then serves until killed.
User "tester", password "secret pass".
"""
import asyncio
import json
import os
import subprocess
import sys
import threading

import asyncssh
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.servers import FTPServer

ROOT = os.path.abspath(sys.argv[1])
USER, PASSWORD = "tester", "secret pass"
# pyftpdlib servers share one event loop: all are created first, then one thread serves them.
FTP_SERVERS = []


def start_ftp(tls: bool) -> int:
    authorizer = DummyAuthorizer()
    authorizer.add_user(USER, PASSWORD, ROOT, perm="elradfmwMT")

    if tls:
        class Handler(TLS_FTPHandler):
            pass
        certificate = os.path.join(ROOT, "..", "ftps-cert.pem")
        if not os.path.exists(certificate):
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj",
                 "/CN=ftps.conformance.test", "-addext", "subjectAltName=DNS:ftps.conformance.test,DNS:localhost",
                 "-keyout", certificate, "-out", certificate],
                check=True, capture_output=True)
        Handler.certfile = certificate
        Handler.tls_control_required = True
        Handler.tls_data_required = True
    else:
        class Handler(FTPHandler):
            pass
    Handler.authorizer = authorizer
    server = FTPServer(("127.0.0.1", 0), Handler)
    FTP_SERVERS.append(server)
    return server.socket.getsockname()[1]


class Server(asyncssh.SSHServer):
    def __init__(self, interactive: bool):
        self.interactive = interactive

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return not self.interactive

    def validate_password(self, username, password):
        return username == USER and password == PASSWORD

    def kbdint_auth_supported(self):
        return self.interactive

    def get_kbdint_challenge(self, username, lang, submethods):
        return "", "", "en", [("Password: ", False)]

    def validate_kbdint_response(self, username, responses):
        return username == USER and list(responses) == [PASSWORD]


async def start_sftp(key_type: str, interactive: bool = False, **algorithms):
    key = asyncssh.generate_private_key(key_type, **({"key_size": 2048} if key_type == "ssh-rsa" else {}))
    server = await asyncssh.listen(
        "127.0.0.1", 0,
        server_factory=lambda: Server(interactive),
        server_host_keys=[key],
        sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=ROOT.encode()),
        **algorithms)
    return {"port": server.get_port(), "fingerprint": key.get_fingerprint()}


async def main():
    result = {"user": USER, "password": PASSWORD, "ftp": start_ftp(False)}
    try:
        result["ftps"] = start_ftp(True)
    except Exception as error:  # no openssl program: FTPS is simply not offered
        print(f"no FTPS server: {error}", file=sys.stderr)
    threading.Thread(target=FTP_SERVERS[0].serve_forever, daemon=True).start()
    result["sftp"] = {
        # What a current server offers: Ed25519 key, chacha20-poly1305, curve25519.
        "default": await start_sftp("ssh-ed25519"),
        # An older setup: RSA key, classic Diffie-Hellman, AES-256 in counter mode.
        "rsa-dh-aes256": await start_sftp(
            "ssh-rsa", kex_algs=["diffie-hellman-group14-sha256"], encryption_algs=["aes256-ctr"],
            mac_algs=["hmac-sha2-256"]),
        "ecdsa-aes128": await start_sftp(
            "ecdsa-sha2-nistp256", kex_algs=["curve25519-sha256"], encryption_algs=["aes128-ctr"],
            mac_algs=["hmac-sha2-512"]),
        # Password only through "keyboard-interactive" (common with PAM).
        "interactive": await start_sftp("ssh-ed25519", interactive=True),
    }
    print(json.dumps(result), flush=True)
    await asyncio.Event().wait()


asyncio.run(main())
