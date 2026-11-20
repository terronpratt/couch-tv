#!/usr/bin/env python3
"""Privately provision an LG Developer Mode profile into systemd's credential store.

Run the interactive side in a real terminal. No passphrase or key is printed, written
to a project file, or included in command arguments. The receiver runs as couchtv.
"""
import argparse
import base64
import getpass
import ipaddress
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import urllib.request
import warnings

ROOT = Path(__file__).resolve().parents[1]


def receive():
    sys.path.insert(0, str(ROOT / "bridge"))
    from credential_store import configured_store
    from cryptography.hazmat.primitives import serialization

    payload = json.loads(sys.stdin.buffer.read(65537))
    device = payload[0]
    key = base64.b64decode(device["privateKey"], validate=True)
    password = device["passphrase"].encode()
    if len(password) != 6 or device["username"] != "prisoner" or device["port"] != 9922:
        raise ValueError("invalid device profile")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", device["name"]):
        raise ValueError("invalid device name")
    ipaddress.ip_address(device["host"])
    # Check the passphrase in memory before keeping anything. LG uses PEM on
    # older models and may use OpenSSH on newer ones.
    loader = (serialization.load_ssh_private_key if key.startswith(b"-----BEGIN OPENSSH")
              else serialization.load_pem_private_key)
    loader(key, password=password)
    store = configured_store()
    if store is None:
        raise RuntimeError("encrypted storage is required")
    store.write("lg-ares-config", json.dumps(payload))
    print("LG Developer Mode credentials saved in encrypted OS storage.")


def interactive(args):
    ipaddress.ip_address(args.tv)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.server):
        raise ValueError("invalid server address")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", args.device):
        raise ValueError("invalid device name")
    if not sys.stdin.isatty():
        raise RuntimeError("use a private interactive terminal")
    status = ROOT / "build" / "lg-provision-status.json"
    status.parent.mkdir(exist_ok=True)
    status.write_text(json.dumps({"ok": False, "state": "awaiting-entry"}) + "\n")
    status.chmod(0o600)
    print("CouchTV LG pairing: enter the six characters shown beside Passphrase on your TV.")
    print("Typing is hidden. Your streaming and LG account passwords are not needed.")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        password = getpass.getpass("TV passphrase (hidden): ")
    if len(password) != 6 or not password.isascii() or not password.isalnum():
        raise ValueError("the TV passphrase must contain six letters or numbers")
    with urllib.request.urlopen(f"http://{args.tv}:9991/webos_rsa", timeout=10) as response:
        key = response.read(32769)
    if len(key) > 32768 or b"PRIVATE KEY-----" not in key:
        raise ValueError("Key Server did not return an SSH key")
    device = [{"name": args.device, "profile": "tv", "host": args.tv, "port": 9922,
               "username": "prisoner", "privateKey": base64.b64encode(key).decode(),
               "passphrase": password, "files": "sftp", "default": True,
               "description": "CouchTV LG"}]
    remote = ["pct", "exec", str(args.container), "--", "runuser", "-u", "couchtv", "--",
              "env", "COUCHTV_CREDENTIAL_BACKEND=systemd", "COUCHTV_CREDENTIAL_SCOPE=user",
              "COUCHTV_CREDENTIAL_DIR=/home/couchtv/.local/share/couchtv-credentials",
              "/home/couchtv/couch-tv-venv/bin/python",
              "/home/couchtv/couch-tv/scripts/provision-lg-secure.py", "--receive"]
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
         "-o", "ConnectTimeout=10", "root@" + args.server, shlex.join(remote)],
        input=json.dumps(device).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=45, check=False,
    )
    if result.returncode:
        raise RuntimeError("Pairing details could not be validated and encrypted. Check the TV passphrase and try again.")
    print("Saved securely. You can return to the CouchTV chat.")
    status.write_text(json.dumps({"ok": True, "device": args.device}) + "\n")
    status.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receive", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--tv", help="TV address")
    parser.add_argument("--server", help="Proxmox host address")
    parser.add_argument("--container", type=int, help="CouchTV container number")
    parser.add_argument("--device", help="ares device name (the TV id)")
    args = parser.parse_args()
    missing = [n for n in ('--tv', '--server', '--container', '--device') if getattr(args, n.lstrip('-')) is None]
    if not args.receive and missing:
        parser.error("the following arguments are required: " + ", ".join(missing))
    try:
        receive() if args.receive else interactive(args)
        return 0
    except (Exception, KeyboardInterrupt):
        # Do not include exception text: libraries and remote diagnostics can
        # contain credential material. No traceback or failed-command echo.
        print("Secure LG provisioning did not complete. Check Key Server and the TV passphrase, then try again.", file=sys.stderr)
        if not args.receive:
            try:
                status = ROOT / "build" / "lg-provision-status.json"
                status.write_text(json.dumps({"ok": False, "state": "failed"}) + "\n")
                status.chmod(0o600)
            except OSError:
                pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
