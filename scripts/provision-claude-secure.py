#!/usr/bin/env python3
"""Privately save a Claude subscription token in the CouchTV server's OS credential store.

In a separate private Terminal, run the already-installed Claude Code command:
    claude setup-token
Approve its browser sign-in yourself, then copy the subscription token it produces.
Run this helper in Terminal and paste the token at its hidden prompt:
    python3 scripts/provision-claude-secure.py --server <proxmox address> --container <id>

Do not paste the token into chat, a shell command, a project file, or an .env file.
This helper never signs in, generates tokens, or changes Claude's configuration.
"""
import argparse
import getpass
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import warnings

ROOT = Path(__file__).resolve().parents[1]
TOKEN_PATTERN = re.compile(r"sk-ant-oat[0-9]{2}-[A-Za-z0-9_-]{20,4096}\Z")


def validate_token(value):
    if not isinstance(value, str) or not TOKEN_PATTERN.fullmatch(value):
        raise ValueError("a Claude subscription OAuth token is required")
    return value


def read_hidden_token(max_lines=8):
    """`claude setup-token` wraps its token over two lines, and copying it keeps the line break,
    while a hidden prompt stops at the first one: a first try saved only the first 79 characters.
    So keep reading hidden lines and join them, until an empty line (Return on its own)."""
    parts = [getpass.getpass("Claude subscription token (hidden): ").strip()]
    while parts[-1] and len(parts) < max_lines:
        parts.append(getpass.getpass("Rest of the token if it wrapped, else just press Return (hidden): ").strip())
    return "".join(parts)


def write_status(state, *, ok=False, container=None):
    """Only fixed, nonsecret status fields; atomically invalidate any previous success."""
    directory = ROOT / "build"
    directory.mkdir(exist_ok=True)
    payload = {"ok": ok, "state": state}
    if container is not None:
        payload["container"] = container
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".claude-status-", dir=directory)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, directory / "claude-provision-status.json")
        temporary = None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def receive():
    # stdin belongs to the encrypted SSH transport, not a terminal or a token file.
    if sys.stdin.isatty():
        raise RuntimeError("receiver requires a private input pipe")
    raw = sys.stdin.buffer.read(8193)
    if len(raw) > 8192:
        raise ValueError("subscription credential exceeds the size limit")
    token = validate_token(raw.decode("utf-8"))
    sys.path.insert(0, str(ROOT / "bridge"))
    from credential_store import configured_store
    store = configured_store()
    if store is None:
        raise RuntimeError("encrypted credential storage is required")
    store.write("claude-oauth", token)
    print("Claude subscription credential saved in encrypted OS storage.")


def interactive(args):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", args.server):
        raise ValueError("invalid server address")
    if not 100 <= args.container <= 999999999:
        raise ValueError("invalid container number")
    if not sys.stdin.isatty():
        raise RuntimeError("use a private interactive terminal")
    write_status("awaiting-entry")
    print("CouchTV Claude subscription setup")
    print("In a separate private Terminal, run:")
    print("  claude setup-token")
    print("Approve Claude's browser sign-in yourself, then copy the subscription token it produces.")
    print("Paste it below. Typing is hidden; do not paste it into chat or save it in a file.")
    print("If the token was on two lines, it asks for the rest: paste it, then press Return on the empty prompt.")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        token = validate_token(read_hidden_token())
    remote = [
        "pct", "exec", str(args.container), "--", "runuser", "-u", "couchtv", "--",
        "env", "COUCHTV_CREDENTIAL_BACKEND=systemd", "COUCHTV_CREDENTIAL_SCOPE=user",
        "COUCHTV_CREDENTIAL_DIR=/home/couchtv/.local/share/couchtv-credentials",
        "/home/couchtv/couch-tv-venv/bin/python",
        "/home/couchtv/couch-tv/scripts/provision-claude-secure.py", "--receive",
    ]
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
         "-o", "ConnectTimeout=10", "root@" + args.server, shlex.join(remote)],
        input=token.encode("utf-8"), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=45, check=False,
    )
    if result.returncode:
        raise RuntimeError("the server did not confirm encrypted credential storage")
    write_status("saved", ok=True, container=args.container)
    print("Saved securely on the CouchTV server. You can return to the CouchTV chat.")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--receive", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--server", help="Proxmox host address")
    parser.add_argument("--container", type=int, help="CouchTV container number")
    args = parser.parse_args()
    missing = [n for n in ('--server', '--container') if getattr(args, n.lstrip('-')) is None]
    if not args.receive and missing:
        parser.error("the following arguments are required: " + ", ".join(missing))
    try:
        receive() if args.receive else interactive(args)
        return 0
    except (Exception, KeyboardInterrupt):
        # Remote output and exception text may contain a token. Never print either.
        print("Secure Claude provisioning did not complete. Check the subscription token and server access, then try again.",
              file=sys.stderr)
        if not args.receive:
            try:
                write_status("failed")
            except OSError:
                pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
