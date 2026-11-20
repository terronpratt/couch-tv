#!/usr/bin/env python3
"""Deliver the user's Claude subscription OAuth token from OS storage at exec time."""
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bridge"))
from credential_store import CredentialStoreError, configured_store


def launch(arguments, environ=None):
    environ = dict(os.environ if environ is None else environ)
    binary = Path(environ.get("COUCHTV_CLAUDE_BIN", "/opt/couchtv-tools/claude"))
    if not binary.is_absolute() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise CredentialStoreError("official Claude executable is unavailable")
    if binary.resolve() == Path(__file__).resolve():
        raise CredentialStoreError("Claude executable must not point back to the secure launcher")
    store = configured_store()
    if store is None:
        raise CredentialStoreError("encrypted credential storage must be enabled")
    token = store.read("claude-oauth")
    if not token or "\x00" in token or "\n" in token or "\r" in token:
        raise CredentialStoreError("Claude subscription credential is unavailable")
    environ.pop("ANTHROPIC_API_KEY", None)
    environ["CLAUDE_CODE_OAUTH_TOKEN"] = token
    os.execve(str(binary), [str(binary), *arguments], environ)


def main():
    try:
        launch(sys.argv[1:])
    except Exception:
        print("secure Claude launch failed; check the executable and encrypted subscription credential", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
