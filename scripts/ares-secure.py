#!/usr/bin/env python3
"""Run LG's CLI with an encrypted device profile materialized only in private tmpfs.

Install symlinks named ares-launch, ares-install, ares-novacom, ares-device, or
ares-device-info pointing here, or use `ares-secure.py ares-launch ...`.
"""
import base64
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bridge"))
from credential_store import CredentialStoreError, configured_store

COMMANDS = frozenset(("ares-launch", "ares-install", "ares-novacom", "ares-device", "ares-device-info"))
TOKEN_COMMAND = "cat /var/luna/preferences/devmode_enabled"


class SecureCLIError(RuntimeError):
    pass


def command_line(argv):
    name = Path(argv[0]).name
    arguments = list(argv[1:])
    if name not in COMMANDS:
        if not arguments or arguments[0] not in COMMANDS:
            raise SecureCLIError("choose a supported ares command")
        name = arguments.pop(0)
    forbidden = ("--getkey", "-g", "--passphrase", "--password", "--privatekey",
                 "--verbose", "-v", "--level", "--listfull", "-F")
    if any(arg.split("=", 1)[0] in forbidden for arg in arguments):
        raise SecureCLIError("credential setup and verbose output are disabled in the secure wrapper")
    if any("\x00" in arg for arg in arguments):
        raise SecureCLIError("invalid ares arguments")
    return name, arguments


def _unescape_mount_path(value):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)


def tmpfs_mount(path, mountinfo="/proc/self/mountinfo"):
    """Use the most-specific mount, so a disk bind mount nested under /run is rejected."""
    matching = []
    try:
        with open(mountinfo, encoding="utf-8") as f:
            for line in f:
                left, right = line.rstrip().split(" - ", 1)
                fields, filesystem = left.split(), right.split()[0]
                mount = Path(_unescape_mount_path(fields[4]))
                if path == mount or mount in path.parents:
                    matching.append((len(mount.parts), filesystem))
    except (OSError, ValueError, IndexError):
        raise SecureCLIError("cannot verify the runtime filesystem") from None
    return bool(matching) and max(matching, key=lambda item: item[0])[1] == "tmpfs"


def runtime_directory(environ):
    raw = environ.get("COUCHTV_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    path = Path(raw)
    if not path.is_absolute():
        raise SecureCLIError("runtime directory must be an absolute path")
    try:
        if path.is_symlink():
            raise SecureCLIError("runtime directory must not be a symlink")
        path = path.resolve(strict=True)
        info = path.stat()
    except OSError:
        raise SecureCLIError("private runtime directory is unavailable") from None
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise SecureCLIError("runtime directory must be owned by this user with mode 0700")
    if not tmpfs_mount(path):
        raise SecureCLIError("runtime directory must be on tmpfs")
    return path


def device_config(raw):
    try:
        devices = json.loads(raw)
        if not isinstance(devices, list) or not devices:
            raise ValueError()
        for device in devices:
            if (not isinstance(device, dict) or device.get("profile") != "tv"
                    or device.get("username") != "prisoner"
                    or not isinstance(device.get("privateKey"), str)
                    or not isinstance(device.get("passphrase"), str)
                    or len(device["passphrase"]) != 6
                    or not isinstance(device.get("host"), str)
                    or not re.fullmatch(r"[A-Za-z0-9_.:-]+", device["host"])
                    or not isinstance(device.get("name"), str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]+", device["name"])
                    or device.get("port") != 9922):
                raise ValueError()
            if not base64.b64decode(device["privateKey"], validate=True):
                raise ValueError()
        return json.dumps(devices).encode("utf-8")
    except (ValueError, TypeError, KeyError):
        raise SecureCLIError("encrypted LG device configuration is invalid") from None


def token_read(name, arguments):
    if name != "ares-novacom" or "--run" not in arguments:
        return False
    index = arguments.index("--run")
    return index + 2 == len(arguments) and arguments[index + 1] == TOKEN_COMMAND


def stdout_is_pipe():
    try:
        return stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode)
    except (OSError, ValueError, AttributeError):
        return False


def _interrupted(signum, frame):
    raise SecureCLIError("ares command was interrupted")


def invoke(executable, arguments, environ):
    previous = {}
    process = None
    try:
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous[signum] = signal.signal(signum, _interrupted)
        process = subprocess.Popen(
            [str(executable), *arguments], env=environ, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
        stdout, _ = process.communicate(timeout=55)
        if process.returncode:
            raise SecureCLIError("ares command failed; credential-bearing diagnostics were suppressed")
        return stdout
    except (OSError, subprocess.SubprocessError):
        raise SecureCLIError("ares command could not complete") from None
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def run(argv, environ=None):
    environ = dict(os.environ if environ is None else environ)
    name, arguments = command_line(argv)
    is_token = token_read(name, arguments)
    if name == "ares-novacom" and not is_token:
        raise SecureCLIError("only the Developer Mode session check is enabled for ares-novacom")
    if is_token and not stdout_is_pipe():
        raise SecureCLIError("the session-token read requires a private stdout pipe")
    parent = runtime_directory(environ)
    binary_dir = Path(environ.get("COUCHTV_ARES_BIN_DIR", "/opt/couchtv-tools/node_modules/.bin"))
    if not binary_dir.is_absolute():
        raise SecureCLIError("ares binary directory must be an absolute path")
    executable = binary_dir / name
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise SecureCLIError("official ares executable is unavailable")
    if executable.resolve() == Path(__file__).resolve():
        raise SecureCLIError("ares executable must not point back to the secure wrapper")
    store = configured_store()
    if store is None:
        raise SecureCLIError("encrypted credential storage must be enabled")
    raw = store.read("lg-ares-config")
    if not raw:
        raise SecureCLIError("encrypted LG device configuration has not been provisioned")
    config = device_config(raw)
    with tempfile.TemporaryDirectory(prefix="couchtv-ares-", dir=parent) as temporary:
        appdata = Path(temporary)
        profile = appdata / ".webos" / "tv"
        profile.mkdir(mode=0o700, parents=True)
        config_path = profile / "novacom-devices.json"
        fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(config)
        environ["APPDATA"] = str(appdata)
        # Deliberately leave HOME and unrelated user configuration unchanged.
        output = invoke(executable, arguments, environ)
    if is_token:
        candidate = b"".join(line for line in output.splitlines() if not line.startswith(b"[")).strip()
        if not re.fullmatch(rb"[0-9A-Za-z]{16,128}", candidate):
            raise SecureCLIError("ares did not return a valid session token")
        return candidate + b"\n"
    return (name + " completed\n").encode("ascii")


def main():
    try:
        result = run(sys.argv)
        sys.stdout.buffer.write(result)
        return 0
    except (SecureCLIError, CredentialStoreError):
        print("secure ares command failed; check runtime and encrypted-credential setup", file=sys.stderr)
        return 1
    except Exception:
        # Third-party and filesystem exceptions can contain sensitive input; never echo them.
        print("secure ares command could not complete", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
