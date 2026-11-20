"""Opt-in platform storage for LG pairing keys; never persist plaintext here.

systemd-creds keeps the host encryption key in the OS credential store. Only encrypted
credentials reach our files; plaintext is passed over subprocess pipes and held in memory.
"""
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


class CredentialStoreError(RuntimeError):
    """A credential operation failed; messages deliberately omit command output."""


class SystemdCredentialStore:
    executable = "/usr/bin/systemd-creds"

    def __init__(self, directory, *, scope="user", project_root=None):
        if scope not in ("user", "system"):
            raise CredentialStoreError("credential scope must be user or system")
        path = Path(directory).expanduser()
        if not path.is_absolute():
            raise CredentialStoreError("credential directory must be an absolute path")
        self.directory = path.resolve()
        project = Path(project_root or Path(__file__).resolve().parents[1]).resolve()
        if self.directory == project or project in self.directory.parents:
            raise CredentialStoreError("encrypted credentials must be stored outside the project")
        self.scope = scope
        # Require --refuse-null support rather than accepting an older version's insecure
        # null-key ciphertext when the machine has no TPM or Secure Boot.
        result = self._run(["--version"])
        match = re.match(rb"systemd\s+(\d+)", result)
        if not match or int(match[1]) < 259:
            raise CredentialStoreError("secure credential storage requires systemd-creds 259 or newer")

    def _run(self, arguments, *, data=None):
        try:
            result = subprocess.run(
                [self.executable, *arguments], input=data, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=15, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise CredentialStoreError("systemd credential storage is unavailable") from None
        if result.returncode:
            # Never include stderr/stdout, CalledProcessError, input, or the credential.
            raise CredentialStoreError("systemd credential operation failed")
        return result.stdout

    @staticmethod
    def validate_name(name):
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name):
            raise CredentialStoreError("invalid credential name")

    def _path(self, name):
        self.validate_name(name)
        return self.directory / (name + ".cred")

    def _check_directory(self, *, create=False):
        try:
            if create:
                self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            info = self.directory.lstat()
        except FileNotFoundError:
            return False
        except OSError:
            raise CredentialStoreError("credential directory is inaccessible") from None
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise CredentialStoreError("credential directory must be owned by this user with mode 0700")
        return True

    def read(self, name):
        path = self._path(name)
        if not self._check_directory():
            return None
        try:
            # Avoid following a final symlink. The directory is private to this user.
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError:
            raise CredentialStoreError("encrypted credential is inaccessible") from None
        try:
            with os.fdopen(fd, "rb") as f:
                info = os.fstat(f.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 1024 * 1024):
                    raise CredentialStoreError("encrypted credential has unsafe ownership, permissions or size")
                encrypted = f.read()
        except OSError:
            raise CredentialStoreError("encrypted credential could not be read") from None
        plaintext = self._run(
            [*self._options(name), "--refuse-null", "--newline=no", "decrypt", "-", "-"],
            data=encrypted,
        )
        try:
            return plaintext.decode("utf-8").strip() or None
        except UnicodeError:
            raise CredentialStoreError("decrypted credential is not valid text") from None

    def _options(self, name):
        return (["--user"] if self.scope == "user" else []) + ["--no-ask-password", f"--name={name}"]

    def write(self, name, value):
        path = self._path(name)
        if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > 65536:
            raise CredentialStoreError("credential must be nonempty text smaller than 64 KiB")
        encrypted = self._run(
            [*self._options(name), "--with-key=host", "encrypt", "-", "-"],
            data=value.encode("utf-8"),
        )
        if not encrypted:
            raise CredentialStoreError("systemd returned an empty encrypted credential")
        self._check_directory(create=True)
        temporary = None
        try:
            fd, temporary = tempfile.mkstemp(prefix=".credential-", dir=self.directory)
            with os.fdopen(fd, "wb") as f:
                f.write(encrypted)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporary, path)
            temporary = None
        except OSError:
            raise CredentialStoreError("encrypted credential could not be saved") from None
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass


def configured_store():
    """Unset retains existing installations' behavior; explicit secure mode fails closed."""
    backend = os.environ.get("COUCHTV_CREDENTIAL_BACKEND", "").strip()
    if not backend:
        return None
    if backend != "systemd":
        raise CredentialStoreError("unsupported credential backend")
    directory = os.environ.get("COUCHTV_CREDENTIAL_DIR", "").strip()
    if not directory:
        raise CredentialStoreError("COUCHTV_CREDENTIAL_DIR is required for secure storage")
    return SystemdCredentialStore(
        directory, scope=os.environ.get("COUCHTV_CREDENTIAL_SCOPE", "user").strip(),
    )
