"""Encrypted LG credentials: no plaintext files, fallback, or secret-bearing diagnostics."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

BRIDGE = Path(__file__).resolve().parents[1] / "bridge"
sys.path.insert(0, str(BRIDGE))
import credential_store


def completed(stdout=b"", returncode=0, stderr=b""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class SystemdStore(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "encrypted"
        self.run = Mock(return_value=completed(b"systemd 259 (259.1)\n"))
        self.patcher = patch.object(credential_store.subprocess, "run", self.run)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.store = credential_store.SystemdCredentialStore(self.directory)
        self.run.reset_mock()

    def test_write_pipes_secret_and_only_persists_ciphertext(self):
        self.run.return_value = completed(b"opaque-encrypted-credential\n")
        self.store.write("lg-lounge-client-key", "dummy-pairing-key")
        args, options = self.run.call_args
        self.assertNotIn("dummy-pairing-key", " ".join(args[0]))
        self.assertEqual(options["input"], b"dummy-pairing-key")
        self.assertIn("--with-key=host", args[0])
        self.assertIn("--user", args[0])
        self.assertEqual(args[0][-3:], ["encrypt", "-", "-"])
        self.assertEqual(options["stderr"], subprocess.PIPE)
        saved = self.directory / "lg-lounge-client-key.cred"
        self.assertEqual(saved.read_bytes(), b"opaque-encrypted-credential\n")
        self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(list(self.directory.iterdir()), [saved])

    def test_read_uses_authenticated_name_and_refuses_null_key(self):
        self.run.return_value = completed(b"encrypted")
        self.store.write("lg-test-client-key", "dummy-key")
        self.run.return_value = completed(b"dummy-key")
        self.assertEqual(self.store.read("lg-test-client-key"), "dummy-key")
        args, options = self.run.call_args
        self.assertIn("--refuse-null", args[0])
        self.assertIn("--name=lg-test-client-key", args[0])
        self.assertEqual(args[0][-3:], ["decrypt", "-", "-"])
        self.assertEqual(options["input"], b"encrypted")

    def test_failed_encryption_preserves_previous_ciphertext_and_redacts_output(self):
        self.run.return_value = completed(b"previous-encrypted")
        self.store.write("lg-test", "old-dummy-key")
        self.run.return_value = completed(b"new-dummy-key", 1, b"new-dummy-key")
        with self.assertRaises(credential_store.CredentialStoreError) as failure:
            self.store.write("lg-test", "new-dummy-key")
        self.assertNotIn("dummy", str(failure.exception))
        self.assertIsNone(failure.exception.__cause__)
        self.assertEqual((self.directory / "lg-test.cred").read_bytes(), b"previous-encrypted")
        self.assertEqual(len(list(self.directory.iterdir())), 1)

    def test_decryption_failure_does_not_return_or_log_secret(self):
        self.run.return_value = completed(b"encrypted")
        self.store.write("lg-test", "dummy-key")
        self.run.return_value = completed(b"dummy-key", 1, b"dummy-key")
        with self.assertRaisesRegex(credential_store.CredentialStoreError, "operation failed") as failure:
            self.store.read("lg-test")
        self.assertNotIn("dummy-key", str(failure.exception))

    def test_failed_replace_cleans_temporary_ciphertext_and_preserves_previous_key(self):
        self.run.return_value = completed(b"previous-encrypted")
        self.store.write("lg-test", "old-dummy-key")
        self.run.return_value = completed(b"new-encrypted")
        with patch.object(credential_store.os, "replace", side_effect=OSError()):
            with self.assertRaises(credential_store.CredentialStoreError):
                self.store.write("lg-test", "new-dummy-key")
        self.assertEqual((self.directory / "lg-test.cred").read_bytes(), b"previous-encrypted")
        self.assertEqual(len(list(self.directory.iterdir())), 1)

    def test_missing_credential_is_unpaired_without_creating_files(self):
        self.assertIsNone(self.store.read("lg-test"))
        self.run.assert_not_called()
        self.assertFalse(self.directory.exists())

    def test_symlink_and_unsafe_permissions_are_refused(self):
        self.directory.mkdir(mode=0o700)
        target = Path(self.temp.name) / "other"
        target.write_bytes(b"encrypted")
        link = self.directory / "lg-test.cred"
        link.symlink_to(target)
        with self.assertRaises(credential_store.CredentialStoreError):
            self.store.read("lg-test")
        link.unlink()
        link.write_bytes(b"encrypted")
        link.chmod(0o644)
        with self.assertRaises(credential_store.CredentialStoreError):
            self.store.read("lg-test")
        self.run.assert_not_called()

    def test_unsafe_directory_is_refused(self):
        self.directory.mkdir(mode=0o755)
        self.directory.chmod(0o755)
        with self.assertRaises(credential_store.CredentialStoreError):
            self.store.read("lg-test")

    def test_invalid_names_never_invoke_systemd(self):
        for name in ("../key", "/key", "a/b", "", "a\nkey", "x" * 129, None):
            with self.assertRaises(credential_store.CredentialStoreError):
                self.store.write(name, "dummy-key")
        self.run.assert_not_called()

    def test_project_and_relative_directories_are_refused(self):
        for directory in ("relative", BRIDGE / "data" / "encrypted"):
            with self.assertRaises(credential_store.CredentialStoreError):
                credential_store.SystemdCredentialStore(directory)

    def test_old_or_missing_systemd_fails_closed(self):
        self.run.return_value = completed(b"systemd 258\n")
        with self.assertRaisesRegex(credential_store.CredentialStoreError, "259"):
            credential_store.SystemdCredentialStore(self.directory)
        self.run.side_effect = FileNotFoundError()
        with self.assertRaisesRegex(credential_store.CredentialStoreError, "unavailable"):
            credential_store.SystemdCredentialStore(self.directory)

    def test_timeout_is_redacted(self):
        self.run.side_effect = subprocess.TimeoutExpired("command", 15, output=b"dummy-key")
        with self.assertRaises(credential_store.CredentialStoreError) as failure:
            self.store.write("lg-test", "dummy-key")
        self.assertNotIn("dummy-key", str(failure.exception))

    def test_system_scope_is_explicit(self):
        self.run.return_value = completed(b"systemd 259\n")
        store = credential_store.SystemdCredentialStore(self.directory, scope="system")
        self.run.return_value = completed(b"encrypted")
        store.write("lg-test", "dummy-key")
        self.assertNotIn("--user", self.run.call_args.args[0])
        self.assertIn("--with-key=host", self.run.call_args.args[0])


class Selection(unittest.TestCase):
    def test_unset_retains_legacy_but_explicit_backend_never_falls_back(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(credential_store.configured_store())
            os.environ["COUCHTV_CREDENTIAL_BACKEND"] = "invalid"
            with self.assertRaises(credential_store.CredentialStoreError):
                credential_store.configured_store()
            os.environ["COUCHTV_CREDENTIAL_BACKEND"] = "systemd"
            with self.assertRaises(credential_store.CredentialStoreError):
                credential_store.configured_store()


class LGIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # Load the real LG driver without pulling Android-only dependencies into this test.
        modules = {
            "apps": SimpleNamespace(APPS=[], WEBOS={}),
            "config": SimpleNamespace(DATA=self.temp.name),
            "tv": SimpleNamespace(TVUnavailable=RuntimeError),
            "samsung": SimpleNamespace(netflix_id=lambda _: None, youtube_id=lambda _: None),
            "aiohttp": SimpleNamespace(WSMsgType=SimpleNamespace(TEXT=1)),
        }
        spec = importlib.util.spec_from_file_location("_lg_credential_test", BRIDGE / "lg.py")
        self.lg = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, modules):
            spec.loader.exec_module(self.lg)
        self.store = Mock()
        with patch.object(credential_store, "configured_store", return_value=self.store):
            self.tv = self.lg.LGTV({"id": "test", "name": "Test", "ip": "192.0.2.1"})

    def test_driver_reads_secure_store_and_never_plaintext(self):
        self.store.read.return_value = "dummy-key"
        with patch("builtins.open", side_effect=AssertionError("plaintext file read")):
            self.assertEqual(self.tv._key(), "dummy-key")
        self.store.read.assert_called_once_with("lg-test-client-key")

    def test_secure_write_failure_does_not_fall_back(self):
        self.store.write.side_effect = credential_store.CredentialStoreError("store failed")
        with self.assertRaises(credential_store.CredentialStoreError):
            self.tv._save_key("dummy-key")
        self.assertFalse(Path(self.tv.key_file).exists())

    def test_existing_plaintext_needs_explicit_migration(self):
        Path(self.tv.key_file).write_text("dummy-key")
        with patch.object(credential_store, "configured_store", return_value=self.store):
            with self.assertRaisesRegex(credential_store.CredentialStoreError, "explicit migration"):
                self.lg.LGTV({"id": "test", "name": "Test"})
        self.assertEqual(Path(self.tv.key_file).read_text(), "dummy-key")

    def test_registered_handshake_saves_only_to_secure_store(self):
        self.store.read.return_value = None
        messages = iter([{}, {}, {"id": "register_0", "type": "registered",
                                 "payload": {"client-key": "dummy-new-key"}}])

        class WS:
            async def send_json(self, _):
                pass

            async def receive(self):
                return SimpleNamespace(type=1, data=json.dumps(next(messages)))

        asyncio.run(self.tv._handshake(WS(), 1))
        self.store.write.assert_called_once_with("lg-test-client-key", "dummy-new-key")
        self.assertFalse(Path(self.tv.key_file).exists())


if __name__ == "__main__":
    unittest.main()
