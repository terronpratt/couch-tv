import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import warnings


spec = importlib.util.spec_from_file_location(
    "provision_lg_secure", Path(__file__).resolve().parents[1] / "scripts/provision-lg-secure.py")
provision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provision)


class Provisioning(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root_patch = patch.object(provision, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.args = SimpleNamespace(tv="192.0.2.1", server="192.0.2.2", device="test-lg", container=107)

    def test_secret_uses_stdin_and_status_resets_before_input(self):
        build = self.root / "build"
        build.mkdir()
        status = build / "lg-provision-status.json"
        status.write_text('{"ok":true}')

        def hidden_input(prompt):
            self.assertEqual(json.loads(status.read_text()), {"ok": False, "state": "awaiting-entry"})
            return "ABC123"

        key = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nfake test data\n"
        with patch.object(provision.sys.stdin, "isatty", return_value=True), \
                patch.object(provision.getpass, "getpass", side_effect=hidden_input), \
                patch.object(provision.urllib.request, "urlopen", return_value=io.BytesIO(key)), \
                patch.object(provision.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            provision.interactive(self.args)
        command = run.call_args.args[0]
        self.assertNotIn("ABC123", repr(command))
        self.assertNotIn("ABC123", output.getvalue())
        payload = json.loads(run.call_args.kwargs["input"])
        self.assertEqual(payload[0]["passphrase"], "ABC123")
        self.assertTrue(json.loads(status.read_text())["ok"])

    def test_echo_fallback_fails_closed_and_invalidates_old_success(self):
        build = self.root / "build"
        build.mkdir()
        status = build / "lg-provision-status.json"
        status.write_text('{"ok":true}')

        def fallback(prompt):
            warnings.warn("Cannot hide input", provision.getpass.GetPassWarning)
            self.fail("getpass must not continue after the warning")

        with patch.object(provision.sys.stdin, "isatty", return_value=True), \
                patch.object(provision.getpass, "getpass", side_effect=fallback), \
                patch.object(provision.sys, "argv", ["provision-lg-secure.py", "--tv", "192.0.2.1", "--server", "192.0.2.2", "--container", "107", "--device", "test-lg"]), \
                patch.object(provision.subprocess, "run") as run, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(provision.main(), 1)
        run.assert_not_called()
        self.assertEqual(json.loads(status.read_text()), {"ok": False, "state": "failed"})

    def test_remote_diagnostics_never_reach_terminal(self):
        with patch.object(provision.sys.stdin, "isatty", return_value=True), \
                patch.object(provision.getpass, "getpass", return_value="ABC123"), \
                patch.object(provision.urllib.request, "urlopen", return_value=io.BytesIO(b"-----BEGIN PRIVATE KEY-----\nfake")), \
                patch.object(provision.subprocess, "run", return_value=SimpleNamespace(returncode=1, stderr=b"ABC123", stdout=b"ABC123")), \
                patch.object(provision.sys, "argv", ["provision-lg-secure.py", "--tv", "192.0.2.1", "--server", "192.0.2.2", "--container", "107", "--device", "test-lg"]), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(provision.main(), 1)
        self.assertNotIn("ABC123", out.getvalue() + err.getvalue())


if __name__ == "__main__":
    unittest.main()
