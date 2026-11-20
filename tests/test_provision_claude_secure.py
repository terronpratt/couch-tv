"""Subscription provisioning keeps tokens off disk, argv, diagnostics and status files."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import warnings


spec = importlib.util.spec_from_file_location(
    "provision_claude_secure", Path(__file__).resolve().parents[1] / "scripts/provision-claude-secure.py")
provision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provision)
TOKEN = "sk-ant-oat01-" + "DummyTokenForTestingOnly_" * 3


class Provisioning(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        root_patch = patch.object(provision, "ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        self.args = SimpleNamespace(server="192.0.2.2", container=107)

    @property
    def status(self):
        return self.root / "build" / "claude-provision-status.json"

    def test_token_uses_stdin_only_and_status_resets_before_input(self):
        provision.write_status("saved", ok=True, container=107)

        def hidden_input(_):
            self.assertEqual(json.loads(self.status.read_text()), {"ok": False, "state": "awaiting-entry"})
            return TOKEN

        with patch.object(provision.sys.stdin, "isatty", return_value=True), \
                patch.object(provision.getpass, "getpass", side_effect=hidden_input), \
                patch.object(provision.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            provision.interactive(self.args)
        command = run.call_args.args[0]
        self.assertNotIn(TOKEN, repr(command))
        self.assertNotIn(TOKEN, output.getvalue())
        self.assertEqual(run.call_args.kwargs["input"], TOKEN.encode())
        self.assertEqual(run.call_args.kwargs["stdout"], subprocess.PIPE)
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.PIPE)
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("BatchMode=yes", command)
        self.assertEqual(json.loads(self.status.read_text()), {"ok": True, "state": "saved", "container": 107})
        self.assertEqual(self.status.stat().st_mode & 0o777, 0o600)
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn(TOKEN.encode(), path.read_bytes())
        self.assertEqual(len(list(self.status.parent.iterdir())), 1)

    def run_main(self, *, token=TOKEN, result=None, side_effect=None, tty=True):
        with patch.object(provision.sys.stdin, "isatty", return_value=tty), \
                patch.object(provision.getpass, "getpass", return_value=token), \
                patch.object(provision.subprocess, "run", return_value=result, side_effect=side_effect) as run, \
                patch.object(provision.sys, "argv", ["provision-claude-secure.py", "--server", "192.0.2.2", "--container", "107"]), \
                contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            code = provision.main()
        self.assertNotIn(TOKEN, out.getvalue() + err.getvalue())
        return code, run

    def test_echo_fallback_fails_closed_and_invalidates_old_success(self):
        provision.write_status("saved", ok=True)

        def fallback(_):
            warnings.warn("cannot hide input", provision.getpass.GetPassWarning)
            self.fail("must stop before reading echoed input")

        with patch.object(provision.sys.stdin, "isatty", return_value=True), \
                patch.object(provision.getpass, "getpass", side_effect=fallback), \
                patch.object(provision.subprocess, "run") as run, \
                patch.object(provision.sys, "argv", ["provision-claude-secure.py", "--server", "192.0.2.2", "--container", "107"]), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(provision.main(), 1)
        run.assert_not_called()
        self.assertEqual(json.loads(self.status.read_text()), {"ok": False, "state": "failed"})

    def test_remote_failure_and_timeout_never_print_token(self):
        result = SimpleNamespace(returncode=1, stdout=TOKEN.encode(), stderr=TOKEN.encode())
        code, _ = self.run_main(result=result)
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(self.status.read_text())["ok"])
        failure = subprocess.TimeoutExpired(["ssh"], 45, output=TOKEN.encode(), stderr=TOKEN.encode())
        code, _ = self.run_main(side_effect=failure)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(self.status.read_text())["state"], "failed")

    def test_nonterminal_and_api_key_fail_without_transfer(self):
        code, run = self.run_main(tty=False)
        self.assertEqual(code, 1)
        run.assert_not_called()
        code, run = self.run_main(token="sk-ant-api03-" + "Dummy" * 10)
        self.assertEqual(code, 1)
        run.assert_not_called()

    def test_retry_can_succeed_after_failure(self):
        self.assertEqual(self.run_main(result=SimpleNamespace(returncode=1))[0], 1)
        self.assertEqual(self.run_main(result=SimpleNamespace(returncode=0))[0], 0)
        self.assertTrue(json.loads(self.status.read_text())["ok"])

    def test_receiver_validates_then_writes_only_encrypted_store(self):
        store = Mock()
        fake_module = SimpleNamespace(configured_store=Mock(return_value=store))
        stdin = SimpleNamespace(isatty=lambda: False, buffer=io.BytesIO(TOKEN.encode()))
        with patch.object(provision.sys, "stdin", stdin), \
                patch.dict(sys.modules, {"credential_store": fake_module}), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            provision.receive()
        store.write.assert_called_once_with("claude-oauth", TOKEN)
        self.assertNotIn(TOKEN, output.getvalue())
        self.assertFalse(self.status.exists())

    def test_receiver_rejects_invalid_oversized_and_terminal_input(self):
        fake = SimpleNamespace(configured_store=Mock())
        for raw, tty in ((b"sk-ant-api03-invalid", False), (b"x" * 8193, False),
                         (TOKEN.encode() + b"\nextra", False), (TOKEN.encode(), True)):
            with self.subTest(tty=tty, size=len(raw)):
                stdin = SimpleNamespace(isatty=lambda: tty, buffer=io.BytesIO(raw))
                with patch.object(provision.sys, "stdin", stdin), \
                        patch.dict(sys.modules, {"credential_store": fake}):
                    with self.assertRaises((ValueError, RuntimeError)):
                        provision.receive()
        fake.configured_store.assert_not_called()

    def test_receiver_refuses_plaintext_fallback(self):
        stdin = SimpleNamespace(isatty=lambda: False, buffer=io.BytesIO(TOKEN.encode()))
        fake = SimpleNamespace(configured_store=Mock(return_value=None))
        with patch.object(provision.sys, "stdin", stdin), \
                patch.dict(sys.modules, {"credential_store": fake}):
            with self.assertRaises(RuntimeError):
                provision.receive()


if __name__ == "__main__":
    unittest.main()
