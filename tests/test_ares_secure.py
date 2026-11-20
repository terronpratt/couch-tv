"""The LG CLI only sees decrypted configuration inside a private, temporary tmpfs profile."""
import base64
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ares = load_script("ares-secure")
claude = load_script("claude-secure")
DEVICE = [{"name": "lg-cx", "profile": "tv", "host": "192.0.2.1", "port": 9922,
           "username": "prisoner", "privateKey": base64.b64encode(b"dummy-private-key").decode(),
           "passphrase": "DUMMY1", "files": "sftp", "default": True}]


class RuntimeValidation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_real_mount_parser_rejects_disk_mount_nested_in_tmpfs(self):
        info = self.root / "mountinfo"
        info.write_text("1 0 0:1 / / rw - overlay overlay rw\n"
                        "2 1 0:2 / /run rw - tmpfs tmpfs rw\n"
                        "3 2 8:1 / /run/disk rw - ext4 /dev/example rw\n")
        self.assertTrue(ares.tmpfs_mount(Path("/run/user/1000"), info))
        self.assertFalse(ares.tmpfs_mount(Path("/run/disk/secrets"), info))
        self.assertFalse(ares.tmpfs_mount(Path("/home/user"), info))

    def test_mount_parser_handles_escaped_spaces_and_fails_closed(self):
        info = self.root / "mountinfo"
        info.write_text("2 1 0:2 / /run/user\\040name rw - tmpfs tmpfs rw\n")
        self.assertTrue(ares.tmpfs_mount(Path("/run/user name/profile"), info))
        info.write_text("unexpected format")
        with self.assertRaises(ares.SecureCLIError):
            ares.tmpfs_mount(Path("/run"), info)

    def test_runtime_requires_tmpfs_private_permissions_and_no_symlink(self):
        env = {"COUCHTV_RUNTIME_DIR": str(self.root)}
        with patch.object(ares, "tmpfs_mount", return_value=False):
            with self.assertRaisesRegex(ares.SecureCLIError, "tmpfs"):
                ares.runtime_directory(env)
        self.root.chmod(0o755)
        with self.assertRaisesRegex(ares.SecureCLIError, "0700"):
            ares.runtime_directory(env)
        self.root.chmod(0o700)
        link = self.root / "link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ares.SecureCLIError):
            ares.runtime_directory({"COUCHTV_RUNTIME_DIR": str(link)})
        with self.assertRaises(ares.SecureCLIError):
            ares.runtime_directory({"COUCHTV_RUNTIME_DIR": "relative"})


class SecureInvocation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ares.COMMANDS:
            executable = self.bin / name
            executable.write_text("dummy executable; never run")
            executable.chmod(0o700)
        self.env = {"HOME": "/unchanged/user-home", "APPDATA": "/old-appdata",
                    "COUCHTV_ARES_BIN_DIR": str(self.bin), "COUCHTV_RUNTIME_DIR": str(self.root)}
        self.store = Mock()
        self.store.read.return_value = json.dumps(DEVICE)
        patches = [patch.object(ares, "configured_store", return_value=self.store),
                   patch.object(ares, "tmpfs_mount", return_value=True)]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def inspect_runtime(self, executable, arguments, env):
        profile = Path(env["APPDATA"])
        self.assertNotEqual(env["APPDATA"], self.env["APPDATA"])
        self.assertEqual(env["HOME"], self.env["HOME"])
        self.assertEqual(profile.stat().st_mode & 0o777, 0o700)
        config = profile / ".webos/tv/novacom-devices.json"
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(config.read_bytes()), DEVICE)
        self.assertNotIn("DUMMY1", arguments)
        self.assertNotIn("dummy-private-key", arguments)
        return profile

    def test_private_configuration_is_removed_and_child_output_is_suppressed(self):
        seen = []

        def invoke(*args):
            seen.append(self.inspect_runtime(*args))
            return b"CLI diagnostic: DUMMY1 dummy-private-key"

        with patch.object(ares, "invoke", side_effect=invoke):
            result = ares.run(["ares-launch", "--device", "lg-cx", "app.couchtv.home"], self.env)
        self.assertEqual(result, b"ares-launch completed\n")
        self.assertFalse(seen[0].exists())
        self.assertEqual(self.env["APPDATA"], "/old-appdata")

    def test_child_failure_cleans_configuration(self):
        seen = []

        def invoke(*args):
            seen.append(self.inspect_runtime(*args))
            raise ares.SecureCLIError("failure")

        with patch.object(ares, "invoke", side_effect=invoke):
            with self.assertRaises(ares.SecureCLIError):
                ares.run(["ares-install", "--device", "lg-cx", "app.ipk"], self.env)
        self.assertFalse(seen[0].exists())

    def test_concurrent_invocations_have_separate_profiles_and_both_are_cleaned(self):
        seen = []
        barrier = threading.Barrier(2)

        def invoke(*args):
            seen.append(self.inspect_runtime(*args))
            barrier.wait(timeout=3)
            return b"done"

        with patch.object(ares, "invoke", side_effect=invoke):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(ares.run, ["ares-launch", "app.couchtv.home"], self.env)
                           for _ in range(2)]
                for future in futures:
                    self.assertEqual(future.result(), b"ares-launch completed\n")
        self.assertEqual(len(set(seen)), 2)
        self.assertTrue(all(not path.exists() for path in seen))

    def test_missing_credential_never_invokes_cli(self):
        self.store.read.return_value = None
        with patch.object(ares, "invoke") as invoke:
            with self.assertRaises(ares.SecureCLIError):
                ares.run(["ares-launch", "app.couchtv.home"], self.env)
            invoke.assert_not_called()

    def test_only_valid_session_token_can_be_forwarded_to_a_pipe(self):
        arguments = ["ares-novacom", "--device", "lg-cx", "--run", ares.TOKEN_COMMAND]
        with patch.object(ares, "stdout_is_pipe", return_value=False):
            with self.assertRaisesRegex(ares.SecureCLIError, "private stdout pipe"):
                ares.run(arguments, self.env)
        with patch.object(ares, "stdout_is_pipe", return_value=True):
            with patch.object(ares, "invoke", return_value=b"[Info] connected\nDummyToken0123456789\n"):
                self.assertEqual(ares.run(arguments, self.env), b"DummyToken0123456789\n")
            with patch.object(ares, "invoke", return_value=b"DUMMY1 dummy-private-key"):
                with self.assertRaisesRegex(ares.SecureCLIError, "valid session token"):
                    ares.run(arguments, self.env)

    def test_cli_command_and_credential_setup_are_restricted(self):
        for command in (["ares-setup-device", "--add", "test"],
                        ["ares-novacom", "--getkey"], ["ares-novacom", "--getke"],
                        ["ares-novacom", "--run", "echo something"],
                        ["ares-launch", "--level=verbose"], ["ares-launch", "-v"]):
            with self.assertRaises(ares.SecureCLIError):
                ares.run(command, self.env)
        self.assertEqual(ares.command_line(["ares-secure.py", "ares-launch", "app"]),
                         ("ares-launch", ["app"]))

    def test_invalid_config_error_never_contains_credential(self):
        malformed = json.dumps([{**DEVICE[0], "privateKey": "DUMMY_SECRET!!!"}])
        with self.assertRaises(ares.SecureCLIError) as failure:
            ares.device_config(malformed)
        self.assertNotIn("DUMMY_SECRET", str(failure.exception))

    def test_main_redacts_unexpected_exception(self):
        errors = io.StringIO()
        with patch.object(ares, "run", side_effect=RuntimeError("DUMMY_SECRET")):
            with patch.object(ares.sys, "stderr", errors):
                self.assertEqual(ares.main(), 1)
        self.assertNotIn("DUMMY_SECRET", errors.getvalue())


class ChildCleanup(unittest.TestCase):
    def test_timeout_kills_child_group_and_restores_signal_handlers(self):
        process = Mock(pid=12345, returncode=None)
        process.communicate.side_effect = subprocess.TimeoutExpired("dummy", 55, output=b"DUMMY_SECRET")
        process.poll.return_value = None
        handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
        with patch.object(ares.subprocess, "Popen", return_value=process):
            with patch.object(ares.os, "killpg") as kill:
                with self.assertRaises(ares.SecureCLIError) as failure:
                    ares.invoke(Path("/dummy/ares-launch"), [], {})
                kill.assert_called_once_with(12345, signal.SIGKILL)
                process.wait.assert_called_once()
        self.assertNotIn("DUMMY_SECRET", str(failure.exception))
        self.assertEqual(handlers, {sig: signal.getsignal(sig) for sig in handlers})


class ClaudeLauncher(unittest.TestCase):
    def test_oauth_only_in_exec_environment_and_api_key_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "claude"
            binary.touch(mode=0o700)
            env = {"COUCHTV_CLAUDE_BIN": str(binary), "HOME": "/unchanged/home",
                   "ANTHROPIC_API_KEY": "dummy-paid-key"}
            store = Mock()
            store.read.return_value = "dummy-subscription-token"
            with patch.object(claude, "configured_store", return_value=store):
                with patch.object(claude.os, "execve") as execute:
                    claude.launch(["-p", "--mcp-config", "/config/mcp.json"], env)
            path, argv, child_env = execute.call_args.args
            self.assertEqual(path, str(binary))
            self.assertNotIn("dummy-subscription-token", argv)
            self.assertEqual(argv[1:], ["-p", "--mcp-config", "/config/mcp.json"])
            self.assertEqual(child_env["CLAUDE_CODE_OAUTH_TOKEN"], "dummy-subscription-token")
            self.assertNotIn("ANTHROPIC_API_KEY", child_env)
            self.assertEqual(child_env["HOME"], "/unchanged/home")
            self.assertIn("ANTHROPIC_API_KEY", env)

    def test_missing_token_refuses_exec_and_errors_are_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "claude"
            binary.touch(mode=0o700)
            store = Mock()
            store.read.return_value = None
            with patch.object(claude, "configured_store", return_value=store):
                with patch.object(claude.os, "execve") as execute:
                    with self.assertRaises(claude.CredentialStoreError):
                        claude.launch(["-p"], {"COUCHTV_CLAUDE_BIN": str(binary)})
                    execute.assert_not_called()
        errors = io.StringIO()
        with patch.object(claude, "launch", side_effect=RuntimeError("DUMMY_SECRET")):
            with patch.object(claude.sys, "stderr", errors):
                self.assertEqual(claude.main(), 1)
        self.assertNotIn("DUMMY_SECRET", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
