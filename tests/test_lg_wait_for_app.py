"""LG wait_for_app: couch-tv asked for by its LG id (app.couchtv.home) shows up as its package
(app.couchtv.launcher). /api/launch waited for the LG id, never saw it, and called a launch that worked
"not installed" (seen on an LG OLED65CX after reinstalling couch-tv)."""
import asyncio
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1] / "bridge"))
import lg


def tv(**cfg):
    return lg.LGTV({"id": "test", "name": "Test", "kind": "lg", "ip": "192.0.2.1", **cfg})


def wait(t, front, asked, timeout=0.05):
    t.front_package = mock.AsyncMock(return_value=front)
    with mock.patch.object(lg.asyncio, "sleep", new=mock.AsyncMock()):
        return asyncio.run(t.wait_for_app(asked, timeout=timeout))


class WaitForApp(unittest.TestCase):
    def test_couch_tv_by_its_lg_id(self):
        t = tv()
        self.assertEqual(wait(t, lg.HOME_PACKAGE, {t.app_id}), lg.HOME_PACKAGE)

    def test_couch_tv_by_its_package_still_works(self):
        self.assertEqual(wait(tv(), lg.HOME_PACKAGE, {lg.HOME_PACKAGE}), lg.HOME_PACKAGE)

    def test_another_app_by_its_lg_id(self):
        t = tv()
        t.ids = {"netflix": "com.netflix.ninja"}
        self.assertEqual(wait(t, "com.netflix.ninja", {"netflix"}), "com.netflix.ninja")

    def test_something_else_in_front(self):
        t = tv()
        self.assertIsNone(wait(t, "com.netflix.ninja", {t.app_id}))
        self.assertIsNone(wait(t, None, {t.app_id}))


if __name__ == "__main__":
    unittest.main()
