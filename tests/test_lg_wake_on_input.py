"""LG wake_on_input: HDMI 2 opened from couch-tv (its input tile or Input button), LG's home or LG's input
screen wakes the device on it (an Apple TV on the same bridge), for an LG OLED65CX with SIMPLINK's Auto
Power Sync off. An app closing to the input, the TV coming on in it, and Device Connector are left alone."""
import asyncio
from pathlib import Path
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1] / "bridge"))
import lg

HOME, HDMI2, PICKER = "com.webos.app.home", "com.webos.app.hdmi2", "com.webos.app.homeconnect"


def tv(**cfg):
    return lg.LGTV({"id": "test", "name": "Test", "kind": "lg", "ip": "192.0.2.1", **cfg})


class Config(unittest.TestCase):
    def test_ports_become_strings_and_junk_is_dropped(self):
        t = tv(wake_on_input={2: "office-appletv", "3": " shield ", "x": "a", "4": "", "5": 7})
        self.assertEqual(t.wake_on_input, {"2": "office-appletv", "3": "shield"})
        self.assertEqual(tv().wake_on_input, {})
        self.assertEqual(tv(wake_on_input=["2"]).wake_on_input, {})


class Target(unittest.TestCase):
    def setUp(self):
        self.t = tv(wake_on_input={"2": "office-appletv"})

    def test_opened_from_couch_tv_lg_home_or_input_screen(self):
        want = ("2", "office-appletv")
        self.assertEqual(self.t._input_wake_target(self.t.app_id, HDMI2), want)   # input tile, Input button
        self.assertEqual(self.t._input_wake_target(PICKER, HDMI2), want)          # LG's input screen
        self.assertEqual(self.t._input_wake_target(HOME, HDMI2), want)
        self.assertEqual(self.t._input_wake_target(lg.INPUT_SCREEN, HDMI2), want)

    def test_left_alone(self):
        t = self.t
        self.assertIsNone(t._input_wake_target("netflix", HDMI2))      # holding Back in Netflix
        self.assertIsNone(t._input_wake_target("", HDMI2))             # the TV coming on in it
        self.assertIsNone(t._input_wake_target(None, HDMI2))
        self.assertIsNone(t._input_wake_target("com.webos.app.connectionwizard", HDMI2))
        self.assertIsNone(t._input_wake_target("com.webos.app.hdmi1", HDMI2))
        self.assertIsNone(t._input_wake_target(t.app_id, "com.webos.app.hdmi3"))   # no device set
        self.assertIsNone(t._input_wake_target(t.app_id, "netflix"))
        self.assertIsNone(tv()._input_wake_target(t.app_id, HDMI2))    # off by default
        t._extending = True
        self.assertIsNone(t._input_wake_target(t.app_id, HDMI2))


class Wake(unittest.TestCase):
    def run_wake(self, t, now=HDMI2, on=True, wake=None):
        woke = []

        async def read_visible():
            return now

        async def wake_device(target):
            woke.append(target)
            if wake:
                raise wake
        t._read_visible = read_visible
        t.wake_device = wake_device
        with mock.patch.object(lg.LGTV, "is_on", new_callable=mock.PropertyMock, return_value=on), \
                mock.patch.object(lg.asyncio, "sleep", new=mock.AsyncMock()):
            asyncio.run(t._wake_for_input("2", "office-appletv", HDMI2))
        return woke

    def test_wakes_once_still_on_the_input(self):
        t = tv(wake_on_input={"2": "office-appletv"})
        self.assertEqual(self.run_wake(t), ["office-appletv"])
        self.assertIn("HDMI 2 opened, woke office-appletv", t.hook_log[-1][1])
        self.assertEqual(self.run_wake(t), [])   # again within WAKE_AGAIN_SECS: not twice
        t._woke_port_at["2"] = time.monotonic() - lg.WAKE_AGAIN_SECS - 1
        self.assertEqual(self.run_wake(t), ["office-appletv"])

    def test_not_when_the_input_went_away_or_the_tv_is_off(self):
        self.assertEqual(self.run_wake(tv(wake_on_input={"2": "x"}), now="app.couchtv.home"), [])
        self.assertEqual(self.run_wake(tv(wake_on_input={"2": "x"}), on=False), [])

    def test_a_failed_wake_is_noted(self):
        t = tv(wake_on_input={"2": "office-appletv"})
        self.run_wake(t, wake=RuntimeError("no device"))
        self.assertIn("could not wake office-appletv: no device", t.hook_log[-1][1])

    def test_nothing_set_up_to_wake(self):
        t = tv(wake_on_input={"2": "office-appletv"})
        t._read_visible = mock.AsyncMock(return_value=HDMI2)
        with mock.patch.object(lg.LGTV, "is_on", new_callable=mock.PropertyMock, return_value=True), \
                mock.patch.object(lg.asyncio, "sleep", new=mock.AsyncMock()):
            asyncio.run(t._wake_for_input("2", "office-appletv", HDMI2))
        self.assertIn("nothing set up to wake", t.hook_log[-1][1])


if __name__ == "__main__":
    unittest.main()
