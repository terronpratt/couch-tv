"""A per-profile Netflix file is read in one date order: a US "4/12/26" is 12 April, not 4 December."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "importer_netflix", Path(__file__).resolve().parents[1] / "bridge" / "import" / "netflix.py")
netflix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(netflix)


def dates(text):
    return [i["when"] for i in netflix.parse(text, lambda profile: "someone")]


class ProfileFileDates(unittest.TestCase):
    def test_us_file_is_month_first_on_every_row(self):
        text = 'Title,Date\n"A Show: Season 1: One","4/12/26"\n"A Film","7/30/13"\n"Another","1/2/24"\n'
        self.assertEqual(dates(text), ["2026-04-12", "2013-07-30", "2024-01-02"])

    def test_australian_file_stays_day_first(self):
        text = 'Title,Date\n"A Show: Season 1: One","4/12/26"\n"A Film","30/7/13"\n"Another","1/2/24"\n'
        self.assertEqual(dates(text), ["2026-12-04", "2013-07-30", "2024-02-01"])

    def test_only_ambiguous_dates_keep_the_old_day_first_reading(self):
        text = 'Title,Date\n"A Film","4/12/26"\n'
        self.assertEqual(dates(text), ["2026-12-04"])

    def test_other_formats_still_read(self):
        text = 'Title,Date\n"A Film","2026-04-12"\n"B Film","12.04.26"\n'
        self.assertEqual(dates(text), ["2026-04-12", "2026-04-12"])


if __name__ == "__main__":
    unittest.main()
