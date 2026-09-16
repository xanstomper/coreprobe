"""iCloud acquisition tests: warrant gate + pyicloud harness."""

import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from opensleuth import icloud


class Arg:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class WarrantGateTest(unittest.TestCase):
    def test_refuses_without_warrant(self):
        err = icloud.auth_gate(Arg(warrant=None))
        self.assertIn("lawful authorization", err)

    def test_refuses_short_warrant(self):
        err = icloud.auth_gate(Arg(warrant="ab"))
        self.assertIn("warrant", err)

    def test_accepts_warrant(self):
        self.assertIsNone(icloud.auth_gate(Arg(warrant="CR-2026-0417")))

    def test_acquire_no_warrant_ok_false(self):
        r = icloud.acquire(Arg(warrant=None, out=tempfile.mkdtemp()))
        self.assertFalse(r["ok"])
        self.assertIn("lawful authorization", r["error"])

    def test_acquire_reports_missing_pyicloud(self):
        with mock.patch.object(icloud, "_pyicloud", return_value=None):
            with tempfile.TemporaryDirectory() as td:
                r = icloud.acquire(Arg(warrant="CR-1", username="a@b.c",
                                       password="x", out=td))
        self.assertFalse(r["ok"])
        self.assertIn("pyicloud not installed", r["error"])

    def test_acquire_reports_missing_credentials(self):
        with tempfile.TemporaryDirectory() as td:
            r = icloud.acquire(Arg(warrant="CR-1", username=None,
                                   password=None, out=td))
        self.assertFalse(r["ok"])
        self.assertIn("credentials", r["error"])


class PyiCloudHarnessTest(unittest.TestCase):
    def _fake_pyicloud(self):
        class FakeContacts:
            def all(self):
                return iter([{"first": "A", "phones": ["+1 555"], "emails": None}])

        class FakeCalendar:
            def events(self):
                return iter([{"title": "meeting", "when": "2026-09-01"}])

        class FakeNotes:
            def get_notes(self):
                return iter([{"guid": "n1", "text": "note body"}])

        class FakeReminders:
            def get_reminders(self):
                return iter([{"title": "buy milk", "completed": False}])

        class FakePhotos:
            def all(self):
                return iter([1, 2, 3])

        class FakeDevices:
            def all(self):
                return iter([{"name": "iPhone 11", "model": "iPhone"}])

        class FakeAPI:
            requires_2fa = False
            trusted_session = True

            def __init__(self, *a, **k):
                self.contacts = FakeContacts()
                self.calendar = FakeCalendar()
                self.notes = FakeNotes()
                self.reminders = FakeReminders()
                self.photos = FakePhotos()
                self.devices = FakeDevices()

        return FakeAPI

    def test_full_harvest_writes_report(self):
        fake = self._fake_pyicloud()
        with mock.patch.object(icloud, "_pyicloud", return_value=fake):
            with tempfile.TemporaryDirectory() as td:
                r = icloud.acquire(Arg(warrant="CR-2026-01", username="a@b.c",
                                       password="pw", out=td))
                self.assertTrue(r["ok"])
                self.assertEqual(r["summary"]["contacts"], 1)
                self.assertEqual(r["summary"]["calendars"], 1)
                self.assertEqual(r["summary"]["notes"], 1)
                self.assertEqual(r["summary"]["reminders"], 1)
                self.assertEqual(r["summary"]["photos"], 3)
                self.assertEqual(r["summary"]["devices"], 1)
                report = Path(r["report"])
                self.assertTrue(report.exists())
                import json
                data = json.loads(report.read_text())
                self.assertEqual(data["warrant"], "CR-2026-01")
                self.assertEqual(data["contacts"][0]["first"], "A")


if __name__ == "__main__":
    unittest.main()

class RetryTest(unittest.TestCase):
    def test_safe_retries_then_fails(self):
        calls = {"n": 0}

        def boom():
            calls["n"] += 1
            raise RuntimeError("network")

        data, err = icloud._safe(boom, "contacts", retries=2)
        self.assertIsNone(data)
        self.assertEqual(calls["n"], 3)
        self.assertIn("contacts failed", err)

    def test_safe_succeeds_on_retry(self):
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("network")
            return [1, 2]

        data, err = icloud._safe(flaky, "notes", retries=2)
        self.assertEqual(data, [1, 2])
        self.assertIsNone(err)
        self.assertEqual(calls["n"], 2)
