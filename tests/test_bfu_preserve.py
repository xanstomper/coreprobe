"""AFU preservation tests: inactivity-reboot countdown + intake plan.

The countdown models the SEP-held timer only (iOS 18.0: 168h, iOS 18.1+:
72h, pre-18: none). The plan is a playbook - tests pin the honesty block
so no render can quietly drop it.
"""

import unittest
from datetime import datetime, timedelta, timezone

from opensleuth import bfu

NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=timezone.utc)


def ago(hours: float) -> datetime:
    return NOW - timedelta(hours=hours)


class TimeToBfuTest(unittest.TestCase):
    def test_ios18_0_gets_168h_deadline(self):
        r = bfu.time_to_bfu("18.0", ago(1), NOW)
        self.assertTrue(r["applies"])
        self.assertEqual(r["deadline_hours"], 168)

    def test_ios18_0_still_safe_past_72h(self):
        # 168 - 100 = 68h left, still in the >=24h band
        r = bfu.time_to_bfu("18.0.1", ago(100), NOW)
        self.assertEqual(r["state"], "afu-safe")
        self.assertEqual(r["seconds_remaining"], 68 * 3600)

    def test_ios18_1_gets_72h_deadline(self):
        r = bfu.time_to_bfu("18.1", ago(1), NOW)
        self.assertTrue(r["applies"])
        self.assertEqual(r["deadline_hours"], 72)

    def test_ios26_gets_72h_deadline(self):
        r = bfu.time_to_bfu("26.2", ago(1), NOW)
        self.assertTrue(r["applies"])
        self.assertEqual(r["deadline_hours"], 72)

    def test_pre18_has_no_timer(self):
        r = bfu.time_to_bfu("17.5", ago(1), NOW)
        self.assertFalse(r["applies"])
        self.assertIsNone(r["deadline_hours"])
        self.assertIsNone(r["seconds_remaining"])
        self.assertEqual(r["state"], "no-timer")

    def test_unknown_ios_is_unknown(self):
        for bad in ("?", "", "unknown"):
            r = bfu.time_to_bfu(bad, ago(1), NOW)
            self.assertEqual(r["state"], "unknown")
            self.assertIsNone(r["deadline_hours"])
            self.assertIsNone(r["seconds_remaining"])

    def test_missing_last_unlock_is_unknown_but_timer_applies(self):
        r = bfu.time_to_bfu("18.1", None, NOW)
        self.assertEqual(r["state"], "unknown")
        self.assertTrue(r["applies"])
        self.assertEqual(r["deadline_hours"], 72)
        self.assertIsNone(r["seconds_remaining"])
        self.assertIn("last-unlock", r["note"])

    def test_30h_ago_on_18_1_is_afu_safe(self):
        r = bfu.time_to_bfu("18.1", ago(30), NOW)
        self.assertEqual(r["state"], "afu-safe")
        self.assertEqual(r["seconds_remaining"], 42 * 3600)

    def test_50h_ago_on_18_1_is_afu_expiring(self):
        r = bfu.time_to_bfu("18.1", ago(50), NOW)
        self.assertEqual(r["state"], "afu-expiring")
        self.assertEqual(r["seconds_remaining"], 22 * 3600)

    def test_70h_ago_on_18_1_is_bfu_imminent(self):
        r = bfu.time_to_bfu("18.1", ago(70), NOW)
        self.assertEqual(r["state"], "bfu-imminent")
        self.assertEqual(r["seconds_remaining"], 2 * 3600)

    def test_past_deadline_is_already_bfu_window(self):
        r = bfu.time_to_bfu("18.1", ago(80), NOW)
        self.assertEqual(r["state"], "already-bfu-window")
        self.assertEqual(r["seconds_remaining"], 0)

    def test_note_states_sep_holds_deadline(self):
        r = bfu.time_to_bfu("18.1", ago(1), NOW)
        self.assertIn("SEP", r["note"])


class PreservationPlanTest(unittest.TestCase):
    def test_plan_embeds_countdown(self):
        p = bfu.preservation_plan("18.1", ago(70), NOW)
        self.assertEqual(p["countdown"]["state"], "bfu-imminent")
        self.assertEqual(p["countdown"]["deadline_hours"], 72)

    def test_plan_steps_are_ordered(self):
        p = bfu.preservation_plan("26.0", ago(1), NOW)
        phases = [s["phase"] for s in p["steps"]]
        self.assertEqual(phases[0], "record-state")
        self.assertEqual(phases[1], "radio-isolation")
        self.assertEqual(phases[2], "expiry-first-capture")
        self.assertEqual([s["n"] for s in p["steps"]],
                         list(range(1, len(p["steps"]) + 1)))

    def test_plan_lists_five_expiring_classes(self):
        p = bfu.preservation_plan("18.1", ago(1), NOW)
        names = [e["evidence"] for e in p["expiring_evidence"]]
        self.assertEqual(len(names), 5)
        for expected in ("Recently deleted photos", "Deleted iMessages",
                         "Safari history", "KnowledgeC / Biome streams",
                         "Unified logs"):
            self.assertIn(expected, names)

    def test_render_contains_honesty_block(self):
        out = bfu.render_preservation_plan(
            bfu.preservation_plan("18.1", ago(1), NOW))
        self.assertIn("does NOT defeat the SEP timer", out)
        self.assertIn("returns to BFU", out)
        self.assertIn("stay locked", out)
        self.assertIn("No step here", out)

    def test_render_contains_all_five_expiring_classes(self):
        out = bfu.render_preservation_plan(
            bfu.preservation_plan("18.1", ago(1), NOW))
        for expected in ("Recently deleted photos", "Deleted iMessages",
                         "Safari history", "KnowledgeC / Biome streams",
                         "Unified logs"):
            self.assertIn(expected, out)

    def test_render_mentions_radio_isolation(self):
        out = bfu.render_preservation_plan(
            bfu.preservation_plan("18.1", ago(1), NOW))
        self.assertIn("Faraday", out)
        self.assertIn("airplane mode", out)


if __name__ == "__main__":
    unittest.main()
