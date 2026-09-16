"""Offscreen smoke test + screenshot generator for opensleuth studio."""

import os
import sys
from pathlib import Path

os.environ["QT_QPA_PLATFORM"] = "offscreen"
sys.path.insert(0, "/home/jewboy420/coreprobe")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from opensleuth.studio.app import MainWindow  # noqa: E402
from opensleuth.studio.theme import QSS  # noqa: E402


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(QSS)
    w = MainWindow()
    w.show()
    w.resize(1460, 920)
    app.processEvents()

    # 1) case builder with realistic data
    cs = w.case_screen
    cs.fields["examiner"].setText("J. Rivera")
    cs.fields["agency"].setText("Open Forensics Unit")
    cs.fields["location"].setText("Lab 2")
    cs.fields["owner"].setText("Device owner (consent)")
    cs.consent.toggle.setChecked(True)
    cs.notes.setPlainText("Consent reference #2026-0915. Scope: full logical acquisition, AFU.")
    w.nav_to(0)
    app.processEvents()
    w.grab().save("/tmp/studio-1-case.png")

    # 2) device screen
    dev = {"model": "iPhone 11", "product_type": "iPhone12,1", "ios": "26.6.1",
           "build": "23G83", "udid": "00008030-001115EC1498C02E", "state": "AFU", "chip": "A13"}
    w.device_screen._device = dev
    w.device_screen._render()
    w.nav_to(1)
    app.processEvents()
    w.grab().save("/tmp/studio-2-device.png")

    # 3) acquisition screen
    case = {"case_id": "CASE-20260915-101200",
            "destination": "/home/jewboy420/cases/CASE-20260915-101200",
            "examiner": "J. Rivera"}
    Path(case["destination"]).mkdir(parents=True, exist_ok=True)
    w.ctx["case"] = case
    w.acquire_screen.load_device(dev, case)
    for name, b, v in [
        ("Instagram", "com.burbn.instagram", "1060018354"),
        ("Snapchat", "com.toyopagroup.picaboo", "14.23.0.56"),
        ("Polymarket", "com.polymarket.ios-app", "245"),
        ("YouTube", "com.google.ios.youtube", "21.36.6"),
        ("Reddit", "com.reddit.Reddit", "664762"),
        ("Gemini", "com.google.gemini", "1.2026.3570503.0"),
        ("Tailscale", "io.tailscale.ipn.ios", "101.102.4"),
        ("FanDuel", "com.fanduel.sportsbook", "260910163"),
        ("Roblox", "com.roblox.robloxmobile", "2.738.1390"),
    ]:
        w.acquire_screen._app_found({"name": name, "bundle": b, "version": v, "icon": None})
    w.acquire_screen.app_count.setText("70 apps — toggle to include in extraction")
    w.nav_to(2)
    app.processEvents()
    w.grab().save("/tmp/studio-3-acquire.png")

    # 3b) progress page
    w.acquire_screen._clear_steps()
    w.acquire_screen._step_start("Full backup")
    w.acquire_screen._step_done("Full backup", True, "backup complete")
    w.acquire_screen._step_start("Media (AFC)")
    w.acquire_screen.logw.append("copied DCIM")
    w.acquire_screen.stack.slide_to(1)
    app.processEvents()
    w.grab().save("/tmp/studio-3b-progress.png")

    # 4) results
    w.ctx["results"] = {"messages": 312, "contacts": 57, "calls": 143, "history": 1204,
                        "bookmarks": 22, "keychain": 38, "voicemail": 6, "notes": 19, "app_databases": 94}
    w.results_screen.load(w.ctx)
    w.nav_to(3)
    app.processEvents()
    w.grab().save("/tmp/studio-4-results.png")

    print("screenshots written to /tmp/studio-*.png")


if __name__ == "__main__":
    main()
