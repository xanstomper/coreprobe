"""iCloud acquisition harness (lawful-authorization gated).

Only runs when the examiner supplies lawful authorization (--warrant). Uses
pyicloud when installed; pulls account-level data exposed by Apple's web
APIs: contacts, calendars, notes, reminders, and photo/device counts.

Honest limits:
  - Apple controls these web APIs; schema/availability changes break them.
  - Requires the Apple ID + a 2FA session (pyicloud interactive session).
  - Only account-level services are exposed; on-device protected data is NOT
    accessible through iCloud web APIs.
  - Legal: you MUST have a warrant/consent. The tool refuses otherwise.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

WARRANT_REQUIRED = "iCloud acquisition requires lawful authorization: pass --warrant <case-id>"


def auth_gate(args) -> str | None:
    """Return an error string when authorization is missing/incomplete."""
    warrant = getattr(args, "warrant", None)
    if not warrant:
        return WARRANT_REQUIRED
    if len(str(warrant).strip()) < 3:
        return "warrant id too short; use the case/warrant reference"
    return None


def _pyicloud():
    try:
        from pyicloud import PyiCloudService  # type: ignore
        return PyiCloudService
    except ImportError:
        return None


def _safe(fn, name: str, retries: int = 2) -> tuple[Any, str | None]:
    """Call a pyicloud service with retries; returns (data, error)."""
    last = None
    for attempt in range(retries + 1):
        try:
            return fn(), None
        except Exception as exc:  # noqa: BLE001
            last = exc
    return None, f"{name} failed after {retries + 1} attempts: {last}"[:200]


def acquire(args) -> dict[str, Any]:
    gate = auth_gate(args)
    if gate:
        return {"ok": False, "error": gate}

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    cls = _pyicloud()
    if cls is None:
        return {
            "ok": False,
            "error": "pyicloud not installed. Install: pip install pyicloud "
                     "(requires a 2FA session; see pyicloud docs).",
        }
    if not getattr(args, "username", None) or not getattr(args, "password", None):
        return {
            "ok": False,
            "error": "Apple ID credentials required (--username --password). "
                     "Use an account approved under the warrant.",
        }

    api = cls(args.username, args.password)
    if not api.requires_2fa:
        # some sessions already trusted; continue
        pass

    data: dict[str, Any] = {
        "warrant": args.warrant,
        "account": getattr(args, "username", None),
        "trusted": bool(api.trusted_session),
        "requires_2fa": bool(api.requires_2fa),
        "contacts": [],
        "calendars": [],
        "notes": [],
        "reminders": [],
        "photos_count": None,
        "devices": [],
    }

    contacts, err = _safe(lambda: list(api.contacts.all())[:2000], "contacts")
    if err:
        data["contacts_error"] = err
    else:
        for c in contacts or []:
            rec = {k: v for k, v in c.items() if v is not None and k not in ("_recordName",)}
            data["contacts"].append(rec)

    cal, err = _safe(lambda: list(api.calendar.events())[:500], "calendars")
    if err: data["calendars_error"] = err
    else: data["calendars"] = cal or []

    notes, err = _safe(lambda: list(api.notes.get_notes())[:500], "notes")
    if err: data["notes_error"] = err
    else: data["notes"] = notes or []

    rem, err = _safe(lambda: list(api.reminders.get_reminders())[:500], "reminders")
    if err: data["reminders_error"] = err
    else: data["reminders"] = rem or []

    photos, err = _safe(lambda: len(list(api.photos.all())), "photos")
    if err: data["photos_error"] = err
    elif photos is not None: data["photos_count"] = photos

    devs, err = _safe(lambda: list(api.devices.all()), "devices")
    if err: data["devices_error"] = err
    else: data["devices"] = devs or []

    (out / "icloud-report.json").write_text(
        __import__("json").dumps(data, indent=2, default=str))
    return {"ok": True, "report": str(out / "icloud-report.json"), "summary": {
        "contacts": len(data.get("contacts", [])),
        "calendars": len(data.get("calendars", [])),
        "notes": len(data.get("notes", [])),
        "reminders": len(data.get("reminders", [])),
        "photos": data.get("photos_count"),
        "devices": len(data.get("devices", [])),
    }}


def cmd_acquire_icloud(args):
    import sys

    r = acquire(args)
    if not r.get("ok"):
        print(f"icloud: {r.get('error')}", file=sys.stderr)
        sys.exit(1)
    print("icloud report:", r["report"])
    for k, v in r["summary"].items():
        print(f"  {k}: {v}")
    print("  note: account-level data only; on-device protected data is not")
    print("  accessible through iCloud web APIs. Preserve the 2FA session.")