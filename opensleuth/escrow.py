"""Escrow / paired-computer acquisition for iOS (works on ALL models).

Background: when a device is trusted/paired with a computer (iTunes/Finder),
the computer receives an ESCROW record containing a backup-type keybag and -
on macOS/iOS flows - escrowed passcode material. That escrow is the one
passcode-free unlock path that does not depend on chip or iOS version:
Cellebrite-class tools use it for "advanced logical" after prior trust.

This module:
  find      - locate escrow records / backup keybags inside case materials
  describe  - classes covered by an escrow record (which data it can unlock)
  unlock    - attempt encrypted-backup decryption using escrow material
              (honest: reports exactly what was used and what still fails)

Honesty notes:
  - Escrow records sometimes omit passcode material; then decryption still
    requires the device passcode or the paired computer's own keychain.
  - Per-class coverage varies; described precisely from the keybag.
  - This is lawful-acquisition plumbing: records come from consented/
    warranted devices and their paired computers.
"""

from __future__ import annotations

import plistlib
from pathlib import Path
from typing import Any

from .keybag import KeybagError, escrow_keybags, keybag_status, parse_keybag

ESCROW_HINTS = ("EscrowRecords", "escrow", "backupbag", "BackupKeyBag", "systembag")


def find_records(root: str | Path) -> list[dict[str, Any]]:
    """Scan a directory tree for plists that contain kbagic keybags."""
    root = Path(root)
    found: list[dict[str, Any]] = []
    if not root.exists():
        return found
    for f in sorted(root.rglob("*")):
        if not f.is_file():
            continue
        low = f.name.lower()
        if not any(h in low for h in ESCROW_HINTS) and f.suffix.lower() not in (".plist", ".kb", ".keybag"):
            continue
        try:
            data = f.read_bytes()
        except OSError:
            continue
        if b"kbagic" in data or f.suffix.lower() in (".plist", ".kb", ".keybag"):
            bags = []
            try:
                bags = escrow_keybags(f)
            except KeybagError:
                try:
                    bags = [parse_keybag(data, source=str(f))]
                except KeybagError:
                    bags = []
            if bags:
                found.append({
                "path": str(f),
                "size": len(data),
                "keybags": [{"type": b["type_name"], "classes": keybag_status(b)["classes"]}
                            for b in bags],
            })
    return found


def describe(record: str | Path) -> dict[str, Any]:
    """Full description of an escrow record."""
    r = Path(record)
    bags = escrow_keybags(r)
    out = {"path": str(r), "keybags": []}
    try:
        with open(r, "rb") as fh:
            root = plistlib.load(fh)
        out["plist_keys"] = sorted(str(k) for k in root.keys()) if isinstance(root, dict) else []
    except Exception:  # noqa: BLE001
        out["plist_keys"] = []
    for b in bags:
        st = keybag_status(b)
        out["keybags"].append({
            "type": b["type_name"],
            "uuid": b["uuid"],
            "classes": st["classes"],
            "usable_count": st["usable_count"],
        })
    # passcode material indicator (field names vary; presence is honest info)
    out["passcode_material"] = None
    try:
        with open(r, "rb") as fh:
            root = plistlib.load(fh)

        def scan(node: Any, path_str: str = ""):
            if isinstance(node, dict):
                for k, v in node.items():
                    low = str(k).lower()
                    if any(s in low for s in ("password", "passcode", "keychain")) and \
                       isinstance(v, (str, bytes)) and v:
                        out["passcode_material"] = {"field": f"{path_str}/{k}",
                                                    "len": len(v), "value": v}
                    scan(v, f"{path_str}/{k}")
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    scan(v, f"{path_str}[{i}]")
        scan(root)
    except Exception:  # noqa: BLE001
        pass
    return out


def unlock_backup(record: str | Path, backup_dir: str | Path, out: str | Path,
                  pyiosbackup_module: Any = None) -> dict[str, Any]:
    """Attempt encrypted-backup decryption using escrow material.

    Strategy, honest:
      1. extract any passcode material from the escrow record;
      2. if found, run pyiosbackup decryption with it (same as a passcode);
      3. report per-class coverage of the escrow keybag, so the examiner
         knows what the backup CAN contain after unlock.
    """
    backup_dir = Path(backup_dir)
    out = Path(out)
    try:
        d = describe(record)
    except KeybagError as exc:
        return {"ok": False, "error": f"escrow record unreadable: {exc}"}

    def _sanitize(dd):
        for b in dd.get("keybags", []):
            b.pop("value", None)
        dd.pop("value", None)
        return dd

    if not d["keybags"]:
        return {"ok": False, "error": "no keybags in escrow record",
                "escrow": _sanitize(d)}
    pw = d.get("passcode_material")
    if not pw:
        return {
            "ok": False,
            "error": ("escrow record carries no passcode material; "
                      "decryption still needs the passcode or the paired "
                      "computer's keychain (macOS). Coverage below shows "
                      "what the escrow keybag itself would unlock."),
            "escrow": _sanitize(d),
        }
    if pyiosbackup_module is None:
        try:
            import pyiosbackup  # type: ignore
            pyiosbackup_module = pyiosbackup
        except ImportError:
            return {
                "ok": False,
                "error": "pyiosbackup not installed (pip install pyiosbackup)",
                "escrow": _sanitize(d),
            }
    if not hasattr(pyiosbackup_module, "BackupDecrypt"):
        return {
            "ok": False,
            "error": "installed pyiosbackup has no BackupDecrypt API (unexpected version)",
            "escrow": _sanitize(d),
        }
    out.mkdir(parents=True, exist_ok=True)
    value = pw.get("value", "")
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    try:
        bd = pyiosbackup_module.BackupDecrypt(str(backup_dir))
        bd.decrypt(str(out), value)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"decrypt attempt failed: {exc}",
                "escrow": {"type": d["keybags"][0]["type"],
                           "classes": d["keybags"][0]["classes"]}}
    return {
        "ok": True,
        "decrypted": str(out),
        "escrow": {"type": d["keybags"][0]["type"],
                   "classes": d["keybags"][0]["classes"]},
        "note": "decryption completed with escrow material; validate per-class content",
    }


def render_find(found: list[dict[str, Any]]) -> str:
    if not found:
        return "no escrow/backup keybags found under this path"
    lines = [f"escrow records found: {len(found)}", ""]
    for f in found:
        lines.append(f"  {f['path']}  ({f['size']} B)")
        for b in f["keybags"]:
            usable = [c["class"] for c in b["classes"] if c["usable_now"]]
            lines.append(f"    {b['type']} keybag: {len(b['classes'])} classes, "
                         f"{len(usable)} usable now")
            for c in usable:
                lines.append(f"      + {c}")
    lines.append("")
    lines.append("describe:  opensleuth escrow describe <record>")
    lines.append("unlock:    opensleuth escrow unlock <record> <backup-dir> --out <dir>")
    return "\n".join(lines)


def render_describe(d: dict[str, Any]) -> str:
    lines = [f"escrow record: {d['path']}", f"plist keys: {', '.join(d['plist_keys']) or '—'}",
             f"passcode material: {'YES (' + d['passcode_material']['field'] + ')' if d['passcode_material'] else 'NO'}", ""]
    for b in d["keybags"]:
        lines.append(f"  {b['type']} keybag uuid={b['uuid']}  usable classes: {b['usable_count']}")
        for c in b["classes"]:
            lines.append(f"    {'+' if c['usable_now'] else '-'} {c['class']}"
                         f"  ({c['key_material_present']}/{c['keys']} keys)")
    lines.append("")
    if not d["passcode_material"]:
        lines.append("No passcode material: this record alone cannot decrypt an")
        lines.append("encrypted backup. Pair it with the passcode or the paired")
        lines.append("computer's keychain (macOS Keychain escrow).")
    else:
        lines.append("Passcode material present: encrypted-backup decryption may")
        lines.append("succeed without the user entering the passcode. Run:")
        lines.append("  opensleuth escrow unlock <record> <backup-dir> --out <dir>")
    return "\n".join(lines)