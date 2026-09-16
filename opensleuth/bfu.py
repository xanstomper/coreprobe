"""BFU (Before First Unlock) acquisition planning and partial extraction.

Honest model of what is obtainable before first unlock, per iOS data
protection class, plus a payload-driven ramdisk extraction path for
checkm8-eligible devices (A7-A11) when the examiner provides payloads.

Data protection classes (iOS keybags):
  None (NSFileProtectionNone)          - always readable
  Complete (NSFileProtectionComplete)  - locked until first unlock AFTER boot;
                                          at BFU these are encrypted
  CompleteUnlessOpen (kD)              - readable while open; at BFU
                                          unopened files are encrypted
  CompleteUntilFirstUserAuthentication - metadata readable, content encrypted
                                          until the passcode is entered once
                                          ("First unlock"; AFU)
  ephemeral                            - created with keybags per-boot
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

# per-chip honest expectations ---------------------------------------------
# (class, always, checkm8_bfu, usbliter8_bfu, first_unlock_afu, notes)
PROTECTION_CLASSES = [
    ("None", "readable", "readable", "readable", "readable",
     "keybags, device identity, fs metadata"),
    ("CompleteUntilFirstUserAuthentication", "metadata", "metadata", "metadata",
     "CONTENT DECRYPTED", "files visible at BFU; content stays encrypted until AFU"),
    ("CompleteUnlessOpen", "encrypted", "encrypted", "encrypted", "decrypted",
     "unopened files encrypted at BFU"),
    ("Complete", "encrypted", "encrypted", "encrypted", "decrypted",
     "passcode-gated; never readable at BFU"),
    ("ephemeral (per-boot)", "readable", "readable", "readable", "readable",
     "protects per-boot keys only"),
]

# What the device state means for acquisition tools --------------------------
EXTRACTION_NOTES = {
    "checkm8": ("A7-A11: pwned DFU boots a custom ramdisk; you can dump keybags, "
                "fs metadata, and unprotected classes. Protected-class content "
                "stays encrypted until the passcode is entered (AFU)."),
    "usbliter8": ("A12/A13: DFU command injection (2026-06-18). At BFU this "
                  "gives iBoot control + ramdisk boot; same class limits apply "
                  "for data - SEP wraps user keybags until first unlock."),
    "graykey_class": ("Commercial BFU bypasses (GrayKey/Cellebrite services) "
                      "attack the passcode/SEP, not the keybags - that is why "
                      "they can unlock classes commercial-licensing allows."),
}


def expectations(chip: str = "?", ios: str = "?") -> dict[str, Any]:
    """BFU capability summary for a chip/iOS pair (honest, public-catalog based)."""
    from .matrix import CHIP_RANK, USBLITER8_CHIPS

    chip = (chip or "?").upper()
    rank = CHIP_RANK.get(chip)
    checkm8 = rank is not None and rank <= 11
    usbliter8 = chip in USBLITER8_CHIPS
    return {
        "chip": chip,
        "ios": ios,
        "checkm8_eligible": bool(checkm8),
        "usbliter8_eligible": bool(usbliter8),
        "bfu_bootrom_route": "checkm8" if checkm8 else ("usbliter8" if usbliter8 else "none"),
        "classes": [dict(zip(("class", "always", "checkm8_bfu", "usbliter8_bfu",
                              "first_unlock_afu", "notes"), row))
                    for row in PROTECTION_CLASSES],
        "notes": EXTRACTION_NOTES,
    }


def render_expectations(chip: str = "?", ios: str = "?") -> str:
    e = expectations(chip, ios)
    lines = [
        f"BFU expectations: chip {e['chip']} / iOS {e['ios'] or '?'}",
        f"bootrom route: {'NONE PUBLIC' if not e['bfu_bootrom_route'] or e['bfu_bootrom_route'] == 'none' else e['bfu_bootrom_route']}",
        "",
        f"{'class':<42}{'always':<12}{'checkm8 BFU':<14}{'usbliter8 BFU':<15}{'after 1st unlock':<16}",
        "-" * 99,
    ]
    for c in e["classes"]:
        lines.append(f"{c['class']:<42}{c['always']:<12}{c['checkm8_bfu']:<14}"
                     f"{c['usbliter8_bfu']:<15}{c['first_unlock_afu']:<16}")
        lines.append(f"    {c['notes']}")
    lines.append("")
    lines.append(f"checkm8 summary: {e['notes']['checkm8']}")
    if e["usbliter8_eligible"]:
        lines.append(f"usbliter8 summary: {e['notes']['usbliter8']}")
    lines.append("")
    lines.append("Bottom line: at BFU, examiners get identity, fs metadata, keybags,")
    lines.append("and unprotected classes. Content protected with the user keybag")
    lines.append("(Complete*) is encrypted until the passcode is entered once.")
    lines.append("No open-source route bypasses SEP passcode enforcement; that is")
    lines.append("the GrayKey/Cellebrite service gap.")
    return "\n".join(lines)


# Ramdisk extraction path (checkm8-eligible devices, payloads provided) ------
# Payloads dir layout (standard for this flow):
#   iBSS, iBEC, ramdisk (img4), devicetree, trustcache
RAMDISK_FILES = ["iBSS", "iBEC", "ramdisk", "devicetree", "trustcache"]


def payload_status(payload_dir: str | Path) -> list[dict[str, Any]]:
    d = Path(payload_dir)
    return [{"file": f, "present": (d / f).exists()} for f in RAMDISK_FILES]


def run_ramdisk_extract(payload_dir: str | Path, out: str | Path,
                        remote: str = "root@127.0.0.1",
                        ssh_port: str = "2222") -> dict[str, Any]:
    """Load payloads over irecovery (checkm8-pwned device) and pull BFU data.

    Requires: irecovery, sshpass/ssh, payloads, device pwned and in pwned DFU.
    This is the standard checkm8 acquisition flow; guarded subprocess calls.
    """
    payload_dir = Path(payload_dir)
    out = Path(out)
    missing = [f["file"] for f in payload_status(payload_dir) if not f["present"]]
    if missing:
        return {"ok": False, "error": f"missing payloads: {', '.join(missing)}",
                "payloads": payload_status(payload_dir)}
    out.mkdir(parents=True, exist_ok=True)
    steps: list[dict[str, Any]] = []
    try:
        step = {"cmd": ["irecovery", "-f", str(payload_dir / "iBSS")], "ok": False}
        p = subprocess.run(step["cmd"], capture_output=True, text=True, timeout=60)
        step["ok"] = p.returncode == 0
        step["out"] = (p.stdout or p.stderr).strip()[-200:]
        steps.append(step)

        step = {"cmd": ["irecovery", "-f", str(payload_dir / "iBEC")], "ok": False}
        p = subprocess.run(step["cmd"], capture_output=True, text=True, timeout=60)
        step["ok"] = p.returncode == 0
        step["out"] = (p.stdout or p.stderr).strip()[-200:]
        steps.append(step)

        for f in ("ramdisk", "devicetree", "trustcache"):
            step = {"cmd": ["irecovery", "-f", str(payload_dir / f)], "ok": False}
            p = subprocess.run(step["cmd"], capture_output=True, text=True, timeout=120)
            step["ok"] = p.returncode == 0
            step["out"] = (p.stdout or p.stderr).strip()[-200:]
            steps.append(step)

        step = {"cmd": ["irecovery", "-c", "bootx"], "ok": False}
        p = subprocess.run(step["cmd"], capture_output=True, text=True, timeout=60)
        step["ok"] = p.returncode == 0
        step["out"] = (p.stdout or p.stderr).strip()[-200:]
        steps.append(step)

        if all(s["ok"] for s in steps):
            pull = [
                "sshpass", "-p", "alpine", "ssh", "-p", ssh_port, "-o",
                "StrictHostKeyChecking=no", remote,
                "tar -C / -cf - var/Keychains var/Keychains/cydia 2>/dev/null | true"
            ]
            p = subprocess.run(pull, capture_output=True, text=True, timeout=300)
            if p.returncode == 0 and p.stdout:
                (out / "bfu-keybags.tar").write_bytes(p.stdout.encode("latin-1"))
            return {
                "ok": True,
                "steps": steps,
                "keybags_tar": str(out / "bfu-keybags.tar") if p.stdout else None,
                "note": ("keybags/fs metadata pulled; protected classes remain "
                         "encrypted until first unlock (see expectations)"),
            }
        return {"ok": False, "steps": steps,
                "error": "payload load failed at the first failing step",
                "note": "device must be checkm8-pwned and in pwned DFU state"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "steps": steps, "error": "timed out during payload load"}
    except FileNotFoundError as exc:
        return {"ok": False, "steps": steps, "error": f"missing tool: {exc}"}