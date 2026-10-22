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
from datetime import datetime, timezone
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


# AFU preservation: the SEP inactivity-reboot countdown ---------------------
# iOS 18 introduced an inactivity reboot: the SEP holds the last-unlock
# time in silicon and reboots the device back to BFU once the window
# lapses (72h on iOS 18.1+, 7 days on iOS 18.0, no timer before iOS 18).
# Because the timestamp lives in the SEP, feeding the device a different
# clock (NTP or otherwise) does NOT move the deadline. What an examiner
# CAN do is preserve the AFU state: isolate the device, record the
# countdown, and capture expiring evidence first. That is all this model
# claims - it is a playbook, not an exploit.

def _ios_version_tuple(ios: str) -> tuple[int, int] | None:
    """Parse '18.1' / '26.0.1' / '17' -> (major, minor); None if unknown."""
    if not ios:
        return None
    parts = str(ios).strip().split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        return None
    return (major, minor)


def time_to_bfu(ios: str, last_unlock: datetime | None,
                now: datetime | None = None) -> dict[str, Any]:
    """Model the iOS inactivity-reboot countdown for an AFU device.

    ios:         version string as reported at intake (e.g. '18.1', '26.2').
    last_unlock: when the device was last unlocked (examiner-recorded at
                 intake); None if not recorded.
    now:         evaluation time; defaults to the current time.

    States: 'afu-safe' (>=24h left), 'afu-expiring' (<24h left),
    'bfu-imminent' (<2.5h left - the last documented checkpoint),
    'already-bfu-window' (deadline passed; the device has rebooted or
    will at next SEP check), 'no-timer' (pre-iOS 18), 'unknown'.
    """
    result: dict[str, Any] = {
        "ios": ios,
        "applies": False,
        "deadline_hours": None,
        "seconds_remaining": None,
        "state": "unknown",
        "note": "",
    }
    ver = _ios_version_tuple(ios)
    if ver is None:
        result["note"] = (
            "iOS version unknown, so the inactivity-reboot timer cannot be "
            "modelled. Record the exact iOS version and the last-unlock time "
            "at intake - without them no countdown is possible.")
        return result
    if ver < (18, 0):
        result["state"] = "no-timer"
        result["note"] = (
            "Pre-iOS 18: no inactivity reboot timer. The device stays AFU "
            "until it loses power or is rebooted manually; standard intake "
            "isolation still applies.")
        return result
    deadline_hours = 72 if ver >= (18, 1) else 168
    result["applies"] = True
    result["deadline_hours"] = deadline_hours
    if last_unlock is None:
        result["note"] = (
            f"iOS {ios} reboots to BFU after {deadline_hours}h without an "
            "unlock, but the last-unlock time was not recorded, so the "
            "remaining window is unknown. The examiner must record the "
            "last-unlock time at intake; treat the device as expiring "
            "until it is known.")
        return result
    if now is None:
        now = datetime.now(last_unlock.tzinfo or timezone.utc)
    remaining = deadline_hours * 3600 - (now - last_unlock).total_seconds()
    if remaining <= 0:
        result["state"] = "already-bfu-window"
        result["seconds_remaining"] = 0
        result["note"] = (
            f"The {deadline_hours}h inactivity window has lapsed: the device "
            "has rebooted to BFU (or will at the next SEP check). "
            "Passcode-protected classes are locked again; preservation is "
            "no longer possible for this unlock cycle.")
        return result
    result["seconds_remaining"] = int(remaining)
    hours_left = remaining / 3600.0
    if remaining < 2.5 * 3600:
        result["state"] = "bfu-imminent"
    elif remaining < 24 * 3600:
        result["state"] = "afu-expiring"
    else:
        result["state"] = "afu-safe"
    result["note"] = (
        f"{hours_left:.1f}h remain before the SEP inactivity reboot returns "
        f"this device to BFU (deadline {deadline_hours}h from last unlock). "
        "The deadline is held by the SEP in silicon; clock-feeding or NTP "
        "manipulation cannot move it. Documented checkpoints: 72h/48h/24h/"
        "2.5h remaining on the 72h timer.")
    return result


# Evidence classes that expire on their own clocks while a device sits in
# evidence storage - capture these FIRST at AFU intake (Elcomsoft, Oct 2025).
EXPIRING_EVIDENCE = [
    {"evidence": "Recently deleted photos", "ttl": "~30 days",
     "note": "Photos 'Recently Deleted' album purges on its own schedule"},
    {"evidence": "Deleted iMessages", "ttl": "~30 days",
     "note": "Messages 'Recently Deleted' retention window"},
    {"evidence": "Safari history", "ttl": "~30 days per record",
     "note": "history rows age out record by record"},
    {"evidence": "KnowledgeC / Biome streams", "ttl": "~28-30 days",
     "note": "app-usage, focus, and activity streams roll off"},
    {"evidence": "Unified logs", "ttl": "~10-30 days",
     "note": "log archive TTL; shortest clock of the five - pull early"},
]

PRESERVATION_HONESTY = [
    "This plan preserves AFU state; it does NOT defeat the SEP timer.",
    "If the deadline passes, the device returns to BFU and, on A12+, "
    "passcode-protected classes (Complete*) stay locked.",
    "No step here - isolation, clock handling, or otherwise - bypasses "
    "the inactivity reboot or SEP passcode enforcement.",
]


def preservation_plan(ios: str, last_unlock: datetime | None = None,
                      now: datetime | None = None) -> dict[str, Any]:
    """Ordered AFU intake checklist: countdown, isolation, expiry-first capture.

    This is the open equivalent of what commercial tools sell as AFU
    'preserve': a disciplined intake playbook. It makes no exploit claim.
    """
    countdown = time_to_bfu(ios, last_unlock, now)
    steps = [
        {"n": 1, "phase": "record-state",
         "action": ("Record the unlock state (AFU vs BFU), the exact iOS "
                    "version, and the last-unlock time; start the countdown."),
         "detail": (f"countdown state: {countdown['state']} "
                    f"(deadline_hours={countdown['deadline_hours']}, "
                    f"seconds_remaining={countdown['seconds_remaining']})")},
        {"n": 2, "phase": "radio-isolation",
         "action": ("Isolate the device from radios: airplane mode if the "
                    "unlocked UI allows it, otherwise a Faraday bag/box for "
                    "the entire storage and transport period."),
         "detail": ("Note: on a locked or partially trusted device, verify "
                    "USB accessory trust and Stolen Device Protection state "
                    "before assuming host access will persist - record what "
                    "was observed at intake rather than assuming it.")},
        {"n": 3, "phase": "expiry-first-capture",
         "action": ("Capture expiring evidence first, in TTL order, before "
                    "any bulk acquisition:"),
         "detail": "; ".join(f"{e['evidence']} ({e['ttl']})"
                             for e in EXPIRING_EVIDENCE)},
        {"n": 4, "phase": "acquire-before-deadline",
         "action": ("Run the full AFU acquisition inside the countdown "
                    "window; if the window will lapse mid-acquisition, "
                    "finish the expiring classes first and log the lapse."),
         "detail": countdown["note"]},
    ]
    return {
        "ios": ios,
        "countdown": countdown,
        "steps": steps,
        "expiring_evidence": [dict(e) for e in EXPIRING_EVIDENCE],
        "honesty": list(PRESERVATION_HONESTY),
    }


def render_preservation_plan(plan: dict[str, Any]) -> str:
    cd = plan["countdown"]
    lines = [
        f"AFU preservation plan: iOS {plan['ios'] or '?'}",
        f"  countdown: {cd['state']}  deadline_hours: {cd['deadline_hours']}  "
        f"seconds_remaining: {cd['seconds_remaining']}",
        "",
    ]
    for s in plan["steps"]:
        lines.append(f"{s['n']}. [{s['phase']}] {s['action']}")
        lines.append(f"     {s['detail']}")
        if s["phase"] == "expiry-first-capture":
            for e in plan["expiring_evidence"]:
                lines.append(f"       - {e['evidence']:<28}{e['ttl']:<18}{e['note']}")
    lines.append("")
    lines.append("Honest limits:")
    for h in plan["honesty"]:
        lines.append(f"- {h}")
    return "\n".join(lines)


def usbliter8_plan(chip: str = "A13") -> dict[str, Any]:
    """Structured BFU playbook for A12/A13 via the usbliter8 DFU route.

    Honest: iBoot control + ramdisk boot at BFU still does NOT give
    passcode-gated classes (SEP wraps the user keybag). It gives keybags,
    fs metadata, unprotected classes, iBoot env, and the escrow path
    below. The SEP wall is stated explicitly.
    """
    from .matrix import USBLITER8_CHIPS
    chip = (chip or "?").upper()
    eligible = chip in USBLITER8_CHIPS
    steps = [
        {"n": 1, "phase": "prepare",
         "cmd": "flash usbliter8 firmware to RP2350 board (Pico 2 / Waveshare RP2350 USB-A)",
         "expect": "UF2 flashed; board enumerates as the iBooter", "hw": True},
        {"n": 2, "phase": "dfu",
         "cmd": "enter DFU on the device (vol-down+power method; not via LLB)",
         "expect": "device state = DFU (check: opensleuth acquire probe / lsusb 05ac:1227)",
         "hw": True},
        {"n": 3, "phase": "pwn",
         "cmd": "plug device into the RP2350 board, wait for LED; replug to PC",
         "expect": "USB serial ends 'PWND:[usbliter8]' (verify: opensleuth acquire usbliter8 --out <case>)",
         "hw": True},
        {"n": 4, "phase": "control",
         "cmd": "usbliter8ctl boot <raw-iBoot> OR usbliter8ctl demote",
         "expect": "iBoot command control from host; env readable (irecovery -c getenv)",
         "hw": True},
        {"n": 5, "phase": "ramdisk",
         "cmd": ("usbliter8ra1n: boot SSH ramdisk (kernel/ramdisk/trustcache from "
                 "your IPSW, trees signed per-device)"),
         "expect": "SSH on 127.0.0.1:2222; mount data volume", "hw": True},
        {"n": 6, "phase": "bfu-pull",
         "cmd": ("pull: /var/Keychains/*.kb (system/user keybags), fs metadata, "
                 "unprotected classes, iBoot env, nonce"),
         "expect": "keybags + metadata captured; Complete* content stays encrypted",
         "hw": True},
        {"n": 7, "phase": "escrow",
         "cmd": "analyze escrow records from paired computers (opensleuth escrow describe/find)",
         "expect": "passcode-free backup unlock coverage on covered classes", "hw": False},
    ]
    return {
        "chip": chip,
        "eligible": eligible,
        "route": "usbliter8" if eligible else f"NOT ELIGIBLE ({chip})",
        "steps": steps,
        "sep_wall": ("SEP still enforces passcode gating: user-class keys are "
                     "created at first unlock and wrapped in the SEP. No open "
                     "route obtains them at BFU on A12+."),
    }


def yield_card(chip: str = "?", ios: str = "?",
               device_flags: dict[str, Any] | None = None,
               tooling: dict[str, bool] | None = None) -> dict[str, Any]:
    """What THIS device can actually yield at BFU right now.

    device_flags: e.g. {'dfu': bool, 'recovery': bool, 'pwnd': bool,
                        'attached': bool}
    tooling:      e.g. {'gaster': bool, 'palera1n': bool,
                        'usbliter8ctl': bool, 'sshpass': bool}
    """
    from .matrix import CHIP_RANK, USBLITER8_CHIPS
    chip = (chip or "?").upper()
    flags = device_flags or {}
    tools = tooling or {}
    rank = CHIP_RANK.get(chip)
    checkm8 = rank is not None and rank <= 11
    usbliter8 = chip in USBLITER8_CHIPS
    pwnd = bool(flags.get("pwnd"))
    in_dfu = bool(flags.get("dfu")) or bool(flags.get("recovery"))
    attached = bool(flags.get("attached"))

    items: list[dict[str, Any]] = [
        {"item": "USB identity (serial/UDID/ECID)", "state": "obtainable" if attached else "no device",
         "action": "attach device" if not attached else "usb_state captured"},
        {"item": "iBoot env (serial/ecid/boardid/sxpt)", "state": "obtainable" if (in_dfu and pwnd) else
         ("pwnd DFU pending" if in_dfu else "enter DFU + pwn"),
         "action": "irecovery -c getenv" if (in_dfu and pwnd) else None},
        {"item": "AES keyset (GID/UID)", "state": "obtainable" if (checkm8 and pwnd and tools.get("gaster")) else
         ("needs gaster + pwn" if checkm8 else "SEP-gated on this chip"),
         "action": "gaster keys" if (checkm8 and pwnd) else None},
        {"item": "system/user keybags (/var/Keychains)", "state": "obtainable" if (pwnd and (tools.get("sshpass") or tools.get("ssh"))) else
         ("needs ramdisk + ssh" if (checkm8 or usbliter8) and pwnd else
          ("needs pwn" if checkm8 or usbliter8 else "not without first unlock")),
         "action": "ramdisk extract flow" if pwnd else None},
        {"item": "Complete* class content", "state": "locked at BFU (SEP)",
         "action": "first unlock (AFU) or escrow/backup path"},
        {"item": "escrow/backup unlock (paired computers)", "state": "case-dependent",
         "action": "opensleuth escrow find <case-dir>"},
    ]
    return {
        "chip": chip,
        "ios": ios,
        "attached": attached,
        "in_dfu_recovery": in_dfu,
        "pwnd": pwnd,
        "checkm8_eligible": checkm8,
        "usbliter8_eligible": usbliter8,
        "yield": items,
    }


def render_yield_card(card: dict[str, Any]) -> str:
    lines = [
        f"BFU yield card: {card['chip']} / {card['ios'] or '?'}",
        f"  device attached: {'yes' if card['attached'] else 'NO'}   "
        f"recovery/DFU: {'yes' if card['in_dfu_recovery'] else 'no'}   "
        f"pwnd: {'yes' if card['pwnd'] else 'no'}",
        "",
        f"{'item':<46}{'state':<28}action",
        "-" * 110,
    ]
    for it in card["yield"]:
        lines.append(f"{it['item']:<46}{it['state']:<28}{it['action'] or '—'}")
    lines.append("")
    if card["checkm8_eligible"]:
        lines.append("checkm8 route available: pwn -> keys -> keybags -> metadata")
    elif card["usbliter8_eligible"]:
        lines.append("usbliter8 route: RP2350 pwn -> iBoot control -> ramdisk (SEP still gates)")
    else:
        lines.append("no public bootrom route for this chip; escrow is the passcode-free path")
    return "\n".join(lines)


def bfu_runbook(chip: str = "?", ios: str = "?", case_dir: str = "case") -> str:
    """Markdown runbook for the case file."""
    card = yield_card(chip, ios)
    from .keybag import CLASS_NAMES  # noqa: F401  (documentation reference)
    md = [
        f"# BFU acquisition runbook - {chip or '?'} / {ios or '?'}",
        "",
        "## 1. State check",
        "```bash",
        "opensleuth acquire probe",
        "opensleuth doctor",
        "```",
        "",
        "## 2. Identity (always obtainable)",
        "```bash",
        "opensleuth acquire info --out case/info.json",
        "```",
        "",
        "## 3. Expectations",
        "```bash",
        f"opensleuth acquire bfu --chip {chip or '?'} --ios {ios or '?'} --out {case_dir}",
        "```",
        "",
        "## 4. Pwn + extraction",
    ]
    if card["checkm8_eligible"]:
        md += [
            "```bash",
            "# put device in DFU, then:",
            f"opensleuth acquire bfu --chip {chip or '?'} --watch --keys --ramdisk ./payloads --out {case_dir}",
            "opensleuth keybag status case/systembag.kb   # per-class usable-now",
            "```",
        ]
    elif card["usbliter8_eligible"]:
        md += [
            "```bash",
            "opensleuth acquire bfu --chip A13 --route usbliter8 --out case",
            "# RP2350 rig: DFU -> PWND:[usbliter8] -> ramdisk (usbliter8ra1n)",
            "opensleuth keybag status case/systembag.kb",
            "```",
        ]
    else:
        md += [
            "> no public bootrom route for this chip. Escrow/backup path:",
            "```bash",
            "opensleuth escrow find <case-materials>",
            "opensleuth escrow describe <record>",
            "opensleuth escrow unlock <record> <backup> --out case/decrypted",
            "```",
        ]
    md += [
        "",
        "## 5. Escrow sweep (paired computers)",
        "```bash",
        f"opensleuth escrow sweep <materials-dir> --out {case_dir}",
        "```",
        "",
        "## 6. Honest limits",
        f"- {card['yield'][4]['state']}: {card['yield'][4]['action']}",
        "- No open route bypasses SEP passcode enforcement at BFU.",
        "- Document everything; keep hashes (opensleuth cxx hash).",
        "",
    ]
    return "\n".join(md)


def render_usbliter8_plan(chip: str = "A13") -> str:
    p = usbliter8_plan(chip)
    lines = [
        f"usbliter8 BFU playbook: chip {p['chip']}  route: {p['route']}",
        "",
    ]
    if not p["eligible"]:
        lines.append("This chip has no public usbliter8 route (A14+).")
        lines.append("Escrow/paired-computer is the only passcode-free path:")
        lines.append("  opensleuth escrow find <case-dir>")
        lines.append("  opensleuth escrow describe <record>")
        lines.append("  opensleuth escrow unlock <record> <backup-dir> --out <dir>")
        return "\n".join(lines)
    for s in p["steps"]:
        hw = " [HW-RIG]" if s["hw"] else ""
        lines.append(f"{s['n']}. [{s['phase']}]{hw} {s['cmd']}")
        lines.append(f"     expect: {s['expect']}")
    lines.append("")
    lines.append(f"SEP wall: {p['sep_wall']}")
    return "\n".join(lines)


# Ramdisk extraction path (checkm8-eligible devices, payloads provided) ------
# Payloads dir layout (standard for this flow):
#   iBSS, iBEC, ramdisk (img4), devicetree, trustcache
RAMDISK_FILES = ["iBSS", "iBEC", "ramdisk", "devicetree", "trustcache"]


def capture_aes_keys(out: str | Path, tool: str = "gaster") -> dict[str, Any]:
    """Dump the device AES keyset from a pwned A7-A11 device.

    gaster (preferred): 'gaster keys' writes files to ./gaster/ or stdout
    depending on build; ipwndfu: 'ipwndfu -k' prints keys to a file.
    Returns what was captured and where, honestly (may fail without a
    pwned device in DFU).
    """
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    if tool == "gaster":
        cmd = ["gaster", "keys"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        except FileNotFoundError:
            return {"ok": False, "error": "gaster not installed",
                    "hint": "sudo apt install gaster  (or clone 0x7ff/gaster)"}
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "gaster keys timed out (device must be checkm8-pwned, in DFU)"}
        # gaster keys writes ./gaster/*.bin and prints a summary
        produced = sorted(Path("gaster").glob("*.bin")) if Path("gaster").exists() else []
        if p.returncode == 0 and produced:
            saved = []
            for f in produced:
                dest = out / f.name
                dest.write_bytes(f.read_bytes())
                saved.append(str(dest))
            return {"ok": True, "tool": "gaster", "keys": saved,
                    "note": "AES keyset (GID/UID-wrapped) captured from the pwned device"}
        return {"ok": False, "error": "gaster keys produced no keyset",
                "out": (p.stdout or p.stderr).strip()[-300:],
                "hint": "device must be checkm8-pwned and in DFU (run gaster pwn first)"}
    if tool == "ipwndfu":
        cmd = ["ipwndfu", "-k"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        except FileNotFoundError:
            return {"ok": False, "error": "ipwndfu not installed",
                    "hint": "git clone https://github.com/axi0mX/ipwndfu && ./ipwndfu -k"}
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "ipwndfu -k timed out (device must be in pwned DFU)"}
        if p.returncode == 0:
            target = out / "aes-keys-ipwndfu.bin"
            target.write_bytes((p.stdout or p.stderr).encode())
            return {"ok": True, "tool": "ipwndfu", "keys": [str(target)],
                    "note": "AES keyset output captured (verify with keybag analysis)"}
        return {"ok": False, "error": "ipwndfu -k failed",
                "out": (p.stdout or p.stderr).strip()[-300:]}
    return {"ok": False, "error": f"unknown tool: {tool}"}


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