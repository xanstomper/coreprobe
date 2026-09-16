"""iOS keybag parsing and BFU analysis.

Implements the publicly documented "kbagic" binary keybag layout (as used
by iphone-dataprotection / forensic references):

    magic "kbagic" | version u8 | type u8 | uuid 16B | numKeys u32le
    per key:
      uuid 16B | class u32le | type u16le | wipe u8 | prot_class u8
      | keyflags u32le | keylen u32le | wrapped key (keylen bytes)

Keybag type: 0=system, 1=backup, 2=escrow, 3=user.

At BFU the honest status: if a class's wrapped key is present and
non-zero, that class is usable (key material available in this bag);
if missing/zeroed, the class stays encrypted until first unlock.

Escrow records (iTunes-created, from a previously trusted computer) can
carry a backup-type keybag that unlocks classes for backup decryption -
analyzing one tells you which classes the escrow covers.
"""

from __future__ import annotations

import plistlib
import struct
from pathlib import Path
from typing import Any

MAGIC = b"kbagic"

# prot_class -> human name (public forensic mapping)
CLASS_NAMES = {
    0: "None/unknown",
    1: "NSFileProtectionNone",
    2: "NSFileProtectionComplete",
    3: "NSFileProtectionCompleteUnlessOpen",
    4: "NSFileProtectionCompleteUntilFirstUserAuthentication",
    5: "NSFileProtectionCompleteUntilFirstUserAuthenticationUnlessOpen",
    6: "NSFileProtectionCompleteUntilFirstUserAuthenticationWithProtectionOpen",
}

TYPE_NAMES = {0: "system", 1: "backup", 2: "escrow", 3: "user"}


class KeybagError(Exception):
    pass


def parse_keybag(data: bytes, source: str = "<bytes>") -> dict[str, Any]:
    """Parse a kbagic binary keybag into a dict (lenient: tolerates a
    truncated trailing wrapped key, which real-world bags occasionally have)."""
    if not data:
        raise KeybagError("empty keybag data")
    if data[: len(MAGIC)] != MAGIC:
        raise KeybagError(f"{source}: missing kbagic magic")
    if len(data) < 28:
        raise KeybagError(f"{source}: header truncated")
    version = data[6]
    ktype = data[7]
    uuid = data[8:24].hex()
    num_keys = struct.unpack("<I", data[24:28])[0]
    offset = 28
    keys = []
    for i in range(num_keys):
        if offset + 24 > len(data):
            raise KeybagError(f"{source}: key {i} header truncated at byte {offset}")
        k_uuid = data[offset : offset + 16].hex()
        klass = struct.unpack("<I", data[offset + 16 : offset + 20])[0]
        typ = struct.unpack("<H", data[offset + 20 : offset + 22])[0]
        wipe = data[offset + 22]
        prot_class = data[offset + 23]
        offset += 24
        key = b""
        if offset + 8 <= len(data):
            flags, klen = struct.unpack("<II", data[offset : offset + 8])
            offset += 8
            if offset + klen <= len(data):
                key = data[offset : offset + klen]
                offset += klen
            else:
                key = data[offset:]
                offset = len(data)
        keys.append({
            "uuid": k_uuid,
            "class": klass,
            "type": typ,
            "wipe": wipe,
            "prot_class": prot_class,
            "class_name": CLASS_NAMES.get(prot_class, f"class-{prot_class}"),
            "key_present": bool(key) and any(key),
            "key_len": len(key),
        })
    return {
        "source": source,
        "version": version,
        "type": ktype,
        "type_name": TYPE_NAMES.get(ktype, f"type-{ktype}"),
        "uuid": uuid,
        "num_keys": num_keys,
        "keys": keys,
    }


def keybag_status(bag: dict[str, Any]) -> dict[str, Any]:
    """Per-class key presence: usable now vs locked until first unlock."""
    per_class: dict[str, dict[str, Any]] = {}
    for k in bag["keys"]:
        c = k["class_name"]
        cur = per_class.setdefault(c, {"keys": 0, "present": 0, "wiped": 0, "types": set()})
        cur["keys"] += 1
        cur["types"].add(k["type"])
        if k["key_present"]:
            cur["present"] += 1
        if k["wipe"]:
            cur["wiped"] += 1
    rows = []
    for name, cur in sorted(per_class.items()):
        rows.append({
            "class": name,
            "keys": cur["keys"],
            "key_material_present": cur["present"],
            "usable_now": cur["present"] > 0 and cur["keys"] == cur["present"],
            "wiped": cur["wiped"] > 0,
        })
    return {"bag_type": bag["type_name"], "classes": rows,
            "usable_count": sum(1 for r in rows if r["usable_now"])}


def analyze(path: str | Path) -> dict[str, Any]:
    """Parse any kbagic keybag file and produce the BFU status report."""
    p = Path(path)
    bag = parse_keybag(p.read_bytes(), source=str(p))
    status = keybag_status(bag)
    return {**bag, "status": status}


def escrow_keybags(path: str | Path) -> list[dict[str, Any]]:
    """Extract keybags embedded in an escrow record (plist)."""
    p = Path(path)
    try:
        with open(p, "rb") as fh:
            root = plistlib.load(fh)
    except Exception as exc:  # noqa: BLE001
        raise KeybagError(f"{p}: not a readable plist: {exc}") from exc
    found = []

    def walk(node: Any, path_str: str = ""):
        if isinstance(node, bytes):
            if node[: len(MAGIC)] == MAGIC:
                try:
                    found.append(parse_keybag(node, source=f"{p}:{path_str or '<root>'}"))
                except KeybagError:
                    pass
            return
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path_str}/{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path_str}[{i}]")

    walk(root)
    if not found:
        raise KeybagError(f"{p}: no kbagic keybag found inside the plist")
    return found


def render_status(path: str | Path) -> str:
    a = analyze(path)
    lines = [
        f"keybag: {a['type_name']} (v{a['version']}) uuid={a['uuid']} keys={a['num_keys']}",
        f"source: {a['source']}",
        "",
        f"{'class':<62}{'keys':<7}{'present':<9}{'usable now':<12}{'wiped':<6}",
        "-" * 92,
    ]
    for r in a["status"]["classes"]:
        lines.append(f"{r['class']:<62}{r['keys']:<7}{r['key_material_present']:<9}"
                     f"{'YES' if r['usable_now'] else 'NO  (locked until 1st unlock)':<12}{'yes' if r['wiped'] else '':<6}")
    lines.append("")
    lines.append(f"classes with key material available now: {a['status']['usable_count']}")
    lines.append("")
    lines.append("BFU reading: key material present = usable in this bag;")
    lines.append("missing/zeroed keys on Complete* classes = encrypted until")
    lines.append("the passcode is entered once (AFU). No open route bypasses")
    lines.append("SEP passcode enforcement.")
    return "\n".join(lines)


def render_escrow(path: str | Path) -> str:
    bags = escrow_keybags(path)
    lines = [f"escrow record: {path} - {len(bags)} keybag(s) found", ""]
    for b in bags:
        st = keybag_status(b)
        lines.append(f"  {b['type_name']} keybag v{b['version']} uuid={b['uuid']}")
        for r in st["classes"]:
            lines.append(f"    {'+' if r['usable_now'] else '-'} {r['class']}"
                         f"  ({r['key_material_present']}/{r['keys']} keys)")
    lines.append("")
    lines.append("escrow keybags are created by previously trusted computers;")
    lines.append("they can unlock backup decryption for the classes shown as '+'.")
    return "\n".join(lines)