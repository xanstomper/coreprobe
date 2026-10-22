"""Route-aware payload registry, fetch, and verification for AFU exploits.

Why this module exists
----------------------
The auto-exploiter's app-based routes (Dopamine, Serotonin, NathanLR,
TrollStore, Misaka/Nugget, ...) each need *their own* payload file. Before
this module existed, the runner installed whichever ``*.ipa``/``*.tipa``
happened to be lying in ``~/payloads`` / ``~/cases`` / the cwd — so a
"Dopamine" route could silently install a Serotonin file, and CoreProbe had
no way to obtain the correct payload at all: no registry, no download, no
hash verification.

This module fixes that with three rules, in line with the repo's honesty
standard:

1. **Registry first.** Every payload is a registry entry: which routes it
   serves (keywords), who publishes it, the official repo, the exact release
   asset, and — only where a hash was verified against the publisher's own
   release metadata — a pinned SHA-256. Hashes are NEVER invented: entries
   whose hash could not be verified carry ``sha256 = None`` and are pinned
   at first fetch instead (see rule 3).
2. **Route-specific matching.** ``find_payload_for(route)`` only returns a
   file that belongs to that route (stored as ``<slug>--<asset>`` by
   :func:`fetch_payload`, or named for the route by the examiner). A file
   claimed by a *different* registry entry is never handed to the wrong
   route. Unclaimed generic files are the only fallback, so an examiner's
   hand-placed ``agent.ipa`` still works for an unknown route.
3. **Fetch = verify + record.** :func:`fetch_payload` downloads only from
   the entry's official release URL, computes SHA-256, and records it in
   ``<payloads_dir>/manifest.json``. If the entry pins a hash — or a hash
   was recorded by an earlier fetch — a mismatch is a hard failure and the
   downloaded file is deleted, never kept.

Payloads live flat in ``payloads_dir()`` (``~/payloads`` by default, or
``$OPENSLEUTH_PAYLOADS_DIR``) named ``<slug>--<asset>`` so simple
non-recursive globs still see them.

Stdlib only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

__all__ = [
    "REGISTRY",
    "payloads_dir",
    "route_keywords",
    "entry_for_route",
    "find_payload_for",
    "list_payloads",
    "fetch_payload",
    "sha256_of",
]

MANIFEST_NAME = "manifest.json"
_CHUNK = 1 << 16


# ---------------------------------------------------------------------------
# Registry
#
# Honesty notes:
# * Dopamine: verified 2026-10-22 against the official GitHub release API —
#   opa334/Dopamine release 3.0.12 (published 2026-10-20) ships
#   Dopamine.ipa / Dopamine.tipa with publisher digest
#   sha256:aa77b06a6b607c356cdf3416b3062480e21db8bedd2297d0c092aa66a1bc08bc.
#   The URL below is that exact release, so the pinned hash is real.
# * TrollStore: verified 2026-10-22 — opa334/TrollStore's latest release
#   (2.1.1) ships NO installable .ipa/.tipa asset (it ships TrollStore.tar
#   plus persistence-helper .debs). The installable TrollStore .tipa is
#   examiner-supplied via the official TrollStore guide, so this entry is
#   manual=True with no download URL and no hash.
# * Serotonin / NathanLR / Misaka-Nugget: keyword entries so route matching
#   and failure messages are route-specific. No official release asset was
#   verified for them when this registry was written, so they are
#   manual=True — examiner supplies the file. Do not add a URL or hash here
#   without verifying it against the publisher's own release first.
# ---------------------------------------------------------------------------

REGISTRY: list[dict[str, Any]] = [
    {
        "slug": "dopamine",
        "name": "Dopamine",
        "vendor": "opa334 (Lars Fröder)",
        "repo": "https://github.com/opa334/Dopamine",
        "keywords": ["dopamine", "cleassword"],
        "asset": "Dopamine.ipa",
        "kind": ".ipa",
        "url": "https://github.com/opa334/Dopamine/releases/download/3.0.12/Dopamine.ipa",
        "version": "3.0.12",
        "sha256": "aa77b06a6b607c356cdf3416b3062480e21db8bedd2297d0c092aa66a1bc08bc",
        "manual": False,
        "notes": (
            "Rootless semi-untethered jailbreak. The 3.x line is the iOS 26-era "
            "release (Dopamine 3.0, Aug 2026) whose chain includes ClearSword, "
            "the cleaned DarkSword-derived exploit, plus Titan/momentarius "
            "PPL/SPTM bypasses — chip/iOS gating is the planner's job, not the "
            "payload's. Pinned hash is the publisher digest of the 3.0.12 "
            "release asset, verified via the GitHub release API 2026-10-22. "
            "Dopamine.tipa (same release, same digest) also works: rename a "
            "fetched copy to dopamine--Dopamine.tipa if a .tipa is preferred."
        ),
    },
    {
        "slug": "trollstore",
        "name": "TrollStore",
        "vendor": "opa334 (Lars Fröder)",
        "repo": "https://github.com/opa334/TrollStore",
        "keywords": ["trollstore", "coretrust"],
        "asset": "TrollStore.tipa",
        "kind": ".tipa",
        "url": None,
        "version": None,
        "sha256": None,
        "manual": True,
        "notes": (
            "CoreTrust permanent-signing installer. The official repo's "
            "latest release (2.1.1, verified 2026-10-22) ships TrollStore.tar "
            "and persistence helpers, NOT an installable .ipa/.tipa — so "
            "there is honestly nothing for this registry to download. "
            "Examiner: obtain the TrollStore .tipa / TrollInstaller from the "
            "official TrollStore guide for your iOS version and place it in "
            "the payloads dir as trollstore--TrollStore.tipa."
        ),
    },
    {
        "slug": "serotonin",
        "name": "Serotonin",
        "vendor": "Serotonin contributors",
        "repo": None,
        "keywords": ["serotonin"],
        "asset": "Serotonin.tipa",
        "kind": ".tipa",
        "url": None,
        "version": None,
        "sha256": None,
        "manual": True,
        "notes": (
            "TrollStore semi-jailbreak (SpringBoard tweak injection). "
            "Examiner-supplied: no official release asset was verified when "
            "this registry entry was written. Place the .tipa in the "
            "payloads dir as serotonin--Serotonin.tipa."
        ),
    },
    {
        "slug": "nathanlr",
        "name": "NathanLR",
        "vendor": "NathanLR contributors",
        "repo": None,
        "keywords": ["nathanlr", "nathan"],
        "asset": "NathanLR.tipa",
        "kind": ".tipa",
        "url": None,
        "version": None,
        "sha256": None,
        "manual": True,
        "notes": (
            "Serotonin fork for iOS 17.0-class targets. Examiner-supplied: "
            "no official release asset was verified when this registry "
            "entry was written. Place the .tipa in the payloads dir as "
            "nathanlr--NathanLR.tipa."
        ),
    },
    {
        "slug": "misaka-nugget",
        "name": "Misaka / Nugget (MobileGestalt)",
        "vendor": "Misaka / Nugget contributors",
        "repo": None,
        "keywords": ["misaka", "nugget", "mobilegestalt"],
        "asset": "Misaka.tipa",
        "kind": ".tipa",
        "url": None,
        "version": None,
        "sha256": None,
        "manual": True,
        "notes": (
            "MobileGestalt userspace tools for the 26.0-26.1 window. "
            "Examiner-supplied: no official release asset was verified when "
            "this registry entry was written. Place the tool .tipa in the "
            "payloads dir as misaka-nugget--Misaka.tipa (or a Nugget .tipa "
            "named for nugget)."
        ),
    },
    {
        "slug": "examiner",
        "name": "Examiner-provided payload",
        "vendor": "examiner",
        "repo": None,
        "keywords": [],
        "asset": None,
        "kind": None,
        "url": None,
        "version": None,
        "sha256": None,
        "manual": True,
        "notes": (
            "Generic entry: any .ipa/.tipa the examiner placed in the "
            "payloads dir that is not claimed by another registry entry. "
            "Used as the fallback for routes with no registry entry."
        ),
    },
]

_BY_SLUG = {e["slug"]: e for e in REGISTRY}


# ---------------------------------------------------------------------------
# Locations + manifest
# ---------------------------------------------------------------------------


def payloads_dir() -> Path:
    """Where payload files + manifest.json live.

    ``$OPENSLEUTH_PAYLOADS_DIR`` wins; default ``~/payloads`` (the first
    root the runner's legacy payload search already used).
    """
    env = os.environ.get("OPENSLEUTH_PAYLOADS_DIR")
    if env:
        return Path(env).expanduser()
    return Path.home() / "payloads"


def _manifest_path(directory: Optional[Path] = None) -> Path:
    return (directory or payloads_dir()) / MANIFEST_NAME


def _load_manifest(directory: Optional[Path] = None) -> dict[str, Any]:
    try:
        data = json.loads(_manifest_path(directory).read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_manifest(data: dict[str, Any], directory: Optional[Path] = None) -> None:
    path = _manifest_path(directory)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
    tmp.replace(path)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Route matching
# ---------------------------------------------------------------------------


def _normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).strip()


def route_keywords(route_name: str) -> list[str]:
    """Registry keywords that a free-form route name activates.

    Route names come from the catalog/planner ("Dopamine 3", "TrollStore 2",
    "Misaka26 MobileGestalt", ...). A keyword matches when it appears in the
    normalized route name, so "dopamine" matches "Dopamine 2" and
    "Dopamine 3" alike.
    """
    norm = f" {_normalize(route_name)} "
    hits: list[str] = []
    for entry in REGISTRY:
        for kw in entry["keywords"]:
            if f" {kw} " in norm or kw in norm.replace(" ", ""):
                if kw not in hits:
                    hits.append(kw)
    return hits


def entry_for_route(route_name: str) -> Optional[dict[str, Any]]:
    """The registry entry serving a route, or None if no entry claims it."""
    kws = set(route_keywords(route_name))
    if not kws:
        return None
    for entry in REGISTRY:
        if kws.intersection(entry["keywords"]):
            return entry
    return None


def _entry_claiming_file(filename: str) -> Optional[dict[str, Any]]:
    """Which registry entry a payload filename belongs to (if any).

    A file is claimed by an entry when it carries the entry's stored prefix
    (``<slug>--``) or its name contains one of the entry's keywords.
    """
    low = filename.lower()
    for entry in REGISTRY:
        if low.startswith(f"{entry['slug']}--"):
            return entry
        if any(kw in low for kw in entry["keywords"]):
            return entry
    return None


def _local_files(directory: Path) -> list[Path]:
    try:
        return sorted(
            p for p in directory.iterdir()
            if p.is_file() and p.suffix.lower() in (".ipa", ".tipa")
        )
    except OSError:
        return []


def find_payload_for(route_name: str, directory: Optional[Path] = None) -> Optional[Path]:
    """The payload file for a route, if one is present locally.

    Preference order:
    1. A file stored by :func:`fetch_payload` for the route's entry
       (``<slug>--<asset>``).
    2. Any local file named for the route's entry (keyword in filename).
    3. An *unclaimed* generic .ipa/.tipa — never a file another registry
       entry claims. This is the only fallback, and it is what keeps a
       Dopamine route from being handed a Serotonin file.

    With an empty route name, step 3 is the whole search (legacy behavior).
    """
    directory = directory or payloads_dir()
    files = _local_files(directory)
    if not files:
        return None
    entry = entry_for_route(route_name) if route_name else None
    if entry is not None:
        prefix = f"{entry['slug']}--"
        for f in files:
            if f.name.lower().startswith(prefix):
                return f
        for f in files:
            if any(kw in f.name.lower() for kw in entry["keywords"]):
                return f
    for f in files:
        if _entry_claiming_file(f.name) is None:
            return f
    return None


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------


def list_payloads(directory: Optional[Path] = None) -> list[dict[str, Any]]:
    """Registry + local presence + recorded hashes, for CLI/UI display."""
    directory = directory or payloads_dir()
    manifest = _load_manifest(directory)
    out: list[dict[str, Any]] = []
    for entry in REGISTRY:
        rec = manifest.get(entry["slug"]) or {}
        present = None
        if entry["slug"] != "examiner":
            hit = find_payload_for(entry["name"], directory)
            # find_payload_for may fall back to a generic file; only count a
            # file this entry actually claims as "present" for the entry.
            if hit is not None and _entry_claiming_file(hit.name) is entry:
                present = str(hit)
        out.append({
            "slug": entry["slug"],
            "name": entry["name"],
            "vendor": entry["vendor"],
            "repo": entry["repo"],
            "asset": entry["asset"],
            "kind": entry["kind"],
            "url": entry["url"],
            "version": entry["version"],
            "manual": entry["manual"],
            "pinned_sha256": entry["sha256"],
            "recorded_sha256": rec.get("sha256"),
            "present_path": present,
            "notes": entry["notes"],
        })
    return out


# ---------------------------------------------------------------------------
# Fetch + verify
# ---------------------------------------------------------------------------


def fetch_payload(route_name: str, dest_dir: Optional[Path] = None) -> Path:
    """Download the official payload for a route, verify it, record its hash.

    Raises ValueError with an examiner-actionable message when the route has
    no downloadable registry entry, and RuntimeError when a downloaded file
    fails its pinned/recorded hash (the file is deleted in that case).
    """
    entry = entry_for_route(route_name)
    if entry is None:
        raise ValueError(
            f"no payload registry entry matches route {route_name!r}; "
            "place the payload .ipa/.tipa in the payloads dir manually"
        )
    if entry["manual"] or not entry["url"]:
        raise ValueError(
            f"{entry['name']} is examiner-supplied (no verified official "
            f"download in the registry): obtain {entry['asset'] or 'the payload'} "
            f"from {entry['repo'] or 'the project'} and place it in "
            f"{payloads_dir()} as {entry['slug']}--{entry['asset'] or 'payload.ipa'}"
        )
    dest_dir = dest_dir or payloads_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{entry['slug']}--{entry['asset']}"

    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(
        entry["url"], headers={"User-Agent": "opensleuth-payloads/1"})
    with urllib.request.urlopen(req) as resp, open(tmp, "wb") as fh:  # noqa: S310
        while True:
            chunk = resp.read(_CHUNK)
            if not chunk:
                break
            fh.write(chunk)

    digest = sha256_of(tmp)
    manifest = _load_manifest(dest_dir)
    recorded = (manifest.get(entry["slug"]) or {}).get("sha256")
    expected = entry["sha256"] or recorded
    if expected and digest != expected:
        tmp.unlink(missing_ok=True)
        raise RuntimeError(
            f"hash mismatch for {entry['name']} {entry['asset']}: "
            f"expected sha256 {expected}, got {digest} — download deleted, "
            "nothing installed. The upstream release may have changed; "
            "verify it manually before trusting a new hash."
        )
    tmp.replace(dest)
    manifest[entry["slug"]] = {
        "file": dest.name,
        "sha256": digest,
        "url": entry["url"],
        "version": entry["version"],
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "pinned": bool(entry["sha256"]),
    }
    _save_manifest(manifest, dest_dir)
    return dest
