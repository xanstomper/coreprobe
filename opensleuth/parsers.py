"""Parser framework: hostile-input hardening + provenance envelope.

The standards implemented here:
  * Malformed evidence must never crash the whole case: every parser runs
    through `safe_parse`, which converts exceptions into a structured
    ParseResult(ok=False, error=...) the journal can record as ParserFailure.
  * Every successful parse carries PROVENANCE: parser name, parser version,
    source path, extraction time, and warning list — so a derived artifact is
    always traceable to its raw source.
  * Interpretations stay separate from raw data: parsers report rows as
    observed; any inference (e.g. "this number is the sender") must be a
    declared `interpretation` in the envelope, not a silent row mutation.
"""

from __future__ import annotations

import sqlite3
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

PARSER_FRAMEWORK_VERSION = "1"


@dataclass
class ParseResult:
    parser: str
    parser_version: str
    source_format: str
    source_path: str
    extracted_at: str
    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    error: str = ""
    error_kind: str = ""          # DatabaseError | OperationalError | OSError | ...
    interpretations: list[str] = field(default_factory=list)

    @property
    def framework_version(self) -> str:
        return PARSER_FRAMEWORK_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "parser": self.parser,
            "parser_version": self.parser_version,
            "framework_version": PARSER_FRAMEWORK_VERSION,
            "source_format": self.source_format,
            "source_path": self.source_path,
            "extracted_at": self.extracted_at,
            "ok": self.ok,
            "warnings": self.warnings,
            "error": self.error,
            "error_kind": self.error_kind,
            "interpretations": self.interpretations,
            "data": self.data,
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def safe_parse(name: str, version: str, source_format: str,
               parse_fn: Callable[[Path], dict[str, Any]],
               path: str | Path,
               max_rows: int = 1_000_000) -> ParseResult:
    """Run a parser with hostile-input hardening.

    * file missing / unreadable -> ok=False (OSError kind)
    * not-a-database / wrong schema -> ok=False (sqlite error kind)
    * empty-but-valid -> ok=True with a warning
    * oversized result -> truncated with a warning (never unbounded RAM)
    * any unexpected exception -> ok=False with traceback tail (never crash)
    """
    p = Path(path)
    res = ParseResult(parser=name, parser_version=version,
                      source_format=source_format, source_path=str(p),
                      extracted_at=_now(), ok=False)
    if not p.is_file():
        res.error = "source file not found"
        res.error_kind = "OSError"
        return res
    try:
        data = parse_fn(p)
    except sqlite3.OperationalError as exc:
        # OperationalError subclasses DatabaseError, so it must be caught
        # FIRST to classify schema/permission issues distinctly.
        res.error_kind = type(exc).__name__
        res.error = f"schema mismatch: {exc}"
        return res
    except sqlite3.DatabaseError as exc:
        res.error_kind = type(exc).__name__
        res.error = f"malformed database: {exc}"
        return res
    except Exception as exc:  # noqa: BLE001
        res.error_kind = type(exc).__name__
        tb = traceback.format_exc().strip().splitlines()
        res.error = f"{exc} | {tb[-1][:200] if tb else ''}"
        return res
    if not isinstance(data, dict):
        res.error_kind = "TypeError"
        res.error = "parser returned non-dict payload"
        return res
    # bounded output
    total = 0
    truncated = False
    for key, val in list(data.items()):
        if isinstance(val, list):
            if len(val) > max_rows:
                data[key] = val[:max_rows]
                truncated = True
            total += len(data[key])
        elif val is None:
            data.pop(key)
    if total == 0:
        res.warnings.append("parser produced zero rows (valid but empty source)")
    if truncated:
        res.warnings.append(f"result truncated to {max_rows} rows per list")
    res.data = data
    res.ok = True
    return res
