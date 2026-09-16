"""Backup index: reads Manifest.db and extracts files from an iOS backup."""

import plistlib
import sqlite3
import shutil
from pathlib import Path


class BackupError(Exception):
    pass


class Backup:
    """A directory produced by ``idevicebackup2 backup`` (or iTunes).

    Files are stored as ``<root>/<fileID[:2]>/<fileID>`` and indexed by
    ``Manifest.db`` with columns (fileID, domain, relativePath, flags, file).
    """

    def __init__(self, root: str):
        self.root = Path(root)
        self.manifest_db = self.root / "Manifest.db"
        if not self.manifest_db.exists():
            raise BackupError(f"not a backup (no Manifest.db): {self.root}")
        self.conn = sqlite3.connect(f"file:{self.manifest_db}?mode=ro", uri=True)
        self.conn.row_factory = sqlite3.Row
        self.manifest = {}
        mp = self.root / "Manifest.plist"
        if mp.exists():
            with open(mp, "rb") as fh:
                self.manifest = plistlib.load(fh)

    # ------------------------------------------------------------- index
    def files(self):
        cur = self.conn.execute(
            "SELECT fileID, domain, relativePath, flags, file AS size FROM Files"
        )
        for row in cur:
            yield dict(row)

    def stats(self):
        row = self.conn.execute(
            "SELECT COUNT(*) AS files, COALESCE(SUM(file), 0) AS bytes FROM Files"
        ).fetchone()
        return {"files": row["files"], "bytes": row["bytes"]}

    def find(self, domain=None, pattern=None):
        """Yield index rows matching optional domain and SQL LIKE pattern."""
        sql = "SELECT fileID, domain, relativePath, flags, file AS size FROM Files WHERE 1=1"
        args = []
        if domain:
            sql += " AND domain = ?"
            args.append(domain)
        if pattern:
            sql += " AND relativePath LIKE ?"
            args.append(pattern)
        for row in self.conn.execute(sql, args):
            yield dict(row)

    def get_path(self, domain, relative_path):
        row = self.conn.execute(
            "SELECT fileID FROM Files WHERE domain=? AND relativePath=?",
            (domain, relative_path),
        ).fetchone()
        if row is None:
            return None
        candidate = self.root / row["fileID"][:2] / row["fileID"]
        return candidate if candidate.is_file() else None

    # ---------------------------------------------------------- extraction
    def extract(self, outdir: Path, domains=None, pattern=None):
        """Copy indexed files into outdir mirroring ``domain/relativePath``.

        ``domains`` is a list of domain names or glob patterns (``%`` wildcard);
        ``None`` copies every domain. ``pattern`` filters relativePath the same
        way. Returns number of files copied.
        """
        import fnmatch

        outdir = Path(outdir)
        doms = list(domains) if domains else []
        copied = 0
        for rec in self.files():
            if pattern and not fnmatch.fnmatchcase(rec["relativePath"], pattern.replace("%", "*")):
                continue
            if doms and not any(
                fnmatch.fnmatchcase(rec["domain"], d.strip().replace("%", "*")) for d in doms
            ):
                continue
            src = self.root / rec["fileID"][:2] / rec["fileID"]
            if not src.is_file():
                continue
            dst = outdir / rec["domain"] / rec["relativePath"]
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copyfile(src, dst)
                copied += 1
            except OSError:
                continue
        return copied

    def app_domains(self):
        rows = self.conn.execute(
            "SELECT domain, COUNT(*) AS files, COALESCE(SUM(file), 0) AS bytes "
            "FROM Files WHERE domain LIKE 'AppDomain-%' GROUP BY domain ORDER BY bytes DESC"
        )
        return [dict(r) for r in rows]

    def backup_state(self):
        return {
            "udid": self.manifest.get("UDID"),
            "version": self.manifest.get("Version"),
            "encrypted": bool(self.manifest.get("IsEncrypted")),
            "state": self.manifest.get("BackupState"),
            "product": self.manifest.get("ProductVersion"),
            "serial": self.manifest.get("SerialNumber"),
            "device_info": self.manifest.get("DeviceInfo") or {},
        }

    def close(self):
        self.conn.close()