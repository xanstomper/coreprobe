"""Integration tests for the native C++ tier (osleuth_core).

Skips when no compiler/cmake is available. Cross-validates the C++ MBDB
parser against bytes produced by the verified Python restore writer
(cve2026_84598_restore), and native SHA-256 against hashlib.
"""

import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

pytestmark = pytest.mark.skipif(
    shutil.which("cmake") is None or shutil.which("g++") is None,
    reason="C++ toolchain not available",
)

from opensleuth import cxx  # noqa: E402


@pytest.fixture(scope="module")
def binary():
    return cxx.ensure_built()


@pytest.fixture(scope="module")
def crafted_mbdb(tmp_path_factory):
    """Manifest.mbdb produced by the verified Python writer (device-tested)."""
    from opensleuth.cve2026_84598_restore import build_backup_dir

    base = tmp_path_factory.mktemp("cross")
    bdir = base / "backup" / "TESTUDID"
    bdir.mkdir(parents=True)
    build_backup_dir(bdir.parent, "TESTUDID")
    return bdir / "Manifest.mbdb"


def test_native_selftest(binary):
    r = subprocess.run([str(binary), "selftest"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout
    assert "PASSED" in r.stdout


def test_native_hash_matches_hashlib(binary, tmp_path):
    f = tmp_path / "evidence.bin"
    f.write_bytes(bytes(range(256)) * 4096)
    r = subprocess.run([str(binary), "hash", str(f)], capture_output=True, text=True)
    assert r.returncode == 0
    line = r.stdout.strip().splitlines()[-1]
    native_hex = line.split()[1]
    assert native_hex == hashlib.sha256(f.read_bytes()).hexdigest()


def test_native_verify(binary, tmp_path):
    f = tmp_path / "v.bin"
    f.write_bytes(b"coreprobe-native")
    good = hashlib.sha256(f.read_bytes()).hexdigest()
    ok = subprocess.run([str(binary), "verify", str(f), good],
                        capture_output=True, text=True)
    assert ok.returncode == 0 and "MATCH" in ok.stdout
    bad = subprocess.run([str(binary), "verify", str(f), "0" * 64],
                         capture_output=True, text=True)
    assert bad.returncode == 1 and "MISMATCH" in bad.stdout


def test_native_manifest(binary, tmp_path):
    d = tmp_path / "extract"
    (d / "a" / "b").mkdir(parents=True)
    (d / "a" / "b" / "one.dat").write_bytes(b"x" * 100)
    (d / "two.txt").write_bytes(b"hello")
    r = subprocess.run([str(binary), "manifest", str(d)], capture_output=True, text=True)
    assert r.returncode == 0
    assert "# osleuth_core manifest" in r.stdout
    assert "one.dat" in r.stdout and "two.txt" in r.stdout
    for line in r.stdout.splitlines():
        if line.startswith("#"):
            continue
        parts = line.split()
        assert len(parts) == 3 and len(parts[0]) == 64  # sha256 size relpath
        assert parts[1].isdigit()


def test_cross_language_mbdb_flags_traversals(binary, crafted_mbdb):
    """C++ parser must read the Python writer's bytes and flag all escapes."""
    r = subprocess.run([str(binary), "mbdb", str(crafted_mbdb)],
                       capture_output=True, text=True)
    assert r.returncode == 0
    assert "major=5 count=4" in r.stdout
    assert "traversal entries: 3" in r.stdout
    assert "SysContainerDomain-../../" in r.stdout


def test_cross_language_mbdb_roundtrip_fields(binary, crafted_mbdb):
    r = subprocess.run([str(binary), "mbdb", str(crafted_mbdb)],
                       capture_output=True, text=True)
    lines = [l for l in r.stdout.splitlines() if not l.startswith("#")]
    # header line
    assert lines and "major=" in lines[0]
    # header + 4 records + traversal summary = 6 lines
    assert len(lines) == 6
    assert "uid=501 gid=501" in r.stdout
    assert "mode=100644" in r.stdout


def test_ensure_built_idempotent(binary):
    assert cxx.ensure_built() == binary


def test_cli_cxx_selftest():
    r = subprocess.run(
        [sys.executable, "-m", "opensleuth", "cxx", "selftest"],
        capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0
    assert "PASSED" in r.stdout


def test_cli_cxx_mbdb(crafted_mbdb):
    r = subprocess.run(
        [sys.executable, "-m", "opensleuth", "cxx", "mbdb", str(crafted_mbdb)],
        capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0
    assert "traversal entries: 3" in r.stdout