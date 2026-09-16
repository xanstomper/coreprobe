"""Native C++ tier bridge (osleuth_core).

Exposes the zero-dependency C++17 core - SHA-256/SHA-1 evidence hashing,
Manifest.mbdb parsing with traversal detection (CVE-2026-84598 shape), and
throughput benchmarks - through the opensleuth CLI. Builds the binary via
CMake on first use (or when a source file is newer).

Commands:  opensleuth cxx selftest | hash | verify | bench | mbdb | manifest
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "build" / "osleuth_core"
_SOURCES = sorted(
    str(p) for p in (ROOT / "core").glob("*.cpp") if p.name != "tests.cpp"
) + [str(ROOT / "core" / "core.h"), str(ROOT / "CMakeLists.txt")]


def binary() -> Path:
    """Locate the native binary (build tree first, then PATH)."""
    if BIN.exists():
        return BIN
    on_path = shutil.which("osleuth_core")
    if on_path:
        return Path(on_path)
    raise FileNotFoundError(
        "osleuth_core not built. Run: cmake -B build && cmake --build build\n"
        "or:  sudo ./install.sh --with-cxx"
    )


def needs_rebuild() -> bool:
    if not BIN.exists():
        return True
    try:
        btime = BIN.stat().st_mtime
    except OSError:
        return True
    for src in _SOURCES:
        try:
            if Path(src).stat().st_mtime > btime:
                return True
        except OSError:
            pass
    return False


def ensure_built(force: bool = False) -> Path:
    if force or needs_rebuild():
        if not shutil.which("cmake"):
            raise FileNotFoundError("cmake not found; install with: sudo ./install.sh --with-cxx")
        subprocess.run(
            ["cmake", "-B", str(ROOT / "build"), "-S", str(ROOT),
             "-DCMAKE_BUILD_TYPE=Release"],
            check=True, capture_output=True)
        subprocess.run(
            ["cmake", "--build", str(ROOT / "build"), "-j", "4"],
            check=True, capture_output=True)
    return binary()


def run(args, check=True, capture=True):
    """Run the native binary. Returns CompletedProcess with text output."""
    return subprocess.run(
        [str(ensure_built())] + args, check=check, capture_output=capture, text=True)


# ------------------------------------------------------------------ cli --
def add_parser(sub):
    p = sub.add_parser("cxx", help="native C++ core: hash, manifest, mbdb, bench (zero-dep C++17)")
    p_sub = p.add_subparsers(dest="cxx", required=True)

    st = p_sub.add_parser("selftest", help="run native unit tests (FIPS vectors + MBDB)")
    st.set_defaults(fn=cmd_selftest)

    h = p_sub.add_parser("hash", help="SHA-256 (+SHA-1) evidence hash of files")
    h.add_argument("--sha1", action="store_true", help="also print SHA-1")
    h.add_argument("files", nargs="+")
    h.set_defaults(fn=cmd_hash)

    v = p_sub.add_parser("verify", help="check a file against an expected SHA-256")
    v.add_argument("file")
    v.add_argument("expected")
    v.set_defaults(fn=cmd_verify)

    b = p_sub.add_parser("bench", help="native hashing throughput (default 1 GiB)")
    b.add_argument("bytes", nargs="?", default="1073741824")
    b.set_defaults(fn=cmd_bench)

    m = p_sub.add_parser("mbdb", help="parse Manifest.mbdb and flag traversal entries")
    m.add_argument("file", help="path to Manifest.mbdb")
    m.set_defaults(fn=cmd_mbdb)

    mn = p_sub.add_parser("manifest", help="walk a directory and SHA-256 every file (chain of custody)")
    mn.add_argument("dir", help="evidence / extraction directory")
    mn.add_argument("--out", help="also write the manifest to this file")
    mn.set_defaults(fn=cmd_manifest)


def _pre():
    try:
        ensure_built()
    except FileNotFoundError as exc:
        print(f"cxx: {exc}", file=sys.stderr)
        sys.exit(2)


def cmd_selftest(args):
    _pre()
    r = run(["selftest"], check=False)
    print(r.stdout, end="")
    sys.exit(r.returncode)


def cmd_hash(args):
    _pre()
    cmd = ["hash"] + (["--sha1"] if args.sha1 else []) + args.files
    r = run(cmd, check=False)
    print(r.stdout, end="")
    sys.exit(r.returncode)


def cmd_verify(args):
    _pre()
    r = run(["verify", args.file, args.expected], check=False)
    print(r.stdout, end="")
    sys.exit(r.returncode)


def cmd_bench(args):
    _pre()
    r = run(["bench", args.bytes], check=False)
    print(r.stdout, end="")
    sys.exit(r.returncode)


def cmd_mbdb(args):
    _pre()
    r = run(["mbdb", args.file], check=False)
    print(r.stdout, end="")
    sys.exit(r.returncode)


def cmd_manifest(args):
    _pre()
    r = run(["manifest", args.dir], check=False)
    print(r.stdout, end="")
    if args.out:
        Path(args.out).write_text(r.stdout)
    sys.exit(r.returncode)