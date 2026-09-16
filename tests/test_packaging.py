"""Packaging sanity: pyproject entry points and console-script availability."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def test_pyproject_declares_scripts():
    text = (ROOT / "pyproject.toml").read_text()
    assert '[project.scripts]' in text
    assert 'opensleuth = "opensleuth.cli:main"' in text
    assert 'opensleuth-web = "opensleuth.studio_web.server:main"' in text
    assert 'opensleuth-desktop = "opensleuth.studio_desktop:main"' in text
    assert 'requires-python = ">=3.9"' in text


def test_pyproject_packages_static_assets():
    text = (ROOT / "pyproject.toml").read_text()
    assert 'include = ["opensleuth*"]' in text
    assert '"opensleuth.studio_web" = ["static/*"]' in text


@pytest.mark.skipif(shutil.which("opensleuth") is None, reason="not pip-installed")
def test_installed_cli_runs_from_elsewhere(tmp_path):
    r = subprocess.run(["opensleuth", "--version"], capture_output=True, text=True,
                       cwd=tmp_path)
    assert r.returncode == 0
    assert "opensleuth" in r.stdout


@pytest.mark.skipif(sys.version_info < (3, 10), reason="pyproject needs recent pkg")
def test_setuptools_can_parse_metadata():
    # Verifies the pyproject is well-formed for setuptools without building.
    import tomllib
    with open(ROOT / "pyproject.toml", "rb") as f:
        data = tomllib.load(f)
    assert data["project"]["scripts"]["opensleuth"] == "opensleuth.cli:main"