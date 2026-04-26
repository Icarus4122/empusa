"""Tests for scripts/dev/version-sanity.py and scripts/dev/package-sanity.py.

Both scripts are static-only (no Empusa import, no network) and exit
with canonical [PASS] / [FAIL] markers.  We exercise them via subprocess
so the tests catch the same failure mode CI would.
"""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts" / "dev"
VERSION_SANITY = SCRIPTS / "version-sanity.py"
PACKAGE_SANITY = SCRIPTS / "package-sanity.py"


def _run(script: Path, *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else None,
    )


# ── version-sanity ──────────────────────────────────────────────────


class TestVersionSanityRealRepo:
    def test_passes_against_real_repo(self) -> None:
        r = _run(VERSION_SANITY)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "[PASS]" in r.stdout


class TestVersionSanityFixture:
    """Drop a copy of the script into a fake repo and parse."""

    @staticmethod
    def _fake_repo(tmp_path: Path, py_version: str, init_version: str) -> Path:
        (tmp_path / "empusa").mkdir()
        (tmp_path / "scripts" / "dev").mkdir(parents=True)
        (tmp_path / "pyproject.toml").write_text(
            f'[project]\nname = "empusa"\nversion = "{py_version}"\n',
            encoding="utf-8",
        )
        (tmp_path / "empusa" / "__init__.py").write_text(f'__version__ = "{init_version}"\n', encoding="utf-8")
        # Copy script into the fake repo so REPO_ROOT resolves correctly.
        target = tmp_path / "scripts" / "dev" / "version-sanity.py"
        target.write_bytes(VERSION_SANITY.read_bytes())
        return target

    def test_match_exits_zero(self, tmp_path: Path) -> None:
        script = self._fake_repo(tmp_path, "9.9.9", "9.9.9")
        r = _run(script)
        assert r.returncode == 0
        assert "[PASS]" in r.stdout
        assert "9.9.9" in r.stdout

    def test_mismatch_exits_nonzero(self, tmp_path: Path) -> None:
        script = self._fake_repo(tmp_path, "9.9.9", "0.0.1")
        r = _run(script)
        assert r.returncode != 0
        assert "[FAIL]" in r.stdout
        assert "mismatch" in r.stdout.lower()

    def test_missing_init_version_fails(self, tmp_path: Path) -> None:
        script = self._fake_repo(tmp_path, "1.2.3", "1.2.3")
        # Overwrite __init__.py with no __version__ definition.
        (tmp_path / "empusa" / "__init__.py").write_text("# no version\n", encoding="utf-8")
        r = _run(script)
        assert r.returncode != 0
        assert "[FAIL]" in r.stdout

    def test_missing_pyproject_version_fails(self, tmp_path: Path) -> None:
        script = self._fake_repo(tmp_path, "1.2.3", "1.2.3")
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "empusa"\n', encoding="utf-8")
        r = _run(script)
        assert r.returncode != 0
        assert "[FAIL]" in r.stdout


# ── package-sanity ──────────────────────────────────────────────────


def _make_wheel(dest: Path, members: dict[str, bytes]) -> Path:
    """Build a minimal .whl-shaped zip; package-sanity only checks names."""
    wheel = dest / "empusa-0.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return wheel


def _stage_script(tmp_path: Path) -> tuple[Path, Path]:
    """Create a fake repo dir holding scripts/dev/package-sanity.py and dist/."""
    (tmp_path / "scripts" / "dev").mkdir(parents=True)
    (tmp_path / "dist").mkdir()
    target = tmp_path / "scripts" / "dev" / "package-sanity.py"
    target.write_bytes(PACKAGE_SANITY.read_bytes())
    return target, tmp_path / "dist"


class TestPackageSanity:
    def test_clean_wheel_passes(self, tmp_path: Path) -> None:
        script, dist = _stage_script(tmp_path)
        _make_wheel(
            dist,
            {
                "empusa/__init__.py": b'__version__="0.0.0"\n',
                "empusa/hooks/modules/foo/module.json": b"{}",
                "empusa/hooks/modules/foo/Makefile": b"all:\n",
                "empusa/hooks/modules/foo/main.c": b"int main(){return 0;}\n",
                "empusa-0.0.0.dist-info/METADATA": b"Metadata-Version: 2.1\n",
                "empusa-0.0.0.dist-info/RECORD": b"",
            },
        )
        r = _run(script)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "[PASS]" in r.stdout

    def test_pycache_fails(self, tmp_path: Path) -> None:
        script, dist = _stage_script(tmp_path)
        _make_wheel(
            dist,
            {
                "empusa/__init__.py": b"",
                "empusa/__pycache__/x.cpython-39.pyc": b"",
                "empusa-0.0.0.dist-info/METADATA": b"",
            },
        )
        r = _run(script)
        assert r.returncode != 0
        assert "[FAIL]" in r.stdout
        assert "__pycache__" in r.stdout

    def test_obj_dir_fails(self, tmp_path: Path) -> None:
        script, dist = _stage_script(tmp_path)
        _make_wheel(
            dist,
            {
                "empusa/__init__.py": b"",
                "empusa/hooks/modules/foo/obj/payload.o": b"",
                "empusa-0.0.0.dist-info/METADATA": b"",
            },
        )
        r = _run(script)
        assert r.returncode != 0
        assert "/obj/" in r.stdout

    def test_egg_info_fails(self, tmp_path: Path) -> None:
        script, dist = _stage_script(tmp_path)
        _make_wheel(
            dist,
            {
                "empusa.egg-info/PKG-INFO": b"",
                "empusa-0.0.0.dist-info/METADATA": b"",
            },
        )
        r = _run(script)
        assert r.returncode != 0
        assert "egg-info" in r.stdout

    def test_coverage_artifact_fails(self, tmp_path: Path) -> None:
        script, dist = _stage_script(tmp_path)
        _make_wheel(
            dist,
            {
                "empusa/.coverage": b"",
                "empusa-0.0.0.dist-info/METADATA": b"",
            },
        )
        r = _run(script)
        assert r.returncode != 0
        assert ".coverage" in r.stdout

    def test_no_dist_dir_fails(self, tmp_path: Path) -> None:
        (tmp_path / "scripts" / "dev").mkdir(parents=True)
        target = tmp_path / "scripts" / "dev" / "package-sanity.py"
        target.write_bytes(PACKAGE_SANITY.read_bytes())
        r = _run(target)
        assert r.returncode != 0
        assert "[FAIL]" in r.stdout

    def test_empty_dist_fails(self, tmp_path: Path) -> None:
        script, _ = _stage_script(tmp_path)
        r = _run(script)
        assert r.returncode != 0
        assert "no wheel" in r.stdout.lower()


# ── importable-script smoke ─────────────────────────────────────────


@pytest.mark.parametrize("script", [VERSION_SANITY, PACKAGE_SANITY])
def test_script_is_executable_python(script: Path) -> None:
    assert script.is_file()
    text = script.read_text(encoding="utf-8")
    assert text.startswith("#!") or "def main" in text
    # Static parsing rule: scripts must NOT import empusa.
    for line in text.splitlines():
        s = line.strip()
        assert not s.startswith("import empusa"), f"{script.name} must not import empusa"
        assert not s.startswith("from empusa"), f"{script.name} must not import empusa"
