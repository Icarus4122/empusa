"""
Tests for empusa.cli_modules

Covers: list_modules discovery, .build_ok marker detection,
        create_module_template scaffolding, COMPILER_MAP / LANGUAGE_EXTENSIONS.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from empusa.cli_modules import (
    COMPILER_MAP,
    DEFAULT_COMPILE_CMD,
    LANGUAGE_EXTENSIONS,
    list_modules,
)

# -- Lookup tables ---------------------------------------------------


class TestLookupTables:
    def test_compiler_map_languages(self) -> None:
        expected = {"c", "cpp", "csharp", "rust", "go", "perl", "make"}
        assert set(COMPILER_MAP.keys()) == expected

    def test_default_compile_cmd_keys(self) -> None:
        for lang in COMPILER_MAP:
            assert lang in DEFAULT_COMPILE_CMD

    def test_language_extensions(self) -> None:
        assert LANGUAGE_EXTENSIONS["c"] == ".c"
        assert LANGUAGE_EXTENSIONS["go"] == ".go"
        assert LANGUAGE_EXTENSIONS["rust"] == ".rs"
        assert LANGUAGE_EXTENSIONS["perl"] == ".pl"


# -- list_modules discovery -------------------------------------------


class TestListModules:
    def _make_module(
        self,
        base: Path,
        name: str,
        lang: str = "c",
        compiled: bool = False,
        use_marker: bool = False,
    ) -> Path:
        mod_dir = base / name
        mod_dir.mkdir(parents=True)
        manifest: dict[str, Any] = {
            "name": name,
            "language": lang,
            "description": f"Test module {name}",
            "source": f"main{LANGUAGE_EXTENSIONS.get(lang, '.c')}",
        }
        (mod_dir / "module.json").write_text(json.dumps(manifest))
        (mod_dir / manifest["source"]).write_text("// source")

        if compiled:
            build_dir = mod_dir / "build"
            build_dir.mkdir()
            if use_marker:
                (build_dir / ".build_ok").touch()
            else:
                (build_dir / "output.bin").write_bytes(b"\x00")
        return mod_dir

    def test_discovers_modules(self, tmp_path: Path) -> None:
        self._make_module(tmp_path, "mod_a")
        self._make_module(tmp_path, "mod_b", lang="go")

        with patch("empusa.cli_modules.MODULES_DIR", tmp_path):
            modules = list_modules()

        names = [m["name"] for m in modules]
        assert "mod_a" in names
        assert "mod_b" in names

    def test_build_ok_marker_detected(self, tmp_path: Path) -> None:
        self._make_module(tmp_path, "built_mod", compiled=True, use_marker=True)

        with patch("empusa.cli_modules.MODULES_DIR", tmp_path):
            modules = list_modules()

        assert modules[0]["_compiled"] is True

    def test_nonempty_build_dir_detected(self, tmp_path: Path) -> None:
        self._make_module(tmp_path, "old_mod", compiled=True, use_marker=False)

        with patch("empusa.cli_modules.MODULES_DIR", tmp_path):
            modules = list_modules()

        assert modules[0]["_compiled"] is True

    def test_empty_build_dir_not_compiled(self, tmp_path: Path) -> None:
        mod_dir = self._make_module(tmp_path, "empty_mod")
        (mod_dir / "build").mkdir(exist_ok=True)

        with patch("empusa.cli_modules.MODULES_DIR", tmp_path):
            modules = list_modules()

        assert modules[0]["_compiled"] is False

    def test_dotfile_only_build_not_compiled(self, tmp_path: Path) -> None:
        """build/ containing only dotfiles (like .gitkeep) -> not compiled."""
        mod_dir = self._make_module(tmp_path, "gitkeep_mod")
        build = mod_dir / "build"
        build.mkdir(exist_ok=True)
        (build / ".gitkeep").touch()

        with patch("empusa.cli_modules.MODULES_DIR", tmp_path):
            modules = list_modules()

        assert modules[0]["_compiled"] is False

    def test_missing_modules_dir(self, tmp_path: Path) -> None:
        with patch("empusa.cli_modules.MODULES_DIR", tmp_path / "nonexistent"):
            assert list_modules() == []

    def test_bad_manifest_skipped(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad_mod"
        bad.mkdir()
        (bad / "module.json").write_text("NOT JSON{{{")

        with patch("empusa.cli_modules.MODULES_DIR", tmp_path):
            modules = list_modules()

        assert len(modules) == 0


# -- create_module_template -------------------------------------------


class TestCreateModuleTemplate:
    @pytest.mark.parametrize("lang", ["c", "cpp", "csharp", "rust", "go", "perl"])
    def test_template_created(self, lang: str, tmp_path: Path) -> None:
        from empusa.cli_modules import create_module_template

        with patch("empusa.cli_modules.MODULES_DIR", tmp_path):
            path = create_module_template(lang, f"test_{lang}")

        assert path.is_dir()
        manifest = path / "module.json"
        assert manifest.exists()
        data = json.loads(manifest.read_text())
        assert data["language"] == lang
        assert data["name"] == f"test_{lang}"

    def test_build_dir_created(self, tmp_path: Path) -> None:
        from empusa.cli_modules import create_module_template

        with patch("empusa.cli_modules.MODULES_DIR", tmp_path):
            path = create_module_template("c", "test_c")

        assert (path / "build").is_dir()
