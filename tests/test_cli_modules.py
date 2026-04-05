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


# -- _classify_artifact ------------------------------------------------


class TestClassifyArtifact:
    def test_none_artifact(self) -> None:
        from empusa.cli_modules import _classify_artifact

        assert _classify_artifact(None, "c") == "none"

    def test_missing_path(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _classify_artifact

        assert _classify_artifact(tmp_path / "missing", "c") == "none"

    def test_directory(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _classify_artifact

        d = tmp_path / "build_out"
        d.mkdir()
        assert _classify_artifact(d, "c") == "directory"

    def test_compiled_file(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _classify_artifact

        f = tmp_path / "output.exe"
        f.write_bytes(b"\x00")
        assert _classify_artifact(f, "c") == "file"

    def test_script(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _classify_artifact

        f = tmp_path / "main.pl"
        f.write_text("#!/usr/bin/perl\n")
        assert _classify_artifact(f, "perl") == "script"


# -- _artifact_display_name -------------------------------------------


class TestArtifactDisplayName:
    def test_none_artifact(self) -> None:
        from empusa.cli_modules import _artifact_display_name

        assert _artifact_display_name(None, "none") == "-"

    def test_directory(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _artifact_display_name

        d = tmp_path / "outdir"
        d.mkdir()
        assert _artifact_display_name(d, "directory") == "outdir/"

    def test_file(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _artifact_display_name

        f = tmp_path / "binary.exe"
        f.write_bytes(b"\x00")
        assert _artifact_display_name(f, "file") == "binary.exe"


# -- _artifact_freshness ----------------------------------------------


class TestArtifactFreshness:
    def test_unknown_when_no_artifact(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _artifact_freshness

        src = tmp_path / "main.c"
        src.write_text("int main() {}")
        assert _artifact_freshness(src, None) == "unknown"

    def test_current(self, tmp_path: Path) -> None:
        import time

        from empusa.cli_modules import _artifact_freshness

        src = tmp_path / "main.c"
        src.write_text("int main() {}")
        time.sleep(0.05)
        art = tmp_path / "output"
        art.write_bytes(b"\x00")
        assert _artifact_freshness(src, art) == "current"

    def test_stale(self, tmp_path: Path) -> None:
        import time

        from empusa.cli_modules import _artifact_freshness

        art = tmp_path / "output"
        art.write_bytes(b"\x00")
        time.sleep(0.05)
        src = tmp_path / "main.c"
        src.write_text("int main() { return 1; }")
        assert _artifact_freshness(src, art) == "stale"

    def test_unknown_when_source_missing(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _artifact_freshness

        art = tmp_path / "output"
        art.write_bytes(b"\x00")
        src = tmp_path / "missing.c"
        assert _artifact_freshness(src, art) == "unknown"


# -- _shell_quote -----------------------------------------------------


class TestShellQuote:
    def test_no_special_chars(self) -> None:
        from empusa.cli_modules import _shell_quote

        result = _shell_quote("/usr/bin/gcc")
        assert isinstance(result, str)

    def test_path_with_spaces(self) -> None:
        from empusa.cli_modules import _shell_quote

        result = _shell_quote("C:\\Program Files\\tool.exe")
        # Should be quoted on any platform
        assert "Program" in result


# -- _format_size -----------------------------------------------------


class TestFormatSize:
    def test_none(self) -> None:
        from empusa.cli_modules import _format_size

        assert _format_size(None) == "-"

    def test_bytes(self) -> None:
        from empusa.cli_modules import _format_size

        assert _format_size(512) == "512 B"

    def test_kilobytes(self) -> None:
        from empusa.cli_modules import _format_size

        result = _format_size(2048)
        assert "KB" in result

    def test_megabytes(self) -> None:
        from empusa.cli_modules import _format_size

        result = _format_size(5 * 1024 * 1024)
        assert "MB" in result


# -- _find_alt_output -------------------------------------------------


class TestFindAltOutput:
    def test_rust_candidates(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _find_alt_output

        candidates = _find_alt_output(tmp_path, "rust", "mybin")
        assert len(candidates) >= 2
        assert any("release" in str(c) for c in candidates)
        assert any("debug" in str(c) for c in candidates)

    def test_go_candidates(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _find_alt_output

        candidates = _find_alt_output(tmp_path, "go", "scanner")
        assert any(c.name == "scanner" for c in candidates)

    def test_csharp_with_bin_dir(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _find_alt_output

        bin_release = tmp_path / "bin" / "Release" / "net8.0"
        bin_release.mkdir(parents=True)
        candidates = _find_alt_output(tmp_path, "csharp", "tool")
        assert any("Release" in str(c) for c in candidates)

    def test_make_candidates(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _find_alt_output

        candidates = _find_alt_output(tmp_path, "make", "payload")
        assert any(c.name == "payload" for c in candidates)

    def test_unknown_language_empty(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _find_alt_output

        candidates = _find_alt_output(tmp_path, "brainfuck", "output")
        assert candidates == []


# -- _write_build_meta ------------------------------------------------


class TestWriteBuildMeta:
    def test_writes_file(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _write_build_meta

        _write_build_meta(tmp_path, {"compiler": "gcc", "lang": "c"})
        meta_file = tmp_path / ".build_meta.json"
        assert meta_file.exists()
        data = json.loads(meta_file.read_text())
        assert data["compiler"] == "gcc"
        assert "timestamp" in data

    def test_does_not_overwrite_timestamp(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _write_build_meta

        _write_build_meta(tmp_path, {"timestamp": "custom"})
        data = json.loads((tmp_path / ".build_meta.json").read_text())
        assert data["timestamp"] == "custom"


# -- get_module_artifact_info -----------------------------------------


class TestGetModuleArtifactInfo:
    def _make_mod(self, base: Path, name: str, lang: str = "c", with_artifact: bool = False) -> dict[str, Any]:
        mod_dir = base / name
        mod_dir.mkdir(parents=True)
        manifest: dict[str, Any] = {
            "name": name,
            "language": lang,
            "source": f"main{LANGUAGE_EXTENSIONS.get(lang, '.c')}",
            "output": f"{name}.exe" if lang == "c" else name,
            "_path": str(mod_dir),
        }
        (mod_dir / manifest["source"]).write_text("// source")
        build_dir = mod_dir / "build"
        build_dir.mkdir()
        if with_artifact:
            output = build_dir / manifest["output"]
            output.write_bytes(b"\xde\xad\xbe\xef")
        return manifest

    def test_no_artifact(self, tmp_path: Path) -> None:
        from empusa.cli_modules import get_module_artifact_info

        mod = self._make_mod(tmp_path, "no_art")
        info = get_module_artifact_info(mod)
        assert info["artifact_exists"] is False
        assert info["artifact_kind"] == "none"
        assert info["artifact_display_name"] == "-"

    def test_with_artifact(self, tmp_path: Path) -> None:
        from empusa.cli_modules import get_module_artifact_info

        mod = self._make_mod(tmp_path, "has_art", with_artifact=True)
        info = get_module_artifact_info(mod)
        assert info["artifact_exists"] is True
        assert info["artifact_kind"] == "file"
        assert info["artifact_size"] is not None
        assert info["artifact_size"] > 0
        assert info["last_modified"] is not None

    def test_launch_command_present(self, tmp_path: Path) -> None:
        from empusa.cli_modules import get_module_artifact_info

        mod = self._make_mod(tmp_path, "launch_test", with_artifact=True)
        info = get_module_artifact_info(mod)
        assert info["launch_command"] is not None

    def test_build_command_present(self, tmp_path: Path) -> None:
        from empusa.cli_modules import get_module_artifact_info

        mod = self._make_mod(tmp_path, "build_cmd_test")
        info = get_module_artifact_info(mod)
        # c has a default compile command
        assert info["build_command"] is not None

    def test_perl_script_classification(self, tmp_path: Path) -> None:
        from empusa.cli_modules import get_module_artifact_info

        mod_dir = tmp_path / "perl_mod"
        mod_dir.mkdir()
        build_dir = mod_dir / "build"
        build_dir.mkdir()
        script = build_dir / "script.pl"
        script.write_text("#!/usr/bin/perl\nprint 'hi';\n")
        mod = {
            "name": "perl_mod",
            "language": "perl",
            "source": "main.pl",
            "output": "script.pl",
            "_path": str(mod_dir),
        }
        (mod_dir / "main.pl").write_text("print 'hi';")
        info = get_module_artifact_info(mod)
        assert info["artifact_kind"] == "script"

    def test_checksum_command(self, tmp_path: Path) -> None:
        from empusa.cli_modules import get_module_artifact_info

        mod = self._make_mod(tmp_path, "checksum_test", with_artifact=True)
        info = get_module_artifact_info(mod)
        assert info["checksum_command"] is not None


# -- _validate_module -------------------------------------------------


class TestValidateModule:
    def _make_valid_mod(self, base: Path) -> dict[str, Any]:
        mod_dir = base / "valid_mod"
        mod_dir.mkdir(parents=True)
        build_dir = mod_dir / "build"
        build_dir.mkdir()
        (mod_dir / "main.c").write_text("int main() {}")
        (build_dir / "valid_mod.exe").write_bytes(b"\x00")
        return {
            "name": "valid_mod",
            "language": "c",
            "source": "main.c",
            "description": "A test module",
            "compiler": "",
            "output": "valid_mod.exe",
            "target_os": "any",
            "compile_cmd": "gcc -o {output} {source}",
            "_path": str(mod_dir),
        }

    def test_required_fields_pass(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _validate_module

        mod = self._make_valid_mod(tmp_path)
        findings = _validate_module(mod)
        passes = [f for f in findings if f["level"] == "pass"]
        assert any("name" in f["message"] for f in passes)
        assert any("language" in f["message"] for f in passes)
        assert any("source" in f["message"] for f in passes)

    def test_missing_required_field(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _validate_module

        mod_dir = tmp_path / "incomplete"
        mod_dir.mkdir()
        mod = {"_path": str(mod_dir)}
        findings = _validate_module(mod)
        errors = [f for f in findings if f["level"] == "error"]
        assert any("name" in f["message"] for f in errors)

    def test_source_file_missing(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _validate_module

        mod_dir = tmp_path / "no_source"
        mod_dir.mkdir()
        mod = {
            "name": "no_source",
            "language": "c",
            "source": "missing.c",
            "_path": str(mod_dir),
        }
        findings = _validate_module(mod)
        errors = [f for f in findings if f["level"] == "error"]
        assert any("Source file missing" in f["message"] for f in errors)

    def test_artifact_status(self, tmp_path: Path) -> None:
        from empusa.cli_modules import _validate_module

        mod = self._make_valid_mod(tmp_path)
        findings = _validate_module(mod)
        assert any("Artifact exists" in f["message"] for f in findings)
