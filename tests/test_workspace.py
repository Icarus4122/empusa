"""Tests for empusa.workspace - core workspace lifecycle functions.

Covers:
- create_workspace with htb, research, build, internal profiles
- template seeding and variable substitution
- missing template tracking
- templates_dir not supplied / not a directory
- already-existing workspace short-circuit
- metadata file creation & load_metadata()
- list_workspaces() with mixed valid / invalid entries
- _sanitize() name cleaning
- WorkspaceResult.to_dict()
- ensure_build_layout flat and workspace-nested modes
- BuildLayout dataclass fields
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from empusa.workspace import (
    DEFAULT_WORKSPACE_ROOT,
    METADATA_FILENAME,
    PROFILES,
    WorkspaceResult,
    _sanitize,
    create_workspace,
    ensure_build_layout,
    list_workspaces,
    load_metadata,
)

# ── helpers ──────────────────────────────────────────────────────────


def _make_templates_dir(tmp_path: Path, filenames: list[str]) -> Path:
    """Create a temporary templates directory with dummy .md files."""
    tpl = tmp_path / "templates"
    tpl.mkdir()
    for name in filenames:
        (tpl / name).write_text(f"# {{{{NAME}}}}\n\nTemplate: {name}\n", encoding="utf-8")
    return tpl


# ═══════════════════════════════════════════════════════════════════
#  _sanitize
# ═══════════════════════════════════════════════════════════════════


class TestSanitize:
    def test_passthrough_safe_name(self) -> None:
        assert _sanitize("my-box_01.htb") == "my-box_01.htb"

    def test_strips_spaces(self) -> None:
        assert _sanitize("my box") == "mybox"

    def test_strips_slashes(self) -> None:
        assert _sanitize("../../etc") == "....etc"

    def test_empty_string(self) -> None:
        assert _sanitize("") == ""


# ═══════════════════════════════════════════════════════════════════
#  create_workspace - htb profile
# ═══════════════════════════════════════════════════════════════════


class TestCreateWorkspaceHtb:
    def test_creates_all_profile_dirs(self, tmp_path: Path) -> None:
        create_workspace("target1", profile="htb", root=tmp_path)
        ws = tmp_path / "target1"
        assert ws.is_dir()
        for d in PROFILES["htb"]["dirs"]:
            assert (ws / d).is_dir(), f"missing subdir: {d}"

    def test_result_fields(self, tmp_path: Path) -> None:
        result = create_workspace("target1", profile="htb", root=tmp_path)
        assert result.name == "target1"
        assert result.profile == "htb"
        assert result.workspace_root == str(tmp_path)
        assert result.workspace_path == str(tmp_path / "target1")
        assert result.already_existed is False
        assert result.metadata_path != ""

    def test_metadata_written(self, tmp_path: Path) -> None:
        create_workspace("target1", profile="htb", root=tmp_path)
        meta_path = tmp_path / "target1" / METADATA_FILENAME
        assert meta_path.is_file()
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        assert meta["profile"] == "htb"
        assert meta["name"] == "target1"
        assert "created_at" in meta

    def test_no_templates_without_dir(self, tmp_path: Path) -> None:
        result = create_workspace("target1", profile="htb", root=tmp_path)
        assert result.templates_seeded == []
        assert result.templates_missing == PROFILES["htb"]["templates"]

    def test_templates_seeded_with_dir(self, tmp_path: Path) -> None:
        tpl = _make_templates_dir(tmp_path, PROFILES["htb"]["templates"])
        result = create_workspace("target1", profile="htb", root=tmp_path, templates_dir=tpl)
        assert sorted(result.templates_seeded) == sorted(PROFILES["htb"]["templates"])
        assert result.templates_missing == []
        for name in result.templates_seeded:
            assert (tmp_path / "target1" / name).is_file()

    def test_template_variable_substitution(self, tmp_path: Path) -> None:
        tpl = _make_templates_dir(tmp_path, ["recon.md"])
        create_workspace(
            "mybox",
            profile="htb",
            root=tmp_path,
            templates_dir=tpl,
            template_vars={"NAME": "CustomName"},
        )
        content = (tmp_path / "mybox" / "recon.md").read_text(encoding="utf-8")
        assert "CustomName" in content
        assert "{{NAME}}" not in content

    def test_default_name_substitution(self, tmp_path: Path) -> None:
        tpl = _make_templates_dir(tmp_path, ["recon.md"])
        create_workspace("mybox", profile="htb", root=tmp_path, templates_dir=tpl)
        content = (tmp_path / "mybox" / "recon.md").read_text(encoding="utf-8")
        assert "mybox" in content


# ═══════════════════════════════════════════════════════════════════
#  create_workspace - research profile
# ═══════════════════════════════════════════════════════════════════


class TestCreateWorkspaceResearch:
    def test_creates_research_dirs(self, tmp_path: Path) -> None:
        create_workspace("topic1", profile="research", root=tmp_path)
        ws = tmp_path / "topic1"
        for d in PROFILES["research"]["dirs"]:
            assert (ws / d).is_dir(), f"missing subdir: {d}"

    def test_research_templates(self, tmp_path: Path) -> None:
        tpl = _make_templates_dir(tmp_path, ["recon.md"])
        result = create_workspace("topic1", profile="research", root=tmp_path, templates_dir=tpl)
        assert result.templates_seeded == ["recon.md"]
        assert result.templates_missing == []

    def test_research_no_extra_dirs(self, tmp_path: Path) -> None:
        create_workspace("topic1", profile="research", root=tmp_path)
        ws = tmp_path / "topic1"
        # Only profile dirs + metadata file should exist
        children = {p.name for p in ws.iterdir()}
        expected = set(PROFILES["research"]["dirs"]) | {METADATA_FILENAME}
        assert children == expected


# ═══════════════════════════════════════════════════════════════════
#  create_workspace - build & internal profiles
# ═══════════════════════════════════════════════════════════════════


class TestCreateWorkspaceBuild:
    def test_build_has_no_templates(self, tmp_path: Path) -> None:
        result = create_workspace("proj", profile="build", root=tmp_path)
        assert result.templates_seeded == []
        assert result.templates_missing == []

    def test_build_dirs(self, tmp_path: Path) -> None:
        create_workspace("proj", profile="build", root=tmp_path)
        ws = tmp_path / "proj"
        for d in PROFILES["build"]["dirs"]:
            assert (ws / d).is_dir()


class TestCreateWorkspaceInternal:
    def test_internal_dirs(self, tmp_path: Path) -> None:
        create_workspace("engagement", profile="internal", root=tmp_path)
        ws = tmp_path / "engagement"
        for d in PROFILES["internal"]["dirs"]:
            assert (ws / d).is_dir()

    def test_internal_templates(self, tmp_path: Path) -> None:
        tpl = _make_templates_dir(tmp_path, PROFILES["internal"]["templates"])
        result = create_workspace("engagement", profile="internal", root=tmp_path, templates_dir=tpl)
        assert sorted(result.templates_seeded) == sorted(PROFILES["internal"]["templates"])


# ═══════════════════════════════════════════════════════════════════
#  create_workspace - edge cases
# ═══════════════════════════════════════════════════════════════════


class TestCreateWorkspaceEdgeCases:
    def test_invalid_profile_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="Unknown profile"):
            create_workspace("x", profile="nope", root=tmp_path)

    def test_already_exists(self, tmp_path: Path) -> None:
        create_workspace("dup", profile="htb", root=tmp_path)
        result = create_workspace("dup", profile="htb", root=tmp_path)
        assert result.already_existed is True
        assert result.created_paths == []

    def test_name_sanitized(self, tmp_path: Path) -> None:
        result = create_workspace("my box!!", profile="htb", root=tmp_path)
        assert result.name == "mybox"
        assert (tmp_path / "mybox").is_dir()

    def test_templates_dir_nonexistent(self, tmp_path: Path) -> None:
        bad = tmp_path / "no-such-dir"
        result = create_workspace("t", profile="htb", root=tmp_path, templates_dir=bad)
        assert result.templates_seeded == []
        assert result.templates_missing == PROFILES["htb"]["templates"]

    def test_partial_templates(self, tmp_path: Path) -> None:
        """Only some template files exist - seeded list and missing list both populated."""
        tpl = _make_templates_dir(tmp_path, ["recon.md", "target.md"])
        result = create_workspace("t", profile="htb", root=tmp_path, templates_dir=tpl)
        assert "recon.md" in result.templates_seeded
        assert "target.md" in result.templates_seeded
        # Everything else is missing
        for m in result.templates_missing:
            assert m not in result.templates_seeded

    def test_uses_default_root_constant(self) -> None:
        assert Path("/opt/lab/workspaces") == DEFAULT_WORKSPACE_ROOT


# ═══════════════════════════════════════════════════════════════════
#  WorkspaceResult
# ═══════════════════════════════════════════════════════════════════


class TestWorkspaceResult:
    def test_to_dict(self, tmp_path: Path) -> None:
        result = create_workspace("x", profile="build", root=tmp_path)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert d["name"] == "x"
        assert d["profile"] == "build"
        assert isinstance(d["created_paths"], list)

    def test_defaults(self) -> None:
        r = WorkspaceResult(name="a", profile="htb", workspace_root="/r", workspace_path="/r/a")
        assert r.created_paths == []
        assert r.templates_seeded == []
        assert r.templates_missing == []
        assert r.metadata_path == ""
        assert r.already_existed is False


# ═══════════════════════════════════════════════════════════════════
#  load_metadata
# ═══════════════════════════════════════════════════════════════════


class TestLoadMetadata:
    def test_round_trip(self, tmp_path: Path) -> None:
        create_workspace("ws1", profile="htb", root=tmp_path)
        meta = load_metadata(tmp_path / "ws1")
        assert meta["name"] == "ws1"
        assert meta["profile"] == "htb"
        assert "created_at" in meta

    def test_missing_raises(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(FileNotFoundError):
            load_metadata(empty)

    def test_metadata_has_templates_seeded(self, tmp_path: Path) -> None:
        tpl = _make_templates_dir(tmp_path, ["recon.md"])
        create_workspace("ws1", profile="research", root=tmp_path, templates_dir=tpl)
        meta = load_metadata(tmp_path / "ws1")
        assert meta["templates_seeded"] == ["recon.md"]


# ═══════════════════════════════════════════════════════════════════
#  list_workspaces
# ═══════════════════════════════════════════════════════════════════


class TestListWorkspaces:
    def test_empty_root(self, tmp_path: Path) -> None:
        assert list_workspaces(tmp_path) == []

    def test_nonexistent_root(self, tmp_path: Path) -> None:
        assert list_workspaces(tmp_path / "nope") == []

    def test_finds_workspaces(self, tmp_path: Path) -> None:
        create_workspace("ws1", profile="htb", root=tmp_path)
        create_workspace("ws2", profile="research", root=tmp_path)
        result = list_workspaces(tmp_path)
        names = [w["name"] for w in result]
        assert "ws1" in names
        assert "ws2" in names

    def test_skips_non_workspace_dirs(self, tmp_path: Path) -> None:
        create_workspace("ws1", profile="htb", root=tmp_path)
        # Create a dir without metadata - should be ignored
        (tmp_path / "random-dir").mkdir()
        result = list_workspaces(tmp_path)
        assert len(result) == 1
        assert result[0]["name"] == "ws1"

    def test_skips_corrupt_metadata(self, tmp_path: Path) -> None:
        create_workspace("ws1", profile="htb", root=tmp_path)
        # Create a dir with corrupt metadata
        bad = tmp_path / "bad"
        bad.mkdir()
        (bad / METADATA_FILENAME).write_text("not json", encoding="utf-8")
        result = list_workspaces(tmp_path)
        assert len(result) == 1

    def test_sorted_by_name(self, tmp_path: Path) -> None:
        create_workspace("zzz", profile="build", root=tmp_path)
        create_workspace("aaa", profile="build", root=tmp_path)
        result = list_workspaces(tmp_path)
        assert result[0]["name"] == "aaa"
        assert result[1]["name"] == "zzz"


# ═══════════════════════════════════════════════════════════════════
#  ensure_build_layout - flat mode (no workspace)
# ═══════════════════════════════════════════════════════════════════


class TestBuildLayoutFlat:
    def test_creates_base_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        layout = ensure_build_layout("myenv", ["10.10.10.1"])
        assert layout.base_dir.is_dir()
        assert layout.base_dir.name == "myenv"

    def test_creates_credential_files(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        layout = ensure_build_layout("myenv", ["10.10.10.1"])
        assert layout.users_file.exists()
        assert layout.passwords_file.exists()
        assert layout.commands_log.exists()
        assert layout.users_file.name == "myenv-users.txt"
        assert layout.passwords_file.name == "myenv-passwords.txt"
        assert layout.commands_log.name == "commands_ran.txt"

    def test_scans_dir_equals_base_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        layout = ensure_build_layout("myenv", ["10.10.10.1"])
        assert layout.scans_dir == layout.base_dir

    def test_per_ip_nmap_dirs(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        ips = ["10.10.10.1", "10.10.10.2"]
        layout = ensure_build_layout("myenv", ips)
        assert len(layout.ip_nmap_dirs) == 2
        for ip in ips:
            nmap_dir = layout.ip_nmap_dirs[ip]
            assert nmap_dir.is_dir()
            assert nmap_dir.name == "nmap"
            assert nmap_dir.parent.name == ip

    def test_idempotent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        layout1 = ensure_build_layout("myenv", ["10.10.10.1"])
        layout2 = ensure_build_layout("myenv", ["10.10.10.1"])
        assert layout1.base_dir == layout2.base_dir


# ═══════════════════════════════════════════════════════════════════
#  ensure_build_layout - workspace-nested mode
# ═══════════════════════════════════════════════════════════════════


class TestBuildLayoutWorkspace:
    def test_uses_scans_subdir(self, tmp_path: Path) -> None:
        # Set up a workspace-like structure with scans/ creds/ logs/
        ws = tmp_path / "myws"
        for d in ("scans", "creds", "logs"):
            (ws / d).mkdir(parents=True)

        layout = ensure_build_layout("myenv", ["10.10.10.1"], workspace_path=ws)
        assert layout.scans_dir == ws / "scans"
        assert layout.users_file.parent == ws / "creds"
        assert layout.commands_log.parent == ws / "logs"

    def test_falls_back_to_base_when_no_subdirs(self, tmp_path: Path) -> None:
        ws = tmp_path / "bare_ws"
        ws.mkdir()
        layout = ensure_build_layout("myenv", ["10.10.10.1"], workspace_path=ws)
        assert layout.scans_dir == ws
        assert layout.users_file.parent == ws
        assert layout.commands_log.parent == ws

    def test_nmap_dirs_under_scans(self, tmp_path: Path) -> None:
        ws = tmp_path / "ws"
        (ws / "scans").mkdir(parents=True)
        (ws / "creds").mkdir()
        (ws / "logs").mkdir()

        layout = ensure_build_layout("myenv", ["10.10.10.1", "10.10.10.2"], workspace_path=ws)
        for _ip, nmap_dir in layout.ip_nmap_dirs.items():
            assert nmap_dir.is_dir()
            # The nmap dir should be under scans/
            assert str(nmap_dir).startswith(str(ws / "scans"))

    def test_base_dir_is_workspace_path(self, tmp_path: Path) -> None:
        ws = tmp_path / "ws"
        ws.mkdir()
        layout = ensure_build_layout("myenv", ["10.10.10.1"], workspace_path=ws)
        assert layout.base_dir == ws
