"""Tests for empusa.cli_workspace — non-interactive workspace CLI commands.

Covers:
- cmd_workspace_init: htb, research, invalid profile, templates, --set-active
- cmd_workspace_list: empty, populated, active marke
- cmd_workspace_select: success, missing workspace, missing metadata
- cmd_workspace_status: metadata display, active indicators

All commands are tested via direct function calls with synthetic
argparse.Namespace objects — no interactive menus, no Docker.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from empusa.cli_common import CONFIG, clear_active_workspace, get_active_workspace
from empusa.cli_workspace import (
    cmd_workspace_init,
    cmd_workspace_list,
    cmd_workspace_select,
    cmd_workspace_status,
)
from empusa.workspace import PROFILES

# ── helpers ──────────────────────────────────────────────────────────


def _make_args(**kwargs: Any) -> argparse.Namespace:
    """Build a Namespace with sensible defaults for workspace commands."""
    defaults = {
        "name": "test-ws",
        "profile": "htb",
        "root": None,
        "set_active": False,
        "templates_dir": None,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _make_templates_dir(tmp_path: Path, filenames: list[str]) -> Path:
    tpl = tmp_path / "templates"
    tpl.mkdir(exist_ok=True)
    for name in filenames:
        (tpl / name).write_text(f"# {{{{NAME}}}}\n\nTemplate: {name}\n", encoding="utf-8")
    return tpl


@pytest.fixture(autouse=True)
def _reset_config() -> Any:
    """Reset workspace CONFIG keys before and after each test."""
    clear_active_workspace()
    yield
    clear_active_workspace()


# ═══════════════════════════════════════════════════════════════════
#  cmd_workspace_init
# ═══════════════════════════════════════════════════════════════════


class TestCmdWorkspaceInit:
    def _emit_events(self) -> tuple[list[tuple[str, dict[str, Any]]], Any]:
        captured: list[tuple[str, dict[str, Any]]] = []

        def emit(event: str, ctx: dict[str, Any]) -> None:
            captured.append((event, ctx))

        return captured, emit

    def test_htb_success(self, tmp_path: Path) -> None:
        captured, emit = self._emit_events()
        args = _make_args(name="box1", profile="htb", root=str(tmp_path))
        rc = cmd_workspace_init(args, emit_fn=emit)
        assert rc == 0
        assert (tmp_path / "box1").is_dir()
        for d in PROFILES["htb"]["dirs"]:
            assert (tmp_path / "box1" / d).is_dir()

    def test_research_success(self, tmp_path: Path) -> None:
        captured, emit = self._emit_events()
        args = _make_args(name="topic", profile="research", root=str(tmp_path))
        rc = cmd_workspace_init(args, emit_fn=emit)
        assert rc == 0
        for d in PROFILES["research"]["dirs"]:
            assert (tmp_path / "topic" / d).is_dir()

    def test_invalid_profile(self, tmp_path: Path) -> None:
        captured, emit = self._emit_events()
        args = _make_args(name="x", profile="bogus", root=str(tmp_path))
        rc = cmd_workspace_init(args, emit_fn=emit)
        assert rc == 1

    def test_emits_pre_and_post_events(self, tmp_path: Path) -> None:
        captured, emit = self._emit_events()
        args = _make_args(name="box1", profile="htb", root=str(tmp_path))
        cmd_workspace_init(args, emit_fn=emit)
        event_names = [e[0] for e in captured]
        assert "pre_workspace_init" in event_names
        assert "post_workspace_init" in event_names

    def test_pre_event_payload(self, tmp_path: Path) -> None:
        captured, emit = self._emit_events()
        args = _make_args(name="box1", profile="htb", root=str(tmp_path))
        cmd_workspace_init(args, emit_fn=emit)
        pre = next(e for e in captured if e[0] == "pre_workspace_init")
        assert pre[1]["workspace_name"] == "box1"
        assert pre[1]["profile"] == "htb"

    def test_post_event_has_created_paths(self, tmp_path: Path) -> None:
        captured, emit = self._emit_events()
        args = _make_args(name="box1", profile="htb", root=str(tmp_path))
        cmd_workspace_init(args, emit_fn=emit)
        post = next(e for e in captured if e[0] == "post_workspace_init")
        assert len(post[1]["created_paths"]) > 0

    def test_set_active_updates_config(self, tmp_path: Path) -> None:
        captured, emit = self._emit_events()
        args = _make_args(name="active1", profile="htb", root=str(tmp_path), set_active=True)
        rc = cmd_workspace_init(args, emit_fn=emit)
        assert rc == 0
        ws = get_active_workspace()
        assert ws["name"] == "active1"
        assert ws["profile"] == "htb"
        assert CONFIG["session_env"] == "active1"

    def test_no_set_active_leaves_config(self, tmp_path: Path) -> None:
        captured, emit = self._emit_events()
        args = _make_args(name="passive", profile="htb", root=str(tmp_path), set_active=False)
        cmd_workspace_init(args, emit_fn=emit)
        assert CONFIG["workspace_name"] == ""

    def test_already_exists_returns_zero(self, tmp_path: Path) -> None:
        captured, emit = self._emit_events()
        args = _make_args(name="dup", profile="htb", root=str(tmp_path))
        cmd_workspace_init(args, emit_fn=emit)
        rc = cmd_workspace_init(args, emit_fn=emit)
        assert rc == 0

    def test_templates_seeded(self, tmp_path: Path) -> None:
        tpl = _make_templates_dir(tmp_path, PROFILES["htb"]["templates"])
        captured, emit = self._emit_events()
        args = _make_args(
            name="tpl-ws",
            profile="htb",
            root=str(tmp_path),
            templates_dir=str(tpl),
        )
        rc = cmd_workspace_init(args, emit_fn=emit)
        assert rc == 0
        for t in PROFILES["htb"]["templates"]:
            assert (tmp_path / "tpl-ws" / t).is_file()

    def test_templates_dir_missing_returns_error(self, tmp_path: Path) -> None:
        captured, emit = self._emit_events()
        args = _make_args(
            name="x",
            profile="htb",
            root=str(tmp_path),
            templates_dir=str(tmp_path / "nonexistent"),
        )
        rc = cmd_workspace_init(args, emit_fn=emit)
        assert rc == 1


# ═══════════════════════════════════════════════════════════════════
#  cmd_workspace_list
# ═══════════════════════════════════════════════════════════════════


class TestCmdWorkspaceList:
    def test_empty_root(self, tmp_path: Path) -> None:
        args = _make_args(root=str(tmp_path))
        rc = cmd_workspace_list(args)
        assert rc == 0

    @patch("empusa.cli_workspace.console")
    def test_lists_workspaces(self, mock_console: Any, tmp_path: Path) -> None:
        # Create two workspaces using the init command
        _, emit = [], lambda e, c: None
        cmd_workspace_init(_make_args(name="ws1", profile="htb", root=str(tmp_path)), emit_fn=emit)
        cmd_workspace_init(_make_args(name="ws2", profile="research", root=str(tmp_path)), emit_fn=emit)

        rc = cmd_workspace_list(_make_args(root=str(tmp_path)))
        assert rc == 0
        # console.print was called with a Table
        mock_console.print.assert_called()

    def test_nonexistent_root(self, tmp_path: Path) -> None:
        args = _make_args(root=str(tmp_path / "nope"))
        rc = cmd_workspace_list(args)
        assert rc == 0


# ═══════════════════════════════════════════════════════════════════
#  cmd_workspace_select
# ═══════════════════════════════════════════════════════════════════


class TestCmdWorkspaceSelect:
    def _setup_workspace(self, tmp_path: Path, name: str = "ws1", profile: str = "htb") -> Path:
        """Create a workspace and return its path."""

        def emit(e: str, c: dict[str, Any]) -> None: ...

        cmd_workspace_init(
            _make_args(name=name, profile=profile, root=str(tmp_path)),
            emit_fn=emit,
        )
        return tmp_path / name

    def test_select_success(self, tmp_path: Path) -> None:
        self._setup_workspace(tmp_path, "ws1", "htb")
        captured: list[tuple[str, dict[str, Any]]] = []

        def emit(e: str, c: dict[str, Any]) -> None:
            captured.append((e, c))

        args = _make_args(name="ws1", root=str(tmp_path))
        rc = cmd_workspace_select(args, emit_fn=emit)
        assert rc == 0
        assert CONFIG["workspace_name"] == "ws1"
        assert CONFIG["session_env"] == "ws1"
        assert CONFIG["workspace_profile"] == "htb"

    def test_select_emits_event(self, tmp_path: Path) -> None:
        self._setup_workspace(tmp_path, "ws1")
        captured: list[tuple[str, dict[str, Any]]] = []

        def emit(e: str, c: dict[str, Any]) -> None:
            captured.append((e, c))

        cmd_workspace_select(_make_args(name="ws1", root=str(tmp_path)), emit_fn=emit)
        event_names = [e[0] for e in captured]
        assert "on_workspace_select" in event_names

    def test_select_event_payload(self, tmp_path: Path) -> None:
        self._setup_workspace(tmp_path, "ws1", "htb")
        captured: list[tuple[str, dict[str, Any]]] = []

        def emit(e: str, c: dict[str, Any]) -> None:
            captured.append((e, c))

        cmd_workspace_select(_make_args(name="ws1", root=str(tmp_path)), emit_fn=emit)
        evt = next(e for e in captured if e[0] == "on_workspace_select")
        assert evt[1]["workspace_name"] == "ws1"
        assert evt[1]["profile"] == "htb"
        assert evt[1]["workspace_path"] == str(tmp_path / "ws1")

    def test_select_missing_workspace(self, tmp_path: Path) -> None:
        def emit(e: str, c: dict[str, Any]) -> None: ...

        args = _make_args(name="nope", root=str(tmp_path))
        rc = cmd_workspace_select(args, emit_fn=emit)
        assert rc == 1

    def test_select_missing_metadata(self, tmp_path: Path) -> None:
        # Dir exists but no metadata file
        (tmp_path / "nomd").mkdir()

        def emit(e: str, c: dict[str, Any]) -> None: ...

        args = _make_args(name="nomd", root=str(tmp_path))
        rc = cmd_workspace_select(args, emit_fn=emit)
        assert rc == 1


# ═══════════════════════════════════════════════════════════════════
#  cmd_workspace_status
# ═══════════════════════════════════════════════════════════════════


class TestCmdWorkspaceStatus:
    def _setup_workspace(self, tmp_path: Path, name: str = "ws1", profile: str = "htb") -> None:
        def emit(e: str, c: dict[str, Any]) -> None: ...

        cmd_workspace_init(
            _make_args(name=name, profile=profile, root=str(tmp_path)),
            emit_fn=emit,
        )

    def _render_panel_text(self, mock_console: Any) -> str:
        """Extract the text content from the Panel passed to console.print."""
        from rich.panel import Panel

        for call in mock_console.print.call_args_list:
            if call.args and isinstance(call.args[0], Panel):
                return str(call.args[0].renderable)
        return ""

    @patch("empusa.cli_workspace.console")
    def test_status_success(self, mock_console: Any, tmp_path: Path) -> None:
        self._setup_workspace(tmp_path, "ws1", "htb")
        args = _make_args(name="ws1", root=str(tmp_path))
        rc = cmd_workspace_status(args)
        assert rc == 0
        # Should have printed a Panel with workspace info
        text = self._render_panel_text(mock_console)
        assert "ws1" in text
        assert "htb" in text

    def test_status_missing_workspace(self, tmp_path: Path) -> None:
        args = _make_args(name="nope", root=str(tmp_path))
        rc = cmd_workspace_status(args)
        assert rc == 1

    def test_status_missing_metadata(self, tmp_path: Path) -> None:
        (tmp_path / "nomd").mkdir()
        args = _make_args(name="nomd", root=str(tmp_path))
        rc = cmd_workspace_status(args)
        assert rc == 1

    @patch("empusa.cli_workspace.console")
    def test_status_shows_active_marker(self, mock_console: Any, tmp_path: Path) -> None:
        self._setup_workspace(tmp_path, "ws1", "htb")

        # Select the workspace to make it active
        def emit(e: str, c: dict[str, Any]) -> None: ...

        cmd_workspace_select(_make_args(name="ws1", root=str(tmp_path)), emit_fn=emit)

        args = _make_args(name="ws1", root=str(tmp_path))
        cmd_workspace_status(args)

        text = self._render_panel_text(mock_console)
        assert "Active workspace" in text

    @patch("empusa.cli_workspace.console")
    def test_status_shows_legacy_env_match(self, mock_console: Any, tmp_path: Path) -> None:
        self._setup_workspace(tmp_path, "ws1", "htb")
        # Set session_env to match but do NOT use set_active_workspace
        clear_active_workspace()
        CONFIG["session_env"] = "ws1"

        args = _make_args(name="ws1", root=str(tmp_path))
        cmd_workspace_status(args)

        text = self._render_panel_text(mock_console)
        assert "Legacy environment only" in text
