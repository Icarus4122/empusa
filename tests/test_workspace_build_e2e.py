"""End-to-end tests: workspace subsystem ↔ build/scan flow.

Verifies that workspaces created via workspace.py integrate correctly
with the build flow in cli_scan.py.  Each test is focused on a single
concern — no giant integration tests.

All nmap/OS-detection calls are mocked; no Docker or network required.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from empusa.cli_common import CONFIG, clear_active_workspace, set_active_workspace
from empusa.workspace import (
    METADATA_FILENAME,
    BuildLayout,
    create_workspace,
    ensure_build_layout,
    load_metadata,
)

# ── helpers ──────────────────────────────────────────────────────────


def _create_htb_workspace(root: Path, name: str = "box1") -> Path:
    """Create an HTB workspace and return its path."""
    create_workspace(name, profile="htb", root=root)
    return root / name


def _fake_run_nmap(ip: str, output_path: Path, **kwargs: Any) -> tuple[str, Path]:
    """Stub that writes a synthetic nmap result without running nmap."""
    output_path.mkdir(parents=True, exist_ok=True)
    output_file = output_path / "full_scan.txt"
    output_file.write_text(
        f"Nmap scan report for {ip}\n"
        f"22/tcp   open  ssh     OpenSSH 8.9\n"
        f"80/tcp   open  http    Apache httpd 2.4 (Ubuntu)\n",
        encoding="utf-8",
    )
    return ip, output_file


@pytest.fixture(autouse=True)
def _reset_config() -> Any:
    """Ensure clean workspace CONFIG state for every test."""
    saved = {k: CONFIG[k] for k in CONFIG}
    clear_active_workspace()
    CONFIG["dry_run"] = False
    CONFIG["quiet"] = True
    yield
    for k, v in saved.items():
        CONFIG[k] = v


# ═══════════════════════════════════════════════════════════════════
#  Workspace-nested build layout
# ═══════════════════════════════════════════════════════════════════


class TestWorkspaceBuildLayout:
    """ensure_build_layout inside an HTB workspace."""

    def test_scans_under_workspace_scans_dir(self, tmp_path: Path) -> None:
        ws = _create_htb_workspace(tmp_path)
        layout = ensure_build_layout("box1", ["10.10.10.1"], workspace_path=ws)
        assert layout.scans_dir == ws / "scans"
        assert layout.ip_nmap_dirs["10.10.10.1"].is_dir()
        assert str(layout.ip_nmap_dirs["10.10.10.1"]).startswith(str(ws / "scans"))

    def test_creds_under_workspace_creds_dir(self, tmp_path: Path) -> None:
        ws = _create_htb_workspace(tmp_path)
        layout = ensure_build_layout("box1", ["10.10.10.1"], workspace_path=ws)
        assert layout.users_file.parent == ws / "creds"
        assert layout.passwords_file.parent == ws / "creds"
        assert layout.users_file.name == "box1-users.txt"
        assert layout.passwords_file.name == "box1-passwords.txt"

    def test_logs_under_workspace_logs_dir(self, tmp_path: Path) -> None:
        ws = _create_htb_workspace(tmp_path)
        layout = ensure_build_layout("box1", ["10.10.10.1"], workspace_path=ws)
        assert layout.commands_log.parent == ws / "logs"
        assert layout.commands_log.name == "commands_ran.txt"

    def test_base_dir_is_workspace(self, tmp_path: Path) -> None:
        ws = _create_htb_workspace(tmp_path)
        layout = ensure_build_layout("box1", ["10.10.10.1"], workspace_path=ws)
        assert layout.base_dir == ws

    def test_multiple_ips(self, tmp_path: Path) -> None:
        ws = _create_htb_workspace(tmp_path)
        ips = ["10.10.10.1", "10.10.10.2", "10.10.10.3"]
        layout = ensure_build_layout("box1", ips, workspace_path=ws)
        assert len(layout.ip_nmap_dirs) == 3
        for ip in ips:
            nmap_dir = layout.ip_nmap_dirs[ip]
            assert nmap_dir.is_dir()
            assert nmap_dir.parent.parent == ws / "scans"


# ═══════════════════════════════════════════════════════════════════
#  Standalone (flat) build layout — legacy behavio
# ═══════════════════════════════════════════════════════════════════


class TestStandaloneBuildLayout:
    """ensure_build_layout WITHOUT workspace_path — flat layout."""

    def test_flat_scans_at_root(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        layout = ensure_build_layout("myenv", ["10.10.10.1"])
        assert layout.scans_dir == layout.base_dir
        assert layout.base_dir.name == "myenv"

    def test_flat_creds_at_root(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        layout = ensure_build_layout("myenv", ["10.10.10.1"])
        assert layout.users_file.parent == layout.base_dir
        assert layout.passwords_file.parent == layout.base_dir

    def test_flat_logs_at_root(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        layout = ensure_build_layout("myenv", ["10.10.10.1"])
        assert layout.commands_log.parent == layout.base_dir

    def test_flat_nmap_dir_structure(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        layout = ensure_build_layout("myenv", ["10.10.10.1"])
        nmap_dir = layout.ip_nmap_dirs["10.10.10.1"]
        assert nmap_dir.name == "nmap"
        assert nmap_dir.parent.name == "10.10.10.1"
        assert nmap_dir.parent.parent == layout.base_dir


# ═══════════════════════════════════════════════════════════════════
#  build_env — workspace mode (mocked nmap)
# ═══════════════════════════════════════════════════════════════════


class TestBuildEnvWorkspace:
    """build_env() with workspace_path — full flow with mocked scanning."""

    @pytest.fixture()
    def htb_ws(self, tmp_path: Path) -> Path:
        return _create_htb_workspace(tmp_path)

    @patch("empusa.cli_scan.run_nmap", side_effect=_fake_run_nmap)
    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    @patch("empusa.cli_scan.Confirm.ask", return_value=False)
    def test_returns_layout(self, _confirm: Any, _tool: Any, _nmap: Any, htb_ws: Path) -> None:
        from empusa.cli_scan import build_env

        layout = build_env("box1", ["10.10.10.1"], workspace_path=htb_ws)
        assert layout is not None
        assert isinstance(layout, BuildLayout)

    @patch("empusa.cli_scan.run_nmap", side_effect=_fake_run_nmap)
    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    @patch("empusa.cli_scan.Confirm.ask", return_value=False)
    def test_scan_dirs_under_workspace_scans(self, _confirm: Any, _tool: Any, _nmap: Any, htb_ws: Path) -> None:
        from empusa.cli_scan import build_env

        layout = build_env("box1", ["10.10.10.1"], workspace_path=htb_ws)
        assert layout is not None
        assert layout.scans_dir == htb_ws / "scans"

    @patch("empusa.cli_scan.run_nmap", side_effect=_fake_run_nmap)
    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    @patch("empusa.cli_scan.Confirm.ask", return_value=False)
    def test_creds_under_workspace_creds(self, _confirm: Any, _tool: Any, _nmap: Any, htb_ws: Path) -> None:
        from empusa.cli_scan import build_env

        layout = build_env("box1", ["10.10.10.1"], workspace_path=htb_ws)
        assert layout is not None
        assert layout.users_file.parent == htb_ws / "creds"

    @patch("empusa.cli_scan.run_nmap", side_effect=_fake_run_nmap)
    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    @patch("empusa.cli_scan.Confirm.ask", return_value=False)
    def test_commands_log_under_workspace_logs(self, _confirm: Any, _tool: Any, _nmap: Any, htb_ws: Path) -> None:
        from empusa.cli_scan import build_env

        layout = build_env("box1", ["10.10.10.1"], workspace_path=htb_ws)
        assert layout is not None
        assert layout.commands_log.parent == htb_ws / "logs"
        # The build should have appended a log entry
        content = layout.commands_log.read_text(encoding="utf-8")
        assert "box1" in content

    @patch("empusa.cli_scan.run_nmap", side_effect=_fake_run_nmap)
    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    @patch("empusa.cli_scan.Confirm.ask", return_value=False)
    def test_post_build_reports_workspace_as_env_path(
        self, _confirm: Any, _tool: Any, _nmap: Any, htb_ws: Path
    ) -> None:
        from empusa.cli_scan import build_env

        captured: list[tuple[str, dict[str, Any]]] = []

        def hook(event: str, ctx: dict[str, Any]) -> None:
            captured.append((event, ctx))

        build_env("box1", ["10.10.10.1"], run_hooks_fn=hook, workspace_path=htb_ws)

        post = next(e for e in captured if e[0] == "post_build")
        assert post[1]["env_path"] == str(htb_ws)
        assert post[1]["env_name"] == "box1"
        assert post[1]["ips"] == ["10.10.10.1"]

    @patch("empusa.cli_scan.run_nmap", side_effect=_fake_run_nmap)
    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    @patch("empusa.cli_scan.Confirm.ask", return_value=False)
    def test_pre_build_fires_before_scan(self, _confirm: Any, _tool: Any, _nmap: Any, htb_ws: Path) -> None:
        from empusa.cli_scan import build_env

        captured: list[tuple[str, dict[str, Any]]] = []

        def hook(event: str, ctx: dict[str, Any]) -> None:
            captured.append((event, ctx))

        build_env("box1", ["10.10.10.1"], run_hooks_fn=hook, workspace_path=htb_ws)

        event_names = [e[0] for e in captured]
        assert "pre_build" in event_names
        assert "post_build" in event_names
        assert event_names.index("pre_build") < event_names.index("post_build")

    @patch("empusa.cli_scan.run_nmap", side_effect=_fake_run_nmap)
    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    @patch("empusa.cli_scan.Confirm.ask", return_value=False)
    def test_os_rename_under_scans(self, _confirm: Any, _tool: Any, _nmap: Any, htb_ws: Path) -> None:
        """After scanning, IP dirs should be renamed to {ip}-{os} under scans/."""
        from empusa.cli_scan import build_env

        build_env("box1", ["10.10.10.1"], workspace_path=htb_ws)
        scans = htb_ws / "scans"
        # The fake nmap output contains "Apache" → detect_os returns "Linux"
        renamed = list(scans.iterdir())
        names = [d.name for d in renamed if d.is_dir()]
        assert any("10.10.10.1-" in n for n in names)

    @patch("empusa.cli_scan.run_nmap", side_effect=_fake_run_nmap)
    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    @patch("empusa.cli_scan.Confirm.ask", return_value=False)
    def test_workspace_metadata_untouched(self, _confirm: Any, _tool: Any, _nmap: Any, htb_ws: Path) -> None:
        """Build should not overwrite workspace metadata."""
        from empusa.cli_scan import build_env

        meta_before = load_metadata(htb_ws)
        build_env("box1", ["10.10.10.1"], workspace_path=htb_ws)
        meta_after = load_metadata(htb_ws)
        assert meta_before == meta_after


# ═══════════════════════════════════════════════════════════════════
#  build_env — standalone mode (mocked nmap)
# ═══════════════════════════════════════════════════════════════════


class TestBuildEnvStandalone:
    """build_env() WITHOUT workspace_path — legacy flat behaviour."""

    @patch("empusa.cli_scan.run_nmap", side_effect=_fake_run_nmap)
    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    @patch("empusa.cli_scan.Confirm.ask", return_value=False)
    def test_flat_layout(
        self, _confirm: Any, _tool: Any, _nmap: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from empusa.cli_scan import build_env

        monkeypatch.chdir(tmp_path)
        layout = build_env("legacyenv", ["10.10.10.1"])
        assert layout is not None
        assert layout.scans_dir == layout.base_dir
        assert layout.users_file.parent == layout.base_dir
        assert layout.commands_log.parent == layout.base_dir

    @patch("empusa.cli_scan.run_nmap", side_effect=_fake_run_nmap)
    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    @patch("empusa.cli_scan.Confirm.ask", return_value=False)
    def test_post_build_env_path_is_base_dir(
        self, _confirm: Any, _tool: Any, _nmap: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from empusa.cli_scan import build_env

        monkeypatch.chdir(tmp_path)
        captured: list[tuple[str, dict[str, Any]]] = []

        def hook(event: str, ctx: dict[str, Any]) -> None:
            captured.append((event, ctx))

        layout = build_env("legacyenv", ["10.10.10.1"], run_hooks_fn=hook)
        assert layout is not None

        post = next(e for e in captured if e[0] == "post_build")
        assert post[1]["env_path"] == str(layout.base_dir)

    @patch("empusa.cli_scan.run_nmap", side_effect=_fake_run_nmap)
    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    @patch("empusa.cli_scan.Confirm.ask", return_value=False)
    def test_nmap_dirs_at_root(
        self, _confirm: Any, _tool: Any, _nmap: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from empusa.cli_scan import build_env

        monkeypatch.chdir(tmp_path)
        layout = build_env("legacyenv", ["10.10.10.1", "10.10.10.2"])
        assert layout is not None
        for _ip, nmap_dir in layout.ip_nmap_dirs.items():
            assert nmap_dir.parent.parent == layout.base_dir


# ═══════════════════════════════════════════════════════════════════
#  build_env — validation / abort paths
# ═══════════════════════════════════════════════════════════════════


class TestBuildEnvValidation:
    def test_invalid_ips_returns_none(self, tmp_path: Path) -> None:
        from empusa.cli_scan import build_env

        result = build_env("x", ["not-an-ip"], workspace_path=tmp_path)
        assert result is None

    def test_empty_ips_returns_none(self, tmp_path: Path) -> None:
        from empusa.cli_scan import build_env

        result = build_env("x", [], workspace_path=tmp_path)
        assert result is None

    @patch("empusa.cli_scan.check_tool_exists", return_value=False)
    def test_missing_nmap_returns_none(self, _tool: Any, tmp_path: Path) -> None:
        from empusa.cli_scan import build_env

        result = build_env("x", ["10.10.10.1"], workspace_path=tmp_path)
        assert result is None

    def test_dry_run_returns_none(self, tmp_path: Path) -> None:
        from empusa.cli_scan import build_env

        CONFIG["dry_run"] = True
        result = build_env("x", ["10.10.10.1"], workspace_path=tmp_path)
        assert result is None


# ═══════════════════════════════════════════════════════════════════
#  Full flow: workspace create → activate → build → verify
# ═══════════════════════════════════════════════════════════════════


class TestFullWorkspaceBuildFlow:
    """End-to-end: create workspace, mark active, run build, verify paths."""

    @patch("empusa.cli_scan.run_nmap", side_effect=_fake_run_nmap)
    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    @patch("empusa.cli_scan.Confirm.ask", return_value=False)
    def test_full_htb_flow(self, _confirm: Any, _tool: Any, _nmap: Any, tmp_path: Path) -> None:
        from empusa.cli_scan import build_env

        # 1. Create workspace
        ws_root = tmp_path / "workspaces"
        result = create_workspace("target-box", profile="htb", root=ws_root)
        ws_path = Path(result.workspace_path)
        assert not result.already_existed

        # 2. Mark it active
        set_active_workspace(
            name=result.name,
            root=result.workspace_root,
            path=result.workspace_path,
            profile=result.profile,
        )
        assert CONFIG["workspace_name"] == "target-box"
        assert CONFIG["session_env"] == "target-box"

        # 3. Run build inside workspace
        hooks: list[tuple[str, dict[str, Any]]] = []
        layout = build_env(
            "target-box",
            ["10.10.10.5", "10.10.10.6"],
            run_hooks_fn=lambda e, c: hooks.append((e, c)),
            workspace_path=ws_path,
        )
        assert layout is not None

        # 4. Verify scan artifacts under scans/
        assert layout.scans_dir == ws_path / "scans"
        scans_children = [d.name for d in (ws_path / "scans").iterdir() if d.is_dir()]
        # After rename: {ip}-{os}
        assert any("10.10.10.5" in n for n in scans_children)
        assert any("10.10.10.6" in n for n in scans_children)

        # 5. Verify creds under creds/
        assert (ws_path / "creds" / "target-box-users.txt").exists()
        assert (ws_path / "creds" / "target-box-passwords.txt").exists()

        # 6. Verify log under logs/
        log_content = (ws_path / "logs" / "commands_ran.txt").read_text(encoding="utf-8")
        assert "target-box" in log_content

        # 7. Verify post_build event
        post = next(e for e in hooks if e[0] == "post_build")
        assert post[1]["env_path"] == str(ws_path)

        # 8. Workspace metadata still intact
        meta = load_metadata(ws_path)
        assert meta["profile"] == "htb"
        assert meta["name"] == "target-box"

    @patch("empusa.cli_scan.run_nmap", side_effect=_fake_run_nmap)
    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    @patch("empusa.cli_scan.Confirm.ask", return_value=False)
    def test_full_standalone_flow(
        self, _confirm: Any, _tool: Any, _nmap: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Legacy flat build — no workspace involved."""
        from empusa.cli_scan import build_env

        monkeypatch.chdir(tmp_path)
        clear_active_workspace()

        hooks: list[tuple[str, dict[str, Any]]] = []
        layout = build_env(
            "flat-env",
            ["10.10.10.1"],
            run_hooks_fn=lambda e, c: hooks.append((e, c)),
        )
        assert layout is not None

        # Everything at root level
        assert layout.scans_dir == layout.base_dir
        assert layout.users_file.parent == layout.base_dir
        assert layout.commands_log.parent == layout.base_dir
        assert (layout.base_dir / "flat-env-users.txt").exists()
        assert (layout.base_dir / "flat-env-passwords.txt").exists()

        post = next(e for e in hooks if e[0] == "post_build")
        assert post[1]["env_path"] == str(layout.base_dir)
        # No workspace metadata should exist
        assert not (layout.base_dir / METADATA_FILENAME).exists()
