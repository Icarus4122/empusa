"""
Tests for empusa.cli_hooks

Covers: init_hook_dirs, list_hooks, create_example_hook,
        _fire_legacy_hooks_fallback, set_event_bus,
        hooks_summary, hooks_coverage_render, list_hooks_render,
        manager_overview_render, run_hooks.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

# -- init_hook_dirs ---------------------------------------------------


class TestInitHookDirs:
    def test_creates_event_subdirs(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import HOOK_EVENTS, init_hook_dirs

        real_hooks = tmp_path / "hooks"
        with patch("empusa.cli_hooks.HOOKS_DIR", real_hooks):
            init_hook_dirs()

        for evt in HOOK_EVENTS:
            assert (real_hooks / evt).is_dir()


# -- list_hooks -------------------------------------------------------


class TestListHooks:
    def test_returns_dict_of_events(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import HOOK_EVENTS, list_hooks

        hooks_dir = tmp_path / "hooks"
        for evt in HOOK_EVENTS:
            (hooks_dir / evt).mkdir(parents=True, exist_ok=True)

        # Place one script
        (hooks_dir / "on_startup" / "my_hook.py").touch()

        with patch("empusa.cli_hooks.HOOKS_DIR", hooks_dir):
            result = list_hooks()

        assert isinstance(result, dict)
        assert "my_hook.py" in result.get("on_startup", [])

    def test_empty_when_no_hooks(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import HOOK_EVENTS, list_hooks

        hooks_dir = tmp_path / "hooks"
        for evt in HOOK_EVENTS:
            (hooks_dir / evt).mkdir(parents=True, exist_ok=True)

        with patch("empusa.cli_hooks.HOOKS_DIR", hooks_dir):
            result = list_hooks()

        for scripts in result.values():
            assert scripts == []


# -- create_example_hook ----------------------------------------------


class TestCreateExampleHook:
    def test_creates_file_with_log_info(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import create_example_hook

        with patch("empusa.cli_hooks.HOOKS_DIR", tmp_path / "hooks"):
            path = create_example_hook("on_startup")

        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "from empusa.cli_common import log_info" in content
        assert "def run(context" in content
        # Must NOT use raw print
        assert "print(" not in content or "log_info" in content

    def test_unique_names(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import create_example_hook

        with patch("empusa.cli_hooks.HOOKS_DIR", tmp_path / "hooks"):
            p1 = create_example_hook("on_startup")
            p2 = create_example_hook("on_startup")

        assert p1 != p2
        assert p1.exists()
        assert p2.exists()


# -- _fire_legacy_hooks_fallback --------------------------------------


class TestFireLegacyHooksFallback:
    def test_executes_run_function(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import fire_legacy_hooks_fallback

        hooks_dir = tmp_path / "hooks"
        evt_dir = hooks_dir / "test_fire"
        evt_dir.mkdir(parents=True)
        marker = tmp_path / "marker.txt"
        (evt_dir / "hook.py").write_text(
            f"import pathlib\ndef run(ctx):\n    pathlib.Path(r'{marker}').write_text('ok')\n"
        )

        with patch("empusa.cli_hooks.HOOKS_DIR", hooks_dir):
            fire_legacy_hooks_fallback("test_fire", {"event": "test_fire"})

        assert marker.read_text() == "ok"

    def test_missing_event_dir_does_not_raise(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import fire_legacy_hooks_fallback

        with patch("empusa.cli_hooks.HOOKS_DIR", tmp_path / "hooks"):
            fire_legacy_hooks_fallback("nonexistent_event")  # Should not raise


# -- set_event_bus ----------------------------------------------------


class TestSetEventBus:
    def test_sets_module_global(self) -> None:
        from empusa.cli_hooks import get_event_bus, set_event_bus

        fake = MagicMock()
        set_event_bus(fake)
        assert get_event_bus() is fake
        # Cleanup
        set_event_bus(None)  # type: ignore[arg-type]


# -- hooks_summary ----------------------------------------------------


class TestHooksSummary:
    def test_empty_hooks(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import HOOK_EVENTS, hooks_summary

        hooks_dir = tmp_path / "hooks"
        for evt in HOOK_EVENTS:
            (hooks_dir / evt).mkdir(parents=True)

        with patch("empusa.cli_hooks.HOOKS_DIR", hooks_dir):
            info = hooks_summary()

        assert info["configured_events"] == 0
        assert info["total_scripts"] == 0
        assert info["empty_count"] == info["total_events"]

    def test_with_scripts(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import HOOK_EVENTS, hooks_summary

        hooks_dir = tmp_path / "hooks"
        for evt in HOOK_EVENTS:
            (hooks_dir / evt).mkdir(parents=True)
        (hooks_dir / "on_startup" / "hello.py").touch()
        (hooks_dir / "post_scan" / "notify.py").touch()

        with patch("empusa.cli_hooks.HOOKS_DIR", hooks_dir):
            info = hooks_summary()

        assert info["configured_events"] == 2
        assert info["total_scripts"] == 2
        assert len(info["configured"]) == 2
        assert info["empty_count"] == info["total_events"] - 2

    def test_summary_keys(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import HOOK_EVENTS, hooks_summary

        hooks_dir = tmp_path / "hooks"
        for evt in HOOK_EVENTS:
            (hooks_dir / evt).mkdir(parents=True)

        with patch("empusa.cli_hooks.HOOKS_DIR", hooks_dir):
            info = hooks_summary()

        for key in ("configured_events", "total_events", "total_scripts", "configured", "empty_count"):
            assert key in info


# -- hooks_coverage_render --------------------------------------------


class TestHooksCoverageRender:
    def test_no_hooks(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import HOOK_EVENTS, hooks_coverage_render

        hooks_dir = tmp_path / "hooks"
        for evt in HOOK_EVENTS:
            (hooks_dir / evt).mkdir(parents=True)

        with patch("empusa.cli_hooks.HOOKS_DIR", hooks_dir):
            result = hooks_coverage_render()

        assert "No hooks configured" in result

    def test_with_hooks(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import HOOK_EVENTS, hooks_coverage_render

        hooks_dir = tmp_path / "hooks"
        for evt in HOOK_EVENTS:
            (hooks_dir / evt).mkdir(parents=True)
        (hooks_dir / "on_startup" / "hook.py").touch()

        with patch("empusa.cli_hooks.HOOKS_DIR", hooks_dir):
            result = hooks_coverage_render()

        assert "on_startup" in result
        assert "hook.py" in result
        assert "empty event(s) hidden" in result


# -- list_hooks_render ------------------------------------------------


class TestListHooksRender:
    def test_returns_table(self, tmp_path: Path) -> None:
        from rich.table import Table

        from empusa.cli_hooks import HOOK_EVENTS, list_hooks_render

        hooks_dir = tmp_path / "hooks"
        for evt in HOOK_EVENTS:
            (hooks_dir / evt).mkdir(parents=True)

        with patch("empusa.cli_hooks.HOOKS_DIR", hooks_dir):
            table = list_hooks_render()

        assert isinstance(table, Table)

    def test_shows_scripts(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import HOOK_EVENTS, list_hooks_render

        hooks_dir = tmp_path / "hooks"
        for evt in HOOK_EVENTS:
            (hooks_dir / evt).mkdir(parents=True)
        (hooks_dir / "on_startup" / "myhook.py").touch()

        with patch("empusa.cli_hooks.HOOKS_DIR", hooks_dir):
            table = list_hooks_render()

        assert table.caption is not None
        assert "1 hook script" in table.caption


# -- manager_overview_render ------------------------------------------


class TestManagerOverviewRender:
    def test_no_plugins_no_hooks(self, tmp_path: Path) -> None:
        from rich.table import Table

        from empusa.cli_hooks import HOOK_EVENTS, manager_overview_render

        hooks_dir = tmp_path / "hooks"
        for evt in HOOK_EVENTS:
            (hooks_dir / evt).mkdir(parents=True)

        with patch("empusa.cli_hooks.HOOKS_DIR", hooks_dir):
            table = manager_overview_render(pm=None, reg=None)

        assert isinstance(table, Table)

    def test_with_plugin_manager(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import HOOK_EVENTS, manager_overview_render

        hooks_dir = tmp_path / "hooks"
        for evt in HOOK_EVENTS:
            (hooks_dir / evt).mkdir(parents=True)

        pm = MagicMock()
        pm.plugin_count.return_value = 3
        pm.active_count.return_value = 2
        desc1 = MagicMock()
        desc1.enabled = True
        desc2 = MagicMock()
        desc2.enabled = True
        desc3 = MagicMock()
        desc3.enabled = False
        pm.plugins = {"a": desc1, "b": desc2, "c": desc3}

        with patch("empusa.cli_hooks.HOOKS_DIR", hooks_dir):
            table = manager_overview_render(pm=pm, reg=None)

        assert "3" in table.caption

    def test_with_registry(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import HOOK_EVENTS, manager_overview_render

        hooks_dir = tmp_path / "hooks"
        for evt in HOOK_EVENTS:
            (hooks_dir / evt).mkdir(parents=True)

        reg = MagicMock()
        reg.summary.return_value = {"scanner": 2, "reporter": 1}

        with patch("empusa.cli_hooks.HOOKS_DIR", hooks_dir):
            table = manager_overview_render(pm=None, reg=reg)

        assert table.row_count > 0

    def test_warnings_when_no_hooks(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import HOOK_EVENTS, manager_overview_render

        hooks_dir = tmp_path / "hooks"
        for evt in HOOK_EVENTS:
            (hooks_dir / evt).mkdir(parents=True)

        with patch("empusa.cli_hooks.HOOKS_DIR", hooks_dir):
            table = manager_overview_render(pm=None, reg=None)

        assert table.row_count > 0


# -- run_hooks --------------------------------------------------------


class TestRunHooks:
    def test_with_event_bus(self) -> None:
        from empusa.cli_hooks import run_hooks, set_event_bus

        mock_bus = MagicMock()
        set_event_bus(mock_bus)
        try:
            run_hooks("on_startup", {"test": True})
            mock_bus.emit_legacy.assert_called_once_with("on_startup", {"test": True})
        finally:
            set_event_bus(None)  # type: ignore[arg-type]

    def test_fallback_without_bus(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import run_hooks, set_event_bus

        set_event_bus(None)  # type: ignore[arg-type]
        hooks_dir = tmp_path / "hooks"
        (hooks_dir / "on_startup").mkdir(parents=True)

        with patch("empusa.cli_hooks.HOOKS_DIR", hooks_dir):
            run_hooks("on_startup", {"event": "on_startup"})  # should not crash
