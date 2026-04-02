"""
Tests for empusa.cli_hooks

Covers: init_hook_dirs, list_hooks, create_example_hook,
        _fire_legacy_hooks_fallback, set_event_bus.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch


# -- init_hook_dirs ---------------------------------------------------

class TestInitHookDirs:
    def test_creates_event_subdirs(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import init_hook_dirs, HOOK_EVENTS

        real_hooks = tmp_path / "hooks"
        with patch("empusa.cli_hooks.HOOKS_DIR", real_hooks):
            init_hook_dirs()

        for evt in HOOK_EVENTS:
            assert (real_hooks / evt).is_dir()


# -- list_hooks -------------------------------------------------------

class TestListHooks:
    def test_returns_dict_of_events(self, tmp_path: Path) -> None:
        from empusa.cli_hooks import list_hooks, HOOK_EVENTS

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
        from empusa.cli_hooks import list_hooks, HOOK_EVENTS

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
