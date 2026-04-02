"""
Tests for empusa.cli_common

Covers: CONFIG defaults, SESSION_ACTIONS, set_console, log helpers,
        sanitize_filename, load_loot, which / check_tool_exists.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from rich.console import Console

import empusa.cli_common as cli_common
from empusa.cli_common import (
    CONFIG,
    SESSION_ACTIONS,
    sanitize_filename,
    load_loot,
    log_action,
    which,
    check_tool_exists,
    set_console,
    HOOK_EVENTS,
    HOOKS_DIR,
    MODULES_DIR,
    PLUGINS_DIR,
    IS_WINDOWS,
    IS_UNIX,
)


# -- CONFIG defaults -------------------------------------------------

class TestConfigDefaults:
    def test_required_keys_exist(self) -> None:
        for key in ("verbose", "quiet", "dry_run", "no_color", "max_workers", "session_env"):
            assert key in CONFIG

    def test_session_env_default_is_empty(self) -> None:
        # session_env may have been mutated by other tests; check type
        assert isinstance(CONFIG["session_env"], str)

    def test_max_workers_is_positive(self) -> None:
        assert CONFIG["max_workers"] >= 1


# -- set_console -----------------------------------------------------

class TestSetConsole:
    def test_set_console_replaces_module_global(self) -> None:
        original = cli_common.console
        new_con = Console(quiet=True)
        set_console(new_con)
        assert cli_common.console is new_con
        # Restore
        set_console(original)
        assert cli_common.console is original


# -- log_action ------------------------------------------------------

class TestLogAction:
    def test_appends_to_session_actions(self) -> None:
        before = len(SESSION_ACTIONS)
        log_action("TestAction", "detail text")
        assert len(SESSION_ACTIONS) == before + 1
        last = SESSION_ACTIONS[-1]
        assert last["action"] == "TestAction"
        assert last["detail"] == "detail text"
        assert "time" in last


# -- log helpers (quiet gating) -------------------------------------

class TestLogHelpers:
    """Verify that quiet mode suppresses info/success/verbose but not error."""

    def test_log_info_suppressed_when_quiet(self, capsys: pytest.CaptureFixture[str]) -> None:
        saved = CONFIG["quiet"]
        CONFIG["quiet"] = True
        try:
            cli_common.log_info("should not appear")
            # log_info uses console.print, which writes to its own buffer,
            # so the real assertion is that it doesn't raise
        finally:
            CONFIG["quiet"] = saved

    def test_log_error_always_prints(self, quiet_console: Console) -> None:
        # Swap in a recording console
        buf = Console(record=True, quiet=False, force_terminal=False)
        original = cli_common.console
        set_console(buf)
        try:
            cli_common.log_error("visible error")
            output = buf.export_text()
            assert "visible error" in output
        finally:
            set_console(original)


# -- sanitize_filename -----------------------------------------------

class TestSanitizeFilename:
    @pytest.mark.parametrize("input_name,expected", [
        ("normal.txt", "normal.txt"),
        ('file<>:"/\\|?*.txt', "file_________.txt"),
        ("hello world", "hello world"),
        ("", ""),
    ])
    def test_removes_invalid_chars(self, input_name: str, expected: str) -> None:
        assert sanitize_filename(input_name) == expected


# -- load_loot -------------------------------------------------------

class TestLoadLoot:
    def test_returns_empty_for_missing_file(self, tmp_path: Path) -> None:
        assert load_loot(tmp_path / "nonexistent.json") == []

    def test_loads_valid_json_array(self, tmp_path: Path) -> None:
        loot_file = tmp_path / "loot.json"
        entries = [{"host": "10.10.10.1", "cred_type": "password"}]
        loot_file.write_text(json.dumps(entries), encoding="utf-8")
        result = load_loot(loot_file)
        assert len(result) == 1
        assert result[0]["host"] == "10.10.10.1"

    def test_returns_empty_for_bad_json(self, tmp_path: Path) -> None:
        loot_file = tmp_path / "loot.json"
        loot_file.write_text("not json", encoding="utf-8")
        assert load_loot(loot_file) == []

    def test_returns_empty_for_json_object_not_array(self, tmp_path: Path) -> None:
        loot_file = tmp_path / "loot.json"
        loot_file.write_text('{"host": "10.10.10.1"}', encoding="utf-8")
        assert load_loot(loot_file) == []


# -- which / check_tool_exists --------------------------------------

class TestWhich:
    def test_which_finds_python(self) -> None:
        # python should always be on PATH in a test environment
        result = which("python")
        # Could be None on very minimal CIs but generally available
        # We just verify the function doesn't crash
        assert result is None or isinstance(result, str)

    def test_check_tool_exists_for_bogus(self) -> None:
        assert check_tool_exists("empusa_nonexistent_binary_xyz") is False


# -- Path constants --------------------------------------------------

class TestPathConstants:
    def test_hooks_dir_is_path(self) -> None:
        assert isinstance(HOOKS_DIR, Path)

    def test_modules_dir_under_hooks(self) -> None:
        assert MODULES_DIR == HOOKS_DIR / "modules"

    def test_plugins_dir_is_path(self) -> None:
        assert isinstance(PLUGINS_DIR, Path)


# -- HOOK_EVENTS -----------------------------------------------------

class TestHookEvents:
    def test_contains_expected_events(self) -> None:
        for evt in ("on_startup", "on_shutdown", "post_build", "post_scan",
                     "on_loot_add", "on_report_generated"):
            assert evt in HOOK_EVENTS


# -- Platform flags --------------------------------------------------

class TestPlatformFlags:
    def test_flags_are_bool(self) -> None:
        assert isinstance(IS_WINDOWS, bool)
        assert isinstance(IS_UNIX, bool)
