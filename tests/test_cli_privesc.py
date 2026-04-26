"""
Tests for empusa.cli_privesc

Covers: WINDOWS_ENUM_COMMANDS, LINUX_ENUM_COMMANDS data structures.
"""

from __future__ import annotations

from empusa.cli_privesc import LINUX_ENUM_COMMANDS, WINDOWS_ENUM_COMMANDS


class TestWindowsEnumCommands:
    def test_minimum_entries(self) -> None:
        assert len(WINDOWS_ENUM_COMMANDS) >= 10

    def test_tuple_structure(self) -> None:
        for entry in WINDOWS_ENUM_COMMANDS:
            assert len(entry) == 2
            label, command = entry
            assert isinstance(label, str) and label
            assert isinstance(command, str) and command

    def test_contains_core_checks(self) -> None:
        labels = [e[0] for e in WINDOWS_ENUM_COMMANDS]
        assert "Identity" in labels
        assert "Privileges" in labels
        assert "System Info" in labels


class TestLinuxEnumCommands:
    def test_minimum_entries(self) -> None:
        assert len(LINUX_ENUM_COMMANDS) >= 10

    def test_tuple_structure(self) -> None:
        for entry in LINUX_ENUM_COMMANDS:
            assert len(entry) == 2
            label, command = entry
            assert isinstance(label, str) and label
            assert isinstance(command, str) and command

    def test_contains_core_checks(self) -> None:
        labels = [e[0] for e in LINUX_ENUM_COMMANDS]
        assert "Identity" in labels
        assert "SUID Binaries" in labels
        assert "Kernel" in labels


# -- Interactive generator dispatch -----------------------------------


from pathlib import Path  # noqa: E402
from unittest.mock import patch  # noqa: E402

import pytest  # noqa: E402


def _ans(values: list[str]):
    it = iter(values)
    return lambda *a, **k: next(it)


class TestPrivescGenerator:
    def test_back_choice_returns_early(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from empusa import cli_privesc

        monkeypatch.chdir(tmp_path)
        with patch("empusa.cli_privesc.Prompt.ask", side_effect=_ans(["0"])):
            cli_privesc.privesc_enum_generator()
        assert list(tmp_path.iterdir()) == []

    def test_windows_print_only_no_file(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from empusa import cli_privesc

        monkeypatch.chdir(tmp_path)
        # OS=1 (Windows), fmt=1 (print only)
        with patch("empusa.cli_privesc.Prompt.ask", side_effect=_ans(["1", "1"])):
            cli_privesc.privesc_enum_generator()
        assert not any(p.suffix == ".sh" for p in tmp_path.iterdir())

    def test_linux_save_writes_file(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from empusa import cli_privesc
        from empusa.cli_common import CONFIG

        prev = CONFIG.get("session_env", "")
        CONFIG["session_env"] = str(tmp_path)
        try:
            with patch(
                "empusa.cli_privesc.Prompt.ask",
                side_effect=_ans(["2", "2", "linux_pe.sh"]),
            ):
                cli_privesc.privesc_enum_generator()
        finally:
            CONFIG["session_env"] = prev

        out = tmp_path / "linux_pe.sh"
        assert out.exists()
        text = out.read_text()
        assert "Linux Privilege Escalation Enumeration" in text
        assert "linPEAS" in text
        assert "sudo -l" in text

    def test_windows_save_both(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from empusa import cli_privesc
        from empusa.cli_common import CONFIG

        prev = CONFIG.get("session_env", "")
        CONFIG["session_env"] = str(tmp_path)
        try:
            with patch(
                "empusa.cli_privesc.Prompt.ask",
                side_effect=_ans(["1", "3", "win_pe.sh"]),
            ):
                cli_privesc.privesc_enum_generator()
        finally:
            CONFIG["session_env"] = prev

        out = tmp_path / "win_pe.sh"
        assert out.exists()
        text = out.read_text()
        assert "Windows Privilege Escalation Enumeration" in text
        assert "winPEAS" in text
