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
