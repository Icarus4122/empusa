"""
Tests for empusa.services

Covers: LoggerService, ArtifactWriter boundary enforcement,
        LootAccessor CRUD, EnvResolver, CommandRunner dry-run,
        Services container wiring.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from empusa.services import (
    ArtifactWriter,
    CommandRunner,
    EnvResolver,
    LoggerService,
    LootAccessor,
)

# -- LoggerService ---------------------------------------------------


class TestLoggerService:
    def test_info_does_not_raise(self, quiet_console: Console) -> None:
        logger = LoggerService(quiet_console, verbose=False, quiet=True)
        logger.info("test message")

    def test_error_does_not_raise(self, quiet_console: Console) -> None:
        logger = LoggerService(quiet_console, verbose=False, quiet=True)
        logger.error("error message")

    def test_verbose_suppressed_when_not_verbose(self, quiet_console: Console) -> None:
        logger = LoggerService(quiet_console, verbose=False, quiet=False)
        # Should not raise
        logger.verbose("suppressed")

    def test_verbose_prints_when_verbose(self) -> None:
        con = Console(record=True, force_terminal=False)
        logger = LoggerService(con, verbose=True, quiet=False)
        logger.verbose("verbose msg")
        assert "verbose msg" in con.export_text()

    def test_warn_and_success(self, quiet_console: Console) -> None:
        logger = LoggerService(quiet_console, verbose=False, quiet=False)
        logger.warn("warning")
        logger.success("ok")


# -- EnvResolver -----------------------------------------------------


class TestEnvResolver:
    def test_env_name_from_config(self) -> None:
        config: dict[str, Any] = {"session_env": "my_env"}
        resolver = EnvResolver(config)
        assert resolver.env_name() == "my_env"

    def test_env_path_when_set(self, tmp_path: Path) -> None:
        config: dict[str, Any] = {"session_env": str(tmp_path)}
        resolver = EnvResolver(config)
        assert resolver.env_path() == tmp_path

    def test_env_path_none_when_empty(self) -> None:
        config: dict[str, Any] = {"session_env": ""}
        resolver = EnvResolver(config)
        assert resolver.env_path() is None

    def test_is_active(self) -> None:
        assert EnvResolver({"session_env": "x"}).is_active() is True
        assert EnvResolver({"session_env": ""}).is_active() is False

    def test_hosts_lists_dash_dirs(self, tmp_path: Path) -> None:
        (tmp_path / "10.10.10.1-Linux").mkdir()
        (tmp_path / "notes.txt").touch()
        config: dict[str, Any] = {"session_env": str(tmp_path)}
        resolver = EnvResolver(config)
        hosts = resolver.hosts()
        assert "10.10.10.1-Linux" in hosts
        assert "notes.txt" not in hosts


# -- ArtifactWriter --------------------------------------------------


class TestArtifactWriter:
    def test_write_creates_file(self, tmp_path: Path) -> None:
        config: dict[str, Any] = {"session_env": str(tmp_path)}
        resolver = EnvResolver(config)
        writer = ArtifactWriter(resolver)
        p = writer.write("output/test.txt", "hello world")
        assert p.exists()
        assert p.read_text() == "hello world"

    def test_write_bytes_creates_file(self, tmp_path: Path) -> None:
        config: dict[str, Any] = {"session_env": str(tmp_path)}
        resolver = EnvResolver(config)
        writer = ArtifactWriter(resolver)
        p = writer.write_bytes("binary.dat", b"\x00\x01\x02")
        assert p.exists()
        assert p.read_bytes() == b"\x00\x01\x02"

    def test_path_traversal_blocked(self, tmp_path: Path) -> None:
        config: dict[str, Any] = {"session_env": str(tmp_path)}
        resolver = EnvResolver(config)
        writer = ArtifactWriter(resolver)
        with pytest.raises(ValueError, match="escape"):
            writer.write("../../etc/passwd", "hacked")

    def test_exists_false_for_traversal(self, tmp_path: Path) -> None:
        config: dict[str, Any] = {"session_env": str(tmp_path)}
        resolver = EnvResolver(config)
        writer = ArtifactWriter(resolver)
        assert writer.exists("../../etc/passwd") is False

    def test_write_raises_without_env(self) -> None:
        config: dict[str, Any] = {"session_env": ""}
        resolver = EnvResolver(config)
        writer = ArtifactWriter(resolver)
        with pytest.raises(RuntimeError, match="No active environment"):
            writer.write("test.txt", "data")


# -- LootAccessor ---------------------------------------------------


class TestLootAccessor:
    def test_read_all_empty(self, tmp_path: Path) -> None:
        config: dict[str, Any] = {"session_env": str(tmp_path)}
        loot = LootAccessor(EnvResolver(config))
        assert loot.read_all() == []

    def test_append_and_read(self, tmp_path: Path) -> None:
        config: dict[str, Any] = {"session_env": str(tmp_path)}
        loot = LootAccessor(EnvResolver(config))
        loot.append({"host": "10.10.10.1", "cred_type": "password", "username": "admin"})
        entries = loot.read_all()
        assert len(entries) == 1
        assert entries[0]["host"] == "10.10.10.1"
        assert "added_at" in entries[0]

    def test_count(self, tmp_path: Path) -> None:
        config: dict[str, Any] = {"session_env": str(tmp_path)}
        loot = LootAccessor(EnvResolver(config))
        assert loot.count() == 0
        loot.append({"host": "a"})
        assert loot.count() == 1

    def test_search(self, tmp_path: Path) -> None:
        config: dict[str, Any] = {"session_env": str(tmp_path)}
        loot = LootAccessor(EnvResolver(config))
        loot.append({"host": "10.10.10.1", "cred_type": "password"})
        loot.append({"host": "10.10.10.2", "cred_type": "hash"})
        results = loot.search("cred_type", "password")
        assert len(results) == 1
        assert results[0]["host"] == "10.10.10.1"

    def test_append_raises_without_env(self) -> None:
        config: dict[str, Any] = {"session_env": ""}
        loot = LootAccessor(EnvResolver(config))
        with pytest.raises(RuntimeError, match="No active environment"):
            loot.append({"host": "x"})


# -- CommandRunner ---------------------------------------------------


class TestCommandRunner:
    def test_dry_run_returns_zero(self, quiet_console: Console) -> None:
        logger = LoggerService(quiet_console, verbose=False, quiet=True)
        runner = CommandRunner(logger, dry_run=True)
        result = runner.run(["echo", "hello"])
        assert result.returncode == 0
        assert result.stdout == ""

    def test_dry_run_does_not_execute(self, quiet_console: Console) -> None:
        logger = LoggerService(quiet_console, verbose=False, quiet=True)
        runner = CommandRunner(logger, dry_run=True)
        result = runner.run(["rm", "-rf", "/"])
        assert result.returncode == 0  # No actual execution

    def test_emit_fn_called(self, quiet_console: Console) -> None:
        calls: list[tuple[str, dict[str, Any]]] = []

        def fake_emit(evt: str, ctx: dict[str, Any]) -> None:
            calls.append((evt, ctx))

        logger = LoggerService(quiet_console, verbose=False, quiet=True)
        runner = CommandRunner(logger, dry_run=True, emit_fn=fake_emit)
        runner.run(["echo", "test"])
        event_names: list[str] = [c[0] for c in calls]
        # In dry-run mode, only pre_command fires (returns before post)
        assert "pre_command" in event_names

    def test_command_not_found_handled(self, quiet_console: Console) -> None:
        logger = LoggerService(quiet_console, verbose=False, quiet=True)
        runner = CommandRunner(logger, dry_run=False)
        result = runner.run(["empusa_nonexistent_binary_xyz_99"])
        assert result.returncode == 127


# -- Services container ----------------------------------------------


class TestServicesContainer:
    def test_wires_all_services(self, make_services: Any) -> None:
        svc = make_services()
        assert svc.logger is not None
        assert svc.artifact is not None
        assert svc.loot is not None
        assert svc.env is not None
        assert svc.runner is not None
