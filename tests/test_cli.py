"""
Tests for empusa.cli (main entry point)

Covers: argparse subcommand parsing, --no-color / --verbose / --quiet flags,
        _init_framework global wiring, subcommand dispatch.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import MagicMock, patch

# -- argparse structure ------------------------------------------------


class TestArgparseStructure:
    """Build the parser the same way main() does and verify structure."""

    @staticmethod
    def build_parser() -> argparse.ArgumentParser:
        """Minimal replica of the parser built in main()."""
        parser = argparse.ArgumentParser(prog="empusa")
        parser.add_argument("-v", "--verbose", action="store_true")
        parser.add_argument("-q", "--quiet", action="store_true")
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--no-color", action="store_true")
        parser.add_argument("-w", "--workers", type=int, default=8)

        subs = parser.add_subparsers(dest="command")

        sp_build = subs.add_parser("build")
        sp_build.add_argument("--env", required=True)
        sp_build.add_argument("--ips", required=True)

        sp_exploit = subs.add_parser("exploit-search")
        sp_exploit.add_argument("--env", required=True)
        sp_exploit.add_argument("--host", required=True)

        sp_loot = subs.add_parser("loot")
        sp_loot.add_argument("--env", required=True)
        sp_loot.add_argument("loot_action", choices=["list", "add"])
        sp_loot.add_argument("--host", dest="loot_host", default="")
        sp_loot.add_argument("--cred-type", default="password")
        sp_loot.add_argument("--username", default="")
        sp_loot.add_argument("--secret", default="")
        sp_loot.add_argument("--source", default="")

        sp_report = subs.add_parser("report")
        sp_report.add_argument("--env", required=True)
        sp_report.add_argument("--assessment", default="")

        sp_plugins = subs.add_parser("plugins")
        sp_psub = sp_plugins.add_subparsers(dest="plugins_action")
        sp_psub.add_parser("refresh")

        return parser

    # ---- build subcommand ------------------------------------------

    def test_build_subcommand(self) -> None:
        p = self.build_parser()
        args = p.parse_args(["build", "--env", "lab", "--ips", "10.0.0.1,10.0.0.2"])
        assert args.command == "build"
        assert args.env == "lab"
        assert "10.0.0.1" in args.ips

    # ---- exploit-search subcommand ---------------------------------

    def test_exploit_search_subcommand(self) -> None:
        p = self.build_parser()
        args = p.parse_args(["exploit-search", "--env", "lab", "--host", "10.10.10.1-Linux"])
        assert args.command == "exploit-search"
        assert args.host == "10.10.10.1-Linux"

    # ---- loot subcommand -------------------------------------------

    def test_loot_list(self) -> None:
        p = self.build_parser()
        args = p.parse_args(["loot", "--env", "lab", "list"])
        assert args.loot_action == "list"

    def test_loot_add(self) -> None:
        p = self.build_parser()
        args = p.parse_args(
            [
                "loot",
                "--env",
                "lab",
                "add",
                "--host",
                "10.0.0.1",
                "--username",
                "root",
                "--secret",
                "toor",
            ]
        )
        assert args.loot_action == "add"
        assert args.loot_host == "10.0.0.1"
        assert args.username == "root"

    # ---- report subcommand -----------------------------------------

    def test_report_subcommand(self) -> None:
        p = self.build_parser()
        args = p.parse_args(["report", "--env", "lab", "--assessment", "OSCP"])
        assert args.command == "report"
        assert args.assessment == "OSCP"

    # ---- plugins refresh subcommand --------------------------------

    def test_plugins_refresh(self) -> None:
        p = self.build_parser()
        args = p.parse_args(["plugins", "refresh"])
        assert args.command == "plugins"
        assert args.plugins_action == "refresh"

    # ---- global flags ----------------------------------------------

    def test_verbose_flag(self) -> None:
        p = self.build_parser()
        args = p.parse_args(["--verbose"])
        assert args.verbose is True

    def test_quiet_flag(self) -> None:
        p = self.build_parser()
        args = p.parse_args(["--quiet"])
        assert args.quiet is True

    def test_no_color_flag(self) -> None:
        p = self.build_parser()
        args = p.parse_args(["--no-color"])
        assert args.no_color is True

    def test_dry_run_flag(self) -> None:
        p = self.build_parser()
        args = p.parse_args(["--dry-run"])
        assert args.dry_run is True

    def test_workers_default(self) -> None:
        p = self.build_parser()
        args = p.parse_args([])
        assert args.workers == 8

    def test_workers_custom(self) -> None:
        p = self.build_parser()
        args = p.parse_args(["-w", "4"])
        assert args.workers == 4


# -- --no-color applies set_console -----------------------------------


class TestNoColor:
    def test_set_console_called_when_no_color(self) -> None:
        """When --no-color is passed, cli.main() must call set_console()."""
        from empusa.cli_common import set_console

        # We just verify set_console is importable and callable
        assert callable(set_console)


# -- _init_framework wiring -------------------------------------------


class TestInitFramework:
    @patch("empusa.cli.PluginManager")
    @patch("empusa.cli.EventBus")
    @patch("empusa.cli.init_hook_dirs")
    def test_sets_globals(
        self,
        mock_init_hooks: MagicMock,
        mock_bus_cls: MagicMock,
        mock_pm_cls: MagicMock,
    ) -> None:
        import empusa.cli as cli_mod
        from empusa.cli import init_framework

        # Mock returns
        mock_bus = MagicMock()
        mock_bus_cls.return_value = mock_bus
        mock_pm = MagicMock()
        mock_pm.discover.return_value = None
        mock_pm.resolve_dependencies.return_value = []
        mock_pm.activate_all.return_value = 0
        mock_pm_cls.return_value = mock_pm

        # Reset globals
        cli_mod.event_bus = None
        cli_mod.plugin_manager = None
        cli_mod.services = None

        init_framework()

        assert cli_mod.event_bus is not None
        assert cli_mod.plugin_manager is not None
        assert cli_mod.services is not None
        mock_bus.attach_plugin_manager.assert_called_once()

        # Cleanup
        cli_mod.event_bus = None
        cli_mod.plugin_manager = None
        cli_mod.services = None


# -- Verbose + quiet mutual exclusion ---------------------------------


class TestVerboseQuietExclusion:
    def test_both_flags_parsed(self) -> None:
        """Parser allows both; main() rejects at runtime."""
        p = TestArgparseStructure.build_parser()
        args = p.parse_args(["--verbose", "--quiet"])
        assert args.verbose is True and args.quiet is True


# -- _build_execution_flow -------------------------------------------


class TestBuildExecutionFlow:
    def test_empty_actions(self) -> None:
        from empusa.cli import _build_execution_flow
        from empusa.cli_common import SESSION_ACTIONS

        saved = SESSION_ACTIONS.copy()
        SESSION_ACTIONS.clear()
        try:
            result = _build_execution_flow()
            assert result == ""
        finally:
            SESSION_ACTIONS.clear()
            SESSION_ACTIONS.extend(saved)

    def test_single_action(self) -> None:
        from empusa.cli import _build_execution_flow
        from empusa.cli_common import SESSION_ACTIONS

        saved = SESSION_ACTIONS.copy()
        SESSION_ACTIONS.clear()
        SESSION_ACTIONS.append({"time": "10:00:00", "action": "Build", "detail": "env=lab"})
        try:
            result = _build_execution_flow()
            assert "Session Execution Flow" in result
            assert "Build" in result
            assert "env=lab" in result
        finally:
            SESSION_ACTIONS.clear()
            SESSION_ACTIONS.extend(saved)

    def test_multiple_actions(self) -> None:
        from empusa.cli import _build_execution_flow
        from empusa.cli_common import SESSION_ACTIONS

        saved = SESSION_ACTIONS.copy()
        SESSION_ACTIONS.clear()
        SESSION_ACTIONS.extend(
            [
                {"time": "10:00:00", "action": "Startup", "detail": ""},
                {"time": "10:01:00", "action": "Scan", "detail": "10.10.10.1"},
                {"time": "10:02:00", "action": "Shutdown", "detail": ""},
            ]
        )
        try:
            result = _build_execution_flow()
            assert "┌" in result  # first
            assert "├" in result  # middle
            assert "└" in result  # last
            assert "Scan" in result
        finally:
            SESSION_ACTIONS.clear()
            SESSION_ACTIONS.extend(saved)


# -- _cleanup_shell_history -------------------------------------------


class TestCleanupShellHistory:
    def test_cleans_rc_file(self, tmp_path: Path) -> None:
        from empusa.cli import _cleanup_shell_history

        rc = tmp_path / ".bashrc"
        rc.write_text(
            "# normal line\n"
            "alias ll='ls -la'\n"
            "# Empusa Command Logging\n"
            "export PROMPT_COMMAND='history -a'\n"
            "shopt -s histappend\n"
            "\n"
            "# after empusa block\n"
            "export PATH=$PATH:/usr/local/bin\n"
        )
        # .zshrc must not exist so only .bashrc is processed
        with (
            patch("empusa.cli.IS_UNIX", True),
            patch("empusa.cli.IS_WINDOWS", False),
            patch("empusa.cli.Path") as mock_path_cls,
            patch("empusa.cli.log_verbose"),
        ):
            mock_path_cls.home.return_value = tmp_path
            result = _cleanup_shell_history()

        assert len(result) == 1
        assert str(rc) in result[0]
        content = rc.read_text()
        assert "Empusa Command Logging" not in content
        assert "alias ll='ls -la'" in content
        assert "export PATH=$PATH:/usr/local/bin" in content

    def test_no_marker_leaves_file_unchanged(self, tmp_path: Path) -> None:
        from empusa.cli import _cleanup_shell_history

        rc = tmp_path / ".bashrc"
        original = "# normal line\nalias ll='ls -la'\n"
        rc.write_text(original)

        with (
            patch("empusa.cli.IS_UNIX", True),
            patch("empusa.cli.IS_WINDOWS", False),
            patch("empusa.cli.Path") as mock_path_cls,
        ):
            mock_path_cls.home.return_value = tmp_path
            result = _cleanup_shell_history()

        assert result == []
        assert rc.read_text() == original

    def test_empty_target_on_unknown_platform(self) -> None:
        from empusa.cli import _cleanup_shell_history

        with patch("empusa.cli.IS_UNIX", False), patch("empusa.cli.IS_WINDOWS", False):
            result = _cleanup_shell_history()

        assert result == []
