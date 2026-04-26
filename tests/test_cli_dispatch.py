"""
Direct dispatch tests for empusa.cli command handlers.

Covers the non-interactive entry points exposed by ``empusa.cli`` —
``_cmd_build``, ``_cmd_loot``, ``_cmd_report``, ``_cmd_workspace`` and
``_shutdown`` — using mocks/stubs so no real subprocesses or network
activity occurs and no prompts are shown.

Notes:
    * Each test that touches ``_shutdown`` resets the
      ``_shutdown._done`` idempotency guard to allow re-entry.
    * ``_init_framework`` is patched out so tests do not load real
      plugins or bind global services.
"""

from __future__ import annotations

import argparse
import contextlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def _reset_shutdown() -> None:
    """Allow ``_shutdown`` to run again in the next test."""
    from empusa import cli as cli_mod

    if hasattr(cli_mod._shutdown, "_done"):
        cli_mod._shutdown._done = False  # type: ignore[attr-defined]


# -- _cmd_build dispatch ----------------------------------------------


class TestCmdBuildDispatch:
    def _args(self, **overrides: object) -> argparse.Namespace:
        ns = argparse.Namespace(
            env="lab",
            ips="10.0.0.1,10.0.0.2",
            shell_history=None,
            force_overwrite=False,
        )
        for k, v in overrides.items():
            setattr(ns, k, v)
        return ns

    def _run(self, ns: argparse.Namespace):
        _reset_shutdown()
        with (
            patch("empusa.cli._init_framework"),
            patch("empusa.cli._run_hooks"),
            patch("empusa.cli._shutdown"),
            patch("empusa.cli.build_env") as mock_build,
        ):
            from empusa.cli import _cmd_build

            rc = _cmd_build(ns)
        return rc, mock_build

    def test_calls_build_env_non_interactive(self) -> None:
        rc, mock_build = self._run(self._args())
        assert rc == 0
        mock_build.assert_called_once()
        kwargs = mock_build.call_args.kwargs
        assert kwargs["interactive"] is False
        assert kwargs["shell_history"] is None
        assert kwargs["overwrite_existing"] is None  # force_overwrite=False -> None

    def test_force_overwrite_passes_true(self) -> None:
        _, mock_build = self._run(self._args(force_overwrite=True))
        assert mock_build.call_args.kwargs["overwrite_existing"] is True

    def test_shell_history_explicit_false(self) -> None:
        _, mock_build = self._run(self._args(shell_history=False))
        assert mock_build.call_args.kwargs["shell_history"] is False

    def test_empty_ips_returns_one(self) -> None:
        _reset_shutdown()
        with (
            patch("empusa.cli._init_framework"),
            patch("empusa.cli.build_env") as mock_build,
        ):
            from empusa.cli import _cmd_build

            rc = _cmd_build(self._args(ips=" , , "))
        assert rc == 1
        mock_build.assert_not_called()


# -- _cmd_loot dispatch -----------------------------------------------


class TestCmdLootDispatch:
    def test_unknown_action_returns_one(self) -> None:
        _reset_shutdown()
        ns = argparse.Namespace(env="lab", loot_action="bogus")
        with patch("empusa.cli._init_framework"), patch("empusa.cli._shutdown"), patch("empusa.cli._run_hooks"):
            from empusa.cli import _cmd_loot

            assert _cmd_loot(ns) == 1

    def test_list_action_with_no_loot_file(self, tmp_path: Path) -> None:
        _reset_shutdown()
        ns = argparse.Namespace(env=str(tmp_path), loot_action="list")
        with patch("empusa.cli._init_framework"), patch("empusa.cli._shutdown"), patch("empusa.cli._run_hooks"):
            from empusa.cli import _cmd_loot

            assert _cmd_loot(ns) == 0

    def test_add_action_appends_to_services_loot(self, tmp_path: Path) -> None:
        _reset_shutdown()
        ns = argparse.Namespace(
            env=str(tmp_path),
            loot_action="add",
            loot_host="10.0.0.5",
            cred_type="password",
            username="root",
            secret="toor",
            source="manual",
        )
        fake_services = MagicMock()
        with (
            patch("empusa.cli._init_framework"),
            patch("empusa.cli._shutdown"),
            patch("empusa.cli._run_hooks"),
            patch("empusa.cli.services", fake_services),
        ):
            from empusa.cli import _cmd_loot

            rc = _cmd_loot(ns)
        assert rc == 0
        fake_services.loot.append.assert_called_once()
        entry = fake_services.loot.append.call_args.args[0]
        assert entry["host"] == "10.0.0.5"
        assert entry["secret"] == "toor"


# -- _cmd_report dispatch ---------------------------------------------


class TestCmdReportDispatch:
    def test_missing_env_returns_one(self, tmp_path: Path) -> None:
        _reset_shutdown()
        ns = argparse.Namespace(env=str(tmp_path / "nope"), assessment="")
        with patch("empusa.cli._init_framework"), patch("empusa.cli._shutdown"), patch("empusa.cli._run_hooks"):
            from empusa.cli import _cmd_report

            assert _cmd_report(ns) == 1

    def test_writes_report_under_env_dir(self, tmp_path: Path) -> None:
        _reset_shutdown()
        ns = argparse.Namespace(env=str(tmp_path), assessment="OSCP Test")
        with patch("empusa.cli._init_framework"), patch("empusa.cli._shutdown"), patch("empusa.cli._run_hooks"):
            from empusa.cli import _cmd_report

            rc = _cmd_report(ns)
        assert rc == 0
        report = tmp_path / "OSCP_Test_report.md"
        assert report.exists()
        text = report.read_text(encoding="utf-8")
        assert "OSCP Test - Penetration Test Report" in text


# -- _cmd_workspace dispatch ------------------------------------------


class TestCmdWorkspaceDispatch:
    def _ns(self, action: str | None) -> argparse.Namespace:
        return argparse.Namespace(ws_action=action)

    def test_init_dispatches(self) -> None:
        _reset_shutdown()
        parser = MagicMock()
        with (
            patch("empusa.cli._init_framework"),
            patch("empusa.cli._shutdown"),
            patch("empusa.cli.cmd_workspace_init", return_value=0) as mock_init,
        ):
            from empusa.cli import _cmd_workspace

            assert _cmd_workspace(self._ns("init"), parser) == 0
            mock_init.assert_called_once()

    def test_list_dispatches(self) -> None:
        _reset_shutdown()
        parser = MagicMock()
        with (
            patch("empusa.cli._init_framework"),
            patch("empusa.cli._shutdown"),
            patch("empusa.cli.cmd_workspace_list", return_value=0) as mock_list,
        ):
            from empusa.cli import _cmd_workspace

            assert _cmd_workspace(self._ns("list"), parser) == 0
            mock_list.assert_called_once()

    def test_select_dispatches(self) -> None:
        _reset_shutdown()
        parser = MagicMock()
        with (
            patch("empusa.cli._init_framework"),
            patch("empusa.cli._shutdown"),
            patch("empusa.cli.cmd_workspace_select", return_value=0) as mock_select,
        ):
            from empusa.cli import _cmd_workspace

            assert _cmd_workspace(self._ns("select"), parser) == 0
            mock_select.assert_called_once()

    def test_status_dispatches(self) -> None:
        _reset_shutdown()
        parser = MagicMock()
        with (
            patch("empusa.cli._init_framework"),
            patch("empusa.cli._shutdown"),
            patch("empusa.cli.cmd_workspace_status", return_value=0) as mock_status,
        ):
            from empusa.cli import _cmd_workspace

            assert _cmd_workspace(self._ns("status"), parser) == 0
            mock_status.assert_called_once()

    def test_no_action_calls_help(self) -> None:
        _reset_shutdown()
        parser = MagicMock()
        # parser.parse_args(["workspace","--help"]) typically SystemExits via argparse;
        # MagicMock just records the call and returns.
        with patch("empusa.cli._init_framework"):
            from empusa.cli import _cmd_workspace

            rc = _cmd_workspace(self._ns(None), parser)
        assert rc == 1
        parser.parse_args.assert_called_with(["workspace", "--help"])


# -- _shutdown -------------------------------------------------------


class TestShutdown:
    def test_idempotent_second_call_is_noop(self) -> None:
        from empusa import cli as cli_mod

        _reset_shutdown()
        with (
            patch("empusa.cli._kill_child_processes", return_value=[]) as mock_kill,
            patch("empusa.cli._cleanup_shell_history", return_value=[]),
            patch("empusa.cli._run_hooks"),
            patch("empusa.cli.plugin_manager", None),
        ):
            cli_mod._shutdown()
            cli_mod._shutdown()  # second call should early-return
        # _kill_child_processes only called once because of the _done guard
        assert mock_kill.call_count == 1

    def test_skips_shell_history_when_hooks_disabled(self) -> None:
        from empusa import cli as cli_mod

        _reset_shutdown()
        prev = cli_mod.CONFIG.get("enable_shell_hooks", False)
        cli_mod.CONFIG["enable_shell_hooks"] = False
        try:
            with (
                patch("empusa.cli._kill_child_processes", return_value=[]),
                patch("empusa.cli._cleanup_shell_history") as mock_clean,
                patch("empusa.cli._run_hooks"),
                patch("empusa.cli.plugin_manager", None),
            ):
                cli_mod._shutdown()
            mock_clean.assert_not_called()
        finally:
            cli_mod.CONFIG["enable_shell_hooks"] = prev

    def test_runs_shell_cleanup_when_hooks_enabled(self) -> None:
        from empusa import cli as cli_mod

        _reset_shutdown()
        prev = cli_mod.CONFIG.get("enable_shell_hooks", False)
        cli_mod.CONFIG["enable_shell_hooks"] = True
        try:
            with (
                patch("empusa.cli._kill_child_processes", return_value=[]),
                patch("empusa.cli._cleanup_shell_history", return_value=[]) as mock_clean,
                patch("empusa.cli._run_hooks"),
                patch("empusa.cli.plugin_manager", None),
            ):
                cli_mod._shutdown()
            mock_clean.assert_called_once()
        finally:
            cli_mod.CONFIG["enable_shell_hooks"] = prev

    def test_quiet_skips_panel_render(self) -> None:
        from empusa import cli as cli_mod

        _reset_shutdown()
        prev_quiet = cli_mod.CONFIG.get("quiet", False)
        cli_mod.CONFIG["quiet"] = True
        try:
            with (
                patch("empusa.cli._kill_child_processes", return_value=["nmap (PID 1)"]),
                patch("empusa.cli._cleanup_shell_history", return_value=["/tmp/.bashrc"]),
                patch("empusa.cli._run_hooks"),
                patch("empusa.cli.plugin_manager", None),
                patch("empusa.cli.console") as mock_console,
            ):
                cli_mod._shutdown()
            # Quiet mode: no Panel print
            mock_console.print.assert_not_called()
        finally:
            cli_mod.CONFIG["quiet"] = prev_quiet

    def test_panel_render_with_kills_and_workspace(self) -> None:
        from empusa import cli as cli_mod

        _reset_shutdown()
        prev_quiet = cli_mod.CONFIG.get("quiet", False)
        prev_ws = cli_mod.CONFIG.get("workspace_name", "")
        prev_ws_p = cli_mod.CONFIG.get("workspace_profile", "")
        cli_mod.CONFIG["quiet"] = False
        cli_mod.CONFIG["workspace_name"] = "lab1"
        cli_mod.CONFIG["workspace_profile"] = "default"
        try:
            with (
                patch("empusa.cli._kill_child_processes", return_value=["nmap (PID 1)"]),
                patch("empusa.cli._cleanup_shell_history", return_value=["/tmp/.bashrc"]),
                patch("empusa.cli._run_hooks"),
                patch("empusa.cli.plugin_manager", None),
                patch("empusa.cli.console") as mock_console,
            ):
                cli_mod._shutdown()
            assert mock_console.print.called
        finally:
            cli_mod.CONFIG["quiet"] = prev_quiet
            cli_mod.CONFIG["workspace_name"] = prev_ws
            cli_mod.CONFIG["workspace_profile"] = prev_ws_p

    def test_panel_render_session_env_only(self) -> None:
        from empusa import cli as cli_mod

        _reset_shutdown()
        prev_quiet = cli_mod.CONFIG.get("quiet", False)
        prev_env = cli_mod.CONFIG.get("session_env", "")
        prev_ws = cli_mod.CONFIG.get("workspace_name", "")
        cli_mod.CONFIG["quiet"] = False
        cli_mod.CONFIG["workspace_name"] = ""
        cli_mod.CONFIG["session_env"] = "envX"
        try:
            with (
                patch("empusa.cli._kill_child_processes", return_value=[]),
                patch("empusa.cli._cleanup_shell_history", return_value=[]),
                patch("empusa.cli._run_hooks"),
                patch("empusa.cli.plugin_manager", None),
                patch("empusa.cli.console") as mock_console,
            ):
                cli_mod._shutdown()
            assert mock_console.print.called
        finally:
            cli_mod.CONFIG["quiet"] = prev_quiet
            cli_mod.CONFIG["session_env"] = prev_env
            cli_mod.CONFIG["workspace_name"] = prev_ws

    def test_deactivates_plugins_when_present(self) -> None:
        from empusa import cli as cli_mod

        _reset_shutdown()
        fake_pm = MagicMock()
        fake_pm.deactivate_all.return_value = 2
        with (
            patch("empusa.cli._kill_child_processes", return_value=[]),
            patch("empusa.cli._cleanup_shell_history", return_value=[]),
            patch("empusa.cli._run_hooks"),
            patch("empusa.cli.plugin_manager", fake_pm),
        ):
            cli_mod._shutdown()
        fake_pm.deactivate_all.assert_called_once()


# -- _handle_sigint ---------------------------------------------------


class TestHandleSigint:
    def test_calls_shutdown_and_exits(self) -> None:
        import pytest

        from empusa.cli import _handle_sigint

        _reset_shutdown()
        with patch("empusa.cli._shutdown") as mock_shutdown, pytest.raises(SystemExit) as exc:
            _handle_sigint(2, None)
        assert exc.value.code == 0
        mock_shutdown.assert_called_once()


# -- _detect_environments / _show_environments -----------------------


class TestDetectEnvironments:
    def test_finds_env_with_nmap_subdir(self, tmp_path: Path, monkeypatch) -> None:
        from empusa.cli import _detect_environments

        env = tmp_path / "lab"
        host = env / "10.10.10.1-Linux"
        (host / "nmap").mkdir(parents=True)
        # An ordinary file at top level should be ignored
        (tmp_path / "ignore.txt").write_text("x")
        monkeypatch.chdir(tmp_path)
        envs = _detect_environments()
        assert "lab" in envs

    def test_handles_unreadable_dir(self, tmp_path: Path, monkeypatch) -> None:
        from empusa.cli import _detect_environments

        monkeypatch.chdir(tmp_path)
        # No envs — should return []
        assert _detect_environments() == []


class TestShowEnvironments:
    def test_empty_returns_silently(self) -> None:
        from empusa.cli import _show_environments

        with patch("empusa.cli.console") as mc:
            _show_environments([])
        mc.print.assert_not_called()

    def test_marker_for_active_env(self) -> None:
        from empusa import cli as cli_mod

        prev = cli_mod.CONFIG.get("session_env", "")
        prev_q = cli_mod.CONFIG.get("quiet", False)
        cli_mod.CONFIG["session_env"] = "alpha"
        cli_mod.CONFIG["quiet"] = False
        try:
            with patch("empusa.cli.console") as mc:
                cli_mod._show_environments(["alpha", "beta"])
            assert mc.print.called
        finally:
            cli_mod.CONFIG["session_env"] = prev
            cli_mod.CONFIG["quiet"] = prev_q


# -- summarize_command ------------------------------------------------


class TestSummarizeCommand:
    def test_runs_without_error(self) -> None:
        from empusa.cli import summarize_command

        summarize_command()


# -- _render_session_status ------------------------------------------


class TestRenderSessionStatus:
    def test_quiet_returns(self) -> None:
        from empusa import cli as cli_mod

        prev = cli_mod.CONFIG.get("quiet", False)
        cli_mod.CONFIG["quiet"] = True
        try:
            with patch("empusa.cli.console") as mc:
                cli_mod._render_session_status()
            mc.print.assert_not_called()
        finally:
            cli_mod.CONFIG["quiet"] = prev

    def test_workspace_branch(self) -> None:
        from empusa import cli as cli_mod

        prev = dict(cli_mod.CONFIG)
        cli_mod.CONFIG["quiet"] = False
        cli_mod.CONFIG["workspace_name"] = "ws"
        cli_mod.CONFIG["workspace_profile"] = "prof"
        try:
            with patch("empusa.cli.console") as mc:
                cli_mod._render_session_status()
            assert mc.print.called
        finally:
            cli_mod.CONFIG.clear()
            cli_mod.CONFIG.update(prev)

    def test_session_env_branch(self) -> None:
        from empusa import cli as cli_mod

        prev = dict(cli_mod.CONFIG)
        cli_mod.CONFIG["quiet"] = False
        cli_mod.CONFIG["workspace_name"] = ""
        cli_mod.CONFIG["session_env"] = "env1"
        try:
            with patch("empusa.cli.console") as mc:
                cli_mod._render_session_status()
            assert mc.print.called
        finally:
            cli_mod.CONFIG.clear()
            cli_mod.CONFIG.update(prev)

    def test_no_active(self) -> None:
        from empusa import cli as cli_mod

        prev = dict(cli_mod.CONFIG)
        cli_mod.CONFIG["quiet"] = False
        cli_mod.CONFIG["workspace_name"] = ""
        cli_mod.CONFIG["session_env"] = ""
        try:
            with patch("empusa.cli.console") as mc:
                cli_mod._render_session_status()
            assert mc.print.called
        finally:
            cli_mod.CONFIG.clear()
            cli_mod.CONFIG.update(prev)


# -- _ask_env / _select_environment ----------------------------------


class TestAskEnv:
    def test_prompt_returns_value(self) -> None:
        from empusa import cli as cli_mod

        prev = cli_mod.CONFIG.get("session_env", "")
        cli_mod.CONFIG["session_env"] = ""
        try:
            with patch("empusa.cli.Prompt") as mp:
                mp.ask.return_value = "newenv"
                got = cli_mod._ask_env("Pick")
            assert got == "newenv"
            assert cli_mod.CONFIG["session_env"] == "newenv"
        finally:
            cli_mod.CONFIG["session_env"] = prev

    def test_prompt_with_default(self) -> None:
        from empusa import cli as cli_mod

        prev = cli_mod.CONFIG.get("session_env", "")
        cli_mod.CONFIG["session_env"] = "existing"
        try:
            with patch("empusa.cli.Prompt") as mp:
                mp.ask.return_value = "existing"
                got = cli_mod._ask_env()
            assert got == "existing"
        finally:
            cli_mod.CONFIG["session_env"] = prev


class TestSelectEnvironment:
    def test_no_envs_logs_and_returns(self) -> None:
        from empusa.cli import _select_environment

        with patch("empusa.cli.Prompt") as mp:
            _select_environment([])
            mp.ask.assert_not_called()

    def test_pick_zero_clears_session(self) -> None:
        from empusa import cli as cli_mod

        prev = cli_mod.CONFIG.get("session_env", "")
        cli_mod.CONFIG["session_env"] = "previous"
        try:
            with patch("empusa.cli.Prompt") as mp:
                mp.ask.return_value = "0"
                cli_mod._select_environment(["a", "b"])
            assert cli_mod.CONFIG["session_env"] == ""
        finally:
            cli_mod.CONFIG["session_env"] = prev

    def test_pick_index_sets_env_and_fires_hook(self) -> None:
        from empusa import cli as cli_mod

        prev = cli_mod.CONFIG.get("session_env", "")
        cli_mod.CONFIG["session_env"] = ""
        try:
            with (
                patch("empusa.cli.Prompt") as mp,
                patch("empusa.cli._run_hooks") as mock_hooks,
            ):
                mp.ask.return_value = "2"
                cli_mod._select_environment(["a", "b"])
            assert cli_mod.CONFIG["session_env"] == "b"
            mock_hooks.assert_called_once()
            evt = mock_hooks.call_args.args[0]
            assert evt == "on_env_select"
        finally:
            cli_mod.CONFIG["session_env"] = prev


# -- print_banner -----------------------------------------------------


class TestPrintBanner:
    def test_quiet_returns(self) -> None:
        from empusa import cli as cli_mod

        prev = cli_mod.CONFIG.get("quiet", False)
        cli_mod.CONFIG["quiet"] = True
        try:
            with patch("empusa.cli.console") as mc:
                cli_mod.print_banner()
            mc.print.assert_not_called()
        finally:
            cli_mod.CONFIG["quiet"] = prev

    def test_prints_when_not_quiet(self) -> None:
        from empusa import cli as cli_mod

        prev = cli_mod.CONFIG.get("quiet", False)
        cli_mod.CONFIG["quiet"] = False
        try:
            with patch("empusa.cli.console") as mc:
                cli_mod.print_banner()
            assert mc.print.called
        finally:
            cli_mod.CONFIG["quiet"] = prev


# -- _kill_child_processes ------------------------------------------


class TestKillChildProcesses:
    def test_unix_kills_via_pgrep_pkill(self) -> None:
        from empusa.cli import _kill_child_processes

        with (
            patch("empusa.cli.IS_WINDOWS", False),
            patch("empusa.cli.subprocess.run") as mr,
        ):
            mr.side_effect = [
                MagicMock(stdout="1234 nmap -sV 10.0.0.1\n"),  # pgrep
                MagicMock(stdout=""),  # pkill
                MagicMock(stdout=""),  # pgrep searchsploit (none)
            ]
            killed = _kill_child_processes()
        assert any("nmap" in k for k in killed)

    def test_windows_kills_via_taskkill(self) -> None:
        from empusa.cli import _kill_child_processes

        with (
            patch("empusa.cli.IS_WINDOWS", True),
            patch("empusa.cli.subprocess.run") as mr,
        ):
            mr.side_effect = [
                MagicMock(stdout='"nmap.exe","4242","Console","1","2,000 K"'),  # tasklist
                MagicMock(stdout=""),  # taskkill
                MagicMock(stdout=""),  # tasklist searchsploit
            ]
            killed = _kill_child_processes()
        assert any("nmap.exe" in k for k in killed)

    def test_subprocess_exception_is_swallowed(self) -> None:
        from empusa.cli import _kill_child_processes

        with (
            patch("empusa.cli.IS_WINDOWS", False),
            patch("empusa.cli.subprocess.run", side_effect=RuntimeError("boom")),
        ):
            killed = _kill_child_processes()
        assert killed == []


# -- _cmd_exploit_search ---------------------------------------------


class TestCmdExploitSearch:
    def test_missing_nmap_returns_one(self, tmp_path: Path) -> None:
        from empusa.cli import _cmd_exploit_search

        _reset_shutdown()
        ns = argparse.Namespace(env=str(tmp_path / "noenv"), host="10.0.0.1-Linux")
        with patch("empusa.cli._init_framework"), patch("empusa.cli._shutdown"), patch("empusa.cli._run_hooks"):
            assert _cmd_exploit_search(ns) == 1

    def test_with_nmap_calls_search(self, tmp_path: Path, monkeypatch) -> None:
        from empusa.cli import _cmd_exploit_search

        _reset_shutdown()
        env = tmp_path / "lab"
        nmap_dir = env / "10.0.0.1-Linux" / "nmap"
        nmap_dir.mkdir(parents=True)
        (nmap_dir / "full_scan.txt").write_text("22/tcp open ssh\n")
        monkeypatch.chdir(tmp_path)

        ns = argparse.Namespace(env="lab", host="10.0.0.1-Linux")
        with (
            patch("empusa.cli._init_framework"),
            patch("empusa.cli._shutdown"),
            patch("empusa.cli._run_hooks"),
            patch("empusa.cli.search_exploits_from_nmap") as mock_search,
        ):
            assert _cmd_exploit_search(ns) == 0
        mock_search.assert_called_once()


# -- _cmd_plugins_refresh --------------------------------------------


class TestCmdPluginsRefresh:
    def test_refresh_calls_plugin_manager(self) -> None:
        from empusa import cli as cli_mod

        _reset_shutdown()
        fake_pm = MagicMock()
        fake_pm.refresh.return_value = ["dep missing: foo"]
        fake_pm.active_count.return_value = 3
        fake_pm.plugin_count.return_value = 5
        with (
            patch("empusa.cli._init_framework"),
            patch("empusa.cli._shutdown"),
            patch("empusa.cli.plugin_manager", fake_pm),
        ):
            ns = argparse.Namespace()
            assert cli_mod._cmd_plugins_refresh(ns) == 0
        fake_pm.refresh.assert_called_once()


# -- _cmd_workspace unknown action -----------------------------------


class TestCmdWorkspaceUnknown:
    def test_unknown_action_returns_one(self) -> None:
        from empusa.cli import _cmd_workspace

        _reset_shutdown()
        parser = MagicMock()
        with patch("empusa.cli._init_framework"), patch("empusa.cli._shutdown"):
            ns = argparse.Namespace(ws_action="bogus")
            rc = _cmd_workspace(ns, parser)
        assert rc == 1


# -- main() entry point with subcommand dispatch ---------------------


class TestMainEntry:
    @pytest.fixture(autouse=True)
    def _restore_config(self):
        import pytest as _pytest  # noqa: F401

        from empusa import cli as cli_mod

        snapshot = dict(cli_mod.CONFIG)
        yield
        cli_mod.CONFIG.clear()
        cli_mod.CONFIG.update(snapshot)

    def test_verbose_quiet_exclusion_exits(self) -> None:
        import pytest

        from empusa.cli import main

        _reset_shutdown()
        with patch("sys.argv", ["empusa", "-v", "-q"]), pytest.raises(SystemExit):
            main()

    def test_build_subcommand_routes_to_cmd_build(self) -> None:
        import pytest

        from empusa.cli import main

        _reset_shutdown()
        with (
            patch("sys.argv", ["empusa", "build", "--env", "lab", "--ips", "1.2.3.4"]),
            patch("empusa.cli._cmd_build", return_value=0) as mock_cmd,
            patch("empusa.cli.atexit.register"),
            patch("empusa.cli.signal.signal"),
            pytest.raises(SystemExit) as exc,
        ):
            main()
        assert exc.value.code == 0
        mock_cmd.assert_called_once()

    def test_loot_subcommand_routes(self) -> None:
        import pytest

        from empusa.cli import main

        _reset_shutdown()
        with (
            patch("sys.argv", ["empusa", "loot", "--env", "lab", "list"]),
            patch("empusa.cli._cmd_loot", return_value=0) as mock_cmd,
            patch("empusa.cli.atexit.register"),
            patch("empusa.cli.signal.signal"),
            pytest.raises(SystemExit),
        ):
            main()
        mock_cmd.assert_called_once()

    def test_report_subcommand_routes(self) -> None:
        import pytest

        from empusa.cli import main

        _reset_shutdown()
        with (
            patch("sys.argv", ["empusa", "report", "--env", "lab"]),
            patch("empusa.cli._cmd_report", return_value=0) as mock_cmd,
            patch("empusa.cli.atexit.register"),
            patch("empusa.cli.signal.signal"),
            pytest.raises(SystemExit),
        ):
            main()
        mock_cmd.assert_called_once()

    def test_exploit_search_subcommand_routes(self) -> None:
        import pytest

        from empusa.cli import main

        _reset_shutdown()
        with (
            patch("sys.argv", ["empusa", "exploit-search", "--env", "lab", "--host", "h-Linux"]),
            patch("empusa.cli._cmd_exploit_search", return_value=0) as mock_cmd,
            patch("empusa.cli.atexit.register"),
            patch("empusa.cli.signal.signal"),
            pytest.raises(SystemExit),
        ):
            main()
        mock_cmd.assert_called_once()

    def test_plugins_refresh_subcommand_routes(self) -> None:
        import pytest

        from empusa.cli import main

        _reset_shutdown()
        with (
            patch("sys.argv", ["empusa", "plugins", "refresh"]),
            patch("empusa.cli._cmd_plugins_refresh", return_value=0) as mock_cmd,
            patch("empusa.cli.atexit.register"),
            patch("empusa.cli.signal.signal"),
            pytest.raises(SystemExit),
        ):
            main()
        mock_cmd.assert_called_once()

    def test_no_color_sets_console(self) -> None:
        from empusa.cli import main

        _reset_shutdown()
        with (
            patch("sys.argv", ["empusa", "--no-color", "build", "--env", "x", "--ips", "1.1.1.1"]),
            patch("empusa.cli._cmd_build", return_value=0),
            patch("empusa.cli.set_console") as mock_set,
            patch("empusa.cli.atexit.register"),
            patch("empusa.cli.signal.signal"),
            contextlib.suppress(SystemExit),
        ):
            main()
        # set_console called at least once for no-color path
        assert mock_set.called

    def test_dry_run_logs_info(self) -> None:
        from empusa.cli import main

        _reset_shutdown()
        with (
            patch("sys.argv", ["empusa", "--dry-run", "build", "--env", "x", "--ips", "1.1.1.1"]),
            patch("empusa.cli._cmd_build", return_value=0),
            patch("empusa.cli.atexit.register"),
            patch("empusa.cli.signal.signal"),
            patch("empusa.cli.log_info") as mock_log,
            contextlib.suppress(SystemExit),
        ):
            main()
        # dry-run banner emitted
        called_msgs = [c.args[0] for c in mock_log.call_args_list if c.args]
        assert any("DRY RUN" in m for m in called_msgs)


# -- manage_hooks ----------------------------------------------------


class TestManageHooks:
    def test_back_immediately(self) -> None:
        from empusa.cli import manage_hooks

        with (
            patch("empusa.cli.Prompt") as mp,
            patch("empusa.cli.manager_overview_render"),
            patch("empusa.cli.console"),
            patch("empusa.cli.render_screen"),
            patch("empusa.cli.render_kv"),
        ):
            mp.ask.return_value = "0"
            manage_hooks()

    def test_view_hooks_then_back(self) -> None:
        from empusa.cli import manage_hooks

        with (
            patch("empusa.cli.Prompt") as mp,
            patch("empusa.cli.manager_overview_render"),
            patch("empusa.cli.list_hooks_render") as mock_list,
            patch("empusa.cli.console"),
            patch("empusa.cli.render_screen"),
            patch("empusa.cli.render_kv"),
        ):
            mp.ask.side_effect = ["1", "0"]
            manage_hooks()
        mock_list.assert_called()

    def test_create_hook_then_back(self) -> None:
        from empusa.cli import manage_hooks

        with (
            patch("empusa.cli.Prompt") as mp,
            patch("empusa.cli.manager_overview_render"),
            patch("empusa.cli.create_hook_ui") as mock_create,
            patch("empusa.cli.list_hooks_render"),
            patch("empusa.cli.console"),
            patch("empusa.cli.render_screen"),
            patch("empusa.cli.render_kv"),
        ):
            mp.ask.side_effect = ["2", "0"]
            manage_hooks()
        mock_create.assert_called_once()

    def test_open_hooks_folder(self) -> None:
        from empusa.cli import manage_hooks

        with (
            patch("empusa.cli.Prompt") as mp,
            patch("empusa.cli.manager_overview_render"),
            patch("empusa.cli.open_hooks_dir") as mock_open,
            patch("empusa.cli.console"),
            patch("empusa.cli.render_screen"),
            patch("empusa.cli.render_kv"),
        ):
            mp.ask.side_effect = ["5", "0"]
            manage_hooks()
        mock_open.assert_called_once()

    def test_view_plugins_branch(self) -> None:
        from empusa.cli import manage_hooks

        with (
            patch("empusa.cli.Prompt") as mp,
            patch("empusa.cli.manager_overview_render"),
            patch("empusa.cli.list_plugins_render") as mock_list_plugins,
            patch("empusa.cli.console"),
            patch("empusa.cli.render_screen"),
            patch("empusa.cli.render_kv"),
        ):
            mp.ask.side_effect = ["6", "0"]
            manage_hooks()
        mock_list_plugins.assert_called()

    def test_view_capability_registry(self) -> None:
        from empusa.cli import manage_hooks

        with (
            patch("empusa.cli.Prompt") as mp,
            patch("empusa.cli.manager_overview_render"),
            patch("empusa.cli.show_registry_render") as mock_reg,
            patch("empusa.cli.console"),
            patch("empusa.cli.render_screen"),
            patch("empusa.cli.render_kv"),
        ):
            mp.ask.side_effect = ["12", "0"]
            manage_hooks()
        mock_reg.assert_called()
