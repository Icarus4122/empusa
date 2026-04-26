"""Extended tests for empusa.cli_scan covering scan/build/shell-history paths.

All external scanners are mocked. No real nmap/searchsploit/network calls.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from empusa import cli_scan
from empusa.cli_common import CONFIG

# -- search_exploits_from_nmap ---------------------------------------


class TestSearchExploitsFromNmap:
    def test_missing_nmap_file(self, tmp_path: Path) -> None:
        cli_scan.search_exploits_from_nmap(tmp_path / "missing.txt")

    @patch("empusa.cli_scan.check_tool_exists", return_value=False)
    def test_no_searchsploit(self, _mock, tmp_path: Path) -> None:
        f = tmp_path / "scan.txt"
        f.write_text("80/tcp open http Apache 2.4\n")
        cli_scan.search_exploits_from_nmap(f)

    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    def test_dry_run_skips(self, _mock, tmp_path: Path) -> None:
        f = tmp_path / "scan.txt"
        f.write_text("80/tcp open http Apache 2.4\n")
        prev = CONFIG["dry_run"]
        CONFIG["dry_run"] = True
        try:
            cli_scan.search_exploits_from_nmap(f)
        finally:
            CONFIG["dry_run"] = prev
        assert not (tmp_path / "searchsploit_results.md").exists()

    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    @patch("empusa.cli_scan.subprocess.run")
    def test_writes_results(self, mock_run, _tool, tmp_path: Path) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            ["searchsploit", "x"], 0, stdout="exploit found\n", stderr=""
        )
        f = tmp_path / "scan.txt"
        f.write_text("80/tcp open http Apache 2.4\n22/tcp open ssh OpenSSH 7.4\n")
        prev = CONFIG["dry_run"]
        CONFIG["dry_run"] = False
        try:
            cli_scan.search_exploits_from_nmap(f)
        finally:
            CONFIG["dry_run"] = prev
        out = tmp_path / "searchsploit_results.md"
        assert out.exists()
        text = out.read_text()
        assert "Exploit Search Results" in text
        assert "exploit found" in text

    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    def test_uses_services_runner(self, _tool, tmp_path: Path) -> None:
        services = MagicMock()
        services.runner.run.return_value = subprocess.CompletedProcess(
            ["searchsploit"], 0, stdout="via services\n", stderr=""
        )
        f = tmp_path / "scan.txt"
        f.write_text("80/tcp open http Apache 2.4\n")
        prev = CONFIG["dry_run"]
        CONFIG["dry_run"] = False
        try:
            cli_scan.search_exploits_from_nmap(f, services=services)
        finally:
            CONFIG["dry_run"] = prev
        assert services.runner.run.called
        assert "via services" in (tmp_path / "searchsploit_results.md").read_text()

    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    @patch(
        "empusa.cli_scan.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="searchsploit", timeout=30),
    )
    def test_handles_timeout(self, _r, _t, tmp_path: Path) -> None:
        f = tmp_path / "scan.txt"
        f.write_text("80/tcp open http Apache 2.4\n")
        prev = CONFIG["dry_run"]
        CONFIG["dry_run"] = False
        try:
            cli_scan.search_exploits_from_nmap(f)
        finally:
            CONFIG["dry_run"] = prev
        assert "timed out" in (tmp_path / "searchsploit_results.md").read_text()


# -- run_nmap --------------------------------------------------------


class TestRunNmap:
    @patch("empusa.cli_scan.check_tool_exists", return_value=False)
    def test_no_nmap_returns(self, _mock, tmp_path: Path) -> None:
        ip, out = cli_scan.run_nmap("10.0.0.1", tmp_path)
        assert ip == "10.0.0.1"
        assert out == tmp_path / "full_scan.txt"

    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    def test_dry_run_skips_execution(self, _mock, tmp_path: Path) -> None:
        prev = CONFIG["dry_run"]
        CONFIG["dry_run"] = True
        try:
            ip, out = cli_scan.run_nmap("10.0.0.1", tmp_path)
        finally:
            CONFIG["dry_run"] = prev
        assert ip == "10.0.0.1"
        # Dry-run never produces full_scan.txt
        assert not out.exists()

    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    @patch("empusa.cli_scan.subprocess.run")
    def test_calls_subprocess_and_runs_hooks(self, mock_run, _tool, tmp_path: Path) -> None:
        # Simulate nmap creating output files: greppable then full scan
        def _fake(cmd, capture_output=False, timeout=None, **_kw):
            # Write greppable file with one open port so enrichment runs
            # Find -oG path
            if "-oG" in cmd:
                gp = Path(cmd[cmd.index("-oG") + 1])
                gp.write_text("Host: 10.0.0.1 ()\tPorts: 80/open/tcp//http\n")
            if "-oN" in cmd:
                of = Path(cmd[cmd.index("-oN") + 1])
                of.write_text("80/tcp   open  http  nginx\n")
            return subprocess.CompletedProcess(cmd, 0, b"", b"")

        mock_run.side_effect = _fake

        prev = CONFIG["dry_run"]
        CONFIG["dry_run"] = False
        hooks_seen: list[str] = []
        try:
            ip, out = cli_scan.run_nmap(
                "10.0.0.1",
                tmp_path,
                run_hooks_fn=lambda name, ctx: hooks_seen.append(name),
            )
        finally:
            CONFIG["dry_run"] = prev
        assert ip == "10.0.0.1"
        assert out.exists()
        # Per-port file written under ports/
        port_files = list((tmp_path / "ports").glob("80-*.txt"))
        assert port_files, "expected port file to be created"
        assert "pre_scan_host" in hooks_seen
        assert "post_scan" in hooks_seen


# -- configure_shell_history -----------------------------------------


class TestConfigureShellHistory:
    def test_dry_run_no_write(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        prev = CONFIG["dry_run"]
        CONFIG["dry_run"] = True
        # Force unix-bash branch deterministically
        monkeypatch.setattr(cli_scan, "IS_WINDOWS", False)
        monkeypatch.setattr(cli_scan, "IS_UNIX", True)
        monkeypatch.setattr(os, "environ", {"SHELL": "/bin/bash", "HOME": str(tmp_path)})
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        try:
            cli_scan.configure_shell_history(tmp_path / "hist.log")
        finally:
            CONFIG["dry_run"] = prev
        assert not (tmp_path / ".bashrc").exists()

    def test_bash_writes_rc(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        prev = CONFIG["dry_run"]
        CONFIG["dry_run"] = False
        monkeypatch.setattr(cli_scan, "IS_WINDOWS", False)
        monkeypatch.setattr(cli_scan, "IS_UNIX", True)
        monkeypatch.setattr(os, "environ", {"SHELL": "/bin/bash"})
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        try:
            cli_scan.configure_shell_history(tmp_path / "hist.log")
        finally:
            CONFIG["dry_run"] = prev
        rc = tmp_path / ".bashrc"
        assert rc.exists()
        assert "Empusa Command Logging" in rc.read_text()

    def test_zsh_writes_rc(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        prev = CONFIG["dry_run"]
        CONFIG["dry_run"] = False
        monkeypatch.setattr(cli_scan, "IS_WINDOWS", False)
        monkeypatch.setattr(cli_scan, "IS_UNIX", True)
        monkeypatch.setattr(os, "environ", {"SHELL": "/usr/bin/zsh"})
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        try:
            cli_scan.configure_shell_history(tmp_path / "hist.log")
        finally:
            CONFIG["dry_run"] = prev
        rc = tmp_path / ".zshrc"
        assert rc.exists()
        assert "Empusa Command Logging" in rc.read_text()

    def test_unsupported_shell_returns(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(cli_scan, "IS_WINDOWS", False)
        monkeypatch.setattr(cli_scan, "IS_UNIX", True)
        monkeypatch.setattr(os, "environ", {"SHELL": "/usr/bin/fish"})
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        cli_scan.configure_shell_history(tmp_path / "hist.log")

    def test_idempotent_when_already_configured(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(cli_scan, "IS_WINDOWS", False)
        monkeypatch.setattr(cli_scan, "IS_UNIX", True)
        monkeypatch.setattr(os, "environ", {"SHELL": "/bin/bash"})
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        hist = tmp_path / "hist.log"
        rc = tmp_path / ".bashrc"
        rc.write_text(f'HISTFILE="{hist.absolute()}"\n')
        cli_scan.configure_shell_history(hist)
        # File should be unchanged (no re-append)
        text = rc.read_text()
        assert text.count("HISTFILE=") == 1


# -- build_env (non-interactive paths) -------------------------------


class TestBuildEnv:
    def test_no_valid_ips_returns_none(self) -> None:
        assert cli_scan.build_env("env", ["not-an-ip"], interactive=False) is None

    @patch("empusa.cli_scan.check_tool_exists", return_value=False)
    def test_missing_nmap_returns_none(self, _mock) -> None:
        assert cli_scan.build_env("env", ["10.0.0.1"], interactive=False) is None

    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    def test_dry_run_returns_none(self, _mock) -> None:
        prev = CONFIG["dry_run"]
        CONFIG["dry_run"] = True
        try:
            result = cli_scan.build_env("env", ["10.0.0.1"], interactive=False)
        finally:
            CONFIG["dry_run"] = prev
        assert result is None

    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    def test_existing_dir_non_interactive_aborts(self, _mock, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.chdir(tmp_path)
        env_dir = tmp_path / "labenv"
        env_dir.mkdir()
        (env_dir / "stale.txt").write_text("x")
        prev = CONFIG["dry_run"]
        CONFIG["dry_run"] = False
        try:
            result = cli_scan.build_env(
                "labenv",
                ["10.0.0.1"],
                interactive=False,
                overwrite_existing=False,
            )
        finally:
            CONFIG["dry_run"] = prev
        assert result is None

    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    def test_existing_dir_overwrite_continues(self, _mock, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # Force build_env past the guard then short-circuit run_nmap so we
        # don't actually execute scans. We patch run_nmap to avoid heavy work.
        monkeypatch.chdir(tmp_path)
        env_dir = tmp_path / "labenv"
        env_dir.mkdir()
        (env_dir / "stale.txt").write_text("x")

        def _fake_nmap(ip, output_path, **_kw):
            output_path = Path(output_path)
            output_path.mkdir(parents=True, exist_ok=True)
            f = output_path / "full_scan.txt"
            f.write_text("80/tcp open http Apache\n")
            return ip, f

        monkeypatch.setattr(cli_scan, "run_nmap", _fake_nmap)
        prev = CONFIG["dry_run"]
        CONFIG["dry_run"] = False
        try:
            layout = cli_scan.build_env(
                "labenv",
                ["10.0.0.1"],
                interactive=False,
                overwrite_existing=True,
                shell_history=False,
            )
        finally:
            CONFIG["dry_run"] = prev
        assert layout is not None
        # IP scan dir should have been classified by detect_os and renamed
        scans = list(layout.scans_dir.iterdir())
        assert any("10.0.0.1" in p.name for p in scans)

    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    def test_invalid_ip_skipped_but_others_proceed(
        self, _mock, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)

        def _fake_nmap(ip, output_path, **_kw):
            output_path = Path(output_path)
            output_path.mkdir(parents=True, exist_ok=True)
            f = output_path / "full_scan.txt"
            f.write_text("22/tcp open ssh\n")
            return ip, f

        monkeypatch.setattr(cli_scan, "run_nmap", _fake_nmap)
        prev = CONFIG["dry_run"]
        CONFIG["dry_run"] = False
        try:
            layout = cli_scan.build_env(
                "mixed",
                ["10.0.0.1", "not-an-ip"],
                interactive=False,
                shell_history=False,
            )
        finally:
            CONFIG["dry_run"] = prev
        assert layout is not None
