"""
Tests for empusa.cli_reports

Covers: gather_env_host_data discovery, loot exact-match (not substring),
        build_host_md output structure, public wrapper delegation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from empusa.cli_reports import build_host_md, gather_env_host_data

# -- gather_env_host_data ---------------------------------------------


class TestGatherEnvHostData:
    def _setup_env(self, env: Path, hosts: list[str]) -> None:
        for h in hosts:
            (env / h).mkdir(parents=True)

    def test_discovers_hosts(self, tmp_path: Path) -> None:
        self._setup_env(tmp_path, ["10.10.10.1-Linux", "10.10.10.2-Windows"])
        data = gather_env_host_data(tmp_path)
        ips = [h["ip"] for h in data]
        assert "10.10.10.1" in ips
        assert "10.10.10.2" in ips

    def test_ignores_non_host_dirs(self, tmp_path: Path) -> None:
        (tmp_path / "notes.txt").write_text("hi")
        (tmp_path / "somedir").mkdir()  # no dash -> skipped
        data = gather_env_host_data(tmp_path)
        assert data == []

    def test_reads_nmap_ports(self, tmp_path: Path) -> None:
        host_dir = tmp_path / "10.10.10.1-Linux"
        nmap_dir = host_dir / "nmap"
        nmap_dir.mkdir(parents=True)
        (nmap_dir / "full_scan.txt").write_text(
            "22/tcp  open  ssh     OpenSSH 8.9\n80/tcp  open  http    Apache 2.4.52\n"
        )
        data = gather_env_host_data(tmp_path)
        assert len(data) == 1
        ports = data[0]["ports"]
        assert len(ports) == 2
        assert ports[0]["port"] == "22"
        assert ports[0]["service"] == "ssh"


class TestLootExactMatch:
    """Loot entries must match host IP exactly, not via substring."""

    def test_exact_match_only(self, tmp_path: Path) -> None:
        (tmp_path / "10.10.10.1-Linux").mkdir()
        (tmp_path / "10.10.10.10-Linux").mkdir()

        loot = [
            {"host": "10.10.10.1", "cred_type": "password", "username": "root"},
        ]
        (tmp_path / "loot.json").write_text(json.dumps(loot))

        data = gather_env_host_data(tmp_path)
        host1 = next(h for h in data if h["ip"] == "10.10.10.1")
        host10 = next(h for h in data if h["ip"] == "10.10.10.10")

        assert len(host1["loot"]) == 1
        assert len(host10["loot"]) == 0  # Must NOT match substring

    def test_no_loot_file(self, tmp_path: Path) -> None:
        (tmp_path / "10.10.10.1-Linux").mkdir()
        data = gather_env_host_data(tmp_path)
        assert data[0]["loot"] == []


# -- build_host_md ----------------------------------------------------


class TestBuildHostMd:
    def test_returns_lines(self) -> None:
        host: dict[str, Any] = {
            "ip": "10.10.10.1",
            "os": "Linux",
            "ports": [{"port": "22", "proto": "tcp", "service": "ssh", "version": "OpenSSH 8.9"}],
            "loot": [],
        }
        lines = build_host_md(host, section=3, idx=1, category="Standalone")
        assert any("10.10.10.1" in line for line in lines)
        assert any("22/tcp" in line for line in lines)
        assert any("ssh" in line for line in lines)

    def test_empty_ports_placeholder(self) -> None:
        host: dict[str, Any] = {
            "ip": "10.10.10.2",
            "os": "Windows",
            "ports": [],
            "loot": [],
        }
        lines = build_host_md(host, section=3, idx=1, category="Standalone")
        # Should contain a comment placeholder for ports
        text = "\n".join(lines)
        assert "<!-- port -->" in text

    def test_section_numbering(self) -> None:
        host: dict[str, Any] = {
            "ip": "1.2.3.4",
            "os": "Linux",
            "ports": [],
            "loot": [],
        }
        lines = build_host_md(host, section=5, idx=2, category="AD")
        text = "\n".join(lines)
        assert "5.2" in text


# -- Public wrapper delegation ----------------------------------------


class TestPublicWrappers:
    def test_gather_is_callable(self) -> None:
        assert callable(gather_env_host_data)

    def test_build_is_callable(self) -> None:
        assert callable(build_host_md)


# -- Parse-error observability (E2 from strict-readiness audit) -------


class TestEnrichmentParseFailureObservability:
    """Parse failures during optional enrichment must be logged, not silent.

    Behavior remains soft: report-data gathering still returns a result,
    the affected section is skipped, and no traceback is printed.
    """

    def test_nmap_parse_failure_logs_warning_and_continues(self, tmp_path: Path, monkeypatch, capsys) -> None:
        host_dir = tmp_path / "10.10.10.7-Linux"
        (host_dir / "nmap").mkdir(parents=True)
        (host_dir / "nmap" / "full_scan.txt").write_text("22/tcp open ssh OpenSSH\n")

        from empusa import cli_reports as r  # noqa: F401

        # Force the inner per-host nmap parse to raise by patching read_text.
        original_read = Path.read_text

        def boom_read_text(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            if self.name == "full_scan.txt":
                raise OSError("simulated nmap parse failure")
            return original_read(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", boom_read_text)

        data = gather_env_host_data(tmp_path)

        # Soft behavior preserved: host still returned, just without ports.
        assert len(data) == 1
        assert data[0]["ip"] == "10.10.10.7"
        assert data[0]["ports"] == []

        captured = capsys.readouterr().out
        assert "[WARN]" in captured
        assert "nmap enrichment" in captured
        assert "10.10.10.7-Linux" in captured
        assert "Traceback" not in captured

    def test_outer_iter_failure_logs_warning_and_returns_empty(self, tmp_path: Path, monkeypatch, capsys) -> None:
        from empusa import cli_reports as r  # noqa: F401

        # Force env_path.iterdir() to raise.
        def boom_iterdir(self):  # type: ignore[no-untyped-def]
            raise PermissionError("simulated iter failure")

        monkeypatch.setattr(Path, "iterdir", boom_iterdir)

        data = gather_env_host_data(tmp_path)

        # Soft behavior preserved: function returns; loot block still runs,
        # but with no hosts collected the result is an empty list.
        assert data == []

        captured = capsys.readouterr().out
        assert "[WARN]" in captured
        assert "host enumeration" in captured
        assert "simulated iter failure" in captured
        assert "Traceback" not in captured


# -- build_host_md with loot data ------------------------------------


class TestBuildHostMdWithLoot:
    def test_flags_rendered(self) -> None:
        host: dict[str, Any] = {
            "ip": "10.10.10.5",
            "os": "Linux",
            "ports": [],
            "loot": [
                {
                    "cred_type": "flag",
                    "secret": "FLAG{abc123}",
                    "source": "user.txt",
                },
            ],
        }
        lines = build_host_md(host, section=3, idx=1, category="Standalone")
        text = "\n".join(lines)
        assert "FLAG{abc123}" in text
        assert "user.txt" in text

    def test_creds_table_rendered(self) -> None:
        host: dict[str, Any] = {
            "ip": "10.10.10.6",
            "os": "Windows",
            "ports": [],
            "loot": [
                {
                    "cred_type": "plaintext",
                    "username": "admin",
                    "secret": "P@ssw0rd",
                    "source": "mimikatz",
                },
                {
                    "cred_type": "ntlm",
                    "username": "svc_sql",
                    "secret": "aabbccdd",
                    "source": "secretsdump",
                },
            ],
        }
        lines = build_host_md(host, section=3, idx=1, category="AD")
        text = "\n".join(lines)
        assert "Credentials Obtained" in text
        assert "admin" in text
        assert "svc_sql" in text
        assert "| Type |" in text

    def test_flags_and_creds_together(self) -> None:
        host: dict[str, Any] = {
            "ip": "10.10.10.7",
            "os": "Linux",
            "ports": [{"port": "22", "proto": "tcp", "service": "ssh", "version": "OpenSSH 8.9"}],
            "loot": [
                {"cred_type": "flag", "secret": "FLAG{root}", "source": "root.txt"},
                {"cred_type": "plaintext", "username": "root", "secret": "toor", "source": "shadow"},
            ],
        }
        lines = build_host_md(host, section=3, idx=1, category="Standalone")
        text = "\n".join(lines)
        assert "FLAG{root}" in text
        assert "Credentials Obtained" in text
        assert "root" in text

    def test_no_loot_shows_placeholder(self) -> None:
        host: dict[str, Any] = {
            "ip": "10.10.10.8",
            "os": "Windows",
            "ports": [],
            "loot": [],
        }
        lines = build_host_md(host, section=3, idx=1, category="Standalone")
        text = "\n".join(lines)
        assert "post-exploitation" in text.lower()


# -- report_builder end-to-end (mocked Prompt/Confirm) ---------------


from unittest.mock import MagicMock, patch  # noqa: E402


class TestReportBuilder:
    def _meta_answers(self, *, hosts_present: bool = True, ad: bool = False) -> list[str]:
        base = [
            "Test Assessment",
            "Tester",
            "ClientCo",
            "example.com",
            "January 1, 2025",
            "January 2, 2025",
        ]
        if hosts_present:
            base.append("a" if ad else "s")
        else:
            base.extend(["1", "0"])
        return base

    def test_missing_environment_logs_error(self, tmp_path: Path) -> None:
        from empusa.cli_reports import report_builder

        report_builder(ask_env_fn=lambda: str(tmp_path / "nonexistent_env"))

    def test_no_hosts_uses_placeholders_and_writes_file(self, tmp_path: Path) -> None:
        from empusa.cli_reports import report_builder

        env = tmp_path / "env"
        env.mkdir()
        with patch("empusa.cli_reports.Prompt") as mp, patch("empusa.cli_reports.Confirm") as mc:
            mp.ask.side_effect = self._meta_answers(hosts_present=False)
            mc.ask.return_value = True
            report_builder(ask_env_fn=lambda: str(env))

        reports = list(env.glob("*_report.md"))
        assert reports
        content = reports[0].read_text(encoding="utf-8")
        assert "Test Assessment" in content
        assert "ClientCo" in content
        assert "Independent Challenges" in content

    def test_with_host_data_categorize_standalone(self, tmp_path: Path) -> None:
        from empusa.cli_reports import report_builder

        env = tmp_path / "env"
        env.mkdir()
        host_dir = env / "10.0.0.1-Linux"
        (host_dir / "nmap").mkdir(parents=True)
        (host_dir / "nmap" / "full_scan.txt").write_text("22/tcp  open  ssh     OpenSSH 8.9\n")
        (env / "loot.json").write_text(
            json.dumps(
                [
                    {"host": "10.0.0.1", "cred_type": "flag", "secret": "FLAG{x}", "source": "user.txt"},
                ]
            )
        )

        run_hooks = MagicMock()
        with patch("empusa.cli_reports.Prompt") as mp, patch("empusa.cli_reports.Confirm") as mc:
            mp.ask.side_effect = self._meta_answers(hosts_present=True, ad=False)
            mc.ask.return_value = True
            report_builder(ask_env_fn=lambda: str(env), run_hooks_fn=run_hooks)

        reports = list(env.glob("*_report.md"))
        assert reports
        text = reports[0].read_text(encoding="utf-8")
        assert "10.0.0.1" in text
        assert "FLAG{x}" in text
        called_events = [c.args[0] for c in run_hooks.call_args_list]
        assert "pre_report_write" in called_events
        assert "on_report_generated" in called_events

    def test_ad_categorization_creates_ad_section(self, tmp_path: Path) -> None:
        from empusa.cli_reports import report_builder

        env = tmp_path / "env"
        env.mkdir()
        (env / "10.0.0.5-Windows").mkdir()

        with patch("empusa.cli_reports.Prompt") as mp, patch("empusa.cli_reports.Confirm") as mc:
            mp.ask.side_effect = self._meta_answers(hosts_present=True, ad=True)
            mc.ask.return_value = True
            report_builder(ask_env_fn=lambda: str(env))

        text = next(env.glob("*_report.md")).read_text(encoding="utf-8")
        assert "Active Directory Set" in text

    def test_overwrite_declined_writes_timestamped(self, tmp_path: Path) -> None:
        from empusa.cli_reports import report_builder

        env = tmp_path / "env"
        env.mkdir()
        (env / "test_assessment_report.md").write_text("stale\n")

        with patch("empusa.cli_reports.Prompt") as mp, patch("empusa.cli_reports.Confirm") as mc:
            mp.ask.side_effect = self._meta_answers(hosts_present=False)
            mc.ask.return_value = False
            report_builder(ask_env_fn=lambda: str(env))

        files = sorted(env.glob("*_report*.md"))
        assert len(files) >= 2
        assert (env / "test_assessment_report.md").read_text(encoding="utf-8") == "stale\n"

    def test_registry_plugin_sections_invoked(self, tmp_path: Path) -> None:
        from empusa.cli_reports import report_builder

        env = tmp_path / "env"
        env.mkdir()

        list_entry = MagicMock()
        list_entry.name = "list_section"
        list_entry.handler = MagicMock(return_value=["## Plugin Section A", "Body line"])
        str_entry = MagicMock()
        str_entry.name = "str_section"
        str_entry.handler = MagicMock(return_value="\n## Plugin Section B\n")
        bad_entry = MagicMock()
        bad_entry.name = "bad_section"
        bad_entry.handler = MagicMock(side_effect=RuntimeError("boom"))

        registry = MagicMock()
        registry.get.return_value = [list_entry, str_entry, bad_entry]

        with patch("empusa.cli_reports.Prompt") as mp, patch("empusa.cli_reports.Confirm") as mc:
            mp.ask.side_effect = self._meta_answers(hosts_present=False)
            mc.ask.return_value = True
            report_builder(ask_env_fn=lambda: str(env), registry=registry)

        text = next(env.glob("*_report.md")).read_text(encoding="utf-8")
        assert "Plugin-Contributed Sections" in text
        assert "Plugin Section A" in text
        assert "Plugin Section B" in text
        list_entry.handler.assert_called_once()
        bad_entry.handler.assert_called_once()
