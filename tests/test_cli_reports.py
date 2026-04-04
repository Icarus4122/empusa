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
