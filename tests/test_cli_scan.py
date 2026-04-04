"""Tests for empusa.cli_scan — validators, OS detection, host summarization."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from empusa.cli_scan import detect_os, validate_hostname, validate_ip, validate_port

# -- validate_ip -------------------------------------------------------


class TestValidateIp:
    @pytest.mark.parametrize(
        "ip",
        ["192.168.1.1", "10.0.0.1", "255.255.255.255", "0.0.0.0", "127.0.0.1"],
    )
    def test_valid_ipv4(self, ip: str) -> None:
        assert validate_ip(ip) is True

    @pytest.mark.parametrize("ip", ["::1", "fe80::1", "2001:db8::1"])
    def test_valid_ipv6(self, ip: str) -> None:
        assert validate_ip(ip) is True

    @pytest.mark.parametrize(
        "ip",
        ["", "not-an-ip", "999.999.999.999", "192.168.1", "192.168.1.1.1", "abc"],
    )
    def test_invalid(self, ip: str) -> None:
        assert validate_ip(ip) is False


# -- validate_port ------------------------------------------------------


class TestValidatePort:
    @pytest.mark.parametrize("port", ["1", "80", "443", "8080", "65535"])
    def test_valid(self, port: str) -> None:
        assert validate_port(port) is True

    @pytest.mark.parametrize("port", ["0", "-1", "65536", "99999", "", "abc", "3.14"])
    def test_invalid(self, port: str) -> None:
        assert validate_port(port) is False


# -- validate_hostname --------------------------------------------------


class TestValidateHostname:
    @pytest.mark.parametrize(
        "host",
        ["example.com", "sub.domain.co.uk", "host-name", "a", "localhost"],
    )
    def test_valid_hostnames(self, host: str) -> None:
        assert validate_hostname(host) is True

    def test_valid_ip_passes(self) -> None:
        assert validate_hostname("10.10.10.1") is True

    @pytest.mark.parametrize(
        "host",
        ["", "-leading-dash", "trailing-.dot", "has space", "a" * 64],
    )
    def test_invalid_hostnames(self, host: str) -> None:
        assert validate_hostname(host) is False


# -- detect_os ----------------------------------------------------------


class TestDetectOs:
    def test_detects_windows(self, tmp_path: Path) -> None:
        f = tmp_path / "scan.txt"
        f.write_text("OS: Microsoft Windows 10\n80/tcp open http\n")
        assert detect_os(f) == "Windows"

    def test_detects_linux(self, tmp_path: Path) -> None:
        f = tmp_path / "scan.txt"
        f.write_text("OS: Ubuntu 20.04 LTS\n22/tcp open ssh\n")
        assert detect_os(f) == "Linux"

    def test_detects_linux_via_apache(self, tmp_path: Path) -> None:
        f = tmp_path / "scan.txt"
        f.write_text("80/tcp open http Apache httpd 2.4\n")
        assert detect_os(f) == "Linux"

    def test_unknown_for_ambiguous(self, tmp_path: Path) -> None:
        f = tmp_path / "scan.txt"
        f.write_text("53/tcp open domain\n")
        assert detect_os(f) == "Unknown"

    @patch("empusa.cli_scan.log_verbose")
    def test_missing_file(self, _mock: object) -> None:
        assert detect_os(Path("/nonexistent/scan.txt")) == "Unknown"


# -- summarize_hosts ----------------------------------------------------


class TestSummarizeHosts:
    def test_missing_env_dir(self, tmp_path: Path) -> None:
        from empusa.cli_scan import summarize_hosts

        # Should return silently when dir doesn't exist
        summarize_hosts(str(tmp_path / "nope"))

    @patch("empusa.cli_scan.log_info")
    def test_empty_env_dir(self, mock_info: object, tmp_path: Path) -> None:
        from empusa.cli_scan import summarize_hosts

        env = tmp_path / "lab"
        env.mkdir()
        summarize_hosts(str(env))
        # Should report no results
        mock_info.assert_called_once()  # type: ignore[attr-defined]

    @patch("empusa.cli_scan.console")
    def test_parses_host_dirs(self, mock_console: object, tmp_path: Path) -> None:
        from empusa.cli_scan import summarize_hosts

        env = tmp_path / "lab"
        env.mkdir()

        # Create a host dir matching the pattern "ip-os"
        host_dir = env / "10.10.10.1-Linux"
        nmap_dir = host_dir / "nmap"
        nmap_dir.mkdir(parents=True)

        scan_file = nmap_dir / "full_scan.txt"
        scan_file.write_text("22/tcp   open  ssh\n80/tcp   open  http\n")

        summarize_hosts(str(env))
        # If we got here without error, the parsing succeeded
