"""
Tests for empusa.cli_build

Covers: validate_ip, validate_port, validate_hostname, detect_os,
        _identify_hash, HASH_SIGNATURES patterns.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from empusa.cli_build import (
    HASH_SIGNATURES,
    detect_os,
    identify_hash,
    validate_hostname,
    validate_ip,
    validate_port,
)

# -- validate_ip -------------------------------------------------------


class TestValidateIp:
    @pytest.mark.parametrize(
        "ip",
        [
            "10.10.10.1",
            "192.168.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "127.0.0.1",
            "::1",
            "fe80::1",
        ],
    )
    def test_valid(self, ip: str) -> None:
        assert validate_ip(ip) is True

    @pytest.mark.parametrize(
        "ip",
        [
            "",
            "not-an-ip",
            "999.999.999.999",
            "10.10.10",
            "10.10.10.10.10",
            "abc",
        ],
    )
    def test_invalid(self, ip: str) -> None:
        assert validate_ip(ip) is False


# -- validate_port -----------------------------------------------------


class TestValidatePort:
    @pytest.mark.parametrize("port", ["1", "80", "443", "8080", "65535"])
    def test_valid(self, port: str) -> None:
        assert validate_port(port) is True

    @pytest.mark.parametrize("port", ["0", "-1", "65536", "abc", "", "99999"])
    def test_invalid(self, port: str) -> None:
        assert validate_port(port) is False


# -- validate_hostname -------------------------------------------------


class TestValidateHostname:
    @pytest.mark.parametrize(
        "host",
        [
            "10.10.10.1",
            "dc01.corp.com",
            "web-server-01",
            "a",
            "my.host.name",
        ],
    )
    def test_valid(self, host: str) -> None:
        assert validate_hostname(host) is True

    @pytest.mark.parametrize(
        "host",
        [
            "",
            "...",
            "-start-with-dash.com",
        ],
    )
    def test_invalid(self, host: str) -> None:
        assert validate_hostname(host) is False


# -- detect_os ---------------------------------------------------------


class TestDetectOs:
    def test_windows_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "nmap.txt"
        f.write_text("Nmap scan report\nOS: Microsoft Windows 10 Pro\n")
        assert detect_os(f) == "Windows"

    def test_linux_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "nmap.txt"
        f.write_text("Nmap scan report\nOS: Linux 5.4\nRunning: Ubuntu\n")
        assert detect_os(f) == "Linux"

    def test_unknown_when_ambiguous(self, tmp_path: Path) -> None:
        f = tmp_path / "nmap.txt"
        f.write_text("Nmap scan report\nOpen ports: 22, 80\n")
        assert detect_os(f) == "Unknown"

    def test_missing_file(self, tmp_path: Path) -> None:
        assert detect_os(tmp_path / "missing.txt") == "Unknown"


# -- _identify_hash ----------------------------------------------------


class TestIdentifyHash:
    def test_md5(self) -> None:
        matches = identify_hash("5d41402abc4b2a76b9719d911017c592")
        names = [n for _, n in matches]
        assert any("MD5" in n or "NTLM" in n for n in names)

    def test_sha1(self) -> None:
        matches = identify_hash("a" * 40)
        names = [n for _, n in matches]
        assert any("SHA-1" in n for n in names)

    def test_sha256(self) -> None:
        matches = identify_hash("a" * 64)
        names = [n for _, n in matches]
        assert any("SHA-256" in n for n in names)

    def test_sha512(self) -> None:
        matches = identify_hash("a" * 128)
        names = [n for _, n in matches]
        assert any("SHA-512" in n for n in names)

    def test_bcrypt(self) -> None:
        matches = identify_hash("$2b$12$LJ3m4ys3Lg/1hMwMkOe7Tu.RRG5RxWx0kOJwMTqFSVmJJqem/RvMO")
        names = [n for _, n in matches]
        assert any("bcrypt" in n for n in names)

    def test_kerberoast(self) -> None:
        matches = identify_hash("$krb5tgs$23$*...")
        names = [n for _, n in matches]
        assert any("Kerberoast" in n for n in names)

    def test_asrep(self) -> None:
        matches = identify_hash("$krb5asrep$23$user@domain:deadbeef")
        names = [n for _, n in matches]
        assert any("AS-REP" in n for n in names)

    def test_unknown_hash(self) -> None:
        matches = identify_hash("not_a_hash_at_all_xyz")
        assert matches == []

    def test_sha512crypt(self) -> None:
        matches = identify_hash("$6$rounds=5000$saltsalt$hashed_value")
        names = [n for _, n in matches]
        assert any("sha512crypt" in n for n in names)

    def test_wordpress_phpass(self) -> None:
        matches = identify_hash("$P$BhashValueHere12345")
        names = [n for _, n in matches]
        assert any("WordPress" in n or "phpass" in n for n in names)


class TestHashSignatures:
    def test_minimum_signatures(self) -> None:
        assert len(HASH_SIGNATURES) >= 20

    def test_tuples_have_three_elements(self) -> None:
        for entry in HASH_SIGNATURES:
            assert len(entry) == 3
            mode, name, pattern = entry
            assert isinstance(mode, int)
            assert isinstance(name, str)
            assert isinstance(pattern, str)
