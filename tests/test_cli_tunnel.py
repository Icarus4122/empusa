"""
Tests for empusa.cli_tunnel pure command builders.

Covers each tunnel-type builder, parameter validation (no empty/None
fields slip into commands), the combined Metasploit fwd-block branch,
and the file-formatting helper. No tunnels are launched; no network.
"""

from __future__ import annotations

import pytest

from empusa.cli_tunnel import (
    TUNNEL_TYPES,
    build_chisel_commands,
    build_ligolo_commands,
    build_metasploit_commands,
    build_netsh_commands,
    build_socat_commands,
    build_ssh_local_commands,
    build_ssh_reverse_commands,
    build_ssh_socks_commands,
    format_commands_file,
)


def _flat(commands: list[tuple[str, str]]) -> str:
    return "\n".join(c for _, c in commands)


class TestTunnelRegistry:
    def test_eight_types(self) -> None:
        assert len(TUNNEL_TYPES) == 8
        assert TUNNEL_TYPES["1"] == "Chisel"
        assert TUNNEL_TYPES["8"] == "Metasploit"


class TestChisel:
    def test_basic(self) -> None:
        cmds = build_chisel_commands("10.0.0.1", "8080", "1080")
        text = _flat(cmds)
        assert "chisel server -p 8080" in text
        assert "10.0.0.1:8080 R:1080:socks" in text
        # Ensure no empty fields/None made it through
        for _, c in cmds:
            assert "None" not in c
            assert " :" not in c

    def test_missing_param_raises(self) -> None:
        with pytest.raises(ValueError):
            build_chisel_commands("", "8080", "1080")


class TestSshReverse:
    def test_basic(self) -> None:
        cmds = build_ssh_reverse_commands("root", "10.0.0.1", "9000", "22", "127.0.0.1")
        text = _flat(cmds)
        assert "ssh -R 9000:127.0.0.1:22 root@10.0.0.1" in text
        assert "ServerAliveInterval=60" in text

    def test_default_target_host(self) -> None:
        cmds = build_ssh_reverse_commands("a", "h", "1", "2")
        assert "127.0.0.1" in _flat(cmds)

    def test_missing_user_raises(self) -> None:
        with pytest.raises(ValueError):
            build_ssh_reverse_commands("", "h", "1", "2")


class TestSshLocal:
    def test_basic(self) -> None:
        cmds = build_ssh_local_commands("u", "pivot", "8443", "internal", "443")
        text = _flat(cmds)
        assert "ssh -L 8443:internal:443 u@pivot" in text
        assert "Multiple Ports" in [label for label, _ in cmds]


class TestSshSocks:
    def test_basic(self) -> None:
        cmds = build_ssh_socks_commands("u", "pivot", "1080")
        text = _flat(cmds)
        assert "ssh -D 1080 u@pivot" in text
        assert "proxychains" in text.lower()


class TestLigolo:
    def test_basic(self) -> None:
        cmds = build_ligolo_commands("10.0.0.1", "11601", "10.10.10.0/24")
        text = _flat(cmds)
        assert "0.0.0.0:11601" in text
        assert "10.0.0.1:11601" in text
        assert "ip route add 10.10.10.0/24 dev ligolo" in text


class TestSocat:
    def test_basic(self) -> None:
        cmds = build_socat_commands("8080", "10.0.0.5", "80")
        text = _flat(cmds)
        assert "socat TCP-LISTEN:8080,fork TCP:10.0.0.5:80" in text


class TestNetsh:
    def test_basic(self) -> None:
        cmds = build_netsh_commands("8080", "10.0.0.5", "443")
        text = _flat(cmds)
        assert "listenaddress=0.0.0.0" in text
        assert "listenport=8080" in text
        assert "connectaddress=10.0.0.5" in text
        assert "connectport=443" in text

    def test_custom_listen_addr(self) -> None:
        cmds = build_netsh_commands("8080", "10.0.0.5", "443", "192.168.1.1")
        assert "listenaddress=192.168.1.1" in _flat(cmds)


class TestMetasploit:
    def test_no_fwd_block(self) -> None:
        cmds = build_metasploit_commands("1", "10.10.10.0/24", "8080")
        text = _flat(cmds)
        assert "set SESSION 1" in text
        assert "set SUBNET 10.10.10.0/24" in text
        assert "portfwd add" not in text

    def test_with_fwd_block(self) -> None:
        cmds = build_metasploit_commands("1", "10.10.10.0/24", "8080", "10.10.10.50", "445")
        text = _flat(cmds)
        assert "portfwd add -l 8080 -p 445 -r 10.10.10.50" in text
        assert "portfwd list" in text

    def test_partial_fwd_ignored(self) -> None:
        # target_host set but no target_port -> no fwd block
        cmds = build_metasploit_commands("1", "10.10.10.0/24", "8080", "10.10.10.50", "")
        assert "portfwd add" not in _flat(cmds)


class TestFormatCommandsFile:
    def test_renders_header_and_commands(self) -> None:
        cmds = [("Label A", "cmd-a"), ("Label B", "cmd-b")]
        text = format_commands_file("Chisel", "lab", cmds)
        assert "# Chisel Tunnel Commands" in text
        assert "# Environment: lab" in text
        assert "# Label A" in text
        assert "cmd-a" in text
        assert "cmd-b" in text


class TestBuildReverseTunnelDispatch:
    """Drive the interactive entry point with mocked prompts (no I/O)."""

    def test_choice_zero_returns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from empusa import cli_tunnel as t

        monkeypatch.setattr(t.Prompt, "ask", lambda *a, **k: "0")
        # Should not raise; just returns.
        t.build_reverse_tunnel()

    def test_invalid_choice_returns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from empusa import cli_tunnel as t

        # Drive Chisel happy path; auto-decline file-save Confirm.
        answers = iter(["1", "10.0.0.1", "8080", "1080"])
        monkeypatch.setattr(t.Prompt, "ask", lambda *a, **k: next(answers))
        monkeypatch.setattr(t.Confirm, "ask", lambda *a, **k: False)
        t.build_reverse_tunnel()


# -- Per-tunnel-type branch dispatch ----------------------------------


def _drive(monkeypatch: pytest.MonkeyPatch, prompt_answers: list[str], confirm: bool = False):
    """Helper: drive build_reverse_tunnel with scripted Prompt answers."""
    from empusa import cli_tunnel as t

    it = iter(prompt_answers)
    monkeypatch.setattr(t.Prompt, "ask", lambda *a, **k: next(it))
    monkeypatch.setattr(t.Confirm, "ask", lambda *a, **k: confirm)
    t.build_reverse_tunnel()


class TestBranchDispatch:
    def test_chisel_branch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _drive(monkeypatch, ["1", "10.0.0.1", "8080", "1080"])

    def test_ssh_reverse_branch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _drive(monkeypatch, ["2", "root", "10.0.0.1", "9000", "22", "127.0.0.1"])

    def test_ssh_local_branch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _drive(monkeypatch, ["3", "u", "pivot", "8443", "internal", "443"])

    def test_ssh_socks_branch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _drive(monkeypatch, ["4", "u", "pivot", "1080"])

    def test_ligolo_branch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _drive(monkeypatch, ["5", "10.0.0.1", "11601", "240.0.0.1/24"])

    def test_socat_branch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _drive(monkeypatch, ["6", "8080", "10.0.0.5", "80"])

    def test_netsh_branch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _drive(monkeypatch, ["7", "8080", "10.0.0.5", "443", "0.0.0.0"])

    def test_metasploit_branch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _drive(monkeypatch, ["8", "1", "10.10.10.0/24", "8080", "", ""])


class TestBranchValidationFailures:
    def test_chisel_invalid_ip_returns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Empty hostname fails validate_hostname -> early return after log_error
        _drive(monkeypatch, ["1", ""])

    def test_chisel_invalid_port_returns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _drive(monkeypatch, ["1", "10.0.0.1", "99999"])

    def test_socat_invalid_listen_port_returns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _drive(monkeypatch, ["6", "abc"])  # not a number

    def test_metasploit_invalid_local_port_returns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _drive(monkeypatch, ["8", "1", "10.10.10.0/24", "abc"])


class TestSaveCommandsToFile:
    """When user confirms saving, file is written (CONFIG.dry_run gate respected)."""

    def test_chisel_save_writes_file(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        monkeypatch.chdir(tmp_path)
        # ["1" choice, ip, chisel_port, socks_port, env_name]
        _drive(
            monkeypatch,
            ["1", "10.0.0.1", "8080", "1080", "labenv"],
            confirm=True,
        )
        out = tmp_path / "labenv-chisel-commands.txt"
        assert out.exists()
        text = out.read_text()
        assert "Chisel Tunnel Commands" in text
        assert "10.0.0.1:8080 R:1080:socks" in text

    def test_dry_run_does_not_write(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        from empusa.cli_common import CONFIG

        monkeypatch.chdir(tmp_path)
        prev = CONFIG.get("dry_run", False)
        CONFIG["dry_run"] = True
        try:
            _drive(
                monkeypatch,
                ["1", "10.0.0.1", "8080", "1080", "labenv"],
                confirm=True,
            )
        finally:
            CONFIG["dry_run"] = prev
        assert not (tmp_path / "labenv-chisel-commands.txt").exists()
