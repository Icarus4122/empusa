"""
Tests for empusa.cli_ad — Active Directory playbook generator.

Drives the interactive ``ad_enum_playbook`` with mocked prompts to
exercise both DC-IP-known and DC-IP-blank branches without network
activity. Verifies content fragments and on-disk artifact creation.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


def _ans(values: list[str]):
    """Build a Prompt.ask side-effect that returns scripted strings."""
    it = iter(values)
    return lambda *a, **k: next(it)


class TestAdEnumPlaybook:
    def test_missing_domain_returns_early(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from empusa import cli_ad

        monkeypatch.chdir(tmp_path)
        with patch("empusa.cli_ad.Prompt.ask", side_effect=_ans([""])):
            cli_ad.ad_enum_playbook()

        # Nothing should be written
        assert list(tmp_path.iterdir()) == []

    def test_full_playbook_with_dc_ip_writes_file(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from empusa import cli_ad
        from empusa.cli_common import CONFIG

        prev = CONFIG.get("session_env", "")
        CONFIG["session_env"] = str(tmp_path)
        try:
            with (
                patch(
                    "empusa.cli_ad.Prompt.ask",
                    side_effect=_ans(["corp.com", "stephanie", "10.0.0.1"]),
                ),
                patch("empusa.cli_ad.Confirm.ask", return_value=True),
            ):
                cli_ad.ad_enum_playbook()
        finally:
            CONFIG["session_env"] = prev

        out = tmp_path / "ad_playbook_corp_com.sh"
        assert out.exists()
        text = out.read_text()
        # DC-IP-aware fragments
        assert "10.0.0.1" in text
        assert "stephanie" in text
        assert "DC=corp,DC=com" in text
        assert "Kerberoasting" in text
        # Headers preserved
        assert "Active Directory Enumeration Playbook" in text

    def test_no_dc_ip_branch(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from empusa import cli_ad
        from empusa.cli_common import CONFIG

        prev = CONFIG.get("session_env", "")
        CONFIG["session_env"] = str(tmp_path)
        try:
            with (
                patch(
                    "empusa.cli_ad.Prompt.ask",
                    side_effect=_ans(["acme.local", "alice", ""]),
                ),
                patch("empusa.cli_ad.Confirm.ask", return_value=True),
            ):
                cli_ad.ad_enum_playbook()
        finally:
            CONFIG["session_env"] = prev

        out = tmp_path / "ad_playbook_acme_local.sh"
        assert out.exists()
        text = out.read_text()
        # Should hint that DC IP is not set
        assert "Fill in DC_IP first" in text
        # And no xfreerdp /v: line because DC IP is empty
        assert "xfreerdp" not in text

    def test_decline_save(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from empusa import cli_ad

        monkeypatch.chdir(tmp_path)
        with (
            patch(
                "empusa.cli_ad.Prompt.ask",
                side_effect=_ans(["corp.com", "u", ""]),
            ),
            patch("empusa.cli_ad.Confirm.ask", return_value=False),
        ):
            cli_ad.ad_enum_playbook()

        # Nothing written when user declines
        assert not any(p.suffix == ".sh" for p in tmp_path.iterdir())
