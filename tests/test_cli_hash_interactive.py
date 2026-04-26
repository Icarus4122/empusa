"""
Tests for empusa.cli_hash interactive flows.

Drives ``hash_crack_builder`` and ``generate_hashcat_rules`` with
mocked Prompt/Confirm to cover the previously untested interactive
code paths without invoking hashcat or touching the network.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


def _ans(values: list[str]):
    it = iter(values)
    return lambda *a, **k: next(it)


# -- hash_crack_builder ----------------------------------------------


class TestHashCrackBuilder:
    def test_quit_returns_early(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from empusa import cli_hash

        monkeypatch.chdir(tmp_path)
        with patch("empusa.cli_hash.Prompt.ask", side_effect=_ans(["q"])):
            cli_hash.hash_crack_builder()
        assert list(tmp_path.iterdir()) == []

    def test_unknown_hash_returns_early(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from empusa import cli_hash

        monkeypatch.chdir(tmp_path)
        with patch("empusa.cli_hash.Prompt.ask", side_effect=_ans(["definitely-not-a-hash"])):
            cli_hash.hash_crack_builder()
        assert list(tmp_path.iterdir()) == []

    def test_md5_then_save(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from empusa import cli_hash
        from empusa.cli_common import CONFIG

        # MD5 length matches multiple modes -> need pick + wordlist=1 + rule=1
        prev = CONFIG.get("session_env", "")
        CONFIG["session_env"] = str(tmp_path)
        try:
            with (
                patch(
                    "empusa.cli_hash.Prompt.ask",
                    side_effect=_ans(
                        [
                            "d41d8cd98f00b204e9800998ecf8427e",  # hash
                            "1",  # which type from ambiguous list
                            "1",  # wordlist
                            "1",  # rule (None)
                        ]
                    ),
                ),
                patch("empusa.cli_hash.Confirm.ask", return_value=True),
            ):
                cli_hash.hash_crack_builder()
        finally:
            CONFIG["session_env"] = prev

        scripts = list(tmp_path.glob("crack_*.sh"))
        assert scripts, f"no script saved under {tmp_path}: {list(tmp_path.iterdir())}"
        text = scripts[0].read_text()
        assert "hashcat" in text
        assert "d41d8cd98f00b204e9800998ecf8427e" in text

    def test_unique_hash_skips_picker(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from empusa import cli_hash

        monkeypatch.chdir(tmp_path)
        # bcrypt $2y$ is a unique prefix so no ambiguous pick is needed
        bcrypt = "$2y$10$" + "a" * 53
        with (
            patch(
                "empusa.cli_hash.Prompt.ask",
                side_effect=_ans([bcrypt, "1", "1"]),  # hash, wordlist, rule
            ),
            patch("empusa.cli_hash.Confirm.ask", return_value=False),
        ):
            cli_hash.hash_crack_builder()
        # Decline-save means no file output
        assert not any(p.suffix == ".sh" for p in tmp_path.iterdir())


# -- generate_hashcat_rules -------------------------------------------


class TestGenerateHashcatRules:
    def test_no_password_files_returns(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from empusa import cli_hash

        monkeypatch.chdir(tmp_path)
        # Domain with no matching files; decline custom path search.
        with (
            patch("empusa.cli_hash.Prompt.ask", side_effect=_ans(["ghost"])),
            patch("empusa.cli_hash.Confirm.ask", return_value=False),
        ):
            cli_hash.generate_hashcat_rules()
        assert not any(p.name.endswith(".rule") for p in tmp_path.iterdir())

    def test_dry_run_skips_write(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from empusa import cli_hash
        from empusa.cli_common import CONFIG

        # Seed a password file so the function reaches the dry-run gate
        (tmp_path / "corp-passwords.txt").write_text("Password1\nWelcome2024!\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        prev = CONFIG.get("dry_run", False)
        CONFIG["dry_run"] = True
        try:
            with patch("empusa.cli_hash.Prompt.ask", side_effect=_ans(["corp"])):
                cli_hash.generate_hashcat_rules()
        finally:
            CONFIG["dry_run"] = prev

        # No rule file should be written in dry-run
        assert not (tmp_path / "hashcat_generated.rule").exists()

    def test_writes_rule_file(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from empusa import cli_hash

        pw_path = tmp_path / "corp-passwords.txt"
        pw_path.write_text(
            "Password1\nWelcome2024!\nsummer2023\nP@ssw0rd!\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        with patch("empusa.cli_hash.Prompt.ask", side_effect=_ans(["corp"])):
            cli_hash.generate_hashcat_rules()

        out = tmp_path / "hashcat_generated.rule"
        assert out.exists()
        text = out.read_text()
        assert "Hashcat rules generated by Empusa" in text
        # File should contain at least one rule line beyond the header
        non_comment = [line for line in text.splitlines() if line and not line.startswith("#")]
        assert non_comment

    def test_multi_file_selection(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from empusa import cli_hash

        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        (tmp_path / "a" / "corp-passwords.txt").write_text("alpha\nBeta1\n", encoding="utf-8")
        (tmp_path / "b" / "corp-passwords.txt").write_text("gamma\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        # domain="corp", then pick "1" from the multi-file list
        with patch("empusa.cli_hash.Prompt.ask", side_effect=_ans(["corp", "1"])):
            cli_hash.generate_hashcat_rules()

        # The rule file lives next to the chosen password file
        chosen = list(tmp_path.rglob("hashcat_generated.rule"))
        assert chosen
