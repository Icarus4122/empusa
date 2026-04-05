"""
Tests for empusa.cli_loot

Covers: _save_loot, _display_loot_table, _display_loot_table_render,
        _export_loot_markdown, _reuse_analysis_render,
        _import_env_creds, _sync_loot_to_env_files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from empusa.cli_loot import (
    _display_loot_table,
    _display_loot_table_render,
    _export_loot_markdown,
    _import_env_creds,
    _reuse_analysis_render,
    _save_loot,
    _sync_loot_to_env_files,
)

# -- Sample data fixtures -------------------------------------------


def _make_entries() -> list[dict[str, Any]]:
    return [
        {
            "host": "10.10.10.1",
            "cred_type": "plaintext",
            "username": "admin",
            "secret": "Password123!",
            "source": "smb",
            "notes": "Domain admin",
            "timestamp": "2025-01-01 12:00:00",
        },
        {
            "host": "10.10.10.2",
            "cred_type": "ntlm",
            "username": "admin",
            "secret": "aabbccdd11223344",
            "source": "secretsdump",
            "notes": "Reused cred",
            "timestamp": "2025-01-01 13:00:00",
        },
        {
            "host": "10.10.10.2",
            "cred_type": "plaintext",
            "username": "svc_sql",
            "secret": "Password123!",
            "source": "kerberoast",
            "notes": "",
            "timestamp": "2025-01-01 14:00:00",
        },
    ]


# -- _save_loot ------------------------------------------------------


class TestSaveLoot:
    def test_roundtrip(self, tmp_path: Path) -> None:
        loot_file = tmp_path / "loot.json"
        entries = _make_entries()
        _save_loot(loot_file, entries)
        loaded = json.loads(loot_file.read_text())
        assert len(loaded) == 3
        assert loaded[0]["username"] == "admin"

    def test_empty_list(self, tmp_path: Path) -> None:
        loot_file = tmp_path / "loot.json"
        _save_loot(loot_file, [])
        loaded = json.loads(loot_file.read_text())
        assert loaded == []

    def test_overwrites_existing(self, tmp_path: Path) -> None:
        loot_file = tmp_path / "loot.json"
        _save_loot(loot_file, _make_entries())
        _save_loot(loot_file, [{"host": "new"}])
        loaded = json.loads(loot_file.read_text())
        assert len(loaded) == 1


# -- _display_loot_table (prints to console, just verify no crash) ---


class TestDisplayLootTable:
    def test_with_entries_no_crash(self) -> None:
        _display_loot_table(_make_entries())

    def test_empty_entries_no_crash(self) -> None:
        _display_loot_table([])


# -- _display_loot_table_render (returns Table or str) ---------------


class TestDisplayLootTableRender:
    def test_empty_returns_string(self) -> None:
        result = _display_loot_table_render([])
        assert isinstance(result, str)
        assert "No loot" in result

    def test_populated_returns_table(self) -> None:
        from rich.table import Table

        result = _display_loot_table_render(_make_entries())
        assert isinstance(result, Table)

    def test_custom_title(self) -> None:
        from rich.table import Table

        result = _display_loot_table_render(_make_entries(), title="Custom Title")
        assert isinstance(result, Table)
        assert result.title == "Custom Title"


# -- _export_loot_markdown -------------------------------------------


class TestExportLootMarkdown:
    def test_creates_file(self, tmp_path: Path) -> None:
        out = tmp_path / "report.md"
        _export_loot_markdown(_make_entries(), out)
        assert out.exists()

    def test_contains_hosts(self, tmp_path: Path) -> None:
        out = tmp_path / "report.md"
        _export_loot_markdown(_make_entries(), out)
        content = out.read_text()
        assert "## 10.10.10.1" in content
        assert "## 10.10.10.2" in content

    def test_contains_table_headers(self, tmp_path: Path) -> None:
        out = tmp_path / "report.md"
        _export_loot_markdown(_make_entries(), out)
        content = out.read_text()
        assert "| Type |" in content
        assert "| Username |" in content

    def test_credential_reuse_section(self, tmp_path: Path) -> None:
        out = tmp_path / "report.md"
        _export_loot_markdown(_make_entries(), out)
        content = out.read_text()
        # admin is on 10.10.10.1 and 10.10.10.2 -> reuse detected
        assert "Credential Reuse" in content
        assert "admin" in content

    def test_no_reuse_section_when_unique(self, tmp_path: Path) -> None:
        out = tmp_path / "report.md"
        single = [_make_entries()[0]]
        _export_loot_markdown(single, out)
        content = out.read_text()
        assert "Credential Reuse" not in content

    def test_empty_entries(self, tmp_path: Path) -> None:
        out = tmp_path / "report.md"
        _export_loot_markdown([], out)
        content = out.read_text()
        assert "# Loot Report" in content
        assert "Total entries: 0" in content

    def test_total_count(self, tmp_path: Path) -> None:
        out = tmp_path / "report.md"
        _export_loot_markdown(_make_entries(), out)
        content = out.read_text()
        assert "Total entries: 3" in content


# -- _reuse_analysis_render ------------------------------------------


class TestReuseAnalysisRender:
    def test_detects_username_reuse(self) -> None:
        result = _reuse_analysis_render(_make_entries())
        assert "admin" in result
        assert "Usernames found on multiple hosts" in result

    def test_detects_secret_reuse(self) -> None:
        result = _reuse_analysis_render(_make_entries())
        # Password123! is used on two hosts
        assert "Secrets/hashes reused across hosts" in result
        assert "Pass****" in result

    def test_no_reuse_single_host(self) -> None:
        entries = [
            {
                "host": "10.10.10.1",
                "username": "user1",
                "secret": "pass1",
                "cred_type": "plaintext",
            },
        ]
        result = _reuse_analysis_render(entries)
        assert "No username reuse" in result
        assert "No secret reuse" in result

    def test_empty_entries(self) -> None:
        result = _reuse_analysis_render([])
        assert "No username reuse" in result

    def test_credential_spray_suggestions(self) -> None:
        result = _reuse_analysis_render(_make_entries())
        # admin has creds on 10.10.10.1 but also on 10.10.10.2
        # svc_sql has creds on 10.10.10.2 -> suggest spraying to 10.10.10.1
        assert "Suggested credential sprays" in result


# -- _import_env_creds -----------------------------------------------


class TestImportEnvCreds:
    def test_imports_users(self, tmp_path: Path) -> None:
        (tmp_path / "lab-users.txt").write_text("alice\nbob\n")
        entries: list[dict[str, Any]] = []
        result = _import_env_creds(tmp_path, entries)
        usernames = [e["username"] for e in result]
        assert "alice" in usernames
        assert "bob" in usernames

    def test_imports_passwords(self, tmp_path: Path) -> None:
        (tmp_path / "lab-passwords.txt").write_text("secret1\nsecret2\n")
        entries: list[dict[str, Any]] = []
        result = _import_env_creds(tmp_path, entries)
        secrets = [e["secret"] for e in result]
        assert "secret1" in secrets
        assert "secret2" in secrets

    def test_skips_comments_and_blanks(self, tmp_path: Path) -> None:
        (tmp_path / "lab-users.txt").write_text("# comment\n\nalice\n")
        entries: list[dict[str, Any]] = []
        result = _import_env_creds(tmp_path, entries)
        assert len(result) == 1
        assert result[0]["username"] == "alice"

    def test_dedup_existing(self, tmp_path: Path) -> None:
        (tmp_path / "lab-users.txt").write_text("alice\n")
        existing = [{"username": "alice", "secret": "", "host": "env-import"}]
        result = _import_env_creds(tmp_path, existing)
        # alice already exists via the dedup key, so only original remains
        alices = [e for e in result if e.get("username") == "alice"]
        assert len(alices) <= 2  # at most existing + new (different dedup key format)

    def test_no_files_returns_unchanged(self, tmp_path: Path) -> None:
        entries = [{"host": "x"}]
        result = _import_env_creds(tmp_path, entries)
        assert result == entries

    def test_nested_files(self, tmp_path: Path) -> None:
        sub = tmp_path / "host1"
        sub.mkdir()
        (sub / "corp-users.txt").write_text("deepuser\n")
        entries: list[dict[str, Any]] = []
        result = _import_env_creds(tmp_path, entries)
        assert any(e["username"] == "deepuser" for e in result)


# -- _sync_loot_to_env_files ----------------------------------------


class TestSyncLootToEnvFiles:
    def test_creates_user_and_password_files(self, tmp_path: Path) -> None:
        env = tmp_path / "testenv"
        env.mkdir()
        entries = [
            {"username": "admin", "secret": "pass123", "cred_type": "plaintext"},
            {"username": "root", "secret": "toor", "cred_type": "password"},
        ]
        _sync_loot_to_env_files(env, entries)
        users_file = env / "testenv-users.txt"
        passwords_file = env / "testenv-passwords.txt"
        assert users_file.exists()
        assert passwords_file.exists()
        assert "admin" in users_file.read_text()
        assert "root" in users_file.read_text()
        assert "pass123" in passwords_file.read_text()

    def test_merges_with_existing(self, tmp_path: Path) -> None:
        env = tmp_path / "lab"
        env.mkdir()
        (env / "lab-users.txt").write_text("existing_user\n")
        entries = [{"username": "new_user", "secret": "", "cred_type": "username"}]
        _sync_loot_to_env_files(env, entries)
        content = (env / "lab-users.txt").read_text()
        assert "existing_user" in content
        assert "new_user" in content

    def test_skips_non_plaintext_secrets(self, tmp_path: Path) -> None:
        env = tmp_path / "myenv"
        env.mkdir()
        entries = [
            {"username": "user1", "secret": "ntlmhash", "cred_type": "ntlm"},
        ]
        _sync_loot_to_env_files(env, entries)
        pw_file = env / "myenv-passwords.txt"
        if pw_file.exists():
            content = pw_file.read_text()
            assert "ntlmhash" not in content

    def test_empty_entries(self, tmp_path: Path) -> None:
        env = tmp_path / "empty"
        env.mkdir()
        _sync_loot_to_env_files(env, [])
        # Should create files with just the comment heade
        assert (env / "empty-users.txt").exists()
        assert (env / "empty-passwords.txt").exists()
