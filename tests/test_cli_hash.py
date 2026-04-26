"""Tests for empusa.cli_hash pure utilities.

Covers:
- identify_hash() prefix matches (Kerberos TGS-REP, AS-REP, NetNTLMv2, $1$, $5$, $6$, $2y$, $7z$, $P$)
- identify_hash() length-only matches return MD5/NTLM/LM family
- identify_hash() no match returns empty list
- find_password_files() locates files under a search root and skips non-matches
"""

from __future__ import annotations

from pathlib import Path

from empusa.cli_hash import find_password_files, identify_hash


class TestIdentifyHash:
    def test_kerberoast_tgs_rep(self) -> None:
        matches = identify_hash("$krb5tgs$23$*user$DOMAIN$svc*$abcd$beef")
        modes = [m for m, _ in matches]
        assert 13100 in modes

    def test_asrep_roast(self) -> None:
        matches = identify_hash("$krb5asrep$23$user@DOMAIN:abcd$beef")
        assert 18200 in [m for m, _ in matches]

    def test_netntlmv2(self) -> None:
        matches = identify_hash("user::DOMAIN:1122334455667788:abcd:beef")
        assert any(m in (5500, 5600) for m, _ in matches)

    def test_md5crypt_dollar1(self) -> None:
        matches = identify_hash("$1$abcd$1234567890abcdefghij./")
        assert 500 in [m for m, _ in matches]

    def test_sha256crypt_dollar5(self) -> None:
        matches = identify_hash("$5$rounds=5000$saltsalt$hashedhashed")
        assert 7400 in [m for m, _ in matches]

    def test_sha512crypt_dollar6(self) -> None:
        matches = identify_hash("$6$saltsalt$" + "a" * 86)
        assert 1800 in [m for m, _ in matches]

    def test_bcrypt(self) -> None:
        matches = identify_hash("$2y$10$" + "a" * 53)
        assert 3200 in [m for m, _ in matches]

    def test_seven_zip(self) -> None:
        matches = identify_hash("$7z$0$19$0$$8$abcdef$1234")
        assert 11600 in [m for m, _ in matches]

    def test_wordpress_phpass(self) -> None:
        matches = identify_hash("$P$Brrrrrrrrrrrrrrrrrrrrrrrrrrrrrr.")
        assert 400 in [m for m, _ in matches]

    def test_md5_length_match(self) -> None:
        matches = identify_hash("d41d8cd98f00b204e9800998ecf8427e")
        modes = [m for m, _ in matches]
        # 32-hex matches MD5/NTLM/LM family.
        assert any(m in (0, 1000, 3000) for m in modes)

    def test_sha256_length_match(self) -> None:
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert 1400 in [m for m, _ in identify_hash(h)]

    def test_sha512_length_match(self) -> None:
        h = "a" * 128
        assert 1700 in [m for m, _ in identify_hash(h)]

    def test_no_match(self) -> None:
        assert identify_hash("definitely-not-a-hash") == []

    def test_strip_whitespace(self) -> None:
        h = "  d41d8cd98f00b204e9800998ecf8427e  \n"
        assert identify_hash(h)  # non-empty


class TestFindPasswordFiles:
    def test_finds_matching_file(self, tmp_path: Path) -> None:
        target = tmp_path / "sub" / "corp-passwords.txt"
        target.parent.mkdir()
        target.write_text("hunter2\n", encoding="utf-8")
        results = find_password_files("corp", search_path=tmp_path)
        assert target.resolve() in {p.resolve() for p in results}

    def test_ignores_non_matching_files(self, tmp_path: Path) -> None:
        (tmp_path / "other-passwords.txt").write_text("x", encoding="utf-8")
        (tmp_path / "corp-notes.txt").write_text("x", encoding="utf-8")
        assert find_password_files("corp", search_path=tmp_path) == []

    def test_empty_search_path(self, tmp_path: Path) -> None:
        assert find_password_files("ghost", search_path=tmp_path) == []

    def test_finds_multiple(self, tmp_path: Path) -> None:
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        (tmp_path / "a" / "x-passwords.txt").write_text("1", encoding="utf-8")
        (tmp_path / "b" / "x-passwords.txt").write_text("2", encoding="utf-8")
        results = find_password_files("x", search_path=tmp_path)
        assert len(results) == 2
