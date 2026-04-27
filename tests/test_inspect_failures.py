"""Tests for the schema-failure inspection surface (Phase 48).

Covers:

- the wrapper :func:`evidentia.inspect_failures` (argv shape,
  ``--limit`` / ``--pretty`` forwarding, byte-for-byte stdout
  artifact, stderr handling on failure, top-level-count-only
  parsing),
- the operator-facing CLI command
  :func:`cli_evidentia.cmd_evidentia_inspect_failures`,
- the boundary contract: Empusa must not parse per-event fields
  (the ``schema.validation_failed`` event schema is owned by
  Evidentia),
- top-level dispatcher wiring through ``empusa.cli``,
- the troubleshooting documentation now references the Empusa
  wrapper instead of the raw ``evidentia inspect failures`` call.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path

import pytest

from empusa import cli_evidentia, evidentia

# ── Fake binary helpers ───────────────────────────────────────────


def _python_payload(*, stdout: str, stderr: str, exit_code: int, record_argv_to: Path | None) -> str:
    return (
        "import sys, pathlib\n"
        f"stdout = {stdout!r}\n"
        f"stderr = {stderr!r}\n"
        f"exit_code = {exit_code!r}\n"
        f"record = {str(record_argv_to) if record_argv_to else None!r}\n"
        "if record:\n"
        "    with pathlib.Path(record).open('a', encoding='utf-8') as _f:\n"
        "        if _f.tell() > 0:\n"
        "            _f.write('\\n')\n"
        "        _f.write('\\n'.join(sys.argv))\n"
        "if stdout:\n"
        "    sys.stdout.write(stdout)\n"
        "if stderr:\n"
        "    sys.stderr.write(stderr)\n"
        "sys.exit(exit_code)\n"
    )


def _write_fake_binary(
    dirpath: Path,
    *,
    stdout: str = "",
    stderr: str = "",
    exit_code: int = 0,
    record_argv_to: Path | None = None,
) -> Path:
    payload = _python_payload(stdout=stdout, stderr=stderr, exit_code=exit_code, record_argv_to=record_argv_to)
    if os.name == "nt":
        py_path = dirpath / "evidentia_impl.py"
        py_path.write_text(payload, encoding="utf-8")
        bat_path = dirpath / "evidentia.bat"
        bat_path.write_text(
            f'@echo off\r\n"{sys.executable}" "{py_path!s}" %*\r\nexit /b %ERRORLEVEL%\r\n',
            encoding="utf-8",
        )
        return bat_path
    path = dirpath / "evidentia"
    path.write_text(f"#!{sys.executable}\n{payload}", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    return ws


# Representative ``schema.validation_failed`` event array. Per-event
# fields are only here so the byte-for-byte persistence check has
# something meaningful to compare; the wrapper must NOT parse them.
FAILURES_JSON = (
    "["
    '{"event_id":"evt-1","event_type":"schema.validation_failed",'
    '"sequence":3,"timestamp":"2026-04-26T14:00:00Z",'
    '"payload":{"reason":"missing field foo","record_index":2}},'
    '{"event_id":"evt-2","event_type":"schema.validation_failed",'
    '"sequence":4,"timestamp":"2026-04-26T14:00:01Z",'
    '"payload":{"reason":"unknown field bar","record_index":7}}'
    "]\n"
)


# ── Wrapper: argv shape and contract ──────────────────────────────


class TestInspectFailuresWrapper:
    def test_argv_shape_with_backend_flags(self, tmp_path: Path, workspace: Path) -> None:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        argv_log = tmp_path / "argv.txt"
        binary = _write_fake_binary(bindir, stdout=FAILURES_JSON, record_argv_to=argv_log)

        outcome = evidentia.inspect_failures(
            workspace_path=workspace,
            binary=str(binary),
        )

        assert outcome.result.ok
        recorded = argv_log.read_text(encoding="utf-8").splitlines()
        # argv[0] is the binary; backend flags MUST come before the
        # subcommand and the subcommand MUST be exactly
        # ``inspect failures`` with no extra positional args when
        # neither --limit nor --pretty is set.
        assert recorded[1:5] == [
            "--store",
            "badger",
            "--path",
            str(workspace / evidentia.DEFAULT_DB_DIRNAME),
        ]
        assert recorded[5:7] == ["inspect", "failures"]
        # No --limit / --pretty when defaults are used; any trailing
        # argv must be the post-success ``version`` provenance call.
        tail = recorded[7:]
        if tail:
            assert tail[-1] == "version", f"unexpected trailing argv: {tail}"

    def test_limit_and_pretty_are_forwarded(self, tmp_path: Path, workspace: Path) -> None:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        argv_log = tmp_path / "argv.txt"
        binary = _write_fake_binary(bindir, stdout=FAILURES_JSON, record_argv_to=argv_log)

        evidentia.inspect_failures(
            workspace_path=workspace,
            limit=5,
            pretty=True,
            binary=str(binary),
        )

        recorded = argv_log.read_text(encoding="utf-8").splitlines()
        assert recorded[5:7] == ["inspect", "failures"]
        # Order between --limit and --pretty is fixed by the
        # wrapper: --limit first, then --pretty.
        assert recorded[7:11] == ["--limit", "5", "--pretty"] or recorded[7:10] == [
            "--limit",
            "5",
            "--pretty",
        ], f"unexpected argv tail: {recorded[7:]}"

    def test_limit_zero_is_not_forwarded(self, tmp_path: Path, workspace: Path) -> None:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        argv_log = tmp_path / "argv.txt"
        binary = _write_fake_binary(bindir, stdout=FAILURES_JSON, record_argv_to=argv_log)

        evidentia.inspect_failures(
            workspace_path=workspace,
            limit=0,
            binary=str(binary),
        )

        recorded = argv_log.read_text(encoding="utf-8").splitlines()
        assert "--limit" not in recorded
        assert "--pretty" not in recorded

    def test_negative_limit_raises(self, workspace: Path) -> None:
        with pytest.raises(ValueError):
            evidentia.inspect_failures(workspace_path=workspace, limit=-1)

    def test_success_persists_stdout_byte_for_byte(self, tmp_path: Path, workspace: Path) -> None:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        binary = _write_fake_binary(bindir, stdout=FAILURES_JSON)

        outcome = evidentia.inspect_failures(
            workspace_path=workspace,
            binary=str(binary),
        )

        assert outcome.artifact_path.parent == workspace / evidentia.ARTIFACTS_SUBDIR
        # Filename prefix is distinct from other inspect streams so
        # status rollups can tell them apart.
        assert outcome.artifact_path.name.startswith("inspect-failures-")
        assert outcome.artifact_path.read_bytes() == FAILURES_JSON.encode("utf-8")
        meta_path = outcome.artifact_path.with_suffix(outcome.artifact_path.suffix + ".meta.json")
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        assert meta["exit_code"] == 0
        assert meta["artifact_path"] == str(outcome.artifact_path)

    def test_record_count_is_top_level_array_length(self, tmp_path: Path, workspace: Path) -> None:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        binary = _write_fake_binary(bindir, stdout=FAILURES_JSON)

        outcome = evidentia.inspect_failures(
            workspace_path=workspace,
            binary=str(binary),
        )

        assert outcome.record_count == 2

    def test_record_count_is_none_for_non_array_body(self, tmp_path: Path, workspace: Path) -> None:
        """When no failure events are present the Evidentia CLI may
        emit ``null``; the wrapper must report ``None`` (not ``0``)
        so the operator surface stays unambiguous."""
        bindir = tmp_path / "bin"
        bindir.mkdir()
        binary = _write_fake_binary(bindir, stdout="null\n")

        outcome = evidentia.inspect_failures(
            workspace_path=workspace,
            binary=str(binary),
        )

        assert outcome.record_count is None
        assert outcome.artifact_path.read_bytes() == b"null\n"

    def test_failure_persists_stderr_and_raises(self, tmp_path: Path, workspace: Path) -> None:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        binary = _write_fake_binary(
            bindir,
            stdout="",
            stderr="evidentia inspect failures: store error\n",
            exit_code=1,
        )

        with pytest.raises(evidentia.EvidentiaCLIError) as exc:
            evidentia.inspect_failures(
                workspace_path=workspace,
                binary=str(binary),
            )

        err = exc.value
        assert err.result.exit_code == 1
        assert err.stderr_path is not None
        assert err.stderr_path.exists()
        assert err.stderr_path.name.startswith("inspect-failures-")
        assert "store error" in err.stderr_path.read_text(encoding="utf-8")
        # No success artifact must have been written.
        art_dir = workspace / evidentia.ARTIFACTS_SUBDIR
        json_artifacts = [p for p in art_dir.glob("inspect-failures-*.json") if not p.name.endswith(".meta.json")]
        assert json_artifacts == []

    def test_wrapper_source_does_not_reference_per_event_fields(self) -> None:
        """The wrapper must treat the failures array as opaque: only
        the top-level array length is derived. Referencing any
        per-event field name would imply Empusa is decoding a
        contract owned by Evidentia."""
        text = Path(evidentia.__file__).read_text(encoding="utf-8")
        match = re.search(
            r"def inspect_failures\(.*?(?=\n(?:def |class |@dataclass)|\Z)",
            text,
            flags=re.DOTALL,
        )
        assert match is not None, "could not locate inspect_failures source block"
        body = match.group(0)
        for forbidden in (
            "event_id",
            "event_type",
            "sequence",
            "timestamp",
            "schema.validation_failed",
            "reason",
            "record_index",
        ):
            assert forbidden not in body, f"inspect_failures must not reference per-event field {forbidden!r}"


# ── CLI dispatch ──────────────────────────────────────────────────


def _ok_result(stdout: str = "[]\n") -> evidentia.EvidentiaResult:
    return evidentia.EvidentiaResult(
        argv=["evidentia", "--store", "badger", "--path", "x"],
        exit_code=0,
        stdout=stdout,
        stderr="",
    )


def _fail_result(exit_code: int = 1, stderr: str = "boom") -> evidentia.EvidentiaResult:
    return evidentia.EvidentiaResult(
        argv=["evidentia", "--store", "badger", "--path", "x"],
        exit_code=exit_code,
        stdout="",
        stderr=stderr,
    )


class TestCmdEvidentiaInspectFailures:
    def test_success_displays_artifact_and_record_count(
        self,
        workspace: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        artifact = workspace / "artifacts" / "evidentia" / "inspect-failures-x.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(FAILURES_JSON, encoding="utf-8")

        calls: list[dict] = []

        def fake_inspect(*, workspace_path, limit, pretty, binary, db_path):
            calls.append(
                {
                    "workspace_path": workspace_path,
                    "limit": limit,
                    "pretty": pretty,
                    "binary": binary,
                    "db_path": db_path,
                }
            )
            return evidentia.InspectFailuresOutcome(
                artifact_path=artifact,
                record_count=2,
                result=_ok_result(FAILURES_JSON),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "inspect_failures", fake_inspect)

        args = argparse.Namespace(
            workspace=str(workspace),
            limit=0,
            pretty=False,
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_inspect_failures(args)
        out = capsys.readouterr().out

        assert rc == 0
        assert len(calls) == 1
        assert calls[0]["workspace_path"] == workspace
        assert calls[0]["binary"] == evidentia.DEFAULT_BINARY
        assert calls[0]["db_path"] is None
        assert calls[0]["limit"] is None
        assert calls[0]["pretty"] is False
        assert artifact.name in out
        assert "Exit code" in out
        assert "Records" in out
        assert "2" in out

    def test_forwards_limit_and_pretty(
        self,
        workspace: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        artifact = workspace / "artifacts" / "evidentia" / "inspect-failures-x.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(FAILURES_JSON, encoding="utf-8")

        calls: list[dict] = []

        def fake_inspect(*, workspace_path, limit, pretty, binary, db_path):
            calls.append({"limit": limit, "pretty": pretty})
            return evidentia.InspectFailuresOutcome(
                artifact_path=artifact,
                record_count=2,
                result=_ok_result(FAILURES_JSON),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "inspect_failures", fake_inspect)

        args = argparse.Namespace(
            workspace=str(workspace),
            limit=10,
            pretty=True,
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_inspect_failures(args)

        assert rc == 0
        assert calls == [{"limit": 10, "pretty": True}]

    def test_omits_records_when_count_is_none(
        self,
        workspace: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        artifact = workspace / "artifacts" / "evidentia" / "inspect-failures-y.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("null\n", encoding="utf-8")

        def fake_inspect(**_: object) -> evidentia.InspectFailuresOutcome:
            return evidentia.InspectFailuresOutcome(
                artifact_path=artifact,
                record_count=None,
                result=_ok_result("null\n"),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "inspect_failures", fake_inspect)

        args = argparse.Namespace(
            workspace=str(workspace),
            limit=0,
            pretty=False,
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_inspect_failures(args)
        out = capsys.readouterr().out

        assert rc == 0
        assert "Records" not in out

    def test_failure_surfaces_stderr_path(
        self,
        workspace: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        stderr_path = workspace / "artifacts" / "evidentia" / "inspect-failures-x.stderr"
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.write_text("store error\n", encoding="utf-8")

        def fake_inspect(**_: object) -> evidentia.InspectFailuresOutcome:
            raise evidentia.EvidentiaCLIError(
                _fail_result(exit_code=1, stderr="store error"),
                stderr_path=stderr_path,
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "inspect_failures", fake_inspect)

        args = argparse.Namespace(
            workspace=str(workspace),
            limit=0,
            pretty=False,
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_inspect_failures(args)
        out = capsys.readouterr().out

        assert rc == 1
        assert "exit code: 1" in out.lower()
        assert stderr_path.name in out

    def test_missing_workspace_returns_1(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_inspect(**_: object) -> evidentia.InspectFailuresOutcome:
            raise AssertionError("inspect_failures must not be called")

        monkeypatch.setattr(cli_evidentia.evidentia, "inspect_failures", fake_inspect)

        args = argparse.Namespace(
            workspace=str(tmp_path / "nope"),
            limit=0,
            pretty=False,
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_inspect_failures(args)
        assert rc == 1


# ── Top-level dispatch via empusa.cli ─────────────────────────────


class TestTopLevelDispatch:
    def test_inspect_failures_action_dispatches_to_handler(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from empusa import cli as empusa_cli

        ws = tmp_path / "ws"
        ws.mkdir()

        called: list[argparse.Namespace] = []

        def fake_handler(args: argparse.Namespace) -> int:
            called.append(args)
            return 0

        monkeypatch.setattr(empusa_cli, "cmd_evidentia_inspect_failures", fake_handler)
        monkeypatch.setattr(empusa_cli, "_init_framework", lambda: None)
        monkeypatch.setattr(empusa_cli, "_shutdown", lambda: None)

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="cmd")
        cli_evidentia.register_evidentia_parser(sub)

        args = parser.parse_args(
            [
                "evidentia",
                "inspect-failures",
                "--workspace",
                str(ws),
                "--limit",
                "3",
                "--pretty",
            ]
        )
        rc = empusa_cli._cmd_evidentia(args, parser)

        assert rc == 0
        assert len(called) == 1
        assert called[0].workspace == str(ws)
        assert called[0].limit == 3
        assert called[0].pretty is True


# ── Boundary discipline ───────────────────────────────────────────


class TestBoundaryDiscipline:
    def test_no_evidentia_or_badger_imports_in_empusa_modules(self) -> None:
        forbidden_substrings = (
            "evidentia.pkg",
            "Evidentia.pkg",
            "github.com/Icarus4122/Evidentia",
            "badger",
            "bsddb",
        )
        for mod_path in (Path(evidentia.__file__), Path(cli_evidentia.__file__)):
            text = mod_path.read_text(encoding="utf-8")
            for line in text.splitlines():
                stripped = line.lstrip()
                if not (stripped.startswith("import ") or stripped.startswith("from ")):
                    continue
                lowered = stripped.lower()
                for bad in forbidden_substrings:
                    assert bad.lower() not in lowered, f"forbidden import substring {bad!r} in {mod_path}: {stripped!r}"


# ── Documentation contract ────────────────────────────────────────


class TestTroubleshootingDocReferencesWrapper:
    """The Phase 48 exit criterion is that the troubleshooting doc no
    longer instructs the operator to drop to the raw ``evidentia``
    binary for schema-failure inspection. The wrapper is the
    canonical entry point."""

    def _doc_path(self) -> Path:
        # tests/ -> repo root -> docs/troubleshooting-evidentia.md
        return Path(__file__).resolve().parent.parent / "docs" / "troubleshooting-evidentia.md"

    def test_doc_exists(self) -> None:
        assert self._doc_path().exists(), "troubleshooting-evidentia.md must exist"

    def test_doc_uses_empusa_wrapper_for_schema_failures(self) -> None:
        text = self._doc_path().read_text(encoding="utf-8")
        # The Empusa wrapper must be the documented entry point.
        assert "empusa evidentia inspect-failures" in text
        # The previously-recommended raw invocation pattern that
        # forced the operator to shell directly to ``evidentia``
        # must be gone from the schema-failure remediation steps.
        assert "evidentia --store badger --path" not in text
