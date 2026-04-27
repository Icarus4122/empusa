"""Tests for the build_run inspection surface (Phase 41).

Covers:

- the wrapper :func:`evidentia.inspect_build_runs` (argv shape,
  byte-for-byte stdout artifact, stderr handling on failure,
  top-level-count-only parsing),
- the operator-facing CLI command
  :func:`cli_evidentia.cmd_evidentia_inspect_build_runs`,
- the boundary contract: Empusa must not parse per-record summary
  fields (the ``BuildRunSummary`` contract is owned by Evidentia),
- top-level dispatcher wiring through ``empusa.cli``.

The ``evidentia`` binary is not invoked. A fake script that mirrors
the documented exit-code contract is materialised on disk so we
exercise the real ``subprocess`` boundary, the real
``--store badger --path <db>`` argv injection, and the real
artifact-on-disk persistence path.
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


# Representative build_run summary array. Per-record fields are
# only here so the byte-for-byte persistence check has something
# meaningful to compare; the wrapper must NOT parse them.
SUMMARY_JSON = (
    "["
    '{"entity_id":"build_run/run_id:r-1","workspace_id":"ws-1","run_id":"r-1",'
    '"source_repo":"empusa","source_tool":"empusa","command_name":"build_env",'
    '"started_at":"2026-04-26T14:00:00Z","completed_at":"2026-04-26T14:00:05Z",'
    '"exit_code":0,"input_artifact_count":1,"output_artifact_count":2,'
    '"log_artifact_count":3,"observation_count":2,"last_event_seq":7},'
    '{"entity_id":"build_run/run_id:r-2","workspace_id":"ws-1","run_id":"r-2",'
    '"source_repo":"empusa","source_tool":"empusa","command_name":"build_env",'
    '"started_at":"2026-04-26T15:00:00Z",'
    '"input_artifact_count":0,"output_artifact_count":0,"log_artifact_count":0,'
    '"observation_count":1,"last_event_seq":9}'
    "]\n"
)


# ── Wrapper: argv shape and contract ──────────────────────────────


class TestInspectBuildRunsWrapper:
    def test_argv_shape_with_backend_flags(self, tmp_path: Path, workspace: Path) -> None:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        argv_log = tmp_path / "argv.txt"
        binary = _write_fake_binary(bindir, stdout=SUMMARY_JSON, record_argv_to=argv_log)

        outcome = evidentia.inspect_build_runs(
            workspace_path=workspace,
            binary=str(binary),
        )

        assert outcome.result.ok
        recorded = argv_log.read_text(encoding="utf-8").splitlines()
        # argv[0] is the binary; backend flags MUST come before the
        # subcommand and the subcommand MUST be exactly
        # ``inspect build-runs`` with no extra positional args.
        assert recorded[1:5] == [
            "--store",
            "badger",
            "--path",
            str(workspace / evidentia.DEFAULT_DB_DIRNAME),
        ]
        assert recorded[5:7] == ["inspect", "build-runs"]
        # The wrapper does not expose --limit/--pretty: those are
        # operator flags on the Evidentia CLI, not part of the
        # wrapper contract. Any trailing argv must be the
        # post-success ``version`` provenance call (no backend flags).
        tail = recorded[7:]
        if tail:
            assert tail[-1] == "version", f"unexpected trailing argv: {tail}"

    def test_success_persists_stdout_byte_for_byte(self, tmp_path: Path, workspace: Path) -> None:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        binary = _write_fake_binary(bindir, stdout=SUMMARY_JSON)

        outcome = evidentia.inspect_build_runs(
            workspace_path=workspace,
            binary=str(binary),
        )

        assert outcome.artifact_path.parent == workspace / evidentia.ARTIFACTS_SUBDIR
        # Filename prefix is distinct from ``inspect-provenance-`` so
        # status rollups can tell the two streams apart.
        assert outcome.artifact_path.name.startswith("inspect-build-runs-")
        assert outcome.artifact_path.read_bytes() == SUMMARY_JSON.encode("utf-8")
        meta_path = outcome.artifact_path.with_suffix(outcome.artifact_path.suffix + ".meta.json")
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        assert meta["exit_code"] == 0
        assert meta["artifact_path"] == str(outcome.artifact_path)

    def test_record_count_is_top_level_array_length(self, tmp_path: Path, workspace: Path) -> None:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        binary = _write_fake_binary(bindir, stdout=SUMMARY_JSON)

        outcome = evidentia.inspect_build_runs(
            workspace_path=workspace,
            binary=str(binary),
        )

        assert outcome.record_count == 2

    def test_record_count_is_none_for_non_array_body(self, tmp_path: Path, workspace: Path) -> None:
        """When the state store has no build_run entities the
        Evidentia CLI emits ``null``; the wrapper must report ``None``
        (not ``0``) so the operator surface stays unambiguous."""
        bindir = tmp_path / "bin"
        bindir.mkdir()
        binary = _write_fake_binary(bindir, stdout="null\n")

        outcome = evidentia.inspect_build_runs(
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
            stderr="evidentia inspect build-runs: store error\n",
            exit_code=1,
        )

        with pytest.raises(evidentia.EvidentiaCLIError) as exc:
            evidentia.inspect_build_runs(
                workspace_path=workspace,
                binary=str(binary),
            )

        err = exc.value
        assert err.result.exit_code == 1
        assert err.stderr_path is not None
        assert err.stderr_path.exists()
        assert err.stderr_path.name.startswith("inspect-build-runs-")
        assert "store error" in err.stderr_path.read_text(encoding="utf-8")
        # No success artifact must have been written.
        art_dir = workspace / evidentia.ARTIFACTS_SUBDIR
        json_artifacts = [p for p in art_dir.glob("inspect-build-runs-*.json") if not p.name.endswith(".meta.json")]
        assert json_artifacts == []

    def test_wrapper_source_does_not_reference_per_record_fields(self) -> None:
        """The wrapper must treat the summary as opaque: only the
        top-level array length is derived. Referencing any of the
        per-record field names would imply Empusa is decoding a
        contract owned by Evidentia."""
        text = Path(evidentia.__file__).read_text(encoding="utf-8")
        match = re.search(
            r"def inspect_build_runs\(.*?(?=\n(?:def |class |@dataclass)|\Z)",
            text,
            flags=re.DOTALL,
        )
        assert match is not None, "could not locate inspect_build_runs source block"
        body = match.group(0)
        for forbidden in (
            "entity_id",
            "workspace_id",
            "run_id",
            "source_tool",
            "source_repo",
            "command_name",
            "started_at",
            "completed_at",
            "exit_code",
            "input_artifact_count",
            "output_artifact_count",
            "log_artifact_count",
            "observation_count",
            "last_event_seq",
            "argv",
        ):
            assert forbidden not in body, f"inspect_build_runs must not reference per-record field {forbidden!r}"


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


class TestCmdEvidentiaInspectBuildRuns:
    def test_success_displays_artifact_and_record_count(
        self,
        workspace: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        artifact = workspace / "artifacts" / "evidentia" / "inspect-build-runs-x.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(SUMMARY_JSON, encoding="utf-8")

        calls: list[dict] = []

        def fake_inspect(*, workspace_path, binary, db_path):
            calls.append({"workspace_path": workspace_path, "binary": binary, "db_path": db_path})
            return evidentia.InspectBuildRunsOutcome(
                artifact_path=artifact,
                record_count=2,
                result=_ok_result(SUMMARY_JSON),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "inspect_build_runs", fake_inspect)

        args = argparse.Namespace(
            workspace=str(workspace),
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_inspect_build_runs(args)
        out = capsys.readouterr().out

        assert rc == 0
        assert len(calls) == 1
        assert calls[0]["workspace_path"] == workspace
        assert calls[0]["binary"] == evidentia.DEFAULT_BINARY
        assert calls[0]["db_path"] is None
        assert artifact.name in out
        assert "Exit code" in out
        assert "Records" in out
        assert "2" in out

    def test_omits_records_when_count_is_none(
        self,
        workspace: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        artifact = workspace / "artifacts" / "evidentia" / "inspect-build-runs-y.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("null\n", encoding="utf-8")

        def fake_inspect(**_: object) -> evidentia.InspectBuildRunsOutcome:
            return evidentia.InspectBuildRunsOutcome(
                artifact_path=artifact,
                record_count=None,
                result=_ok_result("null\n"),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "inspect_build_runs", fake_inspect)

        args = argparse.Namespace(
            workspace=str(workspace),
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_inspect_build_runs(args)
        out = capsys.readouterr().out

        assert rc == 0
        assert "Records" not in out

    def test_failure_surfaces_stderr_path(
        self,
        workspace: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        stderr_path = workspace / "artifacts" / "evidentia" / "inspect-build-runs-x.stderr"
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.write_text("store error\n", encoding="utf-8")

        def fake_inspect(**_: object) -> evidentia.InspectBuildRunsOutcome:
            raise evidentia.EvidentiaCLIError(
                _fail_result(exit_code=1, stderr="store error"),
                stderr_path=stderr_path,
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "inspect_build_runs", fake_inspect)

        args = argparse.Namespace(
            workspace=str(workspace),
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_inspect_build_runs(args)
        out = capsys.readouterr().out

        assert rc == 1
        assert "exit code: 1" in out.lower()
        assert stderr_path.name in out

    def test_missing_workspace_returns_1(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_inspect(**_: object) -> evidentia.InspectBuildRunsOutcome:
            raise AssertionError("inspect_build_runs must not be called")

        monkeypatch.setattr(cli_evidentia.evidentia, "inspect_build_runs", fake_inspect)

        args = argparse.Namespace(
            workspace=str(tmp_path / "nope"),
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_inspect_build_runs(args)
        assert rc == 1


# ── Top-level dispatch via empusa.cli ─────────────────────────────


class TestTopLevelDispatch:
    def test_inspect_build_runs_action_dispatches_to_handler(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from empusa import cli as empusa_cli

        ws = tmp_path / "ws"
        ws.mkdir()

        called: list[argparse.Namespace] = []

        def fake_handler(args: argparse.Namespace) -> int:
            called.append(args)
            return 0

        monkeypatch.setattr(empusa_cli, "cmd_evidentia_inspect_build_runs", fake_handler)
        monkeypatch.setattr(empusa_cli, "_init_framework", lambda: None)
        monkeypatch.setattr(empusa_cli, "_shutdown", lambda: None)

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="cmd")
        cli_evidentia.register_evidentia_parser(sub)

        args = parser.parse_args(["evidentia", "inspect-build-runs", "--workspace", str(ws)])
        rc = empusa_cli._cmd_evidentia(args, parser)

        assert rc == 0
        assert len(called) == 1
        assert called[0].workspace == str(ws)


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
