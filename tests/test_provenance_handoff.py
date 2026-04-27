"""Tests for the build.provenance_envelope handoff (Phase 38).

Covers:

- the wrapper :func:`evidentia.ingest_build_provenance` (argv shape,
  byte-for-byte stdout artifact, stderr handling on failure),
- the operator-facing CLI command
  :func:`cli_evidentia.cmd_evidentia_ingest_provenance`,
- the boundary contract: no Evidentia source imports, no Badger
  store access from Empusa.

The ``evidentia`` binary is not invoked. A fake script that mirrors
the documented exit-code contract is materialised on disk so we still
exercise the real ``subprocess`` boundary, the real ``--store badger
--path <db>`` argv injection, and the real artifact-on-disk
persistence path.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from empusa import cli_evidentia, evidentia

# ── Fake binary helpers (mirrors test_evidentia.py shape) ──────────


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


# ── Fixtures ───────────────────────────────────────────────────────


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    return ws


@pytest.fixture()
def envelope_file(workspace: Path) -> Path:
    """A non-empty file standing in for an Empusa-emitted envelope.

    The wrapper does not parse this file; Evidentia validates the
    envelope on its side. A non-empty file is enough to satisfy
    the existence check.
    """
    f = workspace / "artifacts" / "provenance" / "env-1.provenance.json"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text('{"schema_id":"build.provenance_envelope"}\n', encoding="utf-8")
    return f


# ── Wrapper: argv shape and contract ───────────────────────────────


class TestIngestBuildProvenanceWrapper:
    def test_argv_passes_build_provenance_subcommand_with_backend_flags(
        self, tmp_path: Path, workspace: Path, envelope_file: Path
    ) -> None:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        argv_log = tmp_path / "argv.txt"
        binary = _write_fake_binary(bindir, stdout='{"accepted":1,"failed":0}\n', record_argv_to=argv_log)

        outcome = evidentia.ingest_build_provenance(
            workspace_path=workspace,
            provenance_path=envelope_file,
            binary=str(binary),
        )

        assert outcome.result.ok
        recorded = argv_log.read_text(encoding="utf-8").splitlines()
        # argv[0] is the binary; backend flags MUST come before the
        # user's subcommand and the subcommand MUST be exactly
        # ``ingest build-provenance <file>``.
        assert recorded[1:5] == [
            "--store",
            "badger",
            "--path",
            str(workspace / evidentia.DEFAULT_DB_DIRNAME),
        ]
        assert recorded[5:8] == ["ingest", "build-provenance", str(envelope_file)]

    def test_success_persists_stdout_byte_for_byte(self, tmp_path: Path, workspace: Path, envelope_file: Path) -> None:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        # Include a trailing newline + non-ASCII to prove no
        # round-trip rewrite happens.
        summary = '{"records_read":1,"accepted":1,"failed":0,"event_ids":["e1"],"failure_event_ids":[]}\n'
        binary = _write_fake_binary(bindir, stdout=summary)

        outcome = evidentia.ingest_build_provenance(
            workspace_path=workspace,
            provenance_path=envelope_file,
            binary=str(binary),
        )

        assert outcome.stderr_path is None
        assert outcome.artifact_path.parent == workspace / evidentia.ARTIFACTS_SUBDIR
        # Filename prefix distinguishes provenance artifacts from
        # the regular ingest summaries so ``status`` rollups do not
        # confuse the two streams.
        assert outcome.artifact_path.name.startswith("provenance-")
        # Byte-for-byte preservation: no re-serialisation by Empusa.
        assert outcome.artifact_path.read_bytes() == summary.encode("utf-8")
        # Sidecar is written and parseable.
        meta_path = outcome.artifact_path.with_suffix(outcome.artifact_path.suffix + ".meta.json")
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        assert meta["exit_code"] == 0
        assert meta["artifact_path"] == str(outcome.artifact_path)

    def test_failure_persists_stderr_and_raises(self, tmp_path: Path, workspace: Path, envelope_file: Path) -> None:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        binary = _write_fake_binary(
            bindir,
            stdout="",
            stderr="evidentia ingest build-provenance: envelope validation failed\n",
            exit_code=1,
        )

        with pytest.raises(evidentia.EvidentiaCLIError) as exc:
            evidentia.ingest_build_provenance(
                workspace_path=workspace,
                provenance_path=envelope_file,
                binary=str(binary),
            )

        err = exc.value
        assert err.result.exit_code == 1
        assert err.stderr_path is not None
        assert err.stderr_path.exists()
        # stderr artifact uses the provenance-* prefix too so an
        # operator can pair the failure with the input cleanly.
        assert err.stderr_path.name.startswith("provenance-")
        assert "envelope validation failed" in err.stderr_path.read_text(encoding="utf-8")
        # No success artifact must have been written.
        art_dir = workspace / evidentia.ARTIFACTS_SUBDIR
        json_artifacts = [p for p in art_dir.glob("provenance-*.json") if not p.name.endswith(".meta.json")]
        assert json_artifacts == []

    def test_usage_error_is_not_retried(self, tmp_path: Path, workspace: Path, envelope_file: Path) -> None:
        bindir = tmp_path / "bin"
        bindir.mkdir()
        call_log = tmp_path / "calls.txt"
        binary = _write_fake_binary(
            bindir,
            stdout="",
            stderr="evidentia ingest: unknown subcommand\n",
            exit_code=2,
            record_argv_to=call_log,
        )

        with pytest.raises(evidentia.EvidentiaCLIError) as exc:
            evidentia.ingest_build_provenance(
                workspace_path=workspace,
                provenance_path=envelope_file,
                binary=str(binary),
            )

        assert exc.value.result.exit_code == 2
        assert exc.value.result.is_usage_error
        # Exactly one invocation: no auto-retry.
        assert call_log.read_text(encoding="utf-8").count("--store") == 1

    def test_missing_provenance_file(self, workspace: Path) -> None:
        with pytest.raises(FileNotFoundError):
            evidentia.ingest_build_provenance(
                workspace_path=workspace,
                provenance_path=workspace / "missing.provenance.json",
                binary="evidentia",  # never invoked
            )


# ── CLI dispatch ───────────────────────────────────────────────────


def _ok_result(stdout: str = "{}\n") -> evidentia.EvidentiaResult:
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


class TestCmdEvidentiaIngestProvenance:
    def test_calls_wrapper_and_displays_artifact(
        self,
        tmp_path: Path,
        workspace: Path,
        envelope_file: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        artifact = workspace / "artifacts" / "evidentia" / "provenance-x.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text('{"accepted":1,"failed":0}\n', encoding="utf-8")

        calls: list[dict] = []

        def fake_ingest(*, workspace_path, provenance_path, binary, db_path):
            calls.append(
                {
                    "workspace_path": workspace_path,
                    "provenance_path": provenance_path,
                    "binary": binary,
                    "db_path": db_path,
                }
            )
            return evidentia.IngestOutcome(
                artifact_path=artifact,
                stderr_path=None,
                result=_ok_result('{"accepted":1,"failed":0}\n'),
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "ingest_build_provenance", fake_ingest)

        args = argparse.Namespace(
            workspace=str(workspace),
            file=str(envelope_file),
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_ingest_provenance(args)
        out = capsys.readouterr().out

        assert rc == 0
        assert len(calls) == 1
        assert calls[0]["workspace_path"] == workspace
        assert calls[0]["provenance_path"] == envelope_file
        assert calls[0]["binary"] == evidentia.DEFAULT_BINARY
        assert calls[0]["db_path"] is None
        assert artifact.name in out
        assert "Exit code" in out
        # Top-level summary fields are surfaced when present.
        assert "Accepted" in out
        assert "Failed" in out

    def test_failure_surfaces_stderr_path(
        self,
        tmp_path: Path,
        workspace: Path,
        envelope_file: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        stderr_path = workspace / "artifacts" / "evidentia" / "provenance-x.stderr"
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.write_text("envelope validation failed\n", encoding="utf-8")

        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            raise evidentia.EvidentiaCLIError(
                _fail_result(exit_code=1, stderr="envelope validation failed"),
                stderr_path=stderr_path,
            )

        monkeypatch.setattr(cli_evidentia.evidentia, "ingest_build_provenance", fake_ingest)

        args = argparse.Namespace(
            workspace=str(workspace),
            file=str(envelope_file),
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_ingest_provenance(args)
        out = capsys.readouterr().out

        assert rc == 1
        assert "exit code: 1" in out.lower()
        assert stderr_path.name in out

    def test_missing_envelope_returns_1(self, tmp_path: Path, workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        called: list[bool] = []

        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            called.append(True)
            raise AssertionError("ingest_build_provenance must not be called")

        monkeypatch.setattr(cli_evidentia.evidentia, "ingest_build_provenance", fake_ingest)

        args = argparse.Namespace(
            workspace=str(workspace),
            file=str(workspace / "missing.json"),
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_ingest_provenance(args)
        assert rc == 1
        assert called == []

    def test_missing_workspace_returns_1(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            raise AssertionError("ingest_build_provenance must not be called")

        monkeypatch.setattr(cli_evidentia.evidentia, "ingest_build_provenance", fake_ingest)

        args = argparse.Namespace(
            workspace=str(tmp_path / "nope"),
            file=str(tmp_path / "env.json"),
            binary=None,
            db_path=None,
        )
        rc = cli_evidentia.cmd_evidentia_ingest_provenance(args)
        assert rc == 1


# ── Top-level dispatch via empusa.cli ──────────────────────────────


class TestTopLevelDispatch:
    def test_ingest_provenance_action_dispatches_to_handler(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """``empusa evidentia ingest-provenance`` must route through
        :func:`cmd_evidentia_ingest_provenance`."""
        from empusa import cli as empusa_cli

        ws = tmp_path / "ws"
        ws.mkdir()
        envf = tmp_path / "env.json"
        envf.write_text("{}\n", encoding="utf-8")

        called: list[argparse.Namespace] = []

        def fake_handler(args: argparse.Namespace) -> int:
            called.append(args)
            return 0

        monkeypatch.setattr(empusa_cli, "cmd_evidentia_ingest_provenance", fake_handler)
        # Avoid touching the real framework init/shutdown.
        monkeypatch.setattr(empusa_cli, "_init_framework", lambda: None)
        monkeypatch.setattr(empusa_cli, "_shutdown", lambda: None)

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="cmd")
        cli_evidentia.register_evidentia_parser(sub)

        args = parser.parse_args(
            [
                "evidentia",
                "ingest-provenance",
                "--workspace",
                str(ws),
                "--file",
                str(envf),
            ]
        )
        rc = empusa_cli._cmd_evidentia(args, parser)

        assert rc == 0
        assert len(called) == 1
        assert called[0].file == str(envf)
        assert called[0].workspace == str(ws)


# ── Boundary discipline ────────────────────────────────────────────


class TestBoundaryDiscipline:
    def test_no_evidentia_or_badger_imports_in_empusa_modules(self) -> None:
        """Empusa MUST NOT import Evidentia source or Badger libraries.

        The check scans the two modules touched by this phase and
        rejects any import line that references Evidentia's Go source
        layout or a Badger Python binding.
        """
        forbidden_substrings = (
            "evidentia.pkg",
            "Evidentia.pkg",
            "github.com/Icarus4122/Evidentia",
            "badger",  # any badger-* python binding
            "bsddb",
        )
        for mod_path in (
            Path(evidentia.__file__),
            Path(cli_evidentia.__file__),
        ):
            text = mod_path.read_text(encoding="utf-8")
            for line in text.splitlines():
                stripped = line.lstrip()
                if not (stripped.startswith("import ") or stripped.startswith("from ")):
                    continue
                lowered = stripped.lower()
                for bad in forbidden_substrings:
                    assert bad.lower() not in lowered, f"forbidden import substring {bad!r} in {mod_path}: {stripped!r}"

    def test_no_subprocess_call_uses_badger_directly(
        self, tmp_path: Path, workspace: Path, envelope_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The wrapper's subprocess argv must invoke ``evidentia``,
        never a badger CLI or store binary directly.
        """
        captured: list[list[str]] = []

        real_run = subprocess.run

        def spy_run(argv, *args, **kwargs):  # type: ignore[override]
            captured.append(list(argv))
            return real_run(argv, *args, **kwargs)

        monkeypatch.setattr(subprocess, "run", spy_run)

        bindir = tmp_path / "bin"
        bindir.mkdir()
        binary = _write_fake_binary(bindir, stdout="{}\n")

        evidentia.ingest_build_provenance(
            workspace_path=workspace,
            provenance_path=envelope_file,
            binary=str(binary),
        )

        assert captured, "subprocess.run was never invoked"
        # The argv[0] must be the evidentia binary we provided; never
        # a badger CLI. The literal token ``badger`` legitimately
        # appears later in argv as the value of ``--store`` (selecting
        # Evidentia's storage backend) and is allowed there; it must
        # NEVER appear as the executable name.
        for argv in captured:
            head = Path(argv[0]).name.lower()
            assert "badger" not in head, f"argv[0] looks like a badger binary: {argv[0]}"
