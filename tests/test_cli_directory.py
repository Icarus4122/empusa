"""Tests for empusa.cli_directory - Phase 21 directory enumeration workflow.

These tests monkeypatch :mod:`empusa.evidentia` so the wrapper itself
is the unit under test. The boundary rules verified here:

- ``cmd_directory_enumerate`` calls ``ingest_directory`` then
  ``replay`` in order;
- artifact paths and top-level summary fields are surfaced verbatim;
- ingest-stage failures abort before replay;
- replay divergence is reported with the diff count and a non-zero
  exit code;
- ``--no-replay`` skips the replay call entirely;
- the wrapper never opens an Evidentia store directly.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from empusa import cli_directory, evidentia


def _ws(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    return ws


def _input(ws: Path, name: str = "export.json", content: str = "{}\n") -> Path:
    p = ws / name
    p.write_text(content, encoding="utf-8")
    return p


def _ok_result(stdout: str = '{"accepted": 3, "failed": 0}\n') -> evidentia.EvidentiaResult:
    return evidentia.EvidentiaResult(
        argv=["evidentia", "--store", "badger", "--path", "x", "ingest", "powershell-ad", "f"],
        exit_code=0,
        stdout=stdout,
        stderr="",
    )


def _replay_result(diffs: str = "") -> evidentia.EvidentiaResult:
    stdout = '{"diffs": [' + diffs + "]}\n" if diffs else '{"diffs": []}\n'
    return evidentia.EvidentiaResult(
        argv=["evidentia", "--store", "badger", "--path", "x", "replay"],
        exit_code=0,
        stdout=stdout,
        stderr="",
    )


def _make_args(
    ws: Path,
    inp: Path,
    *,
    fmt: str = "powershell",
    no_replay: bool = False,
    binary: str | None = None,
    db_path: str | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        workspace=str(ws),
        input=str(inp),
        format=fmt,
        binary=binary,
        db_path=db_path,
        no_replay=no_replay,
    )


def _patch(monkeypatch: pytest.MonkeyPatch, *, ingest_fn=None, replay_fn=None) -> None:
    """Install fakes for ingest_directory + replay; default to AssertionError."""

    def _bang_ingest(**_: object) -> evidentia.IngestOutcome:
        raise AssertionError("ingest_directory must not be called")

    def _bang_replay(**_: object) -> evidentia.ReplayOutcome:
        raise AssertionError("replay must not be called")

    monkeypatch.setattr(
        cli_directory.evidentia,
        "ingest_directory",
        ingest_fn if ingest_fn is not None else _bang_ingest,
    )
    monkeypatch.setattr(
        cli_directory.evidentia,
        "replay",
        replay_fn if replay_fn is not None else _bang_replay,
    )


# ─────────────────────────────────────────────────────────────────


class TestDirectoryEnumerateHappyPath:
    def test_runs_ingest_then_replay_in_order_and_displays_artifacts(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        ws = _ws(tmp_path)
        inp = _input(ws)
        ingest_artifact = ws / "artifacts" / "evidentia" / "ingest-x.json"
        ingest_artifact.parent.mkdir(parents=True)
        ingest_artifact.write_text("{}\n", encoding="utf-8")
        replay_artifact = ws / "artifacts" / "evidentia" / "replay-x.json"
        replay_artifact.write_text("{}\n", encoding="utf-8")

        order: list[str] = []
        ingest_calls: list[dict] = []
        replay_calls: list[dict] = []

        def fake_ingest(*, workspace_path, input_path, fmt, binary, db_path):
            order.append("ingest")
            ingest_calls.append(
                {
                    "workspace_path": workspace_path,
                    "input_path": input_path,
                    "fmt": fmt,
                    "binary": binary,
                    "db_path": db_path,
                }
            )
            return evidentia.IngestOutcome(
                artifact_path=ingest_artifact,
                stderr_path=None,
                result=_ok_result('{"accepted": 7, "failed": 1}\n'),
            )

        def fake_replay(*, workspace_path, binary, db_path, alert):
            order.append("replay")
            replay_calls.append({"alert": alert})
            return evidentia.ReplayOutcome(
                artifact_path=replay_artifact,
                divergence=False,
                diff_count=0,
                result=_replay_result(),
            )

        _patch(monkeypatch, ingest_fn=fake_ingest, replay_fn=fake_replay)

        rc = cli_directory.cmd_directory_enumerate(_make_args(ws, inp))
        out = capsys.readouterr().out
        flat = "".join(out.split())

        assert rc == 0
        assert order == ["ingest", "replay"]
        assert ingest_calls[0]["fmt"] == "powershell"
        assert ingest_calls[0]["workspace_path"] == ws
        assert ingest_calls[0]["input_path"] == inp
        # Both artifact paths are surfaced verbatim.
        assert "".join(str(ingest_artifact).split()) in flat
        assert "".join(str(replay_artifact).split()) in flat
        # Top-level ingest summary fields appear (no payload parsing
        # beyond the documented allowed fields).
        assert "Accepted" in out and "7" in out
        assert "Failed" in out and "1" in out
        assert "Diff count" in out

    def test_format_ldap_routes_to_ldap_subcommand(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ws = _ws(tmp_path)
        inp = _input(ws, "export.ldif", "dn: x\n")
        ingest_artifact = ws / "artifacts" / "evidentia" / "ingest-x.json"
        ingest_artifact.parent.mkdir(parents=True)
        ingest_artifact.write_text("{}\n", encoding="utf-8")
        replay_artifact = ws / "artifacts" / "evidentia" / "replay-x.json"
        replay_artifact.write_text("{}\n", encoding="utf-8")

        seen_fmt: list[str] = []

        def fake_ingest(*, fmt, **_: object) -> evidentia.IngestOutcome:
            seen_fmt.append(fmt)
            return evidentia.IngestOutcome(
                artifact_path=ingest_artifact,
                stderr_path=None,
                result=_ok_result(),
            )

        def fake_replay(**_: object) -> evidentia.ReplayOutcome:
            return evidentia.ReplayOutcome(
                artifact_path=replay_artifact,
                divergence=False,
                diff_count=0,
                result=_replay_result(),
            )

        _patch(monkeypatch, ingest_fn=fake_ingest, replay_fn=fake_replay)

        rc = cli_directory.cmd_directory_enumerate(_make_args(ws, inp, fmt="ldap"))
        assert rc == 0
        assert seen_fmt == ["ldap"]


class TestDirectoryEnumerateFailureModes:
    def test_ingest_failure_aborts_before_replay_and_surfaces_stderr(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        ws = _ws(tmp_path)
        inp = _input(ws)
        stderr_path = ws / "artifacts" / "evidentia" / "ingest-x.stderr"
        stderr_path.parent.mkdir(parents=True)
        stderr_path.write_text("decode failure\n", encoding="utf-8")

        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            raise evidentia.EvidentiaCLIError(
                evidentia.EvidentiaResult(
                    argv=["evidentia"],
                    exit_code=1,
                    stdout="",
                    stderr="decode failure",
                ),
                stderr_path=stderr_path,
            )

        # Replay must NOT be reached; if it is, the AssertionError
        # default in _patch will fire.
        _patch(monkeypatch, ingest_fn=fake_ingest)

        rc = cli_directory.cmd_directory_enumerate(_make_args(ws, inp))
        out = capsys.readouterr().out

        assert rc == 1
        assert "decode failure" in out
        assert stderr_path.name in out

    def test_replay_divergence_returns_1_with_diff_count(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        ws = _ws(tmp_path)
        inp = _input(ws)
        ingest_artifact = ws / "artifacts" / "evidentia" / "ingest-x.json"
        ingest_artifact.parent.mkdir(parents=True)
        ingest_artifact.write_text("{}\n", encoding="utf-8")
        replay_artifact = ws / "artifacts" / "evidentia" / "replay-x.json"
        replay_artifact.write_text("{}\n", encoding="utf-8")

        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            return evidentia.IngestOutcome(
                artifact_path=ingest_artifact,
                stderr_path=None,
                result=_ok_result(),
            )

        def fake_replay(*, alert, **_: object) -> evidentia.ReplayOutcome:
            alert(replay_artifact, 3)
            return evidentia.ReplayOutcome(
                artifact_path=replay_artifact,
                divergence=True,
                diff_count=3,
                result=_replay_result('"x"'),
            )

        _patch(monkeypatch, ingest_fn=fake_ingest, replay_fn=fake_replay)

        rc = cli_directory.cmd_directory_enumerate(_make_args(ws, inp))
        out = capsys.readouterr().out

        assert rc == 1
        assert "Diff count" in out
        assert "3" in out
        assert "diverged" in out.lower() or "divergence" in out.lower()

    def test_missing_workspace_returns_1_without_calling_evidentia(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _patch(monkeypatch)
        args = _make_args(tmp_path / "nope", tmp_path / "x.json")
        rc = cli_directory.cmd_directory_enumerate(args)
        assert rc == 1

    def test_missing_input_returns_1_without_calling_evidentia(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ws = _ws(tmp_path)
        _patch(monkeypatch)
        args = _make_args(ws, ws / "missing.json")
        rc = cli_directory.cmd_directory_enumerate(args)
        assert rc == 1

    def test_binary_not_found_returns_1(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        ws = _ws(tmp_path)
        inp = _input(ws)

        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            raise FileNotFoundError("evidentia binary not found: /no/such/evidentia")

        _patch(monkeypatch, ingest_fn=fake_ingest)
        rc = cli_directory.cmd_directory_enumerate(_make_args(ws, inp))
        out = capsys.readouterr().out

        assert rc == 1
        assert "binary not found" in out.lower()


class TestDirectoryEnumerateNoReplay:
    def test_no_replay_skips_replay_call(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        ws = _ws(tmp_path)
        inp = _input(ws)
        ingest_artifact = ws / "artifacts" / "evidentia" / "ingest-x.json"
        ingest_artifact.parent.mkdir(parents=True)
        ingest_artifact.write_text("{}\n", encoding="utf-8")

        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            return evidentia.IngestOutcome(
                artifact_path=ingest_artifact,
                stderr_path=None,
                result=_ok_result(),
            )

        # Default _bang_replay raises if replay is invoked.
        _patch(monkeypatch, ingest_fn=fake_ingest)

        rc = cli_directory.cmd_directory_enumerate(_make_args(ws, inp, no_replay=True))
        out = capsys.readouterr().out

        assert rc == 0
        assert "replay skipped" in out.lower()


class TestDirectoryEnumerateBoundary:
    def test_does_not_open_evidentia_store_directly(self) -> None:
        """The wrapper module must not import Evidentia internals or
        store backends; only the public ``empusa.evidentia`` bridge is
        allowed (per Phase 19 contract, carried into Phase 21)."""
        import empusa.cli_directory as mod

        src = Path(mod.__file__).read_text(encoding="utf-8")
        # No direct subprocess use, no badger/store imports.
        for forbidden in ("subprocess", "badger", "memstore", "store/"):
            assert forbidden not in src, f"forbidden import token {forbidden!r} present in cli_directory.py"

    def test_only_top_level_summary_fields_are_parsed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """If the ingest stdout contains nested structures, they must
        not appear in operator output -- only the documented top-level
        ``accepted`` / ``failed`` ints are interpreted."""
        ws = _ws(tmp_path)
        inp = _input(ws)
        ingest_artifact = ws / "artifacts" / "evidentia" / "ingest-x.json"
        ingest_artifact.parent.mkdir(parents=True)
        ingest_artifact.write_text("{}\n", encoding="utf-8")
        replay_artifact = ws / "artifacts" / "evidentia" / "replay-x.json"
        replay_artifact.write_text("{}\n", encoding="utf-8")

        nested_stdout = (
            '{"accepted": 2, "failed": 0, '
            '"event_ids": ["evt-secret-1", "evt-secret-2"], '
            '"failure_event_ids": [], '
            '"records_read": 2}\n'
        )

        def fake_ingest(**_: object) -> evidentia.IngestOutcome:
            return evidentia.IngestOutcome(
                artifact_path=ingest_artifact,
                stderr_path=None,
                result=_ok_result(nested_stdout),
            )

        def fake_replay(**_: object) -> evidentia.ReplayOutcome:
            return evidentia.ReplayOutcome(
                artifact_path=replay_artifact,
                divergence=False,
                diff_count=0,
                result=_replay_result(),
            )

        _patch(monkeypatch, ingest_fn=fake_ingest, replay_fn=fake_replay)

        rc = cli_directory.cmd_directory_enumerate(_make_args(ws, inp))
        out = capsys.readouterr().out

        assert rc == 0
        # Documented top-level fields are surfaced.
        assert "Accepted" in out and "2" in out
        assert "Failed" in out
        # Nested fields must not be parsed/displayed.
        assert "evt-secret-1" not in out
        assert "records_read" not in out


# ─────────────────────────────────────────────────────────────────
# Phase 23: directory inspect
# ─────────────────────────────────────────────────────────────────


def _inspect_args(
    ws: Path,
    *,
    type_: str = "users",
    limit: int = 0,
    pretty: bool = False,
    binary: str | None = None,
    db_path: str | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        workspace=str(ws),
        type=type_,
        limit=limit,
        pretty=pretty,
        binary=binary,
        db_path=db_path,
    )


def _inspect_outcome(
    ws: Path,
    subject: str = "users",
    record_count: int = 3,
) -> evidentia.InspectOutcome:
    artifact = ws / "artifacts" / "evidentia" / f"inspect-directory-{subject}-x.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("[]\n", encoding="utf-8")
    return evidentia.InspectOutcome(
        subject=subject,
        artifact_path=artifact,
        record_count=record_count,
        result=evidentia.EvidentiaResult(
            argv=["evidentia", "inspect", "directory", subject],
            exit_code=0,
            stdout="[]\n",
            stderr="",
        ),
    )


class TestDirectoryInspectHappyPath:
    def test_calls_evidentia_wrapper_only_and_persists_artifact(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        ws = _ws(tmp_path)
        calls: list[dict] = []

        def fake_inspect(*, workspace_path, subject, limit, pretty, binary, db_path):
            calls.append(
                dict(
                    workspace_path=workspace_path,
                    subject=subject,
                    limit=limit,
                    pretty=pretty,
                    binary=binary,
                    db_path=db_path,
                )
            )
            return _inspect_outcome(ws, subject=subject, record_count=4)

        # The wrapper must NOT call ingest or replay.
        def _bang(**_: object):
            raise AssertionError("must not be called")

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory", fake_inspect)
        monkeypatch.setattr(cli_directory.evidentia, "ingest_directory", _bang)
        monkeypatch.setattr(cli_directory.evidentia, "replay", _bang)

        rc = cli_directory.cmd_directory_inspect(_inspect_args(ws, type_="users", limit=0))
        out = capsys.readouterr().out

        assert rc == 0
        assert len(calls) == 1
        assert calls[0]["subject"] == "users"
        assert calls[0]["limit"] is None  # 0 normalized to None
        assert calls[0]["pretty"] is False
        # Operator-visible fields.
        assert "Artifact" in out
        assert "Records" in out and "4" in out

    def test_forwards_limit_and_pretty(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ws = _ws(tmp_path)
        captured: dict = {}

        def fake_inspect(*, workspace_path, subject, limit, pretty, binary, db_path):
            captured.update(limit=limit, pretty=pretty)
            return _inspect_outcome(ws, subject=subject)

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory", fake_inspect)

        rc = cli_directory.cmd_directory_inspect(_inspect_args(ws, type_="relationships", limit=5, pretty=True))
        assert rc == 0
        assert captured == {"limit": 5, "pretty": True}


class TestDirectoryInspectErrors:
    def test_unknown_type_returns_2(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ws = _ws(tmp_path)

        def _bang(**_: object):
            raise AssertionError("must not be called")

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory", _bang)

        rc = cli_directory.cmd_directory_inspect(_inspect_args(ws, type_="frobnicate"))
        assert rc == 2

    def test_evidentia_usage_error_propagates_as_2(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ws = _ws(tmp_path)

        def fake_inspect(**_: object):
            raise evidentia.EvidentiaCLIError(
                evidentia.EvidentiaResult(
                    argv=["evidentia", "inspect", "directory", "users"],
                    exit_code=2,
                    stdout="",
                    stderr="usage error",
                )
            )

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory", fake_inspect)

        rc = cli_directory.cmd_directory_inspect(_inspect_args(ws, type_="users"))
        assert rc == 2

    def test_evidentia_runtime_error_returns_1(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ws = _ws(tmp_path)

        def fake_inspect(**_: object):
            raise evidentia.EvidentiaCLIError(
                evidentia.EvidentiaResult(
                    argv=["evidentia", "inspect", "directory", "users"],
                    exit_code=1,
                    stdout="",
                    stderr="runtime",
                )
            )

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory", fake_inspect)

        rc = cli_directory.cmd_directory_inspect(_inspect_args(ws, type_="users"))
        assert rc == 1

    def test_does_not_decode_records(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Empusa must surface the count only -- never per-record fields."""
        ws = _ws(tmp_path)

        def fake_inspect(**_: object):
            outcome = _inspect_outcome(ws, subject="users", record_count=2)
            # Stuff a unique sentinel into the artifact + stdout so a
            # decoder that walks records would necessarily print it.
            outcome.artifact_path.write_text(
                '[{"sam_account_name":"sentinel-leak"}]\n',
                encoding="utf-8",
            )
            return evidentia.InspectOutcome(
                subject=outcome.subject,
                artifact_path=outcome.artifact_path,
                record_count=outcome.record_count,
                result=evidentia.EvidentiaResult(
                    argv=outcome.result.argv,
                    exit_code=0,
                    stdout='[{"sam_account_name":"sentinel-leak"}]\n',
                    stderr="",
                ),
            )

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory", fake_inspect)

        rc = cli_directory.cmd_directory_inspect(_inspect_args(ws, type_="users"))
        assert rc == 0
        assert "sentinel-leak" not in capsys.readouterr().out


# ─────────────────────────────────────────────────────────────────
# Phase 24: directory neighbors / memberships views
# ─────────────────────────────────────────────────────────────────


def _view_args(
    ws: Path,
    *,
    key: str = "dn:cn=alice,dc=corp,dc=local",
    limit: int = 0,
    pretty: bool = False,
    binary: str | None = None,
    db_path: str | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        workspace=str(ws),
        key=key,
        limit=limit,
        pretty=pretty,
        binary=binary,
        db_path=db_path,
    )


def _view_outcome(
    ws: Path,
    *,
    view: str = "neighbors",
    key: str = "dn:cn=alice,dc=corp,dc=local",
    record_count: int = 2,
    stdout: str = "[]\n",
) -> evidentia.InspectViewOutcome:
    artifact = ws / "artifacts" / "evidentia" / f"inspect-directory-{view}-x.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(stdout, encoding="utf-8")
    return evidentia.InspectViewOutcome(
        view=view,
        key=key,
        artifact_path=artifact,
        record_count=record_count,
        result=evidentia.EvidentiaResult(
            argv=["evidentia", "inspect", "directory", view, key],
            exit_code=0,
            stdout=stdout,
            stderr="",
        ),
    )


class TestDirectoryNeighbors:
    def test_calls_only_inspect_directory_view_with_key(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        ws = _ws(tmp_path)
        calls: list[dict] = []

        def fake_view(*, workspace_path, view, key, limit, pretty, binary, db_path):
            calls.append(
                dict(
                    workspace_path=workspace_path,
                    view=view,
                    key=key,
                    limit=limit,
                    pretty=pretty,
                    binary=binary,
                    db_path=db_path,
                )
            )
            return _view_outcome(ws, view=view, key=key, record_count=3)

        def _bang(**_: object):
            raise AssertionError("must not be called")

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory_view", fake_view)
        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory", _bang)
        monkeypatch.setattr(cli_directory.evidentia, "ingest_directory", _bang)
        monkeypatch.setattr(cli_directory.evidentia, "replay", _bang)

        rc = cli_directory.cmd_directory_neighbors(_view_args(ws, key="dn:CN=Admins,DC=corp,DC=local"))
        out = capsys.readouterr().out

        assert rc == 0
        assert len(calls) == 1
        assert calls[0]["view"] == "neighbors"
        assert calls[0]["key"] == "dn:CN=Admins,DC=corp,DC=local"
        assert calls[0]["limit"] is None  # 0 -> None
        assert calls[0]["pretty"] is False
        assert "Artifact" in out
        assert "Records" in out and "3" in out

    def test_forwards_limit_and_pretty(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ws = _ws(tmp_path)
        captured: dict = {}

        def fake_view(*, workspace_path, view, key, limit, pretty, binary, db_path):
            captured.update(view=view, limit=limit, pretty=pretty)
            return _view_outcome(ws, view=view, key=key)

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory_view", fake_view)

        rc = cli_directory.cmd_directory_neighbors(_view_args(ws, limit=5, pretty=True))
        assert rc == 0
        assert captured == {"view": "neighbors", "limit": 5, "pretty": True}


class TestDirectoryMemberships:
    def test_routes_to_memberships_view(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ws = _ws(tmp_path)
        captured: dict = {}

        def fake_view(*, workspace_path, view, key, limit, pretty, binary, db_path):
            captured["view"] = view
            return _view_outcome(ws, view=view, key=key)

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory_view", fake_view)

        rc = cli_directory.cmd_directory_memberships(_view_args(ws))
        assert rc == 0
        assert captured["view"] == "memberships"


class TestDirectoryViewErrors:
    def test_empty_key_returns_2(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ws = _ws(tmp_path)

        def _bang(**_: object):
            raise AssertionError("must not be called")

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory_view", _bang)

        rc = cli_directory.cmd_directory_neighbors(_view_args(ws, key="   "))
        assert rc == 2

    def test_evidentia_usage_error_propagates_as_2(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ws = _ws(tmp_path)

        def fake_view(**_: object):
            raise evidentia.EvidentiaCLIError(
                evidentia.EvidentiaResult(
                    argv=["evidentia", "inspect", "directory", "neighbors"],
                    exit_code=2,
                    stdout="",
                    stderr="usage error",
                )
            )

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory_view", fake_view)

        rc = cli_directory.cmd_directory_neighbors(_view_args(ws))
        assert rc == 2

    def test_evidentia_runtime_error_returns_1(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ws = _ws(tmp_path)

        def fake_view(**_: object):
            raise evidentia.EvidentiaCLIError(
                evidentia.EvidentiaResult(
                    argv=["evidentia", "inspect", "directory", "memberships"],
                    exit_code=1,
                    stdout="",
                    stderr="boom",
                )
            )

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory_view", fake_view)

        rc = cli_directory.cmd_directory_memberships(_view_args(ws))
        assert rc == 1

    def test_does_not_decode_records(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Empusa must surface the count only -- never per-record fields."""
        ws = _ws(tmp_path)

        def fake_view(*, workspace_path, view, key, limit, pretty, binary, db_path):
            payload = '[{"source":"sentinel-leak","target":"x"}]\n'
            return _view_outcome(ws, view=view, key=key, record_count=1, stdout=payload)

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory_view", fake_view)

        rc = cli_directory.cmd_directory_neighbors(_view_args(ws))
        assert rc == 0
        assert "sentinel-leak" not in capsys.readouterr().out


# ─────────────────────────────────────────────────────────────────
# Phase 32: directory aliases (alias-aware identity lookup)
# ─────────────────────────────────────────────────────────────────


def _alias_args(
    ws: Path,
    *,
    value: str = "S-1-5-21-1-2-3-1001",
    kind: str | None = None,
    limit: int = 0,
    pretty: bool = False,
    binary: str | None = None,
    db_path: str | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        workspace=str(ws),
        value=value,
        kind=kind,
        limit=limit,
        pretty=pretty,
        binary=binary,
        db_path=db_path,
    )


def _alias_outcome(
    ws: Path,
    *,
    value: str = "S-1-5-21-1-2-3-1001",
    kind: str | None = None,
    record_count: int = 1,
    stdout: str = '[{"alias_kind":"sid","alias_value":"S-1-5-21-1-2-3-1001"}]\n',
) -> evidentia.InspectAliasOutcome:
    artifact = ws / "artifacts" / "evidentia" / "inspect-directory-aliases.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(stdout, encoding="utf-8")
    argv = ["evidentia", "inspect", "directory", "aliases", value]
    if kind is not None:
        argv.extend(["--kind", kind])
    return evidentia.InspectAliasOutcome(
        value=value,
        kind=kind,
        artifact_path=artifact,
        record_count=record_count,
        result=evidentia.EvidentiaResult(
            argv=argv,
            exit_code=0,
            stdout=stdout,
            stderr="",
        ),
    )


class TestDirectoryAliases:
    def test_calls_inspect_directory_aliases_with_value(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        ws = _ws(tmp_path)
        calls: list[dict] = []

        def fake_aliases(*, workspace_path, value, kind, limit, pretty, binary, db_path):
            calls.append(
                dict(
                    workspace_path=workspace_path,
                    value=value,
                    kind=kind,
                    limit=limit,
                    pretty=pretty,
                    binary=binary,
                    db_path=db_path,
                )
            )
            return _alias_outcome(ws, value=value, kind=kind, record_count=1)

        def _bang(**_: object):
            raise AssertionError("must not be called")

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory_aliases", fake_aliases)
        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory", _bang)
        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory_view", _bang)
        monkeypatch.setattr(cli_directory.evidentia, "ingest_directory", _bang)
        monkeypatch.setattr(cli_directory.evidentia, "replay", _bang)

        rc = cli_directory.cmd_directory_aliases(_alias_args(ws, value="S-1-5-21-1-2-3-1001", kind="sid"))
        out = capsys.readouterr().out

        assert rc == 0
        assert len(calls) == 1
        assert calls[0]["value"] == "S-1-5-21-1-2-3-1001"
        assert calls[0]["kind"] == "sid"
        assert calls[0]["limit"] is None
        assert calls[0]["pretty"] is False
        assert "Artifact" in out
        assert "Records" in out and "1" in out

    def test_kind_optional(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ws = _ws(tmp_path)
        captured: dict = {}

        def fake_aliases(*, workspace_path, value, kind, limit, pretty, binary, db_path):
            captured.update(value=value, kind=kind)
            return _alias_outcome(ws, value=value, kind=kind)

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory_aliases", fake_aliases)

        rc = cli_directory.cmd_directory_aliases(_alias_args(ws, value="alice"))
        assert rc == 0
        assert captured == {"value": "alice", "kind": None}

    def test_empty_value_returns_2(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ws = _ws(tmp_path)

        def _bang(**_: object):
            raise AssertionError("must not be called")

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory_aliases", _bang)

        rc = cli_directory.cmd_directory_aliases(_alias_args(ws, value="   "))
        assert rc == 2

    def test_unknown_kind_returns_2(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ws = _ws(tmp_path)

        def _bang(**_: object):
            raise AssertionError("must not be called")

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory_aliases", _bang)

        rc = cli_directory.cmd_directory_aliases(_alias_args(ws, value="alice", kind="frobnicate"))
        assert rc == 2

    def test_evidentia_usage_error_propagates_as_2(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ws = _ws(tmp_path)

        def fake_aliases(**_: object):
            raise evidentia.EvidentiaCLIError(
                evidentia.EvidentiaResult(
                    argv=["evidentia", "inspect", "directory", "aliases", "x"],
                    exit_code=2,
                    stdout="",
                    stderr="usage error",
                )
            )

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory_aliases", fake_aliases)

        rc = cli_directory.cmd_directory_aliases(_alias_args(ws))
        assert rc == 2

    def test_evidentia_runtime_error_returns_1(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ws = _ws(tmp_path)

        def fake_aliases(**_: object):
            raise evidentia.EvidentiaCLIError(
                evidentia.EvidentiaResult(
                    argv=["evidentia", "inspect", "directory", "aliases", "x"],
                    exit_code=1,
                    stdout="",
                    stderr="boom",
                )
            )

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory_aliases", fake_aliases)

        rc = cli_directory.cmd_directory_aliases(_alias_args(ws))
        assert rc == 1

    def test_does_not_decode_records_beyond_count(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Empusa surfaces only the count -- not per-record alias fields."""
        ws = _ws(tmp_path)

        def fake_aliases(*, workspace_path, value, kind, limit, pretty, binary, db_path):
            payload = (
                '[{"alias_kind":"sid","alias_value":"S-1-5-21-1-2-3-1001",'
                '"canonical_keys":["dn:cn=sentinel-leak,dc=corp,dc=local"],'
                '"principal_kinds":["user"],"claim_count":2,'
                '"evidence_sources":["adapter:secret"],"last_event_seq":42}]\n'
            )
            return _alias_outcome(ws, value=value, kind=kind, record_count=1, stdout=payload)

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory_aliases", fake_aliases)

        rc = cli_directory.cmd_directory_aliases(_alias_args(ws))
        out = capsys.readouterr().out
        assert rc == 0
        assert "sentinel-leak" not in out
        assert "adapter:secret" not in out
        assert "Records" in out and "1" in out

    def test_conflicting_aliases_preserved_in_artifact(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Multiple canonical_keys on one alias entity must NOT be collapsed."""
        ws = _ws(tmp_path)
        payload = (
            '[{"alias_kind":"sid","alias_value":"S-1-5-21-1-2-3-1001",'
            '"canonical_keys":["dn:cn=alice,dc=corp,dc=local",'
            '"dn:cn=bob,dc=corp,dc=local"],'
            '"principal_kinds":["user"],"claim_count":2,'
            '"evidence_sources":["adapter:a","adapter:b"],"last_event_seq":7}]\n'
        )

        def fake_aliases(*, workspace_path, value, kind, limit, pretty, binary, db_path):
            return _alias_outcome(ws, value=value, kind=kind, record_count=1, stdout=payload)

        monkeypatch.setattr(cli_directory.evidentia, "inspect_directory_aliases", fake_aliases)

        rc = cli_directory.cmd_directory_aliases(_alias_args(ws, value="S-1-5-21-1-2-3-1001", kind="sid"))
        assert rc == 0

        # The wrapper persists stdout byte-for-byte; the artifact must
        # carry both canonical_keys exactly as Evidentia produced them.
        artifact = ws / "artifacts" / "evidentia" / "inspect-directory-aliases.json"
        assert artifact.read_text(encoding="utf-8") == payload
