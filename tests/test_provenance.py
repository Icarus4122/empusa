"""Tests for empusa.provenance — build/workshop provenance envelope emission.

Covers:
- Envelope construction defaults and validation rules
- Wire shape compatibility with Evidentia build.provenance_envelope
- Argv redaction
- Workspace-id determinism
- Artifact write path under workspace logs/
- build_env() integration: envelope artifact appears, build behavior unchanged
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from empusa.cli_common import CONFIG, clear_active_workspace
from empusa.provenance import (
    SCHEMA_ID,
    SCHEMA_VERSION,
    EvidenceSource,
    ProvenanceEnvelope,
    _derive_workspace_id,
    _redact_argv,
    build_envelope,
    emit_build_envelope,
    write_envelope,
)

# ── helpers ──────────────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def _reset_config() -> Any:
    saved = {k: CONFIG[k] for k in CONFIG}
    clear_active_workspace()
    CONFIG["dry_run"] = False
    CONFIG["quiet"] = True
    yield
    for k, v in saved.items():
        CONFIG[k] = v


# ═══════════════════════════════════════════════════════════════════
#  Envelope construction
# ═══════════════════════════════════════════════════════════════════


class TestBuildEnvelopeDefaults:
    def test_required_fields_populated(self, tmp_path: Path) -> None:
        env = build_envelope(command_name="build_env", workspace_path=tmp_path)
        assert env.envelope_id
        assert env.workspace_id
        assert env.run_id
        assert env.source_repo == "empusa"
        assert env.source_tool == "empusa"
        assert env.command_name == "build_env"
        assert env.hostname
        assert env.started_at is not None
        assert env.evidence_source.source_id
        assert env.evidence_source.source_type == "empusa.build"
        assert 0.0 <= env.confidence <= 1.0

    def test_validation_passes_on_defaults(self, tmp_path: Path) -> None:
        env = build_envelope(command_name="build_env", workspace_path=tmp_path)
        env.validate()  # must not raise

    def test_started_at_is_utc(self, tmp_path: Path) -> None:
        env = build_envelope(command_name="build_env", workspace_path=tmp_path)
        assert env.started_at.tzinfo is not None
        assert env.started_at.utcoffset() == timedelta(0)

    def test_completed_at_requires_exit_code(self, tmp_path: Path) -> None:
        started = _now()
        with pytest.raises(ValueError, match="exit_code"):
            ProvenanceEnvelope(
                envelope_id="e",
                workspace_id="w",
                run_id="r",
                source_repo="empusa",
                source_tool="empusa",
                command_name="build",
                hostname="h",
                started_at=started,
                evidence_source=EvidenceSource(
                    source_id="s", source_type="empusa.build", source_name="empusa@x", collected_at=started
                ),
                confidence=1.0,
                completed_at=started + timedelta(seconds=1),
                exit_code=None,
            ).validate()

    def test_completed_before_started_rejected(self, tmp_path: Path) -> None:
        started = _now()
        with pytest.raises(ValueError, match="before started_at"):
            ProvenanceEnvelope(
                envelope_id="e",
                workspace_id="w",
                run_id="r",
                source_repo="empusa",
                source_tool="empusa",
                command_name="build",
                hostname="h",
                started_at=started,
                evidence_source=EvidenceSource(
                    source_id="s", source_type="empusa.build", source_name="empusa@x", collected_at=started
                ),
                confidence=1.0,
                completed_at=started - timedelta(seconds=1),
                exit_code=0,
            ).validate()

    def test_confidence_bounds(self) -> None:
        started = _now()
        with pytest.raises(ValueError, match="confidence"):
            ProvenanceEnvelope(
                envelope_id="e",
                workspace_id="w",
                run_id="r",
                source_repo="empusa",
                source_tool="empusa",
                command_name="build",
                hostname="h",
                started_at=started,
                evidence_source=EvidenceSource(
                    source_id="s", source_type="empusa.build", source_name="empusa@x", collected_at=started
                ),
                confidence=1.5,
            ).validate()


# ═══════════════════════════════════════════════════════════════════
#  Wire shape (Evidentia compatibility)
# ═══════════════════════════════════════════════════════════════════


class TestWireShape:
    def test_self_describing_keys_present(self, tmp_path: Path) -> None:
        env = build_envelope(command_name="build_env", workspace_path=tmp_path)
        body = env.to_json()
        assert body["schema_id"] == SCHEMA_ID
        assert body["schema_version"] == SCHEMA_VERSION
        assert body["schema_id"] == "build.provenance_envelope"
        assert body["schema_version"] == "1.0.0"

    def test_id_fields_use_value_subobject(self, tmp_path: Path) -> None:
        env = build_envelope(command_name="build_env", workspace_path=tmp_path)
        body = env.to_json()
        for key in ("envelope_id", "workspace_id", "run_id"):
            assert isinstance(body[key], dict), f"{key} should be a typed object"
            assert "value" in body[key]
            assert body[key]["value"] == getattr(env, key)

    def test_timestamp_uses_time_subobject(self, tmp_path: Path) -> None:
        env = build_envelope(command_name="build_env", workspace_path=tmp_path)
        body = env.to_json()
        assert "time" in body["started_at"]
        assert body["started_at"]["time"].endswith("Z")

    def test_confidence_uses_value_subobject(self, tmp_path: Path) -> None:
        env = build_envelope(command_name="build_env", workspace_path=tmp_path)
        body = env.to_json()
        assert body["confidence"] == {"value": env.confidence}

    def test_evidence_source_shape(self, tmp_path: Path) -> None:
        env = build_envelope(command_name="build_env", workspace_path=tmp_path)
        body = env.to_json()
        es = body["evidence_source"]
        assert es["source_id"] == {"value": env.evidence_source.source_id}
        assert es["source_type"] == "empusa.build"
        assert es["source_name"].startswith("empusa@")
        assert "time" in es["collected_at"]

    def test_artifact_refs_are_typed(self, tmp_path: Path) -> None:
        env = build_envelope(
            command_name="build_env",
            workspace_path=tmp_path,
            output_artifact_refs=["a", "b"],
            log_artifact_refs=["c"],
        )
        body = env.to_json()
        assert body["output_artifact_refs"] == [{"value": "a"}, {"value": "b"}]
        assert body["log_artifact_refs"] == [{"value": "c"}]

    def test_completed_at_omitted_when_absent(self, tmp_path: Path) -> None:
        env = build_envelope(command_name="build_env", workspace_path=tmp_path)
        body = env.to_json()
        assert "completed_at" not in body
        assert "exit_code" not in body

    def test_completed_at_present_when_set(self, tmp_path: Path) -> None:
        started = _now()
        env = build_envelope(
            command_name="build_env",
            workspace_path=tmp_path,
            started_at=started,
            completed_at=started + timedelta(seconds=2),
            exit_code=0,
        )
        body = env.to_json()
        assert "completed_at" in body and "time" in body["completed_at"]
        assert body["exit_code"] == 0


# ═══════════════════════════════════════════════════════════════════
#  Argv redaction
# ═══════════════════════════════════════════════════════════════════


class TestArgvRedaction:
    def test_separate_value_redacted(self) -> None:
        out = _redact_argv(["empusa", "--password", "hunter2", "--user", "alice"], {"--password"})
        assert out == ["empusa", "--password", "***REDACTED***", "--user", "alice"]

    def test_inline_value_redacted(self) -> None:
        out = _redact_argv(["empusa", "--token=abc123", "rest"], {"--token"})
        assert out == ["empusa", "--token=***REDACTED***", "rest"]

    def test_unknown_keys_pass_through(self) -> None:
        out = _redact_argv(["empusa", "--foo", "bar"], {"--password"})
        assert out == ["empusa", "--foo", "bar"]

    def test_order_preserved(self) -> None:
        argv = ["a", "b", "--password", "x", "c", "d"]
        out = _redact_argv(argv, {"--password"})
        assert [t for t in out if t != "***REDACTED***"] == ["a", "b", "--password", "c", "d"]


# ═══════════════════════════════════════════════════════════════════
#  Workspace ID derivation
# ═══════════════════════════════════════════════════════════════════


class TestWorkspaceID:
    def test_same_path_same_uuid(self, tmp_path: Path) -> None:
        a = _derive_workspace_id(tmp_path)
        b = _derive_workspace_id(tmp_path)
        assert a == b

    def test_different_paths_differ(self, tmp_path: Path) -> None:
        other = tmp_path / "other"
        other.mkdir()
        assert _derive_workspace_id(tmp_path) != _derive_workspace_id(other)

    def test_none_path_yields_uuid(self) -> None:
        a = _derive_workspace_id(None)
        b = _derive_workspace_id(None)
        # both valid UUIDs, but not deterministic across calls
        assert a and b and a != b


# ═══════════════════════════════════════════════════════════════════
#  Writer
# ═══════════════════════════════════════════════════════════════════


class TestWriteEnvelope:
    def test_artifact_written_under_provenance_subdir(self, tmp_path: Path) -> None:
        env = build_envelope(command_name="build_env", workspace_path=tmp_path)
        path = write_envelope(env, tmp_path)
        assert path.is_file()
        assert path.parent == tmp_path / "provenance"
        assert path.name.endswith(".provenance.json")

    def test_artifact_is_valid_json(self, tmp_path: Path) -> None:
        env = build_envelope(command_name="build_env", workspace_path=tmp_path)
        path = write_envelope(env, tmp_path)
        body = json.loads(path.read_text(encoding="utf-8"))
        assert body["schema_id"] == SCHEMA_ID
        assert body["envelope_id"]["value"] == env.envelope_id

    def test_invalid_envelope_not_written(self, tmp_path: Path) -> None:
        env = build_envelope(command_name="build_env", workspace_path=tmp_path)
        env.envelope_id = ""  # corrupt
        with pytest.raises(ValueError):
            write_envelope(env, tmp_path)
        assert not (tmp_path / "provenance").exists()

    def test_emit_convenience(self, tmp_path: Path) -> None:
        started = _now()
        path = emit_build_envelope(
            command_name="build_env",
            workspace_path=tmp_path,
            artifacts_dir=tmp_path,
            started_at=started,
            completed_at=started + timedelta(seconds=1),
            exit_code=0,
            argv=["build_env", "env1", "10.10.10.1"],
            output_artifact_refs=["/tmp/a"],
            log_artifact_refs=["/tmp/log"],
        )
        body = json.loads(path.read_text(encoding="utf-8"))
        assert body["command_name"] == "build_env"
        assert body["exit_code"] == 0
        assert body["output_artifact_refs"] == [{"value": "/tmp/a"}]


# ═══════════════════════════════════════════════════════════════════
#  build_env() integration
# ═══════════════════════════════════════════════════════════════════


def _fake_run_nmap(ip: str, output_path: Path, **kwargs: Any) -> tuple[str, Path]:
    output_path.mkdir(parents=True, exist_ok=True)
    out = output_path / "full_scan.txt"
    out.write_text(f"Nmap scan report for {ip}\n22/tcp open ssh\n", encoding="utf-8")
    return ip, out


class TestBuildEnvIntegration:
    """build_env emits a provenance envelope without altering existing behavior."""

    @patch("empusa.cli_scan.run_nmap", side_effect=_fake_run_nmap)
    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    def test_envelope_artifact_created_in_workspace(
        self,
        _check: Any,
        _nmap: Any,
        tmp_path: Path,
    ) -> None:
        from empusa.cli_scan import build_env
        from empusa.workspace import create_workspace

        create_workspace("box1", profile="htb", root=tmp_path)
        ws = tmp_path / "box1"

        layout = build_env(
            "box1",
            ["10.10.10.1"],
            workspace_path=ws,
            interactive=False,
            shell_history=False,
        )
        assert layout is not None

        provenance_dir = ws / "logs" / "provenance"
        assert provenance_dir.is_dir(), "envelope directory should be created under workspace logs/"
        files = list(provenance_dir.glob("*.provenance.json"))
        assert len(files) == 1, f"expected one envelope, got {files}"

        body = json.loads(files[0].read_text(encoding="utf-8"))
        assert body["schema_id"] == SCHEMA_ID
        assert body["schema_version"] == SCHEMA_VERSION
        assert body["command_name"] == "build_env"
        assert body["exit_code"] == 0
        # Output artifact refs should reference the nmap scan file we faked
        out_refs = [r["value"] for r in body.get("output_artifact_refs", [])]
        assert any("full_scan.txt" in r for r in out_refs)

    @patch("empusa.cli_scan.run_nmap", side_effect=_fake_run_nmap)
    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    def test_existing_post_build_behavior_preserved(
        self,
        _check: Any,
        _nmap: Any,
        tmp_path: Path,
    ) -> None:
        """post_build hook still fires with the same payload contract."""
        from empusa.cli_scan import build_env
        from empusa.workspace import create_workspace

        create_workspace("box2", profile="htb", root=tmp_path)
        ws = tmp_path / "box2"
        captured: list[tuple[str, dict[str, Any]]] = []

        def _hook(event: str, payload: dict[str, Any]) -> None:
            captured.append((event, payload))

        layout = build_env(
            "box2",
            ["10.10.10.1"],
            workspace_path=ws,
            interactive=False,
            shell_history=False,
            run_hooks_fn=_hook,
        )
        assert layout is not None
        events = [e for e, _ in captured]
        assert "pre_build" in events
        assert "post_build" in events
        post = next(p for e, p in captured if e == "post_build")
        assert post["env_name"] == "box2"
        assert post["env_path"] == str(layout.base_dir)
        assert post["ips"] == ["10.10.10.1"]

    @patch("empusa.cli_scan.run_nmap", side_effect=_fake_run_nmap)
    @patch("empusa.cli_scan.check_tool_exists", return_value=True)
    def test_envelope_failure_does_not_break_build(
        self,
        _check: Any,
        _nmap: Any,
        tmp_path: Path,
    ) -> None:
        """If envelope emission raises, build_env still returns the layout."""
        from empusa.cli_scan import build_env
        from empusa.workspace import create_workspace

        create_workspace("box3", profile="htb", root=tmp_path)
        ws = tmp_path / "box3"

        with patch(
            "empusa.cli_scan.emit_build_envelope",
            side_effect=RuntimeError("boom"),
        ):
            layout = build_env(
                "box3",
                ["10.10.10.1"],
                workspace_path=ws,
                interactive=False,
                shell_history=False,
            )
        assert layout is not None
        # Original outputs intact
        assert (ws / "scans").is_dir()
        assert (ws / "logs" / "commands_ran.txt").is_file()
