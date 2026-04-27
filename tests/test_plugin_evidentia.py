"""Tests for the Empusa Evidentia integration plugin.

These tests load the plugin from the real
``empusa/plugins/evidentia/`` directory through the standard
:class:`empusa.plugins.PluginManager` lifecycle and exercise its
capability handlers via the registry. The underlying wrapper
(:mod:`empusa.evidentia`) is monkeypatched -- the wrapper itself is
covered end-to-end in ``test_evidentia.py``.

Goals:

- the plugin loads, activates, and registers all three capabilities;
- each capability handler delegates *only* to the wrapper functions;
- failures preserve the wrapper's stderr artifact path;
- replay divergence surfaces actionable status (`divergence=True`,
  non-zero `diff_count`);
- the plugin source has no forbidden imports.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from empusa import evidentia
from empusa.plugins import PluginManager
from empusa.registry import CapabilityRegistry

# Path to the real, on-disk plugin shipped under empusa/plugins/.
EVIDENTIA_PLUGIN_DIR = Path(evidentia.__file__).resolve().parent / "plugins" / "evidentia"


# -- Helpers --------------------------------------------------------


def _load_plugin() -> tuple[PluginManager, CapabilityRegistry]:
    """Discover + activate just the Evidentia plugin in isolation.

    The plugin lives under the real ``empusa/plugins/`` tree but the
    PluginManager is pointed at *its parent directory* so this test
    doesn't accidentally activate every shipped plugin. To achieve
    isolation we rely on the manager's per-directory discovery.
    """
    registry = CapabilityRegistry()
    pm = PluginManager(EVIDENTIA_PLUGIN_DIR.parent, registry=registry)

    pm.discover()
    pm.resolve_dependencies()
    pm.activate_all()
    return pm, registry


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


# ═══════════════════════════════════════════════════════════════════
#  Lifecycle: discovery + activation + registration
# ═══════════════════════════════════════════════════════════════════


class TestPluginLifecycle:
    def test_plugin_dir_exists(self) -> None:
        assert EVIDENTIA_PLUGIN_DIR.is_dir()
        assert (EVIDENTIA_PLUGIN_DIR / "manifest.json").is_file()
        assert (EVIDENTIA_PLUGIN_DIR / "plugin.py").is_file()

    def test_plugin_loads_and_activates(self) -> None:
        pm, _registry = _load_plugin()
        desc = pm.plugins.get("evidentia")
        assert desc is not None, "evidentia plugin must be discovered"
        assert desc.activatable, "evidentia plugin must be activatable"
        assert desc.activated, "evidentia plugin must activate cleanly"

    def test_plugin_registers_three_capabilities(self) -> None:
        _pm, registry = _load_plugin()
        names = {entry.name for entry in registry.get("analyzer")}
        assert "evidentia.ingest_jsonl" in names
        assert "evidentia.replay" in names
        assert "evidentia.audit_capability_run" in names

        for capname in (
            "evidentia.ingest_jsonl",
            "evidentia.replay",
            "evidentia.audit_capability_run",
        ):
            entry = registry.get_by_name("analyzer", capname)
            assert entry is not None
            assert entry.plugin_name == "evidentia"
            assert callable(entry.handler)


# ═══════════════════════════════════════════════════════════════════
#  Capability handlers: ingest
# ═══════════════════════════════════════════════════════════════════


class TestIngestCapability:
    def test_delegates_to_wrapper_and_returns_artifact(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        artifact = tmp_path / "ingest-x.json"
        artifact.write_text("{}", encoding="utf-8")
        calls: list[dict] = []

        def fake_ingest(*, workspace_path, jsonl_path, binary, db_path):
            calls.append(
                {
                    "workspace_path": workspace_path,
                    "jsonl_path": jsonl_path,
                    "binary": binary,
                    "db_path": db_path,
                }
            )
            return evidentia.IngestOutcome(artifact_path=artifact, stderr_path=None, result=_ok_result())

        monkeypatch.setattr(evidentia, "ingest_jsonl", fake_ingest)

        _pm, registry = _load_plugin()
        handler = registry.get_by_name("analyzer", "evidentia.ingest_jsonl").handler

        result = handler(str(tmp_path), str(tmp_path / "obs.jsonl"))

        assert calls and calls[0]["workspace_path"] == tmp_path
        assert calls[0]["jsonl_path"] == tmp_path / "obs.jsonl"
        assert result["ok"] is True
        assert result["exit_code"] == 0
        assert result["artifact_path"] == artifact
        assert result["stderr_path"] is None

    def test_failure_preserves_stderr_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        stderr_path = tmp_path / "ingest-x.stderr"
        stderr_path.write_text("schema failure", encoding="utf-8")

        def fake_ingest(**_: object):
            raise evidentia.EvidentiaCLIError(
                _fail_result(exit_code=1, stderr="schema failure"),
                stderr_path=stderr_path,
            )

        monkeypatch.setattr(evidentia, "ingest_jsonl", fake_ingest)

        _pm, registry = _load_plugin()
        handler = registry.get_by_name("analyzer", "evidentia.ingest_jsonl").handler

        result = handler(tmp_path, tmp_path / "obs.jsonl")
        assert result["ok"] is False
        assert result["exit_code"] == 1
        assert result["is_usage_error"] is False
        assert result["stderr_path"] == stderr_path
        assert result["stderr"] == "schema failure"

    def test_usage_error_is_not_retried(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        invocations: list[bool] = []

        def fake_ingest(**_: object):
            invocations.append(True)
            raise evidentia.EvidentiaCLIError(
                _fail_result(exit_code=2, stderr="bad usage"),
                stderr_path=None,
            )

        monkeypatch.setattr(evidentia, "ingest_jsonl", fake_ingest)

        _pm, registry = _load_plugin()
        handler = registry.get_by_name("analyzer", "evidentia.ingest_jsonl").handler

        result = handler(tmp_path, tmp_path / "obs.jsonl")
        assert len(invocations) == 1
        assert result["ok"] is False
        assert result["exit_code"] == 2
        assert result["is_usage_error"] is True


# ═══════════════════════════════════════════════════════════════════
#  Capability handlers: replay
# ═══════════════════════════════════════════════════════════════════


class TestReplayCapability:
    def test_no_divergence(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        artifact = tmp_path / "replay-x.json"
        artifact.write_text('{"diffs":[]}', encoding="utf-8")

        def fake_replay(*, workspace_path, binary, db_path, alert):
            # alert MUST NOT be invoked when divergence is False.
            return evidentia.ReplayOutcome(artifact_path=artifact, divergence=False, diff_count=0, result=_ok_result())

        monkeypatch.setattr(evidentia, "replay", fake_replay)

        _pm, registry = _load_plugin()
        handler = registry.get_by_name("analyzer", "evidentia.replay").handler

        result = handler(tmp_path)
        assert result["ok"] is True
        assert result["divergence"] is False
        assert result["diff_count"] == 0
        assert result["alerts"] == []
        assert result["artifact_path"] == artifact

    def test_divergence_is_actionable(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        artifact = tmp_path / "replay-x.json"
        artifact.write_text('{"diffs":[1,2,3]}', encoding="utf-8")

        def fake_replay(*, workspace_path, binary, db_path, alert):
            alert(artifact, 3)
            return evidentia.ReplayOutcome(artifact_path=artifact, divergence=True, diff_count=3, result=_ok_result())

        monkeypatch.setattr(evidentia, "replay", fake_replay)

        _pm, registry = _load_plugin()
        handler = registry.get_by_name("analyzer", "evidentia.replay").handler

        result = handler(tmp_path)
        assert result["ok"] is True
        assert result["divergence"] is True
        assert result["diff_count"] == 3
        assert result["alerts"] == [(artifact, 3)]
        assert result["artifact_path"] == artifact

    def test_failure_preserves_stderr_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        stderr_path = tmp_path / "replay-x.stderr"
        stderr_path.write_text("backend error", encoding="utf-8")

        def fake_replay(**_: object):
            raise evidentia.EvidentiaCLIError(
                _fail_result(exit_code=1, stderr="backend error"),
                stderr_path=stderr_path,
            )

        monkeypatch.setattr(evidentia, "replay", fake_replay)

        _pm, registry = _load_plugin()
        handler = registry.get_by_name("analyzer", "evidentia.replay").handler

        result = handler(tmp_path)
        assert result["ok"] is False
        assert result["exit_code"] == 1
        assert result["stderr_path"] == stderr_path


# ═══════════════════════════════════════════════════════════════════
#  Capability handlers: audit
# ═══════════════════════════════════════════════════════════════════


class TestAuditCapability:
    def test_delegates_to_wrapper(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        artifact = tmp_path / "audit-run-1-x.json"
        artifact.write_text("{}", encoding="utf-8")
        calls: list[dict] = []

        def fake_audit(*, workspace_path, run_id, binary, db_path):
            calls.append(
                {
                    "workspace_path": workspace_path,
                    "run_id": run_id,
                    "binary": binary,
                    "db_path": db_path,
                }
            )
            return evidentia.AuditOutcome(run_id=run_id, artifact_path=artifact, result=_ok_result())

        monkeypatch.setattr(evidentia, "audit_capability_run", fake_audit)

        _pm, registry = _load_plugin()
        handler = registry.get_by_name("analyzer", "evidentia.audit_capability_run").handler

        result = handler(tmp_path, "run-1")
        assert calls and calls[0]["run_id"] == "run-1"
        assert result["ok"] is True
        assert result["run_id"] == "run-1"
        assert result["artifact_path"] == artifact

    def test_failure_preserves_stderr_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        stderr_path = tmp_path / "audit-x.stderr"
        stderr_path.write_text("not found", encoding="utf-8")

        def fake_audit(**_: object):
            raise evidentia.EvidentiaCLIError(
                _fail_result(exit_code=1, stderr="not found"),
                stderr_path=stderr_path,
            )

        monkeypatch.setattr(evidentia, "audit_capability_run", fake_audit)

        _pm, registry = _load_plugin()
        handler = registry.get_by_name("analyzer", "evidentia.audit_capability_run").handler

        result = handler(tmp_path, "run-1")
        assert result["ok"] is False
        assert result["stderr_path"] == stderr_path


# ═══════════════════════════════════════════════════════════════════
#  Contract guard
# ═══════════════════════════════════════════════════════════════════


def test_plugin_only_imports_evidentia_via_wrapper() -> None:
    """The plugin source must not reach into Evidentia directly.

    Only ``empusa.evidentia`` is allowed as the bridge module.
    """
    src = (EVIDENTIA_PLUGIN_DIR / "plugin.py").read_text(encoding="utf-8")
    forbidden = (
        "import pkg.",
        "from pkg.",
        "github.com/Icarus4122/Evidentia",
        "import badger",
        "from badger",
        "subprocess.",  # plugin must NOT spawn the binary itself
    )
    for needle in forbidden:
        assert needle not in src, f"forbidden surface in plugin: {needle}"

    assert "from empusa import evidentia" in src
