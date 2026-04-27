"""
Opt-in smoke test: drive the *real* Evidentia binary through Empusa's
wrapper to catch CLI-contract drift between releases.

This module is intentionally separate from the hermetic suite in
``tests/test_evidentia.py``:

- The hermetic suite uses a fake ``evidentia`` script and pins
  Empusa's side of the contract (argv shape, exit-code routing,
  artifact persistence, sidecar metadata, etc.).
- This smoke test invokes whatever ``evidentia`` is currently on
  ``PATH`` and exercises the end-to-end ``version → ingest → replay``
  flow against real Evidentia output.

Boundary discipline (per ``WORKSPACE.md`` / ``AGENTS.md``):

- No Evidentia Go source is imported.
- No Badger files are read or interpreted.
- No Evidentia output is re-shaped; only top-level keys are asserted.
- Hecate is not exercised; the binary is assumed to already be on
  ``PATH`` (Hecate's verify-host check_evidentia is what guarantees
  that in a real lab).

The whole module is skipped when ``evidentia`` is not on ``PATH``,
so the normal ``pytest`` run on a developer machine without a built
Evidentia binary is unaffected. Set the environment variable
``EMPUSA_REQUIRE_REAL_EVIDENTIA=1`` to turn the skip into a hard
failure (intended for CI lanes that pre-install Evidentia).
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from empusa import evidentia

# --- Skip / require gating ------------------------------------------

_EVIDENTIA_ON_PATH = shutil.which(evidentia.DEFAULT_BINARY)
_REQUIRE = os.environ.get("EMPUSA_REQUIRE_REAL_EVIDENTIA") == "1"

if _EVIDENTIA_ON_PATH is None and _REQUIRE:
    raise RuntimeError(
        "EMPUSA_REQUIRE_REAL_EVIDENTIA=1 but no 'evidentia' binary was "
        "found on PATH; install Evidentia or unset the variable."
    )

pytestmark = pytest.mark.skipif(
    _EVIDENTIA_ON_PATH is None,
    reason="evidentia binary not on PATH; opt-in smoke test skipped",
)


# --- Fixtures -------------------------------------------------------


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A throwaway Empusa workspace root for one smoke test."""
    ws = tmp_path / "ws"
    ws.mkdir()
    return ws


@pytest.fixture
def minimal_jsonl(workspace: Path) -> Path:
    """One minimally-valid Evidentia observation, JSON-encoded.

    Evidentia's JSONL adapter (``pkg/ingest/jsonl``) normalizes ID,
    schema_version, source, timestamps, and provenance, so the
    producer only has to supply the fields ``Observation.Validate``
    requires after normalization:

    - ``kind``            (no default; required)
    - ``confidence.value`` in [0.0, 1.0]
    - ``raw_evidence.format`` non-empty

    Any drift in those required fields will surface here as an
    Evidentia exit code 1 with a ``schema.validation_failed`` event.
    """
    obs = {
        "kind": "host",
        "confidence": {"value": 0.9},
        "raw_evidence": {"format": "json"},
    }
    path = workspace / "obs.jsonl"
    path.write_text(json.dumps(obs) + "\n", encoding="utf-8")
    return path


# --- Tests ----------------------------------------------------------


def test_real_evidentia_version_returns_contract_json() -> None:
    """``evidentia version`` must emit ``{"version": "<non-empty>"}``."""
    evidentia._clear_version_cache()
    resolved = evidentia._resolve_binary(evidentia.DEFAULT_BINARY)
    version, err = evidentia._capture_version(resolved)
    assert err is None, f"version capture failed: {err}"
    assert isinstance(version, str) and version, f"expected non-empty version string, got {version!r}"


def test_real_evidentia_ingest_replay_smoke(
    workspace: Path,
    minimal_jsonl: Path,
) -> None:
    """End-to-end: ingest one observation, then replay; verify shapes."""

    ingest = evidentia.ingest_jsonl(
        workspace_path=workspace,
        jsonl_path=minimal_jsonl,
    )

    assert ingest.result.exit_code == 0, f"ingest exit={ingest.result.exit_code} stderr={ingest.result.stderr!r}"
    assert ingest.stderr_path is None
    assert ingest.artifact_path.is_file()

    summary = json.loads(ingest.artifact_path.read_text(encoding="utf-8"))
    assert isinstance(summary, dict)
    for key in (
        "records_read",
        "accepted",
        "failed",
        "event_ids",
        "failure_event_ids",
    ):
        assert key in summary, f"missing key {key!r} in ingest summary: {summary!r}"
    assert summary["records_read"] == 1
    assert summary["accepted"] == 1
    assert summary["failed"] == 0
    assert isinstance(summary["event_ids"], list) and len(summary["event_ids"]) == 1
    assert isinstance(summary["failure_event_ids"], list)
    assert summary["failure_event_ids"] == []

    replay = evidentia.replay(workspace_path=workspace)
    assert replay.result.exit_code == 0, f"replay exit={replay.result.exit_code} stderr={replay.result.stderr!r}"
    assert replay.artifact_path.is_file()
    assert replay.divergence is False
    assert replay.diff_count == 0

    replay_doc = json.loads(replay.artifact_path.read_text(encoding="utf-8"))
    assert isinstance(replay_doc, dict)
    # Contract: top-level keys present; we do not interpret values.
    assert "reducers" in replay_doc
    assert "applied_count" in replay_doc
