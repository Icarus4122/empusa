"""
Phase 33: Directory investigation scenario smoke test.

This module is the executable companion to
``docs/scenarios/directory-investigation.md``. It drives the full
operator flow against the *real* ``evidentia`` binary using the
synthetic fixtures under ``tests/fixtures/directory_investigation/``.

Boundary discipline (per ``WORKSPACE.md`` / ``AGENTS.md``):

- No Evidentia Go source is imported.
- No Badger files are read or interpreted.
- No Evidentia output is re-shaped; only top-level keys / array
  lengths are asserted.
- Hecate is not exercised; the binary is assumed to already be on
  ``PATH``.

The whole module is skipped when ``evidentia`` is not on ``PATH``,
mirroring ``test_evidentia_real_binary_smoke.py``. Set
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
    reason="evidentia binary not on PATH; opt-in scenario test skipped",
)

# --- Fixture geometry -----------------------------------------------

_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "directory_investigation"
_PSAD_FIXTURE = _FIXTURE_DIR / "powershell-ad.json"
_LDAP_FIXTURE = _FIXTURE_DIR / "ldap.txt"

# Pinned values from the fixtures. Keep these in sync with the
# scenario doc -- they are the operator-visible identities.
_ALICE_DN = "CN=Alice,OU=People,DC=corp,DC=local"
_ALICE_DN_KEY = "dn:cn=alice,ou=people,dc=corp,dc=local"
_ALICE_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
_ADMINS_DN_KEY = "dn:cn=admins,ou=groups,dc=corp,dc=local"


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A throwaway Empusa workspace root for the scenario."""
    ws = tmp_path / "ws"
    (ws / "artifacts" / "evidentia").mkdir(parents=True)
    return ws


# --- Helpers --------------------------------------------------------


def _read_array(artifact: Path) -> list[dict]:
    """Decode a JSON array artifact. Used only for assertion-side
    introspection; Empusa itself does not parse record fields."""
    doc = json.loads(artifact.read_text(encoding="utf-8"))
    assert isinstance(doc, list), f"expected JSON array, got {type(doc).__name__}"
    return doc


# --- Scenario -------------------------------------------------------


def test_directory_investigation_scenario(workspace: Path) -> None:
    """End-to-end: ingest two sources, replay, then exercise every
    read-only directory surface against the synthetic fixtures."""

    # -- Step 1: ingest the PowerShell-AD export, defer replay -----
    psad = evidentia.ingest_directory(
        workspace_path=workspace,
        input_path=_PSAD_FIXTURE,
        fmt="powershell",
    )
    assert psad.result.exit_code == 0, f"powershell ingest failed: stderr={psad.result.stderr!r}"
    assert psad.artifact_path.is_file()

    # -- Step 2: ingest the LDAP-text export -----------------------
    ldap = evidentia.ingest_directory(
        workspace_path=workspace,
        input_path=_LDAP_FIXTURE,
        fmt="ldap",
    )
    assert ldap.result.exit_code == 0, f"ldap ingest failed: stderr={ldap.result.stderr!r}"
    assert ldap.artifact_path.is_file()

    # -- Step 3: replay the combined event log ---------------------
    replay = evidentia.replay(workspace_path=workspace)
    assert replay.result.exit_code == 0, f"replay failed: stderr={replay.result.stderr!r}"
    assert replay.divergence is False, f"replay diverged: diff_count={replay.diff_count}"
    assert replay.diff_count == 0

    # -- Step 3b: materialize derived entities into the live store -
    # ``evidentia ingest`` writes events only; the inspection
    # surfaces below read from the live state store, which is
    # populated by ``replay --write``. Without this step every
    # inspect call would return ``[]``.
    materialize = evidentia.replay(workspace_path=workspace, write=True)
    assert materialize.result.exit_code == 0, f"replay --write failed: stderr={materialize.result.stderr!r}"
    materialize_doc = json.loads(materialize.result.stdout)
    assert materialize_doc.get("wrote") is True, f"replay --write did not report wrote=true: {materialize_doc!r}"
    assert materialize_doc.get("reducers", 0) >= 1
    # Idempotency: a second --write must succeed and not error.
    rewrite = evidentia.replay(workspace_path=workspace, write=True)
    assert rewrite.result.exit_code == 0

    # -- Step 4: users / groups / computers visible ----------------
    users = evidentia.inspect_directory(workspace_path=workspace, subject="users")
    groups = evidentia.inspect_directory(workspace_path=workspace, subject="groups")
    computers = evidentia.inspect_directory(workspace_path=workspace, subject="computers")

    assert users.record_count == 1, f"expected 1 user, got {users.record_count}"
    assert groups.record_count == 1, f"expected 1 group, got {groups.record_count}"
    assert computers.record_count == 1, f"expected 1 computer, got {computers.record_count}"

    # The artifacts are the canonical operator-facing payload; spot
    # check the principal we will follow through the alias surface.
    user_records = _read_array(users.artifact_path)
    user_dns = {r.get("distinguished_name") for r in user_records}
    assert _ALICE_DN in user_dns, f"Alice missing from users artifact; saw {user_dns!r}"

    # -- Step 5: alias lookup resolves Alice's SID -----------------
    alias_outcome = evidentia.inspect_directory_aliases(
        workspace_path=workspace,
        value=_ALICE_SID,
        kind="sid",
    )
    assert alias_outcome.record_count == 1, (
        f"expected exactly one alias entity for Alice's SID, got {alias_outcome.record_count}"
    )
    alias_records = _read_array(alias_outcome.artifact_path)
    alias = alias_records[0]
    # Canonical key is Alice's DN (lower-cased per the alias index
    # casing rules).
    assert alias.get("canonical_keys") == [_ALICE_DN_KEY], (
        f"alias canonical_keys mismatch: {alias.get('canonical_keys')!r}"
    )
    # Two adapters asserted the same SID -> two evidence_sources,
    # not two alias entities. This pins the "no implicit merge"
    # contract on the multi-source side: the reducer adds claims
    # rather than collapsing them.
    sources = alias.get("evidence_sources") or []
    assert len(sources) >= 2, f"expected >=2 evidence_sources (psad + ldap), got {sources!r}"

    # -- Step 6: memberships returns Alice -> Admins ---------------
    memberships = evidentia.inspect_directory_view(
        workspace_path=workspace,
        view="memberships",
        key=_ALICE_DN_KEY,
    )
    assert memberships.record_count >= 1, f"expected at least one membership edge, got {memberships.record_count}"
    edge_records = _read_array(memberships.artifact_path)
    targets = {r.get("target") for r in edge_records}
    assert _ADMINS_DN_KEY in targets, f"Admins membership edge missing; saw targets {targets!r}"

    # -- Step 7: neighbors of Admins includes Alice ----------------
    neighbors = evidentia.inspect_directory_view(
        workspace_path=workspace,
        view="neighbors",
        key=_ADMINS_DN_KEY,
    )
    assert neighbors.record_count >= 1, f"expected at least one neighbour for Admins, got {neighbors.record_count}"
    neighbour_records = _read_array(neighbors.artifact_path)
    sources_seen = {r.get("source") for r in neighbour_records}
    assert _ALICE_DN_KEY in sources_seen, f"Alice missing from Admins neighbours; saw {sources_seen!r}"

    # -- Step 8: payload byte-stability ----------------------------
    # Empusa's wrappers must persist Evidentia stdout byte-for-byte.
    # Re-running an inspection over the same materialized state must
    # produce identical bytes.
    rerun = evidentia.inspect_directory(workspace_path=workspace, subject="users")
    assert rerun.artifact_path.read_bytes() == users.artifact_path.read_bytes(), (
        "users inspect artifact diverged across two read-only invocations"
    )


def test_unknown_alias_returns_empty_not_error(workspace: Path) -> None:
    """An alias value with no matching entity must return ``[]`` and
    exit ``0`` -- the alias surface is read-only and never errors on
    a miss."""

    psad = evidentia.ingest_directory(
        workspace_path=workspace,
        input_path=_PSAD_FIXTURE,
        fmt="powershell",
    )
    assert psad.result.exit_code == 0

    # Materialize so the alias index is non-empty; otherwise the
    # "miss returns []" assertion would pass for the wrong reason
    # (every alias lookup returns [] before replay --write).
    materialize = evidentia.replay(workspace_path=workspace, write=True)
    assert materialize.result.exit_code == 0

    outcome = evidentia.inspect_directory_aliases(
        workspace_path=workspace,
        value="S-1-5-21-9999999999-9999999999-9999999999-9999",
        kind="sid",
    )
    assert outcome.record_count == 0
    assert _read_array(outcome.artifact_path) == []
