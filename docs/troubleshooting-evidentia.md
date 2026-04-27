# Troubleshooting Evidentia reports

`empusa evidentia report` composes
`evidentia inspect workspace-summary` with a read-only
`evidentia replay` and writes a NEW Empusa-owned artifact under:

```text
<workspace>/artifacts/evidentia/report-<timestamp>.json
```

The artifact body has the following keys:

| Key | Meaning |
| --- | --- |
| `generated_at` | UTC ISO timestamp the report was composed. |
| `workspace_path` | Workspace root the report was generated against. |
| `summary_artifact` | Path to the raw `workspace-summary` JSON artifact. |
| `replay_artifact` | Path to the raw `replay` JSON artifact. |
| `replay_diff_count` | Top-level `diffs` length from the replay output. |
| `counts` | Verbatim scalar counters from `workspace-summary`. |
| `warnings` | Stable warning code strings (see below). |

`warnings` is a list of stable, machine-readable strings. The
sections below explain each code and the recommended follow-up
command. The codes are stable contract surface; downstream tooling
may switch on them without parsing prose.

## `schema_failures_present`

**Trigger.** `counts.schema_failure_count > 0` in the underlying
`workspace-summary` snapshot.

**What it means.** At least one ingest call wrote a
`schema.validation_failed` event into the workspace event log. The
event log is append-only, so the failure is preserved verbatim and
will keep appearing in every future report until the underlying
ingest source is corrected and a fresh ingest is performed.

**Recommended next steps.**

```bash
# 1. Surface the failed events so the operator can see which records
#    Evidentia rejected and why. The wrapper persists the JSON array
#    byte-for-byte under artifacts/evidentia/inspect-failures-*.json.
empusa evidentia inspect-failures --workspace <workspace> --pretty
```

Empusa wraps `evidentia inspect failures` and never re-shapes the
failure payload; the artifact is the same JSON document the
underlying CLI emits. Pass `--limit N` to cap the number of records
returned and `--pretty` to request indented output.

After correcting the upstream source, re-run the matching ingest
wrapper (`empusa evidentia ingest`, `empusa evidentia ingest-provenance`,
or `empusa directory enumerate`).

## `replay_diverged`

**Trigger.** `replay_diff_count > 0`. The read-only replay produced
at least one diff between the live state store and the scratch
store rebuilt from events.

**What it means.** The materialized state under
`<workspace>/evidentia.db` does not match a clean replay of the
event log. This is the divergence signal Evidentia is designed to
surface; it is normally caused by an event log that has been
extended since the last `replay --write`.

**Recommended next steps.**

```bash
# 1. Inspect the raw replay artifact referenced from `replay_artifact`
#    to see the diff payload verbatim.
cat <replay_artifact>

# 2. If the diff is expected (e.g. fresh ingest events have not yet
#    been materialized), re-materialize derived entities into the
#    live store. This is destructive and requires both flags.
empusa evidentia replay --workspace <workspace> --write --confirm-write
```

`--write` is rejected without `--confirm-write`, and
`--confirm-write` is rejected without `--write`. Both must be
explicitly passed for the destructive form to run.

## `no_build_runs`

**Trigger.** `counts.build_run_count == 0` in the underlying
`workspace-summary` snapshot.

**What it means.** The workspace contains zero materialized
`build_run` entities. Either no `build.provenance_envelope` artifact
has been ingested, or one has been ingested but not yet replayed
into the live state store.

**Recommended next steps.**

```bash
# 1. Check whether any provenance envelopes have been ingested.
empusa evidentia inspect-provenance --workspace <workspace>

# 2. If the list is empty, ingest one.
empusa evidentia ingest-provenance --workspace <workspace> --file <envelope>.json

# 3. Materialize the new events into the live state store so the
#    build_run entities show up in subsequent reports.
empusa evidentia replay --workspace <workspace> --write --confirm-write

# 4. Confirm.
empusa evidentia inspect-build-runs --workspace <workspace>
```

## `directory_empty`

**Trigger.** All five directory counters in `counts` are zero:
`directory_user_count`, `directory_group_count`,
`directory_computer_count`, `directory_relationship_count`, and
`directory_alias_count`.

**What it means.** No directory adapter (PowerShell-AD, LDAP-text,
or BloodHound) has materialized data into the live state store.
Either nothing has been enumerated yet, or events have been
ingested but not replayed with `--write`.

**Recommended next steps.**

```bash
# 1. Ingest a directory export. `enumerate` runs ingest then replay
#    by default; pass `--no-replay` to defer the replay until after
#    the second source is staged.
empusa directory enumerate --workspace <workspace> \
    --input <export>.json --format powershell

# 2. If events were ingested but `directory_*` counts are still
#    zero, materialize derived entities.
empusa evidentia replay --workspace <workspace> --write --confirm-write

# 3. Confirm via the directory inspection surfaces.
empusa directory inspect --workspace <workspace> --type users
```

See [`docs/directory.md`](directory.md) for the full directory CLI
surface and
[`docs/scenarios/directory-investigation.md`](scenarios/directory-investigation.md)
for a worked end-to-end example.

## When the report itself fails

`empusa evidentia report` propagates the exit code of the first
underlying wrapper that fails:

- exit `1` from `inspect workspace-summary` or `replay` is a runtime
  error. The matching `stderr` stream is persisted as a failure
  artifact under `<workspace>/artifacts/evidentia/` with a
  `.stderr` suffix, alongside a `.meta.json` sidecar that records
  the exact argv, exit code, and timestamp. Use
  `empusa evidentia status --workspace <workspace>` to locate the
  most recent failure artifact, then read the `.stderr` body and
  its `.meta.json` sidecar to diagnose the cause. Re-running the
  report without fixing the cause will fail the same way.
- exit `2` is a usage error in the wrapper. This indicates a bug or
  a misconfigured invocation; do not auto-retry.

Empusa does not retry, rewrite, or hide failures from the
underlying `evidentia` binary; the persisted `.stderr` and
`.meta.json` artifacts are the canonical post-mortem surface.
