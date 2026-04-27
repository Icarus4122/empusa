# Directory investigation scenario

This document walks a new operator through the full directory
investigation flow against a synthetic, hermetic dataset. By the end
you will have:

- ingested two overlapping directory exports,
- replayed deterministically with zero diffs,
- inspected materialized users / groups / computers,
- resolved an SID through the alias index,
- followed a membership edge,
- explored the one-hop neighbourhood,
- and reviewed the workspace audit trail via `evidentia status`.

The fixtures live under
[`tests/fixtures/directory_investigation/`](../../tests/fixtures/directory_investigation/README.md)
and back the opt-in smoke test
`tests/test_scenario_directory_investigation.py`.

## 1. Prerequisites

| Tool        | Required version             | Verified by                                    |
|-------------|------------------------------|------------------------------------------------|
| `python`    | 3.10+                        | `python -m empusa --version`                   |
| `evidentia` | matching the Empusa contract | `evidentia version`                            |
| `empusa`    | this repository              | `python -m empusa --version`                   |

`evidentia` must be on `PATH`. Hecate's `verify-host` step is what
guarantees this in a real lab environment; for ad-hoc runs build it
once from the Evidentia repo and place it on `PATH`.

## 2. Create a workspace

```bash
WS=$(mktemp -d -t evid-scenario-XXXXXX)
mkdir -p "$WS/artifacts/evidentia"
```

The directory commands below only require `--workspace` to point at
an existing directory with an `artifacts/evidentia/` subtree; Empusa
creates the artifact files. If you prefer the full operator profile,
use `python -m empusa workspace init --name scenario --root "$WS"`.

## 3. Stage the fixtures

Copy the two synthetic exports next to the workspace:

```bash
FIX=tests/fixtures/directory_investigation
cp "$FIX/powershell-ad.json" "$WS/powershell-ad.json"
cp "$FIX/ldap.txt"           "$WS/ldap.txt"
```

The PowerShell-AD export contains one user (`alice`), one group
(`Admins`), one computer (`HOST01`), and a `MemberOf` edge from
`alice` to `Admins`. The LDAP-text export re-asserts `alice` and
`HOST01` from a second evidence source so the alias surface can
demonstrate "same canonical key, multiple sources".

## 4. Ingest both sources, then replay

```bash
python -m empusa directory enumerate \
    --workspace "$WS" \
    --input "$WS/powershell-ad.json" \
    --format powershell

python -m empusa directory enumerate \
    --workspace "$WS" \
    --input "$WS/ldap.txt" \
    --format ldap
```

Each invocation runs `evidentia ingest` followed by
`evidentia replay`. A clean run reports `Divergence: No divergence`.
If you prefer to defer the replay until both sources are ingested,
pass `--no-replay` to the first invocation and let the second one
run a single replay over the combined event log:

```bash
python -m empusa directory enumerate \
    --workspace "$WS" --input "$WS/powershell-ad.json" \
    --format powershell --no-replay

python -m empusa directory enumerate \
    --workspace "$WS" --input "$WS/ldap.txt" --format ldap
```

A standalone replay is also available:

```bash
python -m empusa evidentia replay --workspace "$WS"
```

## 5. Materialize derived entities

`evidentia ingest` only writes events. The directory inspection
surfaces (`users`, `groups`, `computers`, `aliases`,
`memberships`, `neighbors`) read from the live state store, which is
populated by running each reducer through its
[`runtime.ReducerRunner`](../../../Evidentia/pkg/runtime/reducer_runner.go).
The CLI exposes this as the opt-in `--write` mode of `replay`:

```bash
python -m empusa evidentia replay --workspace "$WS" --write --confirm-write
```

The output reports per-reducer apply counts and `"wrote": true`.
The flag is opt-in by design — the default `replay` is a read-only
determinism check that compares a scratch store against the live
store and never mutates persistent state. `--write` is the explicit,
auditable handoff that moves data from "ingested" to
"inspectable", and is rejected unless `--confirm-write` is also
passed (and vice versa) so the destructive form can never be
invoked accidentally.

`replay --write` is idempotent: running it a second time against the
same event log applies zero new events per reducer (each runner
remembers the highest sequence number it has already processed).

## 6. Inspect materialized entities

```bash
python -m empusa directory inspect --workspace "$WS" --type users
python -m empusa directory inspect --workspace "$WS" --type groups
python -m empusa directory inspect --workspace "$WS" --type computers
```

Each command shells out to `evidentia inspect directory <type>`,
persists the JSON array as an artifact, and prints the artifact path
plus a record count. Empusa never decodes the per-record payload
beyond the array length — the artifact file is the canonical
operator-facing output.

Expected counts for this fixture set:

| Type        | Records |
|-------------|---------|
| `users`     | 1       |
| `groups`    | 1       |
| `computers` | 1       |

## 7. Resolve an alias

The alias index is the read-only lookup surface for directory
identities. Resolve `alice` by SID:

```bash
python -m empusa directory aliases \
    --workspace "$WS" \
    --kind sid \
    --value S-1-5-21-1111111111-2222222222-3333333333-1001 \
    --pretty
```

The artifact contains a single alias entity whose
`canonical_keys` is `["dn:cn=alice,ou=people,dc=corp,dc=local"]` and
whose `evidence_sources` carries **both** adapters (the PowerShell
adapter and the LDAP-text adapter). The same SID asserted by two
sources does not produce two alias entities and is not collapsed
into the principal record.

You can also look up by GUID, DN, SAM, UPN, or DNS host. Omit
`--kind` to let the inspector match any kind. Unknown aliases return
`[]` with exit code `0` — they are not an error.

## 8. Follow a membership edge

```bash
python -m empusa directory memberships \
    --workspace "$WS" \
    --key dn:cn=alice,ou=people,dc=corp,dc=local \
    --pretty
```

Returns a single edge from `alice` to `Admins` (the `MemberOf`
relationship asserted by both adapters; replay deduplicates the
edge).

## 9. Explore the one-hop neighbourhood

```bash
python -m empusa directory neighbors \
    --workspace "$WS" \
    --key dn:cn=admins,ou=groups,dc=corp,dc=local \
    --pretty
```

Returns the inbound `member_of` edge from `alice`.

## 10. Audit the workspace

```bash
python -m empusa evidentia status --workspace "$WS"
```

Surfaces the latest ingest, replay, and inspect artifacts with their
exit codes and provenance, so the operator can confirm the run
without re-executing it.

## Limitations

- **No implicit alias merging.** Two sources asserting different
  canonical keys for the same alias value (e.g. the same SID under
  two different DNs) produce a single alias entity with **multiple**
  `canonical_keys`. The reducer never collapses or picks a winner —
  conflicts are surfaced verbatim and remain operator-visible. See
  `pkg/reducer/directorystate` in the Evidentia repository for the
  reducer contract.
- **Read-only inspection.** `inspect`, `aliases`, `memberships`, and
  `neighbors` are pure projections over the materialized state. They
  never mutate events, the store, or proposals.
- **No payload rewriting.** Empusa wrappers persist Evidentia stdout
  byte-for-byte and surface only the top-level array length. No
  field is renamed, summarised, or filtered on the Empusa side.
- **No live LDAP / PowerShell.** The fixtures are static text
  exports. Empusa does not call `ldapsearch` or PowerShell cmdlets;
  both adapters consume pre-collected bytes.

## Reproducing in CI

The opt-in smoke test
`tests/test_scenario_directory_investigation.py` runs the full flow
end-to-end against the real `evidentia` binary. It is skipped when
`evidentia` is not on `PATH`. Set
`EMPUSA_REQUIRE_REAL_EVIDENTIA=1` to turn the skip into a hard
failure on a CI lane that pre-installs Evidentia.
