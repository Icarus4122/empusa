# Directory enumeration CLI

Empusa exposes a non-interactive `directory` subcommand that wraps
the Evidentia ingest, replay, and inspect surface for AD-style
exports. Every subcommand shells out to the `evidentia` binary --
no direct store access, no payload reshaping, no field renaming.

The Evidentia-side contract for the underlying CLI lives in the
Evidentia repository under
[`docs/directory.md`](https://github.com/Icarus4122/Evidentia/blob/main/docs/directory.md)
and the canonical key format is documented there.

For a full worked example with synthetic fixtures, see
[`scenarios/directory-investigation.md`](scenarios/directory-investigation.md).

## Subcommands

```bash
empusa directory enumerate    --workspace PATH --input FILE --format {powershell,ldap}
                                                          [--no-replay] [--binary BIN] [--db-path DIR]
empusa directory inspect      --workspace PATH --type {users,groups,computers,relationships}
                                                          [--limit N] [--pretty] [--binary BIN] [--db-path DIR]
empusa directory neighbors    --workspace PATH --key CANONICAL_KEY
                                                          [--limit N] [--pretty] [--binary BIN] [--db-path DIR]
empusa directory memberships  --workspace PATH --key CANONICAL_KEY
                                                          [--limit N] [--pretty] [--binary BIN] [--db-path DIR]
empusa directory aliases      --workspace PATH --value VALUE
                                                          [--kind {dn,guid,sid,sam,upn,dns,dnshost}]
                                                          [--limit N] [--pretty] [--binary BIN] [--db-path DIR]
```

| Subcommand              | Evidentia call                                     | Operator-visible output                       |
| ----------------------- | -------------------------------------------------- | --------------------------------------------- |
| `directory enumerate`   | `ingest powershell-ad`/`ingest ldap` then `replay` | `accepted` / `failed` counts, diff count      |
| `directory inspect`     | `inspect directory <type>`                         | Records count, artifact path                  |
| `directory neighbors`   | `inspect directory neighbors <key>`                | Records count, artifact path                  |
| `directory memberships` | `inspect directory memberships <key>`              | Records count, artifact path                  |
| `directory aliases`     | `inspect directory aliases <value>`                | Records count, artifact path                  |

`enumerate` runs `ingest` followed by `replay` by default. Pass
`--no-replay` to defer the replay (useful when staging multiple
sources before a single combined replay).

`neighbors` returns every one-hop edge that touches the supplied
canonical key. `memberships` is the same filter restricted to
`member_of` edges, so the same command answers both
"what groups is this user in?" (key = user DN) and
"who is in this group?" (key = group DN). An unknown key returns
an empty list with exit `0`; it is not an error.

`aliases` resolves a directory identity by SID, GUID, DN, SAM, UPN,
or DNS host. Omit `--kind` to match any alias kind. An unknown
alias returns an empty list with exit `0`.

## Recommended multi-source flow

When two directory exports describe the same identities (e.g.
a PowerShell-AD export and an LDAP-text export of the same
domain), defer the replay until both ingests are staged so the
divergence check runs once over the combined event log:

```bash
# Stage source 1; ingest only.
empusa directory enumerate \
    --workspace "$WS" --input source-1.json --format powershell --no-replay

# Stage source 2; the default replay covers both.
empusa directory enumerate \
    --workspace "$WS" --input source-2.txt  --format ldap

# Compose a workspace evidence report.
empusa evidentia workspace-summary --workspace "$WS"
empusa evidentia report            --workspace "$WS"
```

To make the inspection surfaces (`inspect`, `neighbors`,
`memberships`, `aliases`) return materialized data, the live state
store must be populated. `enumerate` (and `evidentia replay` on its
own) is read-only by default; materialization is the explicit,
auditable handoff:

```bash
empusa evidentia replay --workspace "$WS" --write --confirm-write
```

`--write` is rejected unless `--confirm-write` is also passed, and
`--confirm-write` is rejected without `--write`. Both flags are
required to acknowledge the destructive write into the live store.

## Boundary

Empusa wrappers persist Evidentia stdout byte-for-byte and surface
only top-level array length / count fields. No record payload is
decoded, renamed, summarized, or filtered on the Empusa side.
Empusa never calls `ldapsearch` or PowerShell cmdlets; both
adapters consume pre-collected bytes that the operator stages into
the workspace.

Sample fixtures suitable for smoke-testing the workflow live in the
Evidentia repository under
[`examples/directory/`](https://github.com/Icarus4122/Evidentia/tree/main/examples/directory).
