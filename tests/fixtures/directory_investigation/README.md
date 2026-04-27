# Directory-investigation scenario fixtures

These files back the `tests/test_scenario_directory_investigation.py`
opt-in smoke test and the operator scenario documented in
[`docs/scenarios/directory-investigation.md`](../../../docs/scenarios/directory-investigation.md).

| File                   | Adapter        | Records                                                |
|------------------------|----------------|--------------------------------------------------------|
| `powershell-ad.json`   | `powershell-ad`| user `alice`, group `Admins`, computer `HOST01`        |
| `ldap.txt`             | `ldap-text`    | user `alice`, computer `HOST01` (re-asserted)          |

The two adapters are intentionally overlapping: both assert the same
`(DN, ObjectGUID, ObjectSid, sAMAccountName)` tuple for `alice` and
`HOST01`. This produces alias entities with one `canonical_keys`
entry and **multiple** `evidence_sources` entries — exercising the
alias surface without triggering any implicit merge of conflicting
facts. See the scenario doc for the full operator flow.

## Boundary

The fixtures are byte-for-byte inputs to Evidentia. Empusa never
edits them; the adapter under test is in
[`pkg/ingest/powershellad`](https://github.com/Icarus4122/Evidentia)
and [`pkg/ingest/ldaptext`](https://github.com/Icarus4122/Evidentia)
in the Evidentia repository.
