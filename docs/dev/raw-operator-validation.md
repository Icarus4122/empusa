# Empusa raw operator validation

Operator-grade checklist for validating Empusa **outside** the unit-test
harness, the way a real user would run it from a terminal.

This document is non-destructive by design:
- Every workspace/env command targets a temp root.
- No real offensive payload is executed.
- No external network target is contacted.
- Module compile, scan execution, and tunnel start are **never** run —
  only their generated commands or `--help` surfaces are inspected.
- Interactive menus (`empusa` with no subcommand) are out of scope; this
  doc validates the **non-interactive** CLI surface and the documented
  Python entry points for areas that have no non-interactive subcommand
  yet (scan, modules, hooks, hash, ad, privesc, tunnel).

It complements:
- `tests/` (pytest unit + functional coverage)
- `scripts/dev/version-sanity.py`
- `scripts/dev/package-sanity.py`

Marker vocabulary used throughout: `[PASS]` `[FAIL]` `[WARN]` `[INFO]`
`[ACTION]`.

## 1. Purpose and scope

- Validate Empusa as a real CLI tool outside `pytest`.
- Confirm that release artifacts (wheel + entry-point) work the same as
  the editable dev install.
- Exercise the canonical operator paths: workspace lifecycle, build
  env, loot, report, plugin discovery, exploit-search.
- Smoke-test the `STRICT_MODULES` and `STRICT_TEMPLATES` environment
  gates that release/CI relies on.
- Provide a record of the last known-good raw run for the current tag.

Out of scope: real scans, real exploit execution, real C2/tunnels,
plugin marketplace activity, and anything that mutates a real operator
workspace tree, real `$HOME`, or a Hecate lab host. Those belong to
Hecate's `docs/dev/raw-operator-validation.md`.

## 2. Prerequisites

| Item | Required |
|---|---|
| Python | `>=3.9`, `<4.0` |
| OS | Linux or WSL preferred; Windows works with `PYTHONIOENCODING=utf-8 PYTHONUTF8=1` (Rich box-drawing chars need UTF-8 console) |
| Tools | `git`, `python -m venv`, `pip`, optional `ruff` (installed via `[dev]` extras) |
| Network | **Not required** for any check in this doc |
| Docker / Hecate | **Not required** |
| Privileges | Unprivileged user; no `sudo` |

All commands assume the working directory is the Empusa repo root.
`$WS` denotes a throwaway workspace root: `WS=$(mktemp -d -t empusa-ws-XXXX)`.
`$ENV` denotes a throwaway env name (e.g. `raw_smoke`).
`$HOME_TMP` denotes a throwaway HOME used **only** when exercising
shell-history mutation: `HOME_TMP=$(mktemp -d -t empusa-home-XXXX)`.

## 3. Clean tree and install validation

| # | Command | Expected RC | Expected output | Pass/Fail |
|---|---|---:|---|:-:|
| 3.1 | `git status --porcelain` | 0 | empty (clean tree) |   |
| 3.2 | `python -m venv .venv` | 0 | venv created |   |
| 3.3 | `source .venv/bin/activate` (POSIX) or `.venv\Scripts\activate` (Windows) | 0 | prompt prefix changes |   |
| 3.4 | `python -m pip install -U pip` | 0 | `Successfully installed pip-…` |   |
| 3.5 | `python -m pip install -e ".[dev]"` | 0 | `Successfully installed empusa-2.3.0` |   |
| 3.6 | `empusa --version` | 0 | `empusa 2.3.0` |   |
| 3.7 | `empusa --help` | 0 | usage with `{build,exploit-search,loot,report,plugins,workspace}` |   |
| 3.8 | `python -m empusa --version` | 0 | `empusa 2.3.0` |   |
| 3.9 | `python -m empusa --help` | 0 | identical help output |   |

Safety: a dirty tree at 3.1 is a release blocker but not a raw-validation
failure — record it and continue.

## 4. Release / dev sanity validation

| # | Command | Expected RC | Expected output | Pass/Fail |
|---|---|---:|---|:-:|
| 4.1 | `python -m ruff check empusa tests scripts` | 0 | `All checks passed!` |   |
| 4.2 | `python -m ruff format --check empusa tests scripts` | 0 | `N files already formatted` |   |
| 4.3 | `python -m pytest -q --cov=empusa --cov-branch` | 0 | coverage `>= 65%`; `Required test coverage … reached.` |   |
| 4.4 | `python scripts/dev/version-sanity.py` | 0 | `[PASS] empusa version 2.3.0 is consistent` |   |
| 4.5 | `python -m build --wheel` | 0 | `dist/empusa-2.3.0-py3-none-any.whl` |   |
| 4.6 | `python scripts/dev/package-sanity.py` | 0 | `[PASS] N wheel(s) clean` |   |

## 5. Workspace lifecycle validation (temp root)

```bash
WS=$(mktemp -d -t empusa-ws-XXXX)
```

| # | Command | Expected RC | Expected output | Expected files | Pass/Fail |
|---|---|---:|---|---|:-:|
| 5.1 | `empusa workspace init --name raw_htb --profile htb --root "$WS"` | 0 | `Workspace Init  raw_htb (htb)` panel | `$WS/raw_htb/{notes,scans,creds,loot,exploits,reports,logs,screenshots,web}` |   |
| 5.2 | `empusa workspace init --name raw_build --profile build --root "$WS"` | 0 | init panel | profile-specific dirs |   |
| 5.3 | `empusa workspace init --name raw_research --profile research --root "$WS"` | 0 | init panel; `[WARN]` on missing `--templates-dir` | research dirs created |   |
| 5.4 | `empusa workspace init --name raw_internal --profile internal --root "$WS"` | 0 | init panel | internal dirs created |   |
| 5.5 | `empusa workspace list --root "$WS"` | 0 | all four workspaces listed; one marked active |   |   |
| 5.6 | `empusa workspace select --name raw_htb --root "$WS"` | 0 | `Workspace Select  raw_htb` panel | active marker updated |   |
| 5.7 | `empusa workspace status --name raw_htb --root "$WS"` | 0 | metadata panel; profile/path absolute |   |   |
| 5.8 | `find "$WS" -name '.empusa-workspace.json' -print` | 0 | one per workspace |   |   |

Safety: `--root "$WS"` is mandatory. Never run 5.x without `--root`.

## 6. Strict workspace / template validation

```bash
VALID_TPL=$(mktemp -d -t empusa-tpl-XXXX)
# Seed with the htb profile's expected template filenames.
for f in $(python -c "from empusa.workspace import PROFILES; print(' '.join(PROFILES['htb']['templates']))"); do
    printf '# %s\n' "$f" > "$VALID_TPL/$f"
done
```

| # | Command | Expected RC | Expected output | Pass/Fail |
|---|---|---:|---|:-:|
| 6.1 | `STRICT_TEMPLATES=1 empusa workspace init --name strict_miss --profile htb --root "$WS"` | **1** | `[FAIL] STRICT_TEMPLATES: profile 'htb' expects templates but --templates-dir was not supplied` |   |
| 6.2 | `STRICT_TEMPLATES=1 empusa workspace init --name strict_bad --profile htb --root "$WS" --templates-dir /no/such/path` | **1** | `[FAIL]` referencing missing dir |   |
| 6.3 | `STRICT_TEMPLATES=1 empusa workspace init --name strict_ok --profile htb --root "$WS" --templates-dir "$VALID_TPL"` | 0 | normal init panel; templates seeded |   |
| 6.4 | `unset STRICT_TEMPLATES; empusa workspace init --name soft --profile htb --root "$WS"` | 0 | warn-and-create preserved |   |

## 7. Build / environment validation (temp root + temp HOME)

The non-interactive `empusa build` only needs `--env` and `--ips`. Use
a throwaway `HOME` whenever exercising `--shell-history` so the real
operator shell profile is never touched.

```bash
ENV_ROOT=$(mktemp -d -t empusa-env-XXXX)
HOME_TMP=$(mktemp -d -t empusa-home-XXXX)
```

| # | Command | Expected RC | Expected output | Expected files | Pass/Fail |
|---|---|---:|---|---|:-:|
| 7.1 | `empusa build --help` | 0 | help text incl. `--env`, `--ips`, `--shell-history`/`--no-shell-history`, `--force-overwrite` |   |   |
| 7.2 | `cd "$ENV_ROOT" && empusa --no-plugins build --env raw --ips 10.0.0.1` | 0 | `[PASS]` env created; **no prompt** | `$ENV_ROOT/raw/` populated; no shell rc files mutated |   |
| 7.3 | `cd "$ENV_ROOT" && empusa --no-plugins build --env raw --ips 10.0.0.1` (re-run) | non-zero | `[FAIL]` non-empty env directory exists |   |   |
| 7.4 | `cd "$ENV_ROOT" && empusa --no-plugins build --env raw --ips 10.0.0.1 --force-overwrite` | 0 | `[PASS]` env recreated |   |   |
| 7.5 | `HOME="$HOME_TMP" empusa --no-plugins --enable-shell-hooks build --env hooked --ips 10.0.0.1 --shell-history` | 0 | `[ACTION]` shell hook installed in `$HOME_TMP` only | `$HOME_TMP/.bashrc` (or equivalent) gains hook lines; real `$HOME` untouched |   |
| 7.6 | `empusa --no-plugins build --env nope --ips not-an-ip` | non-zero | `[FAIL]` invalid IP |   |   |

Safety: 7.5 is the **only** check that may write into `$HOME`. The
explicit `HOME="$HOME_TMP"` override is mandatory; without it, skip 7.5.

## 8. Scan validation (CLI + dry-run only)

`scan` has **no non-interactive subcommand** in the current CLI; it is
reached through the interactive menu. Validate the surface without
executing a real scan:

| # | Command | Expected RC | Expected output | Pass/Fail |
|---|---|---:|---|:-:|
| 8.1 | `empusa --dry-run --no-plugins build --env scan_smoke --ips 127.0.0.1` | 0 | dry-run plan printed; **no** scan launched |   |
| 8.2 | `python -c "import empusa.cli_scan as m; print([x for x in dir(m) if not x.startswith('_')])"` | 0 | helper inventory; expect `validate_ip`, `validate_hostname`, `validate_port`, `summarize_hosts`, `run_nmap`, `search_exploits_from_nmap`, `detect_os` |   |
| 8.3 | `python -c "from empusa.cli_scan import validate_ip; print(validate_ip('127.0.0.1'), validate_ip('not-an-ip'))"` | 0 | `True False` |   |
| 8.4 | `python -c "from empusa.cli_scan import summarize_hosts; print(summarize_hosts(['127.0.0.1','10.0.0.1']))"` | 0 | summary text only; no `subprocess` |   |
| 8.5 | Inventory only / helper not stable for raw one-liner: `run_nmap` / `search_exploits_from_nmap` execute external tooling. Validate via `python -m pytest -q tests/test_cli_scan_extended.py` | 0 | scan helper suite green |   |

Safety: never call `run_nmap` from raw validation — it shells out to
`nmap`. The pure validators (`validate_ip`, `summarize_hosts`) are the
only safe one-liners; everything else is covered by
`tests/test_cli_scan_extended.py`.

## 9. Loot validation (temp env)

```bash
ENV=raw_loot
empusa --no-plugins build --env $ENV --ips 10.0.0.1
```

| # | Command | Expected RC | Expected output | Expected files | Pass/Fail |
|---|---|---:|---|---|:-:|
| 9.1 | `empusa loot --help` | 0 | help with `{list,add}`, `--env`, `--host`, `--cred-type`, `--username`, `--secret`, `--source` |   |   |
| 9.2 | `empusa --no-plugins loot --env $ENV list` | 0 | `[INFO]` empty loot |   |   |
| 9.3 | `empusa --no-plugins loot --env $ENV add --host 10.0.0.1 --cred-type ntlm --username admin --secret aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 --source raw-validation` | 0 | `[PASS]` credential recorded | `<env>/loot/loot.json` (or current schema file) |   |
| 9.4 | `empusa --no-plugins loot --env $ENV list` | 0 | the row from 9.3 visible |   |   |
| 9.5 | `find "$(pwd)/$ENV" -path '*loot*' -print` | 0 | files all rooted under `$ENV` (no traversal) |   |   |

Safety: use synthetic NTLM/MD5 sample hashes only. Never paste real
operator credentials into a raw-validation tree.

## 10. Report validation (temp env)

| # | Command | Expected RC | Expected output | Expected files | Pass/Fail |
|---|---|---:|---|---|:-:|
| 10.1 | `empusa report --help` | 0 | help with `--env`, `--assessment` |   |   |
| 10.2 | seed `$ENV/scans/`, `$ENV/loot/` with sample files (or rely on §9) | 0 | – | sample inputs in place |   |
| 10.3 | `empusa --no-plugins report --env $ENV --assessment "raw-smoke"` | 0 | `[PASS]` report generated | report file in `<env>/reports/` (markdown or current default) |   |
| 10.4 | `grep -E '^## (Hosts|Loot|Scans?)' <env>/reports/<file>` | 0 | stable section headers present |   |   |
| 10.5 | `empusa --no-plugins report --env nonexistent --assessment x` | non-zero | `[FAIL]` env not found; **no traceback** |   |   |

A malformed scan/loot input must produce `[WARN]` and the report must
still complete (matches current behavior). Confirm by truncating one
loot row and re-running 10.3.

## 11. Module workshop validation

`modules` has **no non-interactive subcommand** today; the validation
target is module **discovery** (gated by `STRICT_MODULES`).

| # | Command | Expected RC | Expected output | Pass/Fail |
|---|---|---:|---|:-:|
| 11.1 | `python -c "from empusa.cli_modules import list_modules; print(len(list_modules()))"` | 0 | integer count of bundled modules (currently 22) |   |
| 11.2 | `python -c "from empusa.cli_modules import strict_modules_enabled; print(strict_modules_enabled())"` | 0 | `False` by default; flips to `True` under `STRICT_MODULES=1` |   |
| 11.3 | `STRICT_MODULES=1 python -m pytest -q tests/test_cli_modules.py` | 0 | full module-discovery test class green under strict |   |
| 11.4 | Inventory only / no `EMPUSA_MODULE_PATHS` env var override exists today; bad-manifest rejection is exercised exclusively by `tests/test_cli_modules.py` | 0 | strict rejection path covered by pytest |   |
| 11.5 | `python scripts/dev/package-sanity.py` (after wheel build) | 0 | `[PASS]` no forbidden module artifacts |   |

> Module discovery is rooted at `empusa.cli_modules.MODULES_DIR`
> (bundled `empusa/hooks/modules/`); there is no operator-overrideable
> path. Out-of-tree modules are not part of the current contract.

Safety: never invoke a module compile/run path. `STRICT_MODULES` only
exercises discovery and metadata validation.

## 12. Plugin validation

| # | Command | Expected RC | Expected output | Pass/Fail |
|---|---|---:|---|:-:|
| 12.1 | `empusa plugins --help` | 0 | help with `{refresh}` |   |
| 12.2 | `empusa plugins refresh --help` | 0 | sub-help |   |
| 12.3 | `empusa --no-plugins plugins refresh` | 0 or non-zero per current contract | `[INFO]` plugin discovery skipped or refreshed |   |
| 12.4 | `empusa plugins refresh` | 0 | `[PASS]` per plugin with state (`active` / `enabled` / `disabled` / `blocked`); 0 plugins is a valid result |   |
| 12.5 | `python -c "from empusa.plugins import PluginManager; from empusa.cli_plugins import PLUGINS_DIR; pm=PluginManager(PLUGINS_DIR); pm.discover(); print(pm.plugin_count(), [p.name for p in pm.plugins])"` | 0 | integer count + name list (may be empty) |   |
| 12.6 | Inventory only / no `EMPUSA_PLUGIN_PATHS` env var override exists today; permission-rejection is exercised by `tests/test_cli_plugins.py` and `tests/test_plugins.py` against `PluginManager` directly | 0 | invalid-permission rejection covered by pytest |   |

> Manifest contract is exposed via
> `empusa.plugins.REQUIRED_MANIFEST_FIELDS` and
> `empusa.plugins.VALID_PERMISSIONS`. Plugin discovery is rooted at
> `empusa.cli_plugins.PLUGINS_DIR`; there is no operator-overrideable
> path.

Safety: the bundled plugin set is the only safe activation target.
`--no-plugins` must be respected globally.

## 13. Hooks / events validation

`hooks` is interactive-only today. Validate the public Python surface:

| # | Command | Expected RC | Expected output | Pass/Fail |
|---|---|---:|---|:-:|
| 13.1 | `python -c "import empusa.cli_hooks as m; print(sorted(x for x in dir(m) if not x.startswith('_')))"` | 0 | helper inventory; expect `list_hooks`, `run_hooks`, `test_fire_hook`, `init_hook_dirs`, `HOOK_EVENTS`, `HOOKS_DIR` |   |
| 13.2 | `python -c "from empusa.events import ALL_EVENTS; print(sorted(ALL_EVENTS))"` | 0 | canonical event-name list (17 entries, e.g. `on_startup`, `pre_build`, `post_workspace_init`) |   |
| 13.3 | `python -c "from empusa.cli_hooks import HOOK_EVENTS; from empusa.events import ALL_EVENTS; print(set(HOOK_EVENTS).issubset(set(ALL_EVENTS)))"` | 0 | `True` (hook surface is a subset of the event registry) |   |
| 13.4 | `python -c "from empusa.cli_hooks import list_hooks; h=list_hooks(); print(len(h), sorted(h)[:3])"` | 0 | dict keyed by event; bundled tree may be empty (count `>= 0`) |   |
| 13.5 | Inventory only / no `EMPUSA_HOOKS_DIR` env var override exists today; hook-dir is rooted at `empusa.cli_hooks.HOOKS_DIR`. End-to-end firing is exercised by `tests/test_cli_hooks.py` and `tests/test_events_bus.py` | 0 | hook firing covered by pytest |   |

Safety: do not `run_hooks` from a raw shell — it executes on-disk
scripts. Inventory + registry checks above are read-only.

## 14. Hash utility validation

`hash` is interactive-only today. Validate the helpers:

| # | Command | Expected RC | Expected output | Pass/Fail |
|---|---|---:|---|:-:|
| 14.1 | `python -c "from empusa.cli_hash import identify_hash; print(identify_hash('5f4dcc3b5aa765d61d8327deb882cf99'))"` | 0 | list includes `(0, 'MD5')` and `(1000, 'NTLM')` |   |
| 14.2 | `python -c "from empusa.cli_hash import identify_hash; print(identify_hash('31d6cfe0d16ae931b73c59d7e0c089c0'))"` | 0 | family includes `NTLM` (empty NT half from synthetic LM:NT pair) |   |
| 14.3 | `python -c "from empusa.cli_hash import identify_hash; print(identify_hash('\$2y\$10\$abcdefghijklmnopqrstuv1234567890ABCDEFGHIJKLMNOPQRS'))"` | 0 | family includes `bcrypt ($2)` |   |
| 14.4 | `python -c "from empusa.cli_hash import HASH_SIGNATURES; print(len(HASH_SIGNATURES))"` | 0 | integer signature count (read-only inventory) |   |
| 14.5 | Inventory only / no public file-scanner helper today (the interactive `hash_crack_builder` drives the workshop). Bulk file scan is exercised by `tests/test_cli_hash.py` and `tests/test_cli_hash_interactive.py` | 0 | file scan covered by pytest |   |

Safety: sample hashes are well-known test fixtures, not real secrets.
`find_password_files` walks the filesystem — call it only with an
explicit `search_path=Path("$WS")` if you need to exercise it raw.

## 15. AD playbook validation

`ad` is interactive-only. The only public surface is
`empusa.cli_ad.ad_enum_playbook()`, which prompts for domain/DC inputs;
there is no parameterized one-liner. Validate the inventory and defer
behavior to pytest.

| # | Command | Expected RC | Expected output | Pass/Fail |
|---|---|---:|---|:-:|
| 15.1 | `python -c "import empusa.cli_ad as m; print([x for x in dir(m) if not x.startswith('_')])"` | 0 | inventory includes `ad_enum_playbook` |   |
| 15.2 | Inventory only / `ad_enum_playbook` is interactive-only. Validated via `python -m pytest -q tests/test_cli_ad.py` | 0 | AD playbook suite green |   |

Safety: never run `ad_enum_playbook` from a raw shell — it expects
operator input and may emit commands that target a real DC if the
operator types a real address.

## 16. Privilege escalation validation

`privesc` is interactive-only. The only callable is
`empusa.cli_privesc.privesc_enum_generator()` (interactive); the static
checklists live in the `LINUX_ENUM_COMMANDS` and `WINDOWS_ENUM_COMMANDS`
constants. Validate those directly.

| # | Command | Expected RC | Expected output | Expected files | Pass/Fail |
|---|---|---:|---|---|:-:|
| 16.1 | `python -c "from empusa.cli_privesc import LINUX_ENUM_COMMANDS; print(len(LINUX_ENUM_COMMANDS), LINUX_ENUM_COMMANDS[0])"` | 0 | non-zero count + a `(category, command)` tuple |   |   |
| 16.2 | `python -c "from empusa.cli_privesc import WINDOWS_ENUM_COMMANDS; print(len(WINDOWS_ENUM_COMMANDS), WINDOWS_ENUM_COMMANDS[0])"` | 0 | non-zero count + a `(category, command)` tuple |   |   |
| 16.3 | `python -c "from empusa.cli_privesc import LINUX_ENUM_COMMANDS; open(r'$WS/linux.md','w',encoding='utf-8').write('\n'.join(f'- [{c}] {cmd}' for c,cmd in LINUX_ENUM_COMMANDS))"` | 0 | – | `$WS/linux.md` written from the in-memory checklist |   |
| 16.4 | Inventory only / `privesc_enum_generator` is interactive. Validated via `python -m pytest -q tests/test_cli_privesc.py` | 0 | – | privesc suite green |   |

Safety: no `subprocess`, no system probing — these are static
checklists; row 16.3 only writes inside `$WS`.

## 17. Tunnel command generation validation

`tunnel` is interactive-only. Validate the per-type command builders.
Each `build_*_commands` helper returns `list[tuple[str, str]]` of
`(role, command_string)` pairs and never opens a socket. The
`format_commands_file` helper renders that list to a saveable text
block. The `TUNNEL_TYPES` dict enumerates the supported types.

| # | Type | Command | Expected RC | Expected output | Pass/Fail |
|---|---|---|---:|---|:-:|
| 17.0 | inventory | `python -c "from empusa.cli_tunnel import TUNNEL_TYPES; print(TUNNEL_TYPES)"` | 0 | dict with 8 entries: Chisel, SSH_Reverse, SSH_Local, SSH_SOCKS, Ligolo, Socat, Netsh, Metasploit |   |
| 17.1 | chisel       | `python -c "from empusa.cli_tunnel import build_chisel_commands; print(build_chisel_commands('10.0.0.1','8080','1080')[:1])"` | 0 | first `(role, cmd)` tuple; no execution |   |
| 17.2 | ssh-reverse  | `python -c "from empusa.cli_tunnel import build_ssh_reverse_commands; print(build_ssh_reverse_commands('op','10.0.0.2','4444','22')[:1])"` | 0 | first `(role, cmd)` tuple |   |
| 17.3 | ssh-local    | `python -c "from empusa.cli_tunnel import build_ssh_local_commands; print(build_ssh_local_commands('op','10.0.0.3','8080','127.0.0.1','80')[:1])"` | 0 | first `(role, cmd)` tuple |   |
| 17.4 | ssh-socks    | `python -c "from empusa.cli_tunnel import build_ssh_socks_commands; print(build_ssh_socks_commands('op','10.0.0.4','1080')[:1])"` | 0 | first `(role, cmd)` tuple |   |
| 17.5 | ligolo       | `python -c "from empusa.cli_tunnel import build_ligolo_commands; print(build_ligolo_commands('10.0.0.5','11601','240.0.0.1/24')[:1])"` | 0 | first `(role, cmd)` tuple |   |
| 17.6 | socat        | `python -c "from empusa.cli_tunnel import build_socat_commands; print(build_socat_commands('4444','10.0.0.6','80')[:1])"` | 0 | first `(role, cmd)` tuple |   |
| 17.7 | netsh        | `python -c "from empusa.cli_tunnel import build_netsh_commands; print(build_netsh_commands('4444','10.0.0.7','80')[:1])"` | 0 | first `(role, cmd)` tuple |   |
| 17.8 | metasploit   | `python -c "from empusa.cli_tunnel import build_metasploit_commands; print(build_metasploit_commands('1','10.0.0.0/24','8080')[:1])"` | 0 | first `(role, cmd)` tuple |   |
| 17.9 | save-to-file | `python -c "from empusa.cli_tunnel import build_chisel_commands, format_commands_file; open(r'$WS/tunnel.txt','w',encoding='utf-8').write(format_commands_file('Chisel','raw_smoke', build_chisel_commands('10.0.0.1','8080','1080')))"` | 0 | – (file written under `$WS`) |   |

> Cross-check via
> `python -c "import empusa.cli_tunnel as m; print(sorted(x for x in dir(m) if not x.startswith('_')))"`
> for the current tag. Test-proven invocations live in
> `tests/test_cli_tunnel.py`. The contract is **generation only, no
> socket open, no `subprocess`**.

Safety: every IP must be RFC1918 / TEST-NET fixture. Never generate a
tunnel pointing at a real C2 endpoint during raw validation.

## 18. No-plugin / strict combined smoke

| # | Command | Expected RC | Expected output | Pass/Fail |
|---|---|---:|---|:-:|
| 18.1 | `STRICT_MODULES=1 STRICT_TEMPLATES=1 empusa --no-plugins --help` | 0 | usage text; strict gates do not break help |   |
| 18.2 | `STRICT_MODULES=1 empusa --no-plugins build --help` | 0 | help text only (no discovery invoked) |   |
| 18.3 | `STRICT_MODULES=1 python -c "from empusa.cli_modules import list_modules, strict_modules_enabled; assert strict_modules_enabled(); print(len(list_modules()))"` | 0 | bundled modules clean under strict |   |
| 18.4 | `STRICT_TEMPLATES=1 empusa --no-plugins workspace init --name strict_combo --profile htb --root "$WS" --templates-dir "$VALID_TPL"` | 0 | normal init |   |
| 18.5 | `STRICT_MODULES=1 STRICT_TEMPLATES=1 python -m pytest -q --no-cov` | 0 | full suite green under both gates |   |

## 19. Failure-mode raw checks

| # | Command | Expected RC | Expected output | Pass/Fail |
|---|---|---:|---|:-:|
| 19.1 | `empusa workspace init --name 'bad name' --profile htb --root "$WS"` | non-zero | `[FAIL]` invalid name; no traceback |   |
| 19.2 | `empusa workspace init --name x --profile no-such-profile --root "$WS"` | non-zero | `[FAIL]` invalid profile |   |
| 19.3 | `empusa workspace status --name no_such --root "$WS"` | non-zero | `[FAIL]` workspace not found |   |
| 19.4 | `empusa loot --env no_such_env list` | non-zero | `[FAIL]` env missing |   |
| 19.5 | `empusa report --env no_such_env --assessment x` | non-zero | `[FAIL]` env missing |   |
| 19.6 | Inventory only / no `EMPUSA_PLUGIN_PATHS` env var override exists. Invalid-permission rejection is exercised by `python -m pytest -q tests/test_plugins.py tests/test_cli_plugins.py` against `PluginManager` directly | 0 | permission-validation suite green |   |
| 19.7 | rename `nmap` out of `PATH`, run a build that would invoke it | per current contract | `[WARN]` or `[FAIL]` clean message; no traceback |   |
| 19.8 | `STRICT_TEMPLATES=1 empusa workspace init --name miss --profile htb --root "$WS"` | 1 | `[FAIL] STRICT_TEMPLATES:` |   |
| 19.9 | Inventory only / no `EMPUSA_MODULE_PATHS` env var override exists. Strict module rejection is exercised by `STRICT_MODULES=1 python -m pytest -q tests/test_cli_modules.py` against in-tree fixtures | 0 | strict-rejection suite green |   |

Safety: 19.7 must restore `PATH` after the check. Use a sub-shell:
`( PATH=/tmp empusa --no-plugins build … )`.

## 20. Cleanup

```bash
rm -rf "$WS" "$ENV_ROOT" "$HOME_TMP" "$VALID_TPL"
rm -rf build dist *.egg-info
deactivate 2>/dev/null || true
rm -rf .venv
unset STRICT_MODULES STRICT_TEMPLATES
```

## 21. Last-run results

| Date | Host | Empusa | # | Command | Expected | Actual | RC | P/F | Notes |
|---|---|---|---|---|---|---|---:|:-:|---|
| 2026-04-26 | win11 / py3.9 (no bash) | 2.3.0 | 3.6 | `python -m empusa --version` | `empusa 2.3.0` | `empusa 2.3.0` | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 3.7 | `python -m empusa --help` | usage emitted | usage emitted | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 4.4 | `version-sanity.py` | `[PASS]` consistent | `[PASS] empusa version 2.3.0 is consistent` | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 4.5 | `python -m build --wheel` | wheel produced | `empusa-2.3.0-py3-none-any.whl` | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 4.6 | `package-sanity.py` | `[PASS] N wheel(s) clean` | `[PASS] 1 wheel(s) clean` | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 5.1 | `workspace init htb (temp root)` | full htb tree | full htb tree | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 5.5 | `workspace list (temp root)` | listed | listed | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 5.6 | `workspace select` | `Workspace Select` panel | as expected | 0 | PASS | requires `PYTHONUTF8=1` on Windows |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 5.7 | `workspace status` | metadata panel | as expected | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 6.1 | `STRICT_TEMPLATES=1 init (no --templates-dir)` | `[FAIL]` strict | `[FAIL]` strict | 1 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 6.4 | `unset STRICT_TEMPLATES` repeat | warn-and-create | as expected | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 18.2 | `STRICT_MODULES=1 build --help` | help only | help only | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 8.3 | `validate_ip` smoke | `True False` | `True False` | 0 | PASS | doc-helper accuracy pass |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 8.4 | `summarize_hosts(['127.0.0.1','10.0.0.1'])` | summary text | summary text | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 11.1 | `len(list_modules())` | integer | `22` | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 11.2 | `strict_modules_enabled()` (no env) | `False` | `False` | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 12.5 | `PluginManager(PLUGINS_DIR).discover()` | count + names | `0 []` | 0 | PASS | bundled tree empty by design |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 13.2 | `sorted(ALL_EVENTS)` | 17 events | 17 events | 0 | PASS | registry is `ALL_EVENTS`, not `EVENTS` |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 13.3 | `HOOK_EVENTS ⊆ ALL_EVENTS` | `True` | `True` | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 14.1 | `identify_hash(MD5 fixture)` | includes MD5 | `[(0,'MD5'),(1000,'NTLM'),(3000,'LM')]` | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 14.3 | `identify_hash(bcrypt fixture)` | includes bcrypt | `[(3200,'bcrypt ($2)')]` | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 16.1 | `len(LINUX_ENUM_COMMANDS)` | non-zero | `28` | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 16.2 | `len(WINDOWS_ENUM_COMMANDS)` | non-zero | `24` | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 17.0 | `TUNNEL_TYPES` | 8 entries | 8 entries (Chisel…Metasploit) | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 17.1 | `build_chisel_commands` | tuple list | `[('Attacker','./chisel server -p 8080 --socks5 --reverse')]` | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 17.2 | `build_ssh_reverse_commands` | tuple list | `[('Target','ssh -R 4444:127.0.0.1:22 op@10.0.0.2 -N -f')]` | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 17.3 | `build_ssh_local_commands` | tuple list | OK | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 17.4 | `build_ssh_socks_commands` | tuple list | OK | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 17.5 | `build_ligolo_commands` | tuple list | OK | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 17.6 | `build_socat_commands` | tuple list | OK | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 17.7 | `build_netsh_commands` | tuple list | OK | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 17.8 | `build_metasploit_commands` | tuple list | OK | 0 | PASS | |
| 2026-04-26 | win11 / py3.9 | 2.3.0 | 17.9 | `format_commands_file` | rendered text | header + commands | 0 | PASS | |

Append rows for each subsequent run. Keep at least the **last release
tag** worth of evidence in this table.

## 22. Manual gaps

The following cannot be raw-run safely without a lab, network, or real
external tooling. They are intentionally out of scope and must be
exercised in the appropriate environment:

- **Real scans** — `nmap`, masscan, web fuzzers, etc. against any host
  other than `127.0.0.1`. Validate end-to-end on a Hecate lab host with
  authorized targets only.
- **Module compile / payload execution** — covered by Hecate's
  `tests/e2e/` and `labctl launch` flows; never raw-run.
- **Tunnel start** — generation is validated here; binding sockets and
  proving end-to-end reachability requires a lab with a controlled
  remote endpoint.
- **AD / privesc execution** — playbooks are generated here; running
  them against a target is a lab activity.
- **Plugin marketplace activity** — only the bundled plugin set is
  exercised. Third-party plugin install/upgrade is out of scope.
- **Real shell-history mutation** — only `HOME=$HOME_TMP` overrides are
  permitted in this doc. Production shell-history hooks must be audited
  by the operator on their own host before opt-in.
- **Coverage on Windows-only paths** — Rich box-drawing requires UTF-8
  console (`PYTHONIOENCODING=utf-8 PYTHONUTF8=1`); record cp1252 issues
  here if encountered, do not treat them as Empusa defects.
- **`shellcheck` / `markdownlint`** — neither is required by Empusa CI;
  run if available locally.
