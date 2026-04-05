# Contributing to Empusa

Thanks for your interest in Empusa! Here is how you can help.

## Quick Start

1. Fork & clone the repository.
2. Create a virtual environment and install in editable mode:

   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Linux/macOS
   .venv\Scripts\activate      # Windows
   pip install -e .[dev]
   ```

3. Install pre-commit hooks:

   ```bash
   pre-commit install
   ```

4. Create a feature branch:

   ```bash
   git checkout -b feature/my-feature
   ```

5. Identify the right module for your change:

   | Module | Purpose |
   | -------- | --------- |
   | `empusa/cli_common.py` | Shared helpers, CONFIG, logging, path constants |
   | `empusa/cli_plugins.py` | Plugin UI (list, create, toggle, info, uninstall) |
   | `empusa/cli_hooks.py` | Hook UI and `_run_hooks` dispatch |
   | `empusa/cli_modules.py` | Module Workshop |
   | `empusa/cli_reports.py` | Report Builder |
   | `empusa/cli_build.py` | Env builder, tunnels, loot, exploit search, hash/AD/privesc tools |
   | `empusa/cli.py` | Thin entrypoint — menu routing and framework init only |
   | `empusa/plugins.py` | Layer 3 PluginManager and ScopedServices |
   | `empusa/bus.py` | Layer 1 EventBus |
   | `empusa/services.py` | Layer 5 runtime services |
   | `empusa/registry.py` | Capability registry |
   | `empusa/events.py` | Event name constants |

6. Run the test suite:

   ```bash
   pip install pytest
   python -m pytest
   ```

7. Run Pylance or mypy to verify zero type errors.
8. Submit a pull request with a clear description.

## Code Style

- **Python 3.9+** - use `from __future__ import annotations` if needed.
- **Type annotations** on every function signature.
- **`rich`** for all terminal output - no bare `print()`.
- Keep imports sorted: stdlib -> third-party -> local.
- Docstrings on public functions.
- New domain logic goes in `cli_build.py` or a dedicated sub-module, not `cli.py`.
- Functions needing framework access take keyword-only parameters (`run_hooks_fn`, `services`, `ask_env_fn`) rather than importing globals.

## Documentation Style

These rules apply to all markdown files in both Empusa and Hecate.
Contract docs (`docs/empusa.md`, profile tables, env-var tables) **must** stay
aligned with source code and test assertions — update them in the same commit.

### Badges

- Use `shields.io` flat badges at the top of `README.md` only.
- One line per badge.  No blank lines between badges.
- Link each badge to something actionable (CI page, section anchor, license file).

### Mermaid diagrams

- Use only for: architecture boundaries, lifecycle flows, dispatch graphs, topology.
- Do **not** use FA icons (`fa:fa-*`) — they don't render on GitHub.
- Do **not** add `classDef` / `class` blocks — GitHub ignores custom styles.
- Keep nodes ≤ 2 lines of text.  If a node needs 3+ lines, it belongs in a table.
- Node IDs should map to real files or components (`BUS`, `LABCTL`, not `box1`).

### Tables

- Prefer tables over bullet lists for structured data (flags, variables, paths).
- Environment variables: include **Type**, **Default**, and **Used by** columns.
- CLI flags: include **Type** and **Default** columns.
- Profile/contract tables: reference the source-of-truth file in a caption or header.

Example (env var):

```markdown
| Variable | Type | Default | Used by |
|----------|------|---------|---------|
| `LAB_GPU` | `0\|1` | `0` | launch-lab.sh, lib/compose.sh |
```

### Code fences

- Always tag the language: `` ```bash ``, `` ```python ``, `` ```text ``.
- Use `text` for static output, directory trees, and non-executable content.
- Separate commands from their output — don't paste both in one fence.

### Paths

- Use backtick-wrapped paths: `` `empusa/workspace.py` ``, `` `${LAB_ROOT}/tools/` ``.
- Use forward slashes in docs, even if the host is Windows.
- Prefer `${VAR}` over hardcoded absolute paths when a variable exists.

### Terminology

| Term | Meaning | Do NOT use |
| ------ | --------- | ----------- |
| workspace | An Empusa-managed engagement directory | environment, env |
| profile | A workspace profile (`htb`, `build`, `research`, `internal`) | template, layout |
| Hecate | The platform bootstrap product | lab-bootstrap |
| Empusa | The workspace engine | orchestrator |
| `labctl` | The Hecate CLI dispatcher | lab script |

### Source-of-truth discipline

- Profile definitions (dirs, templates) → `empusa/workspace.py → PROFILES`.
- Template files → `hecate-bootstrap/templates/*.md`.
- Delegation logic → `hecate-bootstrap/scripts/create-workspace.sh`, `launch-lab.sh`.
- If you change a contract surface, update the matching doc table **and** the
  test assertion in the same PR.

## Writing Hooks / Plugins

Empusa 2.0 ships with a hook system. To contribute a hook:

1. Pick an event from the list below.
2. Create a `.py` file with a `run(context: dict) -> None` function.
3. Place it in the matching subdirectory under `empusa/hooks/`.
4. Use **menu option 8 -> Test-fire an event** to verify.

### Available Events

| Event | Fires When | Context Keys |
| ------- | ----------- | -------------- |
| `on_startup` | Empusa launches | `timestamp`, `session_env` |
| `on_shutdown` | Clean exit / Ctrl+C | `killed_pids`, `cleaned_hooks` |
| `pre_build` | Before env build starts | `env_name`, `ips` |
| `post_build` | After env build | `env_name`, `env_path`, `ips` |
| `pre_scan_host` | Before a host scan | `ip`, `env_name` |
| `post_scan` | After host scan | `ip`, `scan_output`, `os_type` |
| `on_loot_add` | After loot saved | `host`, `username`, `secret`, `cred_type` |
| `pre_report_write` | Before report written | `env_name`, `env_path` |
| `on_report_generated` | After report | `report_path`, `env_name` |
| `on_env_select` | Env selected | `env_name` |
| `pre_command` | Before subprocess | `command`, `args`, `working_dir` |
| `post_command` | After subprocess | `command`, `return_code`, `stdout` |
| `post_compile` | After module compiled | `module_name`, `language`, `output_path` |
| `pre_workspace_init` | Before workspace creation | `workspace_name`, `workspace_root`, `profile` |
| `post_workspace_init` | After workspace scaffolding | `workspace_name`, `workspace_path`, `profile` |
| `on_workspace_select` | Workspace activated | `workspace_name`, `workspace_path`, `profile` |
| `test_fire` | Synthetic test event | `ip`, `host`, `username`, `secret`, `cred_type` |

### Hook Template

```python
"""Example hook - prints a message after a new environment is built."""

def run(context: dict) -> None:
    env = context.get("env_name", "unknown")
    print(f"[hook] Build complete for {env}")
```

### Hook Rules

- The file **must** define `run(context)`.
- Hooks that raise exceptions are caught and logged - they will not crash
  Empusa.
- Hooks run synchronously in alphabetical filename order within their event
  directory.
- Keep hooks lightweight; long-running work should spawn a background thread.

## Reporting Issues

Open a GitHub Issue with:

- Empusa version (`empusa --version`)
- Python version (`python --version`)
- OS / distro
- Steps to reproduce
- Full traceback (if applicable)

## License

By contributing you agree that your contributions will be licensed under the
[GPL-3.0-or-later](LICENSE) license.
