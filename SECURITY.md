# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 2.3.x   | ✅ Yes    |
| 2.2.x   | ✅ Yes    |
| < 2.0   | ❌ No     |

## Trust Model

Empusa is a local, single-operator framework. Its extension points are
**trusted local code**, not a sandbox. Operators must understand the
following before installing third-party plugins, hooks, or modules.

### Plugins and hooks

- Plugins (`empusa/plugins/<name>/plugin.py`) and hooks
  (`empusa/hooks/<event>/*.py`, `*.sh`) are **trusted local Python
  and shell code** loaded into the Empusa process or shelled out by it.
- Plugins and hooks are **not OS-sandboxed**. They run with the same
  user, environment, network, and filesystem privileges as the
  invoking `empusa` process.
- The plugin permission system (`network`, `filesystem`, `subprocess`,
  `loot_read`, `loot_write`, `registry`) **only gates Empusa service
  APIs** exposed through `Services`. It is an in-process intent
  declaration, not an OS-level capability boundary, and does not
  prevent a plugin from importing arbitrary Python modules or calling
  into the standard library directly.
- Treat installing a plugin or hook as equivalent to executing
  arbitrary code on the host. Review the source before enabling.

### Module Workshop

- Module manifests (`empusa/hooks/modules/<name>/module.json`) declare
  compile commands that are **trusted module manifest commands**. They
  are executed as-is on the operator's host when the module is built.
- Source assets shipped under `empusa/hooks/modules/` (`.c`, `.cpp`,
  `.cs`, `.csproj`, `.go`, `go.mod`, `.pl`, `.rs`, `Cargo.toml`,
  `Makefile`, `module.json`, `README.md`) are **source templates only**.
- **Precompiled payloads must not be committed** to the repository.
  Build artifacts (`obj/`, `bin/`, `*.exe`, `*.dll`, `*.elf`, etc.)
  are listed in `.gitignore` and are stripped from the published
  wheel by `scripts/dev/package-sanity.py`.

### Authorized use only

- The bundled offensive modules and templates are intended for
  **authorized lab or assessment environments only**.
- Operators are responsible for ensuring **no unauthorized
  persistence, access, or deployment** results from running Empusa,
  its modules, its plugins, or its hooks.
- See the "Legal and Responsible Use" section of `README.md` for the
  full responsibility statement.

### Hardening tips

- Use `empusa --no-plugins` to start the framework without activating
  any plugin. This is the recommended posture for one-off, scripted,
  or audit runs.
- Keep `empusa/plugins/` empty (or audited) for production deployments
  where third-party code is not desired.
- Run Empusa from a dedicated lab user account. Do not run it as root.

## Reporting a Vulnerability

If you discover a security vulnerability in Empusa, please report it
responsibly:

1. **Do not** open a public GitHub issue.
2. Open a [private security advisory](https://github.com/Icarus4122/empusa/security/advisories/new)
   on this repository.
3. Alternatively, contact the maintainer directly via the email listed in the
   Git commit history.

Please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce or a proof of concept.
- The version of Empusa and Python you are using.
- Your operating system.

You should receive an acknowledgment within **72 hours**. A fix or mitigation
will be prioritized based on severity.
