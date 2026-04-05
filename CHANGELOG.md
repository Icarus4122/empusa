# Changelog

All notable changes to Empusa will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [2.2.1] - 2026-04-05

### Added

- **`make_event()` factory** - New canonical constructor in `events.py` that
  resolves event names through `EVENT_MAP`, filters kwargs to valid dataclass
  fields, and returns typed `EmpusaEvent` instances.
- **Contract-pinning test suites** - `TestWorkspaceConstantsPinned`,
  `TestEventPayloadSchemasPinned`, `TestEmitLegacyCanonical`,
  `TestLayoutDivergencePinned`, and `TestBuildEventPayloadsPinned` lock down
  workspace constants, all 17 event field sets, bus canonicalization, and
  workspace-vs-standalone layout separation.

### Changed

- **`bus.emit_legacy()`** - Now delegates to `make_event()` internally,
  confining canonicalization to the bus layer while preserving the `(str, dict)`
  contract at all external boundaries.
- **CLI import cleanup** - Removed unused `make_event` / `EmpusaEvent` imports
  from `cli_workspace`, `cli_scan`, `cli_reports`, `cli_loot`, `cli_modules`,
  `cli_hooks`, `cli`, and `services`.

## [2.2.0] - 2026-03-30

### Added

- **Panel controller architecture** - `manage_hooks()`, `module_workshop()`,
  and `loot_tracker()` now use a persistent content area that renders above
  the menu. Action results replace the content buffer instead of printing
  directly, so output persists across loop iterations until the next action.
- **"Press Enter to return" prompts** - Added to 6 command-generator functions
  (`privesc_enum_generator`, `hash_crack_builder`, `ad_enum_playbook`,
  `build_reverse_tunnel`, `generate_hashcat_rules`, `search_exploits_from_nmap`)
  so output isn't wiped by the next `clear_screen()`.
- **Post-build sub-menu** - Enhanced from 5 to 8 options with OS-aware hints.
  New options: Privesc Enumeration Generator (with Linux/Windows hint),
  Hash Identifier + Crack Builder, AD Enumeration Playbook (with "Windows
  detected" hint). OS detection reads host folder naming convention (`IP-OS`).
- **Render helper functions** - `list_hooks_render()`, `list_plugins_render()`,
  `show_registry_render()`, `_list_modules_render()`,
  `_detect_compilers_render()`, `_display_loot_table_render()`,
  `_reuse_analysis_render()` return Rich renderables for panel controllers.

### Changed

- **README.md** - Full rewrite with emoji section headers, structured tables,
  plugin development guide, and correct module language list (C, C++, C#, Go,
  Rust, Perl, Make). Python badge corrected from 3.11+ to 3.9+.

### Fixed

- **Module packaging** - `pyproject.toml` now declares `[tool.setuptools.package-data]`
  for all 13 module file patterns (`.json`, `.c`, `.cpp`, `.cs`, `.csproj`,
  `.go`, `.mod`, `.pl`, `.rs`, `.toml`, `Makefile`, `.md`, `.gitkeep`).
  `MANIFEST.in` updated to match. Previously, `pipx install .` shipped an
  empty `hooks/modules/` directory, so zero built-in modules were available
  after install.
- **Content ordering** - Panel controllers now render content *above* the menu
  instead of below it, matching the expected UX flow.
- **Stale content messages** - Removed redundant `content = "✔ …"` messages
  from `main_menu()` choices that call functions already holding the screen
  with their own "Press Enter" prompt.

## [2.1.0] - 2026-03-29

### Added

- **Module Workshop** (menu option 9) - Compile, create, and manage shellcode
  modules (C, ASM, Nim, Go, Python). Detects available compilers, compiles
  individual or all modules, shows module metadata, and opens the modules
  folder.
- **Privesc Enumeration Generator** (menu option 10) - Interactive Windows and
  Linux privilege escalation command generator with 50+ techniques covering
  SUID/GUID, sudo misconfigs, writable paths, scheduled tasks, service
  exploits, token impersonation, and more.
- **Hash Identifier + Crack Builder** (menu option 11) - Identifies hash type
  from 27 built-in signatures (MD5, NTLM, SHA-family, bcrypt, Kerberos, etc.)
  and generates a ready-to-run hashcat command with the correct mode flag.
- **AD Enumeration Playbook** (menu option 12) - Structured Active Directory
  enumeration guide covering BloodHound (SharpHound/bloodhound-python),
  PowerView, ldapsearch, impacket (GetNPUsers, GetUserSPNs, secretsdump),
  and SMB enumeration.
- **Layer 3 Plugin Framework** - Full plugin lifecycle manager (`PluginManager`,
  `ScopedServices`, `EventBus`, `registry`, `services`). Plugins declare
  manifests with permissions and dependencies; `ScopedServices` enforces
  capability gating at runtime. Dependency graph is resolved at startup with
  cycle detection and blocking of invalid plugins.

### Changed

- **cli.py refactor** - Split the single 2,783-line `cli.py` into 12 focused
  modules: `cli_common`, `cli_plugins`, `cli_hooks`, `cli_modules`,
  `cli_reports`, `cli_build` (domain logic), `events`, `registry`, `services`,
  `bus`, `plugins`. `cli.py` is now a thin 743-line entrypoint.
- **`which()` cleanup** - Replaced the 15-line subprocess-based `which()` in
  `cli_common.py` with a single `shutil.which()` call; `subprocess` import
  removed from that module entirely.
- **`ScopedServices` import** - Moved from `TYPE_CHECKING` block to a runtime
  import inside `_activate_one()` where it is actually used; `scoped_svc`
  typed as `Any` for clarity.

### Fixed

- **`clear_screen()` timing bug** - All interactive sub-menus (`manage_hooks`,
  `loot_tracker`, `module_workshop`) were calling `clear_screen()` immediately
  after the user's prompt, wiping the current action's output before it could
  be read. Fixed by moving `clear_screen()` to the top of each loop so it
  clears the *previous* iteration's output, not the current one. Same fix
  applied to `main_menu()`.

## [2.0.0] - 2025-07-11

### Added

- **Loot Tracker** - Interactive credential, hash, and flag manager with JSON
  storage, rich tables, credential reuse detection, cross-host spray
  suggestions, environment file sync (`users.txt` / `passwords.txt`), and
  markdown export.
- **Report Builder** - Auto-generates a full  penetration test
  report in Markdown, populated from scan data and loot entries.
- **Environment Detection & Switching** - Auto-discovers previous builds on
  startup, displays them in a selectable table, and stores the active
  environment in `CONFIG['session_env']` for reuse across menu actions.
- **Graceful Shutdown** - `Ctrl+C` and normal exit now kill lingering child
  processes (with PID reporting), strip shell history hooks from
  `.bashrc`/`.zshrc`/PowerShell profile, display a session execution flow
  ASCII diagram, and show a farewell summary panel.
- **Hook / Plugin System** - 7 lifecycle events (`on_startup`, `on_shutdown`,
  `post_build`, `post_scan`, `on_loot_add`, `on_report_generated`,
  `on_env_select`) with drop-in Python scripts under `empusa/hooks/`.
  Includes a built-in manager (menu option 8) to list, create, test-fire,
  and delete hooks.
- **Session Action Tracking** - Every menu action is logged with a timestamp
  and rendered as an ASCII execution flow during shutdown.
- **UX Improvements** - `clear_screen()` between every menu action, `_ask_env()`
  helper to avoid repetitive prompts, rich `Table` host summary after builds,
  `empusa.egg-info` filtered from environment listings.

### Changed

- **CrackMapExec -> NetExec** - All 3 references to `crackmapexec` replaced
  with `nxc` / NetExec to match current tooling.
- **License** - Corrected metadata from MIT to GPL-3.0-or-later (matching
  the actual LICENSE file).
- **Version** - Bumped to 2.0.0.

### Fixed

- 85 Pylance type-annotation warnings resolved (strict mode, 0 remaining).
- `typing_extensions` import error on Kali resolved (now uses stdlib
  `typing` only).
- `from empusa import __version__` failure fixed.
- Loot Tracker `cast()` applied for Pylance strict compliance.

## [1.0.0] - 2025-06-01

### Added

- Initial release with environment builder, reverse tunnel wizard, Hashcat
  rule generator, and exploit search.
