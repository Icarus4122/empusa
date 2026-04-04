"""
Empusa - Module Workshop UI (cli_modules)

Multi-language module compilation and management:

- **COMPILER_MAP / DEFAULT_COMPILE_CMD / LANGUAGE_EXTENSIONS** - lookup tables
- **detect_compilers** - scan PATH for known compilers
- **list_modules** - discover modules under MODULES_DIR
- **module_info** - display detailed info for a single module
- **compile_module** - compile one module according to its manifest
- **create_module_template** - scaffold a new module directory
- **module_workshop** - interactive module workshop menu
"""

from __future__ import annotations

import contextlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import time as _time_mod
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from empusa.cli_common import (
    CONFIG,
    IS_WINDOWS,
    MODULES_DIR,
    console,
    log_error,
    log_info,
    log_success,
    log_verbose,
    render_group_heading,
    render_kv,
    render_screen,
    which,
)

if TYPE_CHECKING:
    from empusa.services import Services


# -- Lookup tables ---------------------------------------------------

COMPILER_MAP: dict[str, list[str]] = {
    "c": ["gcc", "x86_64-w64-mingw32-gcc", "cc"],
    "cpp": ["g++", "x86_64-w64-mingw32-g++", "c++"],
    "csharp": ["dotnet", "mcs", "csc"],
    "rust": ["cargo", "rustc"],
    "go": ["go"],
    "perl": ["perl"],
    "make": ["make", "mingw32-make", "nmake"],
}

DEFAULT_COMPILE_CMD: dict[str, str] = {
    "c": "gcc {source} -o {output}",
    "cpp": "g++ {source} -o {output}",
    "csharp": "dotnet build {source_dir} -o {build_dir}",
    "rust": "cargo build --release --manifest-path {source_dir}/Cargo.toml",
    "go": "go build -o {output} {source}",
    "perl": "perl -c {source}",
    "make": "make -C {source_dir}",
}

LANGUAGE_EXTENSIONS: dict[str, str] = {
    "c": ".c",
    "cpp": ".cpp",
    "csharp": ".cs",
    "rust": ".rs",
    "go": ".go",
    "perl": ".pl",
}

# Languages where "compile" is validation only; the source file IS the
# deployable artifact.  After a successful syntax check the source is
# copied into build/ so the framework treats it like any other output.
INTERPRETED_LANGUAGES = {"perl", "python", "ruby", "shell"}

# Interpreter commands used to build a "suggested invocation" hint for
# script-type modules.  Compiled modules just use the artifact path.
INTERPRETER_HINT: dict[str, str] = {
    "perl": "perl",
    "python": "python3",
    "ruby": "ruby",
    "shell": "bash",
}


# -- Deterministic classification helpers ----------------------------


def _classify_artifact(artifact: Path | None, lang: str) -> str:
    """Deterministic artifact-kind classification.

    Rules (evaluated in strict order):
    1. ``None`` or does not exist -> ``"none"``
    2. Is a directory             -> ``"directory"``
    3. Language ∈ INTERPRETED     -> ``"script"``
    4. Otherwise                  -> ``"file"``  (compiled binary)

    This is the **only** call-site that assigns ``artifact_kind``.
    """
    if artifact is None or not artifact.exists():
        return "none"
    if artifact.is_dir():
        return "directory"
    if lang in INTERPRETED_LANGUAGES:
        return "script"
    return "file"


def _artifact_display_name(artifact: Path | None, kind: str) -> str:
    """Human-friendly display name for an artifact.

    - directory -> ``<dirname>/``
    - script    -> ``<filename>``
    - file      -> ``<filename>``
    - none      -> ``"—"``
    """
    if artifact is None or kind == "none":
        return "—"
    if kind == "directory":
        return f"{artifact.name}/"
    return artifact.name


def _artifact_freshness(source_path: Path, artifact: Path | None) -> str:
    """Compare source mtime vs artifact mtime.

    Returns:
        ``"current"`` - artifact is at least as new as source.
        ``"stale"``   - source has been modified after the last build.
        ``"unknown"`` - not enough information to decide.
    """
    if artifact is None or not artifact.exists():
        return "unknown"
    try:
        src_mtime = source_path.stat().st_mtime if source_path.exists() else 0.0
        # For directories, compare against the dir's own mtime
        art_mtime = artifact.stat().st_mtime
        if src_mtime == 0.0:
            return "unknown"
        return "current" if art_mtime >= src_mtime else "stale"
    except OSError:
        return "unknown"


def _shell_quote(path: str) -> str:
    """Shell-safe quoting for copy-ready command previews.

    Uses ``shlex.quote()`` on POSIX.  On Windows wraps in double-quotes
    only when the path contains characters that need escaping.
    """
    if IS_WINDOWS:
        needs_quoting = " " in path or any(c in path for c in "&|<>^%()")
        return f'"{path}"' if needs_quoting else path
    return shlex.quote(path)


def _open_directory(path: Path) -> bool:
    """Open *path* in the system file manager with graceful degradation.

    Returns ``True`` if a file manager was launched successfully,
    ``False`` in headless / SSH / pipx / WSL-without-GUI environments
    (caller should fall back to printing the path).
    """
    try:
        if IS_WINDOWS:
            os.startfile(str(path))  # type: ignore[attr-defined]
            return True
        if platform.system() == "Darwin":
            result = subprocess.run(
                ["open", str(path)],
                check=False,
                capture_output=True,
            )
            return result.returncode == 0
        # Linux / other POSIX
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            return False  # headless — no GUI to launch into
        opener = shutil.which("xdg-open")
        if not opener:
            return False
        result = subprocess.run(
            [opener, str(path)],
            check=False,
            capture_output=True,
        )
        return result.returncode == 0
    except Exception:
        return False


# -- Compiler detection ----------------------------------------------


def detect_compilers() -> dict[str, list[str]]:
    """Scan PATH for known compilers and return {language: [found binaries]}.

    Returns:
        Dict mapping language keys to a list of compiler binaries found.
    """
    found: dict[str, list[str]] = {}
    for lang, bins in COMPILER_MAP.items():
        available = [b for b in bins if which(b)]
        if available:
            found[lang] = available
    return found


# -- Module discovery ------------------------------------------------


def list_modules() -> list[dict[str, Any]]:
    """Discover all modules under MODULES_DIR.

    Each module is a subdirectory containing a ``module.json`` manifest.

    Returns:
        List of parsed module manifest dicts with an added ``_path`` key.
    """
    modules: list[dict[str, Any]] = []
    skipped: list[str] = []
    if not MODULES_DIR.exists():
        return modules
    for item in sorted(MODULES_DIR.iterdir()):
        manifest = item / "module.json"
        if not item.is_dir():
            continue
        if not manifest.exists():
            # Not a module directory — skip silently
            continue
        try:
            data: dict[str, Any] = json.loads(manifest.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            # LOUD: surface parse failures in normal mode, not just verbose
            msg = f"[yellow]\u26a0[/yellow] Skipping [bold]{item.name}[/bold]: bad module.json — {exc}"
            log_info(msg, "yellow")
            skipped.append(item.name)
            continue

        # Validate required manifest fields
        missing = [f for f in ("name", "language", "source") if f not in data]
        if missing:
            msg = (
                f"[yellow]\u26a0[/yellow] Skipping [bold]{item.name}[/bold]: "
                f"module.json missing required field(s): {', '.join(missing)}"
            )
            log_info(msg, "yellow")
            skipped.append(item.name)
            continue

        data["_path"] = str(item)
        data["_dir_name"] = item.name

        # Validate source file exists
        source_file = item / data["source"]
        if not source_file.exists():
            data["_source_missing"] = True
            log_verbose(
                f"Module {item.name}: source file '{data['source']}' not found",
                "yellow",
            )
        else:
            data["_source_missing"] = False

        # Build-status heuristic:
        # 1. Prefer .build_ok marker written by a successful compile.
        # 2. Fall back to checking non-hidden files in build/.
        # 3. Mark as "stale" when build/ has files but no marker.
        build_dir = item / "build"
        build_marker = build_dir / ".build_ok"
        if build_marker.exists():
            data["_compiled"] = True
            data["_build_stale"] = False
        elif build_dir.exists() and any(f for f in build_dir.iterdir() if not f.name.startswith(".")):
            data["_compiled"] = True
            data["_build_stale"] = True  # No marker -> possibly stale
        else:
            data["_compiled"] = False
            data["_build_stale"] = False

        modules.append(data)

    return modules


# -- Artifact resolution ---------------------------------------------


def get_module_artifact_info(mod: dict[str, Any]) -> dict[str, Any]:
    """Resolve artifact metadata for a module.

    Returns a dict with:
        module_dir, source_path, build_dir, artifact_path,
        artifact_exists, artifact_kind, artifact_display_name,
        artifact_freshness (current / stale / unknown),
        artifact_size, last_modified, interpreter_hint,
        launch_command, build_command, checksum_command.

    Classification rules are centralised in :func:`_classify_artifact`.
    All command strings use :func:`_shell_quote` for copy-ready output.
    """
    from datetime import datetime as _dt

    mod_path = Path(mod["_path"])
    lang = mod.get("language", "")
    source_name = mod.get("source", "")
    source_path = mod_path / source_name
    build_dir = mod_path / "build"
    output_name = mod.get("output", source_path.stem if source_name else "")

    # -- Resolve primary artifact ------------------------------------
    artifact: Path | None = None
    primary = build_dir / output_name if output_name else None
    if primary and primary.exists():
        artifact = primary
    else:
        alt_paths = _find_alt_output(mod_path, lang, output_name) if output_name else []
        artifact = next((p for p in alt_paths if p.exists()), None)
        # Last resort: single non-hidden file in build/
        if artifact is None and build_dir.exists():
            candidates = [f for f in build_dir.iterdir() if not f.name.startswith(".")]
            if len(candidates) == 1:
                artifact = candidates[0]

    # -- Deterministic classification --------------------------------
    kind = _classify_artifact(artifact, lang)
    display_name = _artifact_display_name(artifact, kind)
    freshness = _artifact_freshness(source_path, artifact)

    # -- Size and mtime ----------------------------------------------
    artifact_size: int | None = None
    last_modified: str | None = None
    if artifact is not None and artifact.exists() and not artifact.is_dir():
        try:
            stat = artifact.stat()
            artifact_size = stat.st_size
            last_modified = _dt.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        except OSError:
            pass
    elif artifact is not None and artifact.is_dir():
        with contextlib.suppress(OSError):
            last_modified = _dt.fromtimestamp(artifact.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")

    # -- Build command (shell-quoted) --------------------------------
    compile_cmd = mod.get("compile_cmd", DEFAULT_COMPILE_CMD.get(lang, ""))
    if compile_cmd:
        compile_cmd = compile_cmd.replace("{source}", _shell_quote(str(source_path)))
        out_path = build_dir / output_name if output_name else build_dir / "output"
        compile_cmd = compile_cmd.replace("{output}", _shell_quote(str(out_path)))
        compile_cmd = compile_cmd.replace("{build_dir}", _shell_quote(str(build_dir)))
        compile_cmd = compile_cmd.replace("{source_dir}", _shell_quote(str(mod_path)))

    # -- Interpreter / launch hint (shell-quoted) --------------------
    interp = INTERPRETER_HINT.get(lang)
    if artifact and artifact.exists():
        q_art = _shell_quote(str(artifact))
        launch = f"{interp} {q_art}" if interp else q_art
    else:
        launch = None

    # -- Checksum command (shell-quoted) -----------------------------
    if artifact and artifact.exists() and not artifact.is_dir():
        q_art = _shell_quote(str(artifact))
        checksum_cmd = f"certutil -hashfile {q_art} SHA256" if IS_WINDOWS else f"sha256sum {q_art}"
    else:
        checksum_cmd = None

    return {
        "module_dir": str(mod_path),
        "source_path": str(source_path),
        "build_dir": str(build_dir),
        "artifact_path": str(artifact) if artifact else None,
        "artifact_exists": artifact is not None and artifact.exists(),
        "artifact_kind": kind,
        "artifact_display_name": display_name,
        "artifact_freshness": freshness,
        "artifact_size": artifact_size,
        "last_modified": last_modified,
        "interpreter_hint": interp,
        "launch_command": launch,
        "build_command": compile_cmd or None,
        "checksum_command": checksum_cmd,
    }


# -- Module info (sub-menu) -----------------------------------------


def _format_size(size: int | None) -> str:
    """Human-readable file size."""
    if size is None:
        return "-"
    for unit in ("B", "KB", "MB", "GB"):
        if abs(size) < 1024:
            return f"{size:.1f} {unit}" if unit != "B" else f"{size} {unit}"
        size //= 1024
    return f"{size} TB"


def module_info(
    mod: dict[str, Any],
    *,
    services: Services | None = None,
    run_hooks_fn: Any | None = None,
) -> None:
    """Display detailed module information with an action sub-menu.

    Shows all metadata plus resolved artifact paths, then offers:
    1. Show build command
    2. Show launch command
    3. Open build folder
    4. Source preview
    5. Rebuild
    6. Validate module
    7. Show manifest
    8. Last build result
    0. Back
    """
    _FRESHNESS_STYLE = {
        "current": "[green]✔ current[/green]",
        "stale": "[yellow]⚠ stale (source newer)[/yellow]",
        "unknown": "[dim]unknown[/dim]",
    }

    while True:
        # Re-resolve artifact each iteration (in case a rebuild happened)
        art = get_module_artifact_info(mod)
        mod_path = Path(mod["_path"])
        lang = mod.get("language", "")

        # -- Build status string --
        if mod.get("_compiled"):
            build_status = (
                "[yellow]⚠ stale (no .build_ok marker)[/yellow]"
                if mod.get("_build_stale")
                else "[green]✔ built[/green]"
            )
        else:
            build_status = "[red]✗ not built[/red]"

        # -- Artifact status --
        if art["artifact_exists"]:
            art_display = art["artifact_display_name"]
            art_status = f"[green]✔[/green] {art['artifact_kind']}"
            if art["artifact_size"] is not None:
                art_status += f"  ({_format_size(art['artifact_size'])})"
        else:
            art_display = "[dim]none[/dim]"
            art_status = "[red]✗ missing[/red]"

        # -- Detail table --
        table = Table(
            title=f"Module: {mod.get('name', 'unknown')}",
            show_lines=True,
            border_style="magenta",
            title_style="bold magenta",
            min_width=60,
        )
        table.add_column("Field", style="bold white", min_width=17)
        table.add_column("Value", style="green", overflow="fold")

        table.add_row("Name", mod.get("name", "-"))
        table.add_row("Description", mod.get("description", "-"))
        table.add_row("Language", lang or "-")
        table.add_row("Compiler", mod.get("compiler", "auto-detect"))
        table.add_row("Target OS", mod.get("target_os", "any"))
        table.add_row("Build Status", build_status)
        table.add_row("Artifact Freshness", _FRESHNESS_STYLE.get(art["artifact_freshness"], "[dim]?[/dim]"))
        table.add_row("", "")  # spacer
        table.add_row("Module Dir", art["module_dir"])
        table.add_row("Source", art["source_path"])
        table.add_row("Build Dir", art["build_dir"])
        table.add_row("Artifact", art_display)
        table.add_row("Artifact Path", art["artifact_path"] or "[dim]—[/dim]")
        table.add_row("Artifact Status", art_status)
        if art["last_modified"]:
            table.add_row("Last Modified", art["last_modified"])
        if mod.get("_source_missing"):
            table.add_row("[red]⚠ Warning[/red]", "[red]Source file not found![/red]")

        console.print(table)
        console.print()

        # -- Sub-menu --
        log_info("[bold]Actions:[/]")
        log_info("  1. Show Build Command")
        log_info("  2. Show Launch Command")
        log_info("  3. Open Build Folder")
        log_info("  4. Source Preview")
        log_info("  5. Rebuild")
        log_info("  6. Validate Module")
        log_info("  7. Show Manifest")
        log_info("  8. Last Build Result")
        log_info("  0. Back")

        action = Prompt.ask(
            "Select",
            choices=["0", "1", "2", "3", "4", "5", "6", "7", "8"],
            default="0",
        )

        if action == "0":
            break

        elif action == "1":
            # Show build command
            render_group_heading("Build Command", "bold cyan")
            if art["build_command"]:
                console.print(f"\n  [bold white]cd[/bold white] {_shell_quote(art['module_dir'])}")
                console.print(f"  [bold white]$[/bold white] {art['build_command']}\n")
            else:
                log_info("  No build command configured for this module.", "yellow")

        elif action == "2":
            # Show launch command (non-executing preview)
            render_group_heading("Launch Command Preview", "bold cyan")
            if art["launch_command"]:
                lines_out: list[str] = []
                lines_out.append("")
                lines_out.append(f"  [bold]Artifact:[/bold]     {art['artifact_display_name']}")
                lines_out.append(f"  [bold]Full path:[/bold]    {art['artifact_path']}")
                lines_out.append(f"  [bold]Working dir:[/bold]  {art['module_dir']}")
                lines_out.append(f"  [bold]Type:[/bold]         {art['artifact_kind']}")
                lines_out.append(f"  [bold]Freshness:[/bold]    {_FRESHNESS_STYLE.get(art['artifact_freshness'], '?')}")
                lines_out.append("")
                lines_out.append("  [bold]Suggested invocation:[/bold]")
                lines_out.append(f"  [bold white]$[/bold white] {art['launch_command']}")
                if art["checksum_command"]:
                    lines_out.append("")
                    lines_out.append("  [bold]Verify checksum:[/bold]")
                    lines_out.append(f"  [bold white]$[/bold white] {art['checksum_command']}")
                lines_out.append("")
                console.print("\n".join(lines_out))
            else:
                log_info("  Module not built yet — compile first.", "yellow")

        elif action == "3":
            # Open build folder — with graceful degradation
            build_path = Path(art["build_dir"])
            build_path.mkdir(parents=True, exist_ok=True)
            if _open_directory(build_path):
                log_success(f"  [+] Opened: {build_path}")
            else:
                log_info("  Could not open file manager (headless / SSH?).", "yellow")
                log_info(f"  Path: {build_path}", "cyan")

        elif action == "4":
            # Source preview
            source_file = mod_path / mod.get("source", "")
            if source_file.exists() and source_file.is_file():
                render_group_heading(f"Source Preview — {source_file.name}", "bold cyan")
                raw = source_file.read_text(encoding="utf-8", errors="replace").splitlines()
                preview = "\n".join(raw[:40])
                if len(raw) > 40:
                    preview += f"\n... ({len(raw) - 40} more lines)"
                console.print(Panel(preview, border_style="dim"))
            else:
                log_info("  Source file not found.", "yellow")

        elif action == "5":
            # Rebuild
            if mod.get("_source_missing"):
                log_error("  Cannot rebuild: source file is missing.")
            else:
                log_info("\n  Rebuilding...", "cyan")
                ok = compile_module(mod, services=services, run_hooks_fn=run_hooks_fn)
                if ok:
                    mod["_compiled"] = True
                    mod["_build_stale"] = False

        elif action == "6":
            # Validate module
            render_group_heading("Module Validation", "bold cyan")
            findings = _validate_module(mod)
            _render_validation(findings)

        elif action == "7":
            # Show manifest
            render_group_heading("Module Manifest (module.json)", "bold cyan")
            manifest_path = mod_path / "module.json"
            if manifest_path.exists():
                raw_json = manifest_path.read_text(encoding="utf-8", errors="replace")
                console.print(Panel(raw_json.strip(), border_style="dim", title="module.json"))
            else:
                log_info("  module.json not found.", "yellow")

        elif action == "8":
            # Last build result
            render_group_heading("Last Build Result", "bold cyan")
            meta_path = Path(art["build_dir"]) / ".build_meta.json"
            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                    tbl = Table(show_lines=True, border_style="yellow", min_width=50)
                    tbl.add_column("Field", style="bold white", min_width=14)
                    tbl.add_column("Value", style="green", overflow="fold")
                    for key in (
                        "status",
                        "command",
                        "exit_code",
                        "timestamp",
                        "duration_s",
                        "artifact_path",
                        "module_name",
                        "language",
                    ):
                        val = meta.get(key)
                        if val is not None:
                            style = ""
                            if key == "status":
                                style = "green" if val == "success" else "red"
                            tbl.add_row(key, Text(str(val), style=style))
                    if meta.get("error"):
                        tbl.add_row("error", Text(str(meta["error"])[:300], style="red"))
                    console.print(tbl)
                except (json.JSONDecodeError, OSError) as exc:
                    log_error(f"  Could not read build metadata: {exc}")
            else:
                log_info("  No build metadata found. Compile the module first.", "yellow")


# -- Module validation -----------------------------------------------


def _validate_module(mod: dict[str, Any]) -> list[dict[str, str]]:
    """Run validation checks on a module.

    Returns a list of findings, each a dict with:
        ``level`` (``"pass"`` / ``"warning"`` / ``"error"`` / ``"info"``)
        ``message`` (human-readable description).
    """
    findings: list[dict[str, str]] = []
    mod_path = Path(mod["_path"])
    lang = mod.get("language", "")

    # 1. Required manifest fields
    for field in ("name", "language", "source"):
        if field in mod:
            findings.append({"level": "pass", "message": f"Required field '{field}' present"})
        else:
            findings.append({"level": "error", "message": f"Missing required field: '{field}'"})

    # 2. Optional but recommended fields
    for field in ("description", "compiler", "output", "target_os", "compile_cmd"):
        if field in mod and mod[field]:
            findings.append({"level": "pass", "message": f"Field '{field}' set"})
        else:
            findings.append({"level": "warning", "message": f"Optional field '{field}' not set"})

    # 3. Source file existence
    source_name = mod.get("source", "")
    source_file = mod_path / source_name if source_name else None
    if source_file and source_file.exists():
        findings.append({"level": "pass", "message": f"Source file exists: {source_name}"})
    else:
        findings.append({"level": "error", "message": f"Source file missing: {source_name}"})

    # 4. Source extension matches declared language
    ext = LANGUAGE_EXTENSIONS.get(lang, "")
    if source_name and ext and not source_name.endswith(ext):
        findings.append(
            {
                "level": "warning",
                "message": f"Source '{source_name}' doesn't match expected extension '{ext}' for {lang}",
            }
        )

    # 5. Compiler availability
    compiler_bin = mod.get("compiler", "")
    if compiler_bin:
        if which(compiler_bin):
            findings.append({"level": "pass", "message": f"Compiler '{compiler_bin}' found on PATH"})
        else:
            alt = detect_compilers().get(lang, [])
            if alt:
                findings.append(
                    {
                        "level": "warning",
                        "message": f"Compiler '{compiler_bin}' not found; alternatives: {', '.join(alt)}",
                    }
                )
            else:
                findings.append(
                    {
                        "level": "error",
                        "message": f"Compiler '{compiler_bin}' not found, no alternatives for '{lang}'",
                    }
                )
    elif lang in COMPILER_MAP:
        available = detect_compilers().get(lang, [])
        if available:
            findings.append({"level": "pass", "message": f"Compilers for '{lang}': {', '.join(available)}"})
        else:
            findings.append({"level": "error", "message": f"No compiler found for '{lang}'"})

    # 6. Artifact status & freshness
    art = get_module_artifact_info(mod)
    if art["artifact_exists"]:
        findings.append({"level": "pass", "message": f"Artifact exists ({art['artifact_kind']})"})
        if art["artifact_freshness"] == "stale":
            findings.append({"level": "warning", "message": "Artifact is stale (source newer than build)"})
        elif art["artifact_freshness"] == "current":
            findings.append({"level": "pass", "message": "Artifact is current"})
    else:
        findings.append({"level": "warning", "message": "No artifact found (module not compiled)"})

    # 7. Target OS vs current platform
    target_os = mod.get("target_os", "any").lower()
    if target_os not in ("any", ""):
        current = "windows" if IS_WINDOWS else platform.system().lower()
        if target_os != current:
            findings.append(
                {
                    "level": "info",
                    "message": f"Target OS '{target_os}' differs from current '{current}' (cross-compile)",
                }
            )
        else:
            findings.append({"level": "pass", "message": "Target OS matches current platform"})

    return findings


def _render_validation(findings: list[dict[str, str]]) -> None:
    """Render validation findings as a styled list."""
    _ICONS = {
        "pass": "[green]✔[/green]",
        "warning": "[yellow]⚠[/yellow]",
        "error": "[red]✗[/red]",
        "info": "[cyan]ℹ[/cyan]",
    }
    errors = sum(1 for f in findings if f["level"] == "error")
    warnings = sum(1 for f in findings if f["level"] == "warning")
    console.print()
    for f in findings:
        icon = _ICONS.get(f["level"], "?")
        console.print(f"  {icon}  {f['message']}")
    console.print()
    if errors:
        log_info(f"  [red]{errors} error(s)[/red], {warnings} warning(s)", "red")
    elif warnings:
        log_info(f"  [green]No errors[/green], {warnings} warning(s)", "yellow")
    else:
        log_info("  [green]All checks passed ✔[/green]", "green")


# -- Compile ---------------------------------------------------------


def _write_build_meta(build_dir: Path, data: dict[str, Any]) -> None:
    """Persist build metadata to ``.build_meta.json`` in *build_dir*.

    Adds a UTC ``timestamp`` field automatically.  Errors are swallowed
    so a metadata-write failure never breaks the compile pipeline.
    """
    import contextlib
    from datetime import datetime as _dt

    data.setdefault("timestamp", _dt.now().isoformat())
    with contextlib.suppress(OSError):
        (build_dir / ".build_meta.json").write_text(
            json.dumps(data, indent=2) + "\n",
            encoding="utf-8",
        )


def _find_alt_output(mod_path: Path, lang: str, output_name: str) -> list[Path]:
    """Return alternative locations where a build system may place its artifact.

    Different compilers/build-systems write output to different places:
    - Rust/cargo  ->  ``target/release/<name>`` or ``target/debug/<name>``
    - Go          ->  ``<name>`` in the module root (``go build`` default)
    - dotnet      ->  ``bin/Release/net*/<name>.dll`` or ``bin/Debug/net*/<name>.dll``
    - make        ->  module root (common convention)

    Returns a list of candidate paths (may or may not exist).
    """
    candidates: list[Path] = []
    stem = Path(output_name).stem

    if lang == "rust":
        for profile in ("release", "debug"):
            candidates.append(mod_path / "target" / profile / stem)
            candidates.append(mod_path / "target" / profile / (stem + ".exe"))

    elif lang == "go":
        candidates.append(mod_path / stem)
        candidates.append(mod_path / (stem + ".exe"))

    elif lang == "csharp":
        for config in ("Release", "Debug"):
            bin_dir = mod_path / "bin" / config
            if bin_dir.exists():
                for fw_dir in bin_dir.iterdir():
                    if fw_dir.is_dir():
                        candidates.append(fw_dir / (stem + ".dll"))
                        candidates.append(fw_dir / (stem + ".exe"))

    elif lang == "make":
        candidates.append(mod_path / stem)
        candidates.append(mod_path / (stem + ".exe"))

    return candidates


def compile_module(
    mod: dict[str, Any],
    services: Services | None = None,
    run_hooks_fn: Any | None = None,
) -> bool:
    """Compile a single module according to its manifest.

    Args:
        mod: Parsed module manifest dict (from list_modules).
        services: Optional Services container for CommandRunner usage.
        run_hooks_fn: Optional callback to fire post_compile hooks.

    Returns:
        True if compilation succeeded, False otherwise.
    """
    mod_path = Path(mod["_path"])
    lang = mod.get("language", "")
    source_name = mod.get("source", "")
    source_file = mod_path / source_name
    build_dir = mod_path / "build"
    build_dir.mkdir(exist_ok=True)

    # Pre-flight: validate source file exists
    if not source_file.exists():
        log_error(
            f"Source file not found: {source_file}\n  Check module.json \"source\" field for '{mod.get('name', '?')}'"
        )
        return False

    # Determine output name
    output_name = mod.get("output", source_file.stem)
    if IS_WINDOWS and lang in ("c", "cpp", "go") and not output_name.endswith(".exe"):
        output_name += ".exe"
    output_path = build_dir / output_name

    # Determine compile command
    compile_cmd = mod.get("compile_cmd", DEFAULT_COMPILE_CMD.get(lang, ""))
    if not compile_cmd:
        log_error(f"No compile command for language '{lang}'")
        return False

    # Check if the required compiler is available
    compiler_bin = mod.get("compiler", "")
    if compiler_bin and not which(compiler_bin):
        # Try to find any compiler for this language
        available = detect_compilers().get(lang, [])
        if available:
            log_info(f"'{compiler_bin}' not found, using '{available[0]}' instead", "yellow")
            compiler_bin = available[0]
            compile_cmd = compile_cmd.replace(mod.get("compiler", ""), compiler_bin)
        else:
            log_error(f"Compiler '{compiler_bin}' not found and no alternatives detected for {lang}")
            return False
    elif not compiler_bin and lang in COMPILER_MAP:
        # No explicit compiler — verify at least one is on PATH
        if not detect_compilers().get(lang):
            log_error(f"No compiler found for '{lang}'. Checked: {', '.join(COMPILER_MAP.get(lang, []))}")
            return False

    # Resolve placeholders
    compile_cmd = compile_cmd.replace("{source}", str(source_file))
    compile_cmd = compile_cmd.replace("{output}", str(output_path))
    compile_cmd = compile_cmd.replace("{build_dir}", str(build_dir))
    compile_cmd = compile_cmd.replace("{source_dir}", str(mod_path))

    log_info(f"\n[bold]Compiling:[/bold] {mod.get('name', 'unknown')}")
    log_info(f"[dim]$ {compile_cmd}[/dim]")

    if CONFIG["dry_run"]:
        log_info("[DRY RUN] Would execute the above command", "yellow")
        return True

    t0 = _time_mod.monotonic()
    try:
        if services is not None:
            result = services.runner.run(
                compile_cmd,
                shell=True,
                cwd=str(mod_path),
                timeout=120,
            )
        else:
            result = subprocess.run(
                compile_cmd,
                shell=True,
                capture_output=True,
                text=True,
                cwd=str(mod_path),
                timeout=120,
            )
        elapsed = round(_time_mod.monotonic() - t0, 2)
        if result.returncode == 0:
            # -- Artifact resolution ----------------------------------
            artifact_found = output_path.exists()

            # Interpreted languages: "compile" is validation only —
            # copy source into build/ as the deployable artifact.
            if not artifact_found and lang in INTERPRETED_LANGUAGES:
                shutil.copy2(str(source_file), str(output_path))
                artifact_found = output_path.exists()

            if not artifact_found:
                # Some build systems place output elsewhere; check
                # common alt locations before giving up.
                alt_paths = _find_alt_output(mod_path, lang, output_name)
                found = next((p for p in alt_paths if p.exists()), None)
                if found:
                    if found.is_dir():
                        # Directory artifact (e.g. make writes into
                        # build/).  The directory IS the output.
                        log_verbose(
                            f"Directory artifact at {found}",
                            "yellow",
                        )
                        output_path = found
                        artifact_found = True
                    else:
                        log_info(
                            f"Artifact found at [dim]{found}[/dim], copying to [dim]{output_path}[/dim]",
                            "yellow",
                        )
                        shutil.copy2(str(found), str(output_path))
                        artifact_found = output_path.exists()

            # Last resort: build dir has non-hidden files (build
            # systems that write directly to build/).
            if not artifact_found and any(f for f in build_dir.iterdir() if not f.name.startswith(".")):
                log_verbose("Build directory contains output files", "yellow")
                artifact_found = True

            if not artifact_found:
                log_error(
                    f"Compiler exited 0 but no artifact at {output_path}\n"
                    f"  Check compile_cmd / output field in module.json"
                )
                if result.stdout.strip():
                    console.print(result.stdout.strip(), markup=False, highlight=False)
                if result.stderr.strip():
                    console.print(result.stderr.strip(), markup=False, highlight=False)
                # Remove stale marker if present
                marker = build_dir / ".build_ok"
                if marker.exists():
                    marker.unlink()
                return False

            log_success(f"[+] Build succeeded: {output_path}")
            if result.stdout.strip():
                log_verbose(f"stdout:\n{result.stdout.strip()}")
            # Write a build marker so status detection is reliable
            (build_dir / ".build_ok").write_text(
                f"Built {mod.get('name', 'unknown')} at {__import__('datetime').datetime.now().isoformat()}\n",
                encoding="utf-8",
            )
            # Persist build metadata for "Last Build Result"
            _write_build_meta(
                build_dir,
                {
                    "status": "success",
                    "command": compile_cmd,
                    "exit_code": result.returncode,
                    "duration_s": elapsed,
                    "artifact_path": str(output_path),
                    "module_name": mod.get("name", "unknown"),
                    "language": lang,
                },
            )
            # Fire post_compile hook
            if run_hooks_fn is not None:
                run_hooks_fn(
                    "post_compile",
                    {
                        "module_name": mod.get("name", "unknown"),
                        "language": lang,
                        "output_path": str(output_path),
                        "build_dir": str(build_dir),
                        "source": str(source_file),
                    },
                )
            return True
        else:
            log_error(f"Build failed (exit code {result.returncode})")
            if result.stderr.strip():
                console.print(
                    Panel(
                        Text(result.stderr.strip()),
                        title="Compiler Output",
                        border_style="red",
                    )
                )
            if result.stdout.strip():
                console.print(result.stdout.strip(), markup=False, highlight=False)
            # Remove stale marker on failure
            marker = build_dir / ".build_ok"
            if marker.exists():
                marker.unlink()
            # Persist failure metadata
            _write_build_meta(
                build_dir,
                {
                    "status": "failed",
                    "command": compile_cmd,
                    "exit_code": result.returncode,
                    "duration_s": elapsed,
                    "module_name": mod.get("name", "unknown"),
                    "language": lang,
                    "error": (result.stderr.strip()[:500]) if result.stderr else "",
                },
            )
            return False
    except subprocess.TimeoutExpired:
        _write_build_meta(
            build_dir,
            {
                "status": "timeout",
                "command": compile_cmd,
                "exit_code": -1,
                "duration_s": round(_time_mod.monotonic() - t0, 2),
                "module_name": mod.get("name", "unknown"),
                "language": lang,
                "error": "Build timed out (120s limit)",
            },
        )
        log_error("Build timed out (120s limit)")
        return False
    except Exception as exc:
        _write_build_meta(
            build_dir,
            {
                "status": "crash",
                "command": compile_cmd,
                "exit_code": -1,
                "duration_s": round(_time_mod.monotonic() - t0, 2),
                "module_name": mod.get("name", "unknown"),
                "language": lang,
                "error": str(exc)[:500],
            },
        )
        log_error(f"Build error: {exc}")
        return False


# -- Scaffold --------------------------------------------------------


def create_module_template(language: str, name: str) -> Path:
    """Scaffold a new module directory with boilerplate source and manifest.

    Args:
        language: One of the supported language keys (c, cpp, csharp, etc.).
        name: Directory name for the module.

    Returns:
        Path to the created module directory.
    """
    mod_dir = MODULES_DIR / name
    mod_dir.mkdir(parents=True, exist_ok=True)
    build_dir = mod_dir / "build"
    build_dir.mkdir(exist_ok=True)

    ext = LANGUAGE_EXTENSIONS.get(language, ".txt")
    source_name = f"main{ext}"

    # Determine default compiler
    compilers = detect_compilers().get(language, [])
    default_compiler = compilers[0] if compilers else COMPILER_MAP.get(language, [""])[0]

    # Write module.json
    manifest: dict[str, str] = {
        "name": name,
        "language": language,
        "description": f"{name} - {language} module",
        "compiler": default_compiler,
        "source": source_name,
        "compile_cmd": DEFAULT_COMPILE_CMD.get(language, ""),
        "target_os": "any",
        "output": name + (".exe" if IS_WINDOWS and language in ("c", "cpp", "go") else ""),
    }
    (mod_dir / "module.json").write_text(json.dumps(manifest, indent=4) + "\n", encoding="utf-8")

    # Write boilerplate source
    templates: dict[str, str] = {
        "c": (
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n\n"
            "/*\n"
            f" * {name} - C module for Empusa\n"
            " * Compile: gcc main.c -o build/{name}\n"
            " */\n\n"
            "int main(int argc, char *argv[]) {\n"
            f'    printf("[{name}] Module executed.\\n");\n'
            "    // TODO: Implement module logic\n"
            "    return 0;\n"
            "}\n"
        ),
        "cpp": (
            "#include <iostream>\n"
            "#include <string>\n\n"
            "/*\n"
            f" * {name} - C++ module for Empusa\n"
            " */\n\n"
            "int main(int argc, char* argv[]) {\n"
            f'    std::cout << "[{name}] Module executed." << std::endl;\n'
            "    // TODO: Implement module logic\n"
            "    return 0;\n"
            "}\n"
        ),
        "csharp": (
            "using System;\n\n"
            "namespace Empusa.Modules\n"
            "{\n"
            f"    /// <summary>{name} - C# module for Empusa</summary>\n"
            f"    class {name.replace('-', '_').title().replace('_', '')}\n"
            "    {\n"
            "        static void Main(string[] args)\n"
            "        {\n"
            f'            Console.WriteLine("[{name}] Module executed.");\n'
            "            // TODO: Implement module logic\n"
            "        }\n"
            "    }\n"
            "}\n"
        ),
        "rust": (
            f"//! {name} - Rust module for Empusa\n\n"
            "fn main() {\n"
            f'    println!("[{name}] Module executed.");\n'
            "    // TODO: Implement module logic\n"
            "}\n"
        ),
        "go": (
            "package main\n\n"
            'import "fmt"\n\n'
            f"// {name} - Go module for Empusa\n"
            "func main() {\n"
            f'\tfmt.Println("[{name}] Module executed.")\n'
            "\t// TODO: Implement module logic\n"
            "}\n"
        ),
        "perl": (
            "#!/usr/bin/env perl\n"
            "use strict;\n"
            "use warnings;\n\n"
            f"# {name} - Perl module for Empusa\n\n"
            f'print "[{name}] Module executed.\\n";\n'
            "# TODO: Implement module logic\n"
        ),
    }

    source_content = templates.get(language, f"# {name} - {language} module\n# TODO: Implement\n")
    (mod_dir / source_name).write_text(source_content, encoding="utf-8")

    # For Rust, also create Cargo.toml
    if language == "rust":
        cargo_toml = (
            f'[package]\nname = "{name}"\nversion = "0.1.0"\n'
            'edition = "2021"\n\n'
            "[[bin]]\n"
            f'name = "{name}"\n'
            f'path = "main.rs"\n'
        )
        (mod_dir / "Cargo.toml").write_text(cargo_toml, encoding="utf-8")

    # For C#, create a .csproj
    if language == "csharp":
        csproj = (
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            "  <PropertyGroup>\n"
            "    <OutputType>Exe</OutputType>\n"
            "    <TargetFramework>net8.0</TargetFramework>\n"
            "  </PropertyGroup>\n"
            "</Project>\n"
        )
        (mod_dir / f"{name}.csproj").write_text(csproj, encoding="utf-8")

    # For Go, create go.mod
    if language == "go":
        go_mod = f"module {name}\n\ngo 1.21\n"
        (mod_dir / "go.mod").write_text(go_mod, encoding="utf-8")

    return mod_dir


# -- Render helpers --------------------------------------------------


def _list_modules_render(
    *,
    filter_language: str | None = None,
    filter_built: bool | None = None,
    filter_target_os: str | None = None,
    filter_keyword: str | None = None,
) -> Any:
    """Return the module list as a Rich Table, optionally filtered.

    All filter parameters are optional; ``None`` means "no filter".
    """
    modules = list_modules()
    if not modules:
        return "[yellow]No modules found. Use option 4 to create one.[/yellow]"

    # Apply filters
    filtered = modules
    if filter_language:
        filtered = [m for m in filtered if m.get("language", "").lower() == filter_language.lower()]
    if filter_built is not None:
        filtered = [m for m in filtered if bool(m.get("_compiled")) == filter_built]
    if filter_target_os:
        filtered = [m for m in filtered if m.get("target_os", "any").lower() == filter_target_os.lower()]
    if filter_keyword:
        kw = filter_keyword.lower()
        filtered = [m for m in filtered if kw in m.get("name", "").lower() or kw in m.get("description", "").lower()]

    if not filtered:
        return "[yellow]No modules match the current filter.[/yellow]"

    # Build active-filter subtitle
    active: list[str] = []
    if filter_language:
        active.append(f"lang={filter_language}")
    if filter_built is not None:
        active.append(f"built={'yes' if filter_built else 'no'}")
    if filter_target_os:
        active.append(f"os={filter_target_os}")
    if filter_keyword:
        active.append(f"keyword={filter_keyword}")
    subtitle = f"  Filter: {', '.join(active)}" if active else ""

    table = Table(
        title="Modules" + (f" ({len(filtered)}/{len(modules)})" if active else ""),
        show_lines=True,
        border_style="magenta",
        title_style="bold magenta",
    )
    table.add_column("#", style="dim", width=3)
    table.add_column("Name", style="bold white", min_width=18)
    table.add_column("Language", style="cyan", min_width=8)
    table.add_column("Compiler", style="yellow")
    table.add_column("Target OS", style="green")
    table.add_column("Built", justify="center", min_width=5)
    table.add_column("Description", style="dim")

    for i, mod in enumerate(filtered, 1):
        if mod.get("_compiled"):
            built = "[yellow]\u26a0 stale[/yellow]" if mod.get("_build_stale") else "[green]\u2714[/green]"
        else:
            built = "[red]\u2717[/red]"
        table.add_row(
            str(i),
            mod.get("name", "-"),
            mod.get("language", "-"),
            mod.get("compiler", "auto"),
            mod.get("target_os", "any"),
            built,
            mod.get("description", "-"),
        )

    table.caption = f"Total: {len(filtered)} module(s)" + (f" (of {len(modules)})" if active else "")
    table.caption_style = "magenta"
    if subtitle:
        table.caption = (table.caption or "") + subtitle
    return table


def _detect_compilers_render() -> Table:
    """Return the compiler detection result as a Rich Table."""
    compilers = detect_compilers()

    table = Table(
        title="Available Compilers",
        show_lines=True,
        border_style="yellow",
        title_style="bold yellow",
    )
    table.add_column("Language", style="bold white", min_width=10)
    table.add_column("Checked", style="dim")
    table.add_column("Found", style="green")
    table.add_column("Status", justify="center")

    for lang, bins in COMPILER_MAP.items():
        found = compilers.get(lang, [])
        status = "[green]✔[/green]" if found else "[red]✗[/red]"
        table.add_row(
            lang,
            ", ".join(bins),
            ", ".join(found) if found else "-",
            status,
        )

    total = sum(len(v) for v in compilers.values())
    table.caption = f"{total} compiler(s) found across {len(compilers)} language(s)"
    table.caption_style = "yellow"
    return table


# -- Interactive workshop menu ---------------------------------------


def module_workshop(
    services: Services | None = None,
    run_hooks_fn: Any | None = None,
) -> None:
    """Interactive module workshop for compiling multi-language payloads (panel controller).

    Renders a persistent section with a replaceable content area.
    Actions update the content buffer instead of printing directly.

    Args:
        services: Optional Services container (for CommandRunner).
        run_hooks_fn: Optional callback for post_compile hooks.
    """
    # Ensure modules directory exists
    MODULES_DIR.mkdir(parents=True, exist_ok=True)

    # Default content: module list
    content: Any = _list_modules_render()

    # Active filters (persisted across iterations)
    _filters: dict[str, Any] = {}

    while True:
        render_screen("Module Workshop")
        render_kv("Modules dir", f"[dim]{MODULES_DIR}[/dim]")
        console.print("")

        # -- Content area --
        if content is not None:
            console.print(content)
            console.print("")

        log_info("[bold]Module Workshop Menu:[/]")
        log_info("1. List Modules")
        log_info("2. Compile Module")
        log_info("3. Compile All")
        log_info("4. Create Module")
        log_info("5. Module Info")
        log_info("6. Detect Compilers")
        log_info("7. Open Modules Folder")
        log_info("8. Filter Modules")
        log_info("0. Back to Main Menu")

        choice = Prompt.ask("Select an option", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8"])

        if choice == "0":
            break

        elif choice == "1":
            content = _list_modules_render(**_filters)

        elif choice == "2":
            # Compile one module
            modules = list_modules()
            if not modules:
                content = "[yellow]No modules found. Create one first.[/yellow]"
                continue

            render_group_heading("Compile Module", "bold yellow")
            for i, mod in enumerate(modules, 1):
                built = "✔" if mod.get("_compiled") else "✗"
                log_info(f"  {i}. [{built}] {mod.get('name', '?')} ({mod.get('language', '?')})")

            try:
                idx = int(Prompt.ask("Module #")) - 1
                if 0 <= idx < len(modules):
                    compile_module(modules[idx], services=services, run_hooks_fn=run_hooks_fn)
                else:
                    log_error("Invalid selection.")
            except ValueError:
                log_error("Please enter a valid number.")
            content = _list_modules_render()

        elif choice == "3":
            # Compile all modules
            modules = list_modules()
            if not modules:
                content = "[yellow]No modules found.[/yellow]"
                continue

            log_info(f"\n[bold]Compiling {len(modules)} module(s)...[/bold]")
            success = 0
            fail = 0
            skipped = 0
            failed_names: list[str] = []
            skipped_names: list[str] = []
            for mod in modules:
                mod_name = mod.get("name", mod.get("_dir_name", "?"))
                # Pre-flight: skip modules that cannot possibly build
                if mod.get("_source_missing"):
                    skipped += 1
                    skipped_names.append(f"{mod_name} (source missing)")
                    continue
                mod_lang = mod.get("language", "")
                mod_compiler = mod.get("compiler", "")
                if mod_compiler and not which(mod_compiler) and not detect_compilers().get(mod_lang):
                    skipped += 1
                    skipped_names.append(f"{mod_name} (compiler unavailable)")
                    continue
                try:
                    if compile_module(mod, services=services, run_hooks_fn=run_hooks_fn):
                        success += 1
                    else:
                        fail += 1
                        failed_names.append(mod_name)
                except Exception as exc:
                    fail += 1
                    failed_names.append(f"{mod_name} (crash: {type(exc).__name__})")
                    log_error(f"Unhandled error compiling {mod_name}: {exc}")

            lines = [
                "[bold]Compile All Results:[/bold]",
                f"  [green]{success} succeeded[/green]  [red]{fail} failed[/red]  [yellow]{skipped} skipped[/yellow]",
            ]
            if failed_names:
                lines.append("")
                lines.append("[red]Failed:[/red]")
                for fn in failed_names:
                    lines.append(f"  • {fn}")
            if skipped_names:
                lines.append("")
                lines.append("[yellow]Skipped:[/yellow]")
                for sn in skipped_names:
                    lines.append(f"  • {sn}")
            content = "\n".join(lines)

        elif choice == "4":
            # Create new module
            render_group_heading("Create Module", "bold yellow")
            supported = list(LANGUAGE_EXTENSIONS.keys()) + ["make"]
            found_compilers = detect_compilers()
            log_info("Supported languages:")
            for i, lang in enumerate(supported, 1):
                compilers = found_compilers.get(lang, [])
                tag = f"[green][installed: {', '.join(compilers)}][/green]" if compilers else "[red][unavailable][/red]"
                log_info(f"  {i}. {lang}  {tag}")

            try:
                lang_idx = int(Prompt.ask("Language #")) - 1
                if not (0 <= lang_idx < len(supported)):
                    log_error("Invalid selection.")
                    continue
                language = supported[lang_idx]
            except ValueError:
                log_error("Please enter a valid number.")
                continue

            name = Prompt.ask("Module name (directory name)").strip()
            if not name or not re.match(r"^[a-zA-Z0-9_-]+$", name):
                log_error("Invalid name. Use only letters, numbers, hyphens, underscores.")
                continue

            if (MODULES_DIR / name).exists() and not Confirm.ask(f"Module '{name}' already exists. Overwrite?"):
                continue

            mod_dir = create_module_template(language, name)
            log_success(f"[+] Created module: {mod_dir}")
            log_info("Edit the source file, then use option 2 to compile.", "yellow")
            content = _list_modules_render()

        elif choice == "5":
            # Module info
            modules = list_modules()
            if not modules:
                content = "[yellow]No modules found.[/yellow]"
                continue

            render_group_heading("Module Info", "bold yellow")
            for i, mod in enumerate(modules, 1):
                built = "\u2714" if mod.get("_compiled") else "\u2717"
                log_info(f"  {i}. [{built}] {mod.get('name', '?')} ({mod.get('language', '?')})")
            log_info("  0. Cancel")

            try:
                idx = int(Prompt.ask("Enter module number"))
                if idx == 0:
                    continue
                idx -= 1
                if 0 <= idx < len(modules):
                    module_info(
                        modules[idx],
                        services=services,
                        run_hooks_fn=run_hooks_fn,
                    )
                else:
                    log_error("Invalid selection.")
            except ValueError:
                log_error("Please enter a valid number.")
            content = _list_modules_render(**_filters)

        elif choice == "6":
            content = _detect_compilers_render()

        elif choice == "7":
            # Open modules folder — with graceful degradation
            MODULES_DIR.mkdir(parents=True, exist_ok=True)
            if _open_directory(MODULES_DIR):
                log_success(f"[+] Opened: {MODULES_DIR}")
                content = "[green]✔[/green] Opened modules folder"
            else:
                log_info("Could not open file manager (headless / SSH?).", "yellow")
                log_info(f"Path: {MODULES_DIR}", "cyan")
                content = f"[yellow]Modules folder:[/yellow] {MODULES_DIR}"

        elif choice == "8":
            # Filter modules
            render_group_heading("Filter Modules", "bold yellow")
            log_info("  Leave blank to clear a filter.\n", "dim")

            fl = Prompt.ask("  Language (e.g. c, go, perl, rust, csharp)", default="").strip()
            _filters["filter_language"] = fl or None

            fb = Prompt.ask("  Built? (yes / no / any)", default="any").strip().lower()
            if fb == "yes":
                _filters["filter_built"] = True
            elif fb == "no":
                _filters["filter_built"] = False
            else:
                _filters["filter_built"] = None

            ft = Prompt.ask("  Target OS (e.g. linux, windows, any)", default="").strip()
            _filters["filter_target_os"] = ft if ft and ft.lower() != "any" else None

            fk = Prompt.ask("  Keyword (name / description)", default="").strip()
            _filters["filter_keyword"] = fk or None

            # Remove None entries so **_filters works cleanly
            _filters = {k: v for k, v in _filters.items() if v is not None}
            content = _list_modules_render(**_filters)
