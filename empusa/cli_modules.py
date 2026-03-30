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

import json
import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table

from empusa.cli_common import (
    CONFIG,
    console,
    IS_WINDOWS,
    MODULES_DIR,
    clear_screen,
    log_error,
    log_info,
    log_success,
    log_verbose,
    which,
)

if TYPE_CHECKING:
    from empusa.services import Services


# -- Lookup tables ---------------------------------------------------

COMPILER_MAP: Dict[str, List[str]] = {
    "c":      ["gcc", "x86_64-w64-mingw32-gcc", "cc"],
    "cpp":    ["g++", "x86_64-w64-mingw32-g++", "c++"],
    "csharp": ["dotnet", "mcs", "csc"],
    "rust":   ["cargo", "rustc"],
    "go":     ["go"],
    "perl":   ["perl"],
    "make":   ["make", "mingw32-make", "nmake"],
}

DEFAULT_COMPILE_CMD: Dict[str, str] = {
    "c":      "gcc {source} -o {output}",
    "cpp":    "g++ {source} -o {output}",
    "csharp": "dotnet build {source_dir} -o {build_dir}",
    "rust":   "cargo build --release --manifest-path {source_dir}/Cargo.toml",
    "go":     "go build -o {output} {source}",
    "perl":   "perl -c {source}",
    "make":   "make -C {source_dir}",
}

LANGUAGE_EXTENSIONS: Dict[str, str] = {
    "c": ".c",
    "cpp": ".cpp",
    "csharp": ".cs",
    "rust": ".rs",
    "go": ".go",
    "perl": ".pl",
}


# -- Compiler detection ----------------------------------------------


def detect_compilers() -> Dict[str, List[str]]:
    """Scan PATH for known compilers and return {language: [found binaries]}.

    Returns:
        Dict mapping language keys to a list of compiler binaries found.
    """
    found: Dict[str, List[str]] = {}
    for lang, bins in COMPILER_MAP.items():
        available = [b for b in bins if which(b)]
        if available:
            found[lang] = available
    return found


# -- Module discovery ------------------------------------------------


def list_modules() -> List[Dict[str, Any]]:
    """Discover all modules under MODULES_DIR.

    Each module is a subdirectory containing a ``module.json`` manifest.

    Returns:
        List of parsed module manifest dicts with an added ``_path`` key.
    """
    modules: List[Dict[str, Any]] = []
    if not MODULES_DIR.exists():
        return modules
    for item in sorted(MODULES_DIR.iterdir()):
        manifest = item / "module.json"
        if item.is_dir() and manifest.exists():
            try:
                data: Dict[str, Any] = json.loads(manifest.read_text(encoding="utf-8"))
                data["_path"] = str(item)
                data["_dir_name"] = item.name
                # Check build status
                build_dir = item / "build"
                if build_dir.exists() and any(build_dir.iterdir()):
                    data["_compiled"] = True
                else:
                    data["_compiled"] = False
                modules.append(data)
            except (json.JSONDecodeError, KeyError) as exc:
                log_verbose(f"Skipping {item.name}: {exc}")
    return modules


# -- Module info -----------------------------------------------------


def module_info(mod: Dict[str, Any]) -> None:
    """Display detailed information about a single module."""
    table = Table(
        title=f"Module: {mod.get('name', 'unknown')}",
        show_lines=True,
        border_style="magenta",
        title_style="bold magenta",
    )
    table.add_column("Field", style="bold white", min_width=15)
    table.add_column("Value", style="green")

    table.add_row("Name", mod.get("name", "-"))
    table.add_row("Language", mod.get("language", "-"))
    table.add_row("Description", mod.get("description", "-"))
    table.add_row("Compiler", mod.get("compiler", "auto-detect"))
    table.add_row("Source", mod.get("source", "-"))
    table.add_row("Compile Command", mod.get("compile_cmd", DEFAULT_COMPILE_CMD.get(mod.get("language", ""), "-")))
    table.add_row("Target OS", mod.get("target_os", "any"))
    table.add_row("Output", mod.get("output", "auto"))
    table.add_row("Compiled", "[green]✔[/green]" if mod.get("_compiled") else "[red]✗[/red]")
    table.add_row("Path", mod.get("_path", "-"))

    # Show source preview
    mod_path = Path(mod["_path"])
    source_file = mod_path / mod.get("source", "")
    if source_file.exists() and source_file.is_file():
        console.print(table)
        console.print(f"\n[bold cyan]Source Preview[/bold cyan] ({source_file.name}):")
        lines = source_file.read_text(encoding="utf-8", errors="replace").splitlines()
        preview = "\n".join(lines[:30])
        if len(lines) > 30:
            preview += f"\n... ({len(lines) - 30} more lines)"
        console.print(Panel(preview, border_style="dim"))
    else:
        console.print(table)


# -- Compile ---------------------------------------------------------


def compile_module(
    mod: Dict[str, Any],
    services: Optional[Services] = None,
    run_hooks_fn: Optional[Any] = None,
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

    # Resolve placeholders
    compile_cmd = compile_cmd.replace("{source}", str(source_file))
    compile_cmd = compile_cmd.replace("{output}", str(output_path))
    compile_cmd = compile_cmd.replace("{build_dir}", str(build_dir))
    compile_cmd = compile_cmd.replace("{source_dir}", str(mod_path))

    log_info(f"\n[bold]Compiling:[/bold] {mod.get('name', 'unknown')}")
    log_info(f"[dim]$ {compile_cmd}[/dim]")

    if CONFIG['dry_run']:
        log_info("[DRY RUN] Would execute the above command", "yellow")
        return True

    try:
        if services is not None:
            result = services.runner.run(
                compile_cmd, shell=True,
                cwd=str(mod_path), timeout=120,
            )
        else:
            result = subprocess.run(
                compile_cmd, shell=True,
                capture_output=True, text=True,
                cwd=str(mod_path), timeout=120,
            )
        if result.returncode == 0:
            log_success(f"[+] Build succeeded: {output_path}")
            if result.stdout.strip():
                log_verbose(f"stdout:\n{result.stdout.strip()}")
            # Fire post_compile hook
            if run_hooks_fn is not None:
                run_hooks_fn("post_compile", {
                    "module_name": mod.get("name", "unknown"),
                    "language": lang,
                    "output_path": str(output_path),
                    "build_dir": str(build_dir),
                    "source": str(source_file),
                })
            return True
        else:
            log_error(f"Build failed (exit code {result.returncode})")
            if result.stderr.strip():
                console.print(Panel(result.stderr.strip(), title="Compiler Output", border_style="red"))
            if result.stdout.strip():
                console.print(result.stdout.strip())
            return False
    except subprocess.TimeoutExpired:
        log_error("Build timed out (120s limit)")
        return False
    except Exception as exc:
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
    manifest: Dict[str, str] = {
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
    templates: Dict[str, str] = {
        "c": (
            '#include <stdio.h>\n'
            '#include <stdlib.h>\n\n'
            '/*\n'
            f' * {name} - C module for Empusa\n'
            ' * Compile: gcc main.c -o build/{name}\n'
            ' */\n\n'
            'int main(int argc, char *argv[]) {\n'
            f'    printf("[{name}] Module executed.\\n");\n'
            '    // TODO: Implement module logic\n'
            '    return 0;\n'
            '}\n'
        ),
        "cpp": (
            '#include <iostream>\n'
            '#include <string>\n\n'
            '/*\n'
            f' * {name} - C++ module for Empusa\n'
            ' */\n\n'
            'int main(int argc, char* argv[]) {\n'
            f'    std::cout << "[{name}] Module executed." << std::endl;\n'
            '    // TODO: Implement module logic\n'
            '    return 0;\n'
            '}\n'
        ),
        "csharp": (
            'using System;\n\n'
            'namespace Empusa.Modules\n'
            '{\n'
            f'    /// <summary>{name} - C# module for Empusa</summary>\n'
            f'    class {name.replace("-", "_").title().replace("_", "")}\n'
            '    {\n'
            '        static void Main(string[] args)\n'
            '        {\n'
            f'            Console.WriteLine("[{name}] Module executed.");\n'
            '            // TODO: Implement module logic\n'
            '        }\n'
            '    }\n'
            '}\n'
        ),
        "rust": (
            f'//! {name} - Rust module for Empusa\n\n'
            'fn main() {\n'
            f'    println!("[{name}] Module executed.");\n'
            '    // TODO: Implement module logic\n'
            '}\n'
        ),
        "go": (
            'package main\n\n'
            'import "fmt"\n\n'
            f'// {name} - Go module for Empusa\n'
            'func main() {\n'
            f'\tfmt.Println("[{name}] Module executed.")\n'
            '\t// TODO: Implement module logic\n'
            '}\n'
        ),
        "perl": (
            '#!/usr/bin/env perl\n'
            'use strict;\n'
            'use warnings;\n\n'
            f'# {name} - Perl module for Empusa\n\n'
            f'print "[{name}] Module executed.\\n";\n'
            '# TODO: Implement module logic\n'
        ),
    }

    source_content = templates.get(language, f"# {name} - {language} module\n# TODO: Implement\n")
    (mod_dir / source_name).write_text(source_content, encoding="utf-8")

    # For Rust, also create Cargo.toml
    if language == "rust":
        cargo_toml = (
            f'[package]\nname = "{name}"\nversion = "0.1.0"\n'
            'edition = "2021"\n\n'
            '[[bin]]\n'
            f'name = "{name}"\n'
            f'path = "main.rs"\n'
        )
        (mod_dir / "Cargo.toml").write_text(cargo_toml, encoding="utf-8")

    # For C#, create a .csproj
    if language == "csharp":
        csproj = (
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <PropertyGroup>\n'
            '    <OutputType>Exe</OutputType>\n'
            '    <TargetFramework>net8.0</TargetFramework>\n'
            '  </PropertyGroup>\n'
            '</Project>\n'
        )
        (mod_dir / f"{name}.csproj").write_text(csproj, encoding="utf-8")

    # For Go, create go.mod
    if language == "go":
        go_mod = f'module {name}\n\ngo 1.21\n'
        (mod_dir / "go.mod").write_text(go_mod, encoding="utf-8")

    return mod_dir


# -- Interactive workshop menu ---------------------------------------


def module_workshop(
    services: Optional[Services] = None,
    run_hooks_fn: Optional[Any] = None,
) -> None:
    """Interactive module workshop for compiling multi-language payloads.

    Args:
        services: Optional Services container (for CommandRunner).
        run_hooks_fn: Optional callback for post_compile hooks.
    """
    log_info("\n== Module Workshop ==", "bold magenta")
    log_info(f"Modules directory: [dim]{MODULES_DIR}[/dim]")

    # Ensure modules directory exists
    MODULES_DIR.mkdir(parents=True, exist_ok=True)

    while True:
        clear_screen()
        log_info("\n[bold]Module Workshop Menu:[/]")
        log_info("1. List Modules")
        log_info("2. Compile Module")
        log_info("3. Compile All")
        log_info("4. Create Module")
        log_info("5. Module Info")
        log_info("6. Detect Compilers")
        log_info("7. Open Modules Folder")
        log_info("0. Back to Main Menu")

        choice = Prompt.ask("Select an option", choices=['0', '1', '2', '3', '4', '5', '6', '7'])

        if choice == '0':
            break

        elif choice == '1':
            # List modules
            modules = list_modules()
            if not modules:
                log_info("No modules found. Use option 4 to create one.", "yellow")
                continue

            table = Table(
                title="Modules",
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

            for i, mod in enumerate(modules, 1):
                built = "[green]✔[/green]" if mod.get("_compiled") else "[red]✗[/red]"
                table.add_row(
                    str(i),
                    mod.get("name", "-"),
                    mod.get("language", "-"),
                    mod.get("compiler", "auto"),
                    mod.get("target_os", "any"),
                    built,
                    mod.get("description", "-"),
                )

            console.print(table)
            log_info(f"\nTotal: {len(modules)} module(s)", "magenta")

        elif choice == '2':
            # Compile one module
            modules = list_modules()
            if not modules:
                log_info("No modules found. Create one first.", "yellow")
                continue

            log_info("\n[bold yellow]Compile Module[/bold yellow]")
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

        elif choice == '3':
            # Compile all modules
            modules = list_modules()
            if not modules:
                log_info("No modules found.", "yellow")
                continue

            log_info(f"\n[bold]Compiling {len(modules)} module(s)...[/bold]")
            success = 0
            fail = 0
            for mod in modules:
                if compile_module(mod, services=services, run_hooks_fn=run_hooks_fn):
                    success += 1
                else:
                    fail += 1

            console.print("")
            log_info(f"Results: [green]{success} succeeded[/green], [red]{fail} failed[/red]", "bold")

        elif choice == '4':
            # Create new module
            log_info("\n[bold yellow]Create Module[/bold yellow]")
            supported = list(LANGUAGE_EXTENSIONS.keys()) + ["make"]
            log_info("Supported languages:")
            for i, lang in enumerate(supported, 1):
                compilers = detect_compilers().get(lang, [])
                status = f"[green]({', '.join(compilers)})[/green]" if compilers else "[red](not found)[/red]"
                log_info(f"  {i}. {lang} {status}")

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
            if not name or not re.match(r'^[a-zA-Z0-9_-]+$', name):
                log_error("Invalid name. Use only letters, numbers, hyphens, underscores.")
                continue

            if (MODULES_DIR / name).exists():
                if not Confirm.ask(f"Module '{name}' already exists. Overwrite?"):
                    continue

            mod_dir = create_module_template(language, name)
            log_success(f"[+] Created module: {mod_dir}")
            log_info("Edit the source file, then use option 2 to compile.", "yellow")

        elif choice == '5':
            # Module info
            modules = list_modules()
            if not modules:
                log_info("No modules found.", "yellow")
                continue

            log_info("\n[bold yellow]Module Info[/bold yellow]")
            for i, mod in enumerate(modules, 1):
                log_info(f"  {i}. {mod.get('name', '?')} ({mod.get('language', '?')})")

            try:
                idx = int(Prompt.ask("Module #")) - 1
                if 0 <= idx < len(modules):
                    module_info(modules[idx])
                else:
                    log_error("Invalid selection.")
            except ValueError:
                log_error("Please enter a valid number.")

        elif choice == '6':
            # Detect compilers
            log_info("\n[bold yellow]Compiler Detection[/bold yellow]")
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

            console.print(table)
            total = sum(len(v) for v in compilers.values())
            log_info(f"\n{total} compiler(s) found across {len(compilers)} language(s)", "yellow")

        elif choice == '7':
            # Open modules folder
            try:
                MODULES_DIR.mkdir(parents=True, exist_ok=True)
                if IS_WINDOWS:
                    os.startfile(str(MODULES_DIR))  # type: ignore[attr-defined]
                elif platform.system() == "Darwin":
                    subprocess.run(["open", str(MODULES_DIR)], check=False)
                else:
                    subprocess.run(["xdg-open", str(MODULES_DIR)], check=False)
                log_success(f"[+] Opened: {MODULES_DIR}")
            except Exception as e:
                log_error(f"Could not open directory: {e}")
                log_info(f"Path: {MODULES_DIR}", "yellow")
