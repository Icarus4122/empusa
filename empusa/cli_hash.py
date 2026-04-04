"""Empusa - Hash identifier, crack command builder, and hashcat rule generator."""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from empusa.cli_common import (
    CONFIG,
    console,
    log_error,
    log_info,
    log_success,
    log_verbose,
    render_screen,
)

# (hashcat_mode, hash_name, example_pattern_or_prefix)
HASH_SIGNATURES: list[tuple[int, str, str]] = [
    (0, "MD5", r"^[a-f0-9]{32}$"),
    (100, "SHA-1", r"^[a-f0-9]{40}$"),
    (1400, "SHA-256", r"^[a-f0-9]{64}$"),
    (1700, "SHA-512", r"^[a-f0-9]{128}$"),
    (1000, "NTLM", r"^[a-f0-9]{32}$"),
    (3000, "LM", r"^[a-f0-9]{32}$"),
    (5600, "Net-NTLMv2", r"^\w+::\w+:"),
    (5500, "Net-NTLMv1", r"^\w+::\w+:"),
    (13100, "Kerberoast (TGS-REP)", r"^\$krb5tgs\$"),
    (18200, "AS-REP Roast", r"^\$krb5asrep\$"),
    (13400, "KeePass", r"^\$keepass\$"),
    (22921, "SSH Key (RSA/DSA)", r"^\$sshng\$"),
    (1800, "sha512crypt ($6$)", r"^\$6\$"),
    (500, "md5crypt ($1$)", r"^\$1\$"),
    (3200, "bcrypt ($2)", r"^\$2[aby]?\$"),
    (1500, "DES crypt", r"^[a-zA-Z0-9./]{13}$"),
    (7400, "sha256crypt ($5$)", r"^\$5\$"),
    (11600, "7-Zip", r"^\$7z\$"),
    (13000, "RAR5", r"^\$rar5\$"),
    (9600, "MS Office 2013+", r"^\$office\$\*2013"),
    (9500, "MS Office 2010", r"^\$office\$\*2010"),
    (9400, "MS Office 2007", r"^\$office\$\*2007"),
    (16800, "WPA-PMKID-PBKDF2", r"^[a-f0-9]{32}\*[a-f0-9]+\*"),
    (2500, "WPA-EAPOL-PBKDF2", r"^WPA\*"),
    (11300, "Bitcoin/Litecoin wallet", r"^\$bitcoin\$"),
    (400, "WordPress (phpass)", r"^\$P\$"),
    (7900, "Drupal7", r"^\$S\$"),
]


def identify_hash(hash_str: str) -> list[tuple[int, str]]:
    """Public wrapper for :func:`_identify_hash`."""
    return _identify_hash(hash_str)


def _identify_hash(hash_str: str) -> list[tuple[int, str]]:
    """Identify possible hash types by matching against known patterns.

    Returns:
        List of (hashcat_mode, hash_name) tuples, most specific first.
    """
    hash_str = hash_str.strip()
    matches: list[tuple[int, str]] = []

    # Prefix-based matches first (most reliable)
    prefix_checks: list[tuple[int, str, str]] = [
        (m, n, p) for m, n, p in HASH_SIGNATURES if p.startswith(r"^\$") or p.startswith(r"^\w+::")
    ]
    for mode, name, pattern in prefix_checks:
        if re.match(pattern, hash_str, re.IGNORECASE):
            matches.append((mode, name))

    # Length-based matches (less specific - MD5 vs NTLM are both 32 hex)
    if not matches:
        length_checks: list[tuple[int, str, str]] = [
            (m, n, p) for m, n, p in HASH_SIGNATURES if not p.startswith(r"^\$") and not p.startswith(r"^\w+::")
        ]
        for mode, name, pattern in length_checks:
            if re.match(pattern, hash_str, re.IGNORECASE):
                matches.append((mode, name))

    return matches


def hash_crack_builder() -> None:
    """Interactive hash identifier and hashcat command builder."""
    render_screen(
        "Hash Identifier + Crack Command Builder", "Paste a hash to identify it and generate the hashcat command."
    )

    hash_input = Prompt.ask("Enter hash (or 'q' to quit)").strip()
    if hash_input.lower() == "q":
        return

    matches = _identify_hash(hash_input)

    if not matches:
        log_error("Could not identify hash type.")
        log_info("Try: https://hashcat.net/wiki/doku.php?id=example_hashes", "yellow")
        return

    # Show matches
    table = Table(
        title="Possible Hash Types",
        show_lines=True,
        border_style="green",
        title_style="bold green",
    )
    table.add_column("#", style="dim", width=3)
    table.add_column("Hash Type", style="bold white")
    table.add_column("Hashcat Mode", style="cyan")

    for i, (mode, name) in enumerate(matches, 1):
        table.add_row(str(i), name, str(mode))

    console.print(table)

    # Let user pick if ambiguous
    if len(matches) > 1:
        log_info("\nMultiple matches found. Which type?")
        try:
            idx = int(Prompt.ask("Select #", default="1")) - 1
            if not (0 <= idx < len(matches)):
                idx = 0
        except ValueError:
            idx = 0
        selected_mode, selected_name = matches[idx]
    else:
        selected_mode, selected_name = matches[0]

    log_info(f"\n[bold]Identified:[/bold] {selected_name} (hashcat -m {selected_mode})")

    # Build hashcat command
    log_info("\n[bold]Wordlist options:[/bold]")
    wordlists = [
        ("/usr/share/wordlists/rockyou.txt", "rockyou.txt (default)"),
        ("/usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt", "rockyou-75 (fast)"),
        ("custom", "Enter custom path"),
    ]
    for i, (_, label) in enumerate(wordlists, 1):
        log_info(f"  {i}. {label}")

    wl_choice = Prompt.ask("Select", choices=["1", "2", "3"], default="1")
    wordlist = Prompt.ask("Wordlist path").strip() if wl_choice == "3" else wordlists[int(wl_choice) - 1][0]

    log_info("\n[bold]Rule file options:[/bold]")
    rules = [
        ("", "None"),
        ("/usr/share/hashcat/rules/best64.rule", "best64.rule"),
        ("/usr/share/hashcat/rules/rockyou-30000.rule", "rockyou-30000.rule"),
        ("/usr/share/hashcat/rules/d3ad0ne.rule", "d3ad0ne.rule"),
        ("custom", "Enter custom path"),
    ]
    for i, (_, label) in enumerate(rules, 1):
        log_info(f"  {i}. {label}")

    rule_choice = Prompt.ask("Select", choices=["1", "2", "3", "4", "5"], default="2")
    rule_path = Prompt.ask("Rule file path").strip() if rule_choice == "5" else rules[int(rule_choice) - 1][0]

    # Save hash to file
    hash_file = "hash.txt"
    env = CONFIG.get("session_env", "")
    if env:
        hash_file = f"{env}/hash_{selected_name.lower().replace(' ', '_').replace('-', '_')}.txt"

    # Build the command
    cmd = f"hashcat -m {selected_mode} {hash_file} {wordlist}"
    if rule_path:
        cmd += f" -r {rule_path}"
    cmd += " --force"

    console.print("")
    console.print(
        Panel(
            f"[bold green]# {selected_name} (mode {selected_mode})[/bold green]\n"
            f"[dim]# Save your hash first:[/dim]\n"
            f"echo '{hash_input}' > {hash_file}\n\n"
            f"[bold white]{cmd}[/bold white]\n\n"
            f"[dim]# Show cracked:[/dim]\n"
            f"hashcat -m {selected_mode} {hash_file} --show",
            title="Hashcat Command",
            border_style="green",
        )
    )

    # Offer to save
    if Confirm.ask("\nSave command to file?", default=False):
        out_name = f"crack_{selected_name.lower().replace(' ', '_')}.sh"
        out_path = Path(env) / out_name if env else Path(out_name)
        script = (
            "#!/bin/bash\n"
            f"# Hash Crack Script - {selected_name}\n"
            f"# Generated by Empusa - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"echo '{hash_input}' > {hash_file}\n"
            f"{cmd}\n"
            f"echo '\\n[*] Show results:'\n"
            f"hashcat -m {selected_mode} {hash_file} --show\n"
        )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(script, encoding="utf-8")
        log_success(f"[+] Saved: {out_path}")


def find_password_files(domain: str, search_path: Path | None = None) -> list[Path]:
    """Search for password files matching the domain name."""
    if search_path is None:
        search_path = Path.cwd()

    target_filename = f"{domain}-passwords.txt"
    matches: list[Path] = []

    log_verbose(f"Searching for {target_filename} in {search_path}...")

    try:
        for path in search_path.rglob(target_filename):
            if path.is_file():
                matches.append(path)
                log_verbose(f"Found: {path}", "green")
    except Exception as e:
        log_verbose(f"Warning during search: {e}", "yellow")

    return matches


def generate_hashcat_rules() -> None:
    """Generate hashcat rules from password patterns in environment password file."""
    render_screen("Hashcat Rule Generator")

    domain = Prompt.ask("Enter domain/environment name (used in filename)").strip().rstrip("/")

    matches = find_password_files(domain)

    if not matches:
        log_info(f"No {domain}-passwords.txt found in current directory.", "yellow")
        if Confirm.ask("Search in a different directory?"):
            custom_path = Prompt.ask("Enter directory path to search")
            try:
                matches = find_password_files(domain, Path(custom_path))
            except Exception as e:
                log_error(f"Error searching custom path: {e}")
                return

    if not matches:
        log_error(f"No {domain}-passwords.txt file found.")
        return

    if len(matches) == 1:
        pw_file = matches[0]
    else:
        log_info("Multiple password files found:", "bold yellow")
        for i, path in enumerate(matches):
            log_info(f"{i + 1}. {path}")
        try:
            index = int(Prompt.ask("Select the file to use", choices=[str(i + 1) for i in range(len(matches))])) - 1
            pw_file = matches[index]
        except (ValueError, IndexError):
            log_error("Invalid selection.")
            return

    pw_file = Path(pw_file)
    rule_file = pw_file.parent / "hashcat_generated.rule"

    if (
        rule_file.exists()
        and not CONFIG["dry_run"]
        and not Confirm.ask(f"[yellow]Rule file {rule_file} already exists. Overwrite?[/yellow]")
    ):
        log_info("Operation cancelled.", "yellow")
        return

    if CONFIG["dry_run"]:
        log_info(f"[DRY RUN] Would generate hashcat rules from {pw_file}", "yellow")
        return

    try:
        passwords = [line.strip() for line in pw_file.read_text(errors="ignore").splitlines() if line.strip()]
    except Exception as e:
        log_error(f"Error reading password file: {e}")
        return

    # Analyze password patterns
    rules_list: list[str] = []
    pattern_stats: dict[str, Any] = {
        "lowercase": 0,
        "uppercase": 0,
        "capitalize": 0,
        "reverse": 0,
        "digit_append": Counter(),
        "symbol_append": Counter(),
        "digit_prepend": Counter(),
        "symbol_prepend": Counter(),
        "years": Counter(),
        "lengths": Counter(),
        "leetspeak": 0,
        "duplicates": 0,
    }

    password_set = set(passwords)

    for pw in passwords:
        if not pw:
            continue

        pattern_stats["lengths"][len(pw)] += 1

        # Case transformations
        if pw.islower():
            pattern_stats["lowercase"] += 1
        elif pw.isupper():
            pattern_stats["uppercase"] += 1
            rules_list.append("u")
        elif pw[0].isupper() and pw[1:].islower():
            pattern_stats["capitalize"] += 1
            rules_list.append("c")

        # Reverse
        if pw[::-1] in password_set and pw[::-1] != pw:
            pattern_stats["reverse"] += 1
            rules_list.append("r")

        # Digit patterns at end
        if len(pw) > 1 and pw[-1].isdigit():
            pattern_stats["digit_append"][pw[-1]] += 1
            rules_list.append(f"${pw[-1]}")
            if len(pw) > 2 and pw[-2:].isdigit():
                for char in pw[-2:]:
                    rules_list.append(f"${char}")

        # Digit patterns at start
        if len(pw) > 1 and pw[0].isdigit():
            pattern_stats["digit_prepend"][pw[0]] += 1
            rules_list.append(f"^{pw[0]}")

        # Symbol patterns at end
        if len(pw) > 1 and pw[-1] in "!@#$%^&*()_+-=[]{}|;:,.<>?":
            pattern_stats["symbol_append"][pw[-1]] += 1
            rules_list.append(f"${pw[-1]}")

        # Symbol patterns at start
        if len(pw) > 1 and pw[0] in "!@#$%^&*()_+-=[]{}|;:,.<>?":
            pattern_stats["symbol_prepend"][pw[0]] += 1
            rules_list.append(f"^{pw[0]}")

        # Year detection (1900-2099)
        year_matches = re.findall(r"(19\d{2}|20\d{2})", pw)
        for year in year_matches:
            pattern_stats["years"][year] += 1
            for digit in year:
                rules_list.append(f"${digit}")

        # Leetspeak detection
        leet_chars = {"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "5": "s", "7": "t"}
        if any(char in leet_chars for char in pw):
            pattern_stats["leetspeak"] += 1
            for leet, normal in leet_chars.items():
                if leet in pw:
                    rules_list.append(f"s{normal}{leet}")

        # Duplicate detection
        if re.search(r"(.)\1{1,}", pw):
            pattern_stats["duplicates"] += 1
            rules_list.append("d")

    # Generate common combination rules
    common_combos = [
        "c $1",
        "c $!",
        "c $1 $2",
        "c $2 $0",
        "c $1 $9",
        "u $1",
        "u $!",
        "$1 $2 $3",
        "$! $@ $#",
        "c d",
        "c r",
    ]

    if pattern_stats["years"]:
        most_common_year = pattern_stats["years"].most_common(1)[0][0]
        for digit in most_common_year:
            common_combos.append(f"c ${digit}")

    rule_counter = Counter(rules_list)
    top_individual_rules = [rule for rule, _ in rule_counter.most_common(20)]

    all_rules = top_individual_rules + common_combos

    unique_rules: list[str] = []
    seen: set[str] = set()
    for rule in all_rules:
        if rule not in seen:
            unique_rules.append(rule)
            seen.add(rule)

    try:
        with rule_file.open("w") as rf:
            rf.write("# Hashcat rules generated by Empusa\n")
            rf.write(f"# Generated from {len(passwords)} passwords\n")
            rf.write(f"# Timestamp: {datetime.now().isoformat()}\n\n")
            for rule in unique_rules:
                rf.write(rule + "\n")

        log_info("\nPassword Pattern Analysis:", "bold cyan")
        log_info(f"  Total passwords analyzed: {len(passwords)}")
        log_info(f"  Lowercase: {pattern_stats['lowercase']}")
        log_info(f"  Uppercase: {pattern_stats['uppercase']}")
        log_info(f"  Capitalized: {pattern_stats['capitalize']}")
        log_info(f"  Contains leetspeak: {pattern_stats['leetspeak']}")
        log_info(f"  Has duplicates: {pattern_stats['duplicates']}")
        log_info(f"  Reverse pairs found: {pattern_stats['reverse']}")

        if pattern_stats["digit_append"]:
            top_digits = pattern_stats["digit_append"].most_common(3)
            log_info(f"  Common trailing digits: {', '.join([d for d, _ in top_digits])}")

        if pattern_stats["symbol_append"]:
            top_symbols = pattern_stats["symbol_append"].most_common(3)
            log_info(f"  Common trailing symbols: {', '.join([s for s, _ in top_symbols])}")

        if pattern_stats["years"]:
            top_years = pattern_stats["years"].most_common(3)
            log_info(f"  Common years: {', '.join([y for y, _ in top_years])}")

        common_lengths = pattern_stats["lengths"].most_common(3)
        log_info(f"  Common lengths: {', '.join([str(length) for length, _ in common_lengths])}")

        log_success(f"\n[+] {len(unique_rules)} hashcat rules generated")
        log_success(f"Saved rules to: {rule_file}")
        log_info(f"\nUsage: hashcat -a 0 -m <mode> <hashfile> <wordlist> -r {rule_file}", "yellow")
    except Exception as e:
        log_error(f"Error writing rule file: {e}")
