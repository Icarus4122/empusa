"""
Empusa - Operational Build Domain (cli_build)

Backward-compatible re-export shim.  The actual implementations now
live in focused modules:

- cli_privesc  - privesc enumeration generator
- cli_hash     - hash identifier, crack builder, hashcat rule generator
- cli_ad       - Active Directory enumeration playbook
- cli_scan     - IP/port/hostname validation, nmap, host summary, env build
- cli_tunnel   - reverse tunnel & port forward builder
- cli_loot     - loot tracker
"""

from empusa.cli_ad import ad_enum_playbook as ad_enum_playbook
from empusa.cli_hash import (
    HASH_SIGNATURES as HASH_SIGNATURES,
)
from empusa.cli_hash import (
    find_password_files as find_password_files,
)
from empusa.cli_hash import (
    generate_hashcat_rules as generate_hashcat_rules,
)
from empusa.cli_hash import (
    hash_crack_builder as hash_crack_builder,
)
from empusa.cli_hash import (
    identify_hash as identify_hash,
)
from empusa.cli_loot import loot_tracker as loot_tracker
from empusa.cli_privesc import (
    LINUX_ENUM_COMMANDS as LINUX_ENUM_COMMANDS,
)
from empusa.cli_privesc import (
    WINDOWS_ENUM_COMMANDS as WINDOWS_ENUM_COMMANDS,
)
from empusa.cli_privesc import (
    privesc_enum_generator as privesc_enum_generator,
)
from empusa.cli_scan import (
    build_env as build_env,
)
from empusa.cli_scan import (
    configure_shell_history as configure_shell_history,
)
from empusa.cli_scan import (
    detect_os as detect_os,
)
from empusa.cli_scan import (
    run_nmap as run_nmap,
)
from empusa.cli_scan import (
    search_exploits_from_nmap as search_exploits_from_nmap,
)
from empusa.cli_scan import (
    summarize_hosts as summarize_hosts,
)
from empusa.cli_scan import (
    validate_hostname as validate_hostname,
)
from empusa.cli_scan import (
    validate_ip as validate_ip,
)
from empusa.cli_scan import (
    validate_port as validate_port,
)
from empusa.cli_tunnel import build_reverse_tunnel as build_reverse_tunnel
