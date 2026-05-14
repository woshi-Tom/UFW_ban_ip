# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A bash script (`banIP.sh`) that manages UFW firewall rules to restrict access to specific countries/regions. It uses APNIC delegated stats to get IP ranges and provides a TUI interface via `whiptail`.

## Running

```bash
sudo ./banIP.sh          # 正常模式
sudo ./banIP.sh --dry-run # 预览模式（不修改防火墙）
```

Requires: Linux with UFW installed, `whiptail` (from `newt` package), `wget`, `sudo`.

## Architecture

Single-file script (`banIP.sh`, ~580 lines) with these logical sections:

- **Config & constants** (L1-34): Region codes, internal IP ranges, DRY_RUN flag
- **Validation helpers** (L76-107): `validate_ip_cidr`, `validate_port`, `is_internal_ip`
- **Rule backup/restore** (L109-467): `save_ufw_policy`, `restore_ufw_rules`, `cleanup_on_error`
- **Rule detection** (L156-240): `detect_internal_ports`, `detect_specific_ip_rules` — identifies existing rules to skip
- **Rule application** (L280-422): `get_region_ips` (APNIC + local cache), `apply_single_rule`, `apply_rules_for_ip_and_ports`
- **TUI interface** (L469-584): `whiptail` menus, main loop with arg parsing

## Key Design Decisions

- **Safety-first rule ordering**: New rules are added before old "Anywhere" rules are cleaned, preventing SSH lockout.
- **Scoped error rollback**: ERR trap is only active during rule modification (L541-555). Ctrl-C at menu exits cleanly without rollback.
- **Smart rule skipping**: Internal IP rules and specific-IP rules are detected and preserved. Only "Anywhere" rules get replaced.
- **IP caching**: APNIC data cached in `/tmp/ufw_ip_cache_{REGION}.txt` with 7-day TTL. Subsequent runs skip download.
- **Dry-run mode**: `--dry-run` previews all UFW commands via stderr without executing them.

## Adding New Regions

Edit the `REGIONS` associative array at line 20 in `banIP.sh`. The region code must match APNIC's delegated stats format.

## Runtime Files

- `restricted_ports.txt` — ports extracted from current UFW rules
- `china_ips.txt` — downloaded IP ranges for selected region
- `ufw.policy` — UFW rule backup
- `/tmp/ufw_ip_cache_{REGION}.txt` — APNIC IP list cache (auto-managed)
