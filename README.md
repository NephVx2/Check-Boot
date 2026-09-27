# Check-Boot

🇫🇷 [Version française](README_FRENCH.md)

**Author:** Nephren ([github.com/NephVx2](https://github.com/NephVx2))
**Version:** 6.1
**Compatible:** Windows 10/11 — UEFI / Legacy BIOS — GPT / MBR — English & French Windows

---

## Table of contents

- [Overview](#overview)
- [Screenshots](#screenshots)
- [What it checks](#what-it-checks)
- [Requirements](#requirements)
- [First run (step by step)](#first-run-step-by-step)
- [Usage](#usage)
- [Understanding the score](#understanding-the-score)
- [Reports generated](#reports-generated)
- [Why it's useful](#why-its-useful)

---

## Overview

Check-Boot is a read-only PowerShell diagnostic script that audits the entire Windows startup chain in one run: firmware, BCD, Secure Boot, TPM, EFI/bootloader files, drivers loaded at boot, BitLocker, WinRE, the Recovery partition, disk SMART health, system-image integrity, and the boot event log.

Boot problems are usually invisible until the day Windows won't start — by then it's too late to gather diagnostics. This script is meant to be run *before* that happens: on a healthy machine, it establishes a baseline (hashes of `winload.efi`/`bootmgfw.efi`, DBX revocation-list size, score history) and flags anything that looks abnormal, drifted, or misconfigured — so an actual boot failure later on is faster to diagnose, or never happens at all.

It never modifies the boot configuration. The only optional write action is creating a Windows System Restore point (`-CreateRestorePoint`) before running the slower checks.

---

## Screenshots

<p align="center">
  <img src="https://raw.githubusercontent.com/NephVx2/Check-Boot/main/screenshots/01-banner-sysinfo.png" width="49%">
  <img src="https://raw.githubusercontent.com/NephVx2/Check-Boot/main/screenshots/04-banner-html.png" width="49%">
</p>

More screenshots (Secure Boot section, the final "Audit Complete" summary, the detailed HTML results table, a flagged Boot Log warning) are in the [screenshots folder](https://github.com/NephVx2/Check-Boot/tree/main/screenshots).

---

## What it checks

| Category | What it looks at |
|---|---|
| System | Windows version/build, last boot time, uptime |
| Firmware | UEFI vs Legacy BIOS |
| Disk | System partition style (GPT/MBR) |
| BCD | Boot Configuration Data accessibility, Boot Manager presence, number of Windows boot entries, BCD object count (registry) |
| Secure Boot | Enabled/disabled state |
| TPM | Presence and spec version |
| EFI | EFI partition presence and free space, `winload.efi`/`bootmgfw.efi` presence, SHA256 hashes and drift vs the previous run |
| Legacy BIOS | `winload.exe` presence (non-UEFI systems) |
| Secure Boot Keys | DB / KEK / DBX certificate stores, DBX regression detection |
| Security | BlackLotus bootkit mitigation, VBS (Virtualization Based Security), HVCI (Memory Integrity) |
| Boot Drivers | Unsigned boot-start/system-start drivers |
| Fast Boot | Windows fast startup (Hiberboot) state |
| BitLocker | Protection status on the system drive |
| WinRE | Windows Recovery Environment state |
| Recovery | Recovery partition presence and whether it's improperly exposed with a drive letter |
| SMART | Physical disk health status |
| System Integrity | `SFC /verifyonly` and `DISM /CheckHealth` results |
| Boot Order | Firmware boot order accessibility |
| Dual Boot | Detects a Linux bootloader (GRUB/shim) or Linux partition |
| Hackintosh | Detects OpenCore/Clover bootloader entries |
| Win11 Compatibility | Whether the current boot setup (UEFI + GPT) meets Microsoft's Windows 11 requirements |
| Boot Log | Recent Kernel-Boot errors and unclean shutdowns (Event ID 41) from the last 7/30 days |

Every check is scored: `OK`, `WARNING`, or `ERROR`. Each category also gets its own weighted 0–100 score, on top of the overall health score.

---

## Requirements

- Windows 10 or 11
- PowerShell run as Administrator (the script auto-elevates via a UAC prompt if launched from a non-elevated session)

---

## First run (step by step)

1. Copy `Check-Boot.ps1` to the target machine.

2. Open PowerShell (elevation isn't required to launch it — the script self-elevates via a UAC prompt on its own). Go to the folder that contains the script (adjust the path; keep the quotes if it contains spaces):

   ```powershell
   cd "$HOME\Downloads"
   ```

3. **Unblock the script** if you downloaded it from the Internet. Windows flags downloaded files, and PowerShell's execution policy (`RemoteSigned`, for example) refuses to run a flagged script. From the script's folder:

   ```powershell
   Unblock-File .\Check-Boot.ps1
   ```

   If PowerShell says instead that running scripts is disabled on this system (the Windows default policy is `Restricted`), allow scripts for the current account first (the change applies to this account only, not to the whole machine):

   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
   ```

   Still blocked? See the [step-by-step guide](https://github.com/NephVx2/Script-blocked-Look-at-this).

4. First run the self-test — no files written, no system modifications:

   ```powershell
   .\Check-Boot.ps1 -SelfTest
   ```

   Runs 16 internal assertions (`Add-Result` scoring, `-Category` filtering, `Safe-CommandExists`, `Get-FileSha256`, and MBR/GPT recovery-partition detection). Exit code 0 = everything passes, 1 = at least one failure.

5. Run the full analysis:

   ```powershell
   .\Check-Boot.ps1
   ```

   Takes well under a minute on most machines — `SFC /verifyonly` and `DISM /CheckHealth` are the slowest steps (skip them with `-SkipSlowChecks` for a quick pass). Watch the console for a live, color-coded line per check as each section completes.

6. When it finishes, the console prints a `SUMMARY` box (totals, weighted score, evolution vs the previous run) followed by an `AUDIT COMPLETE` box with a text score bar and the paths to the generated reports.

7. Open the generated HTML report (the script offers to do this automatically unless `-Silent` is used) — check the critical-findings links at the top first if any check failed, then use the search box and status filters for everything else.

8. On the **second and subsequent runs**, the SUMMARY/AUDIT COMPLETE boxes also show the score trend vs the previous run, and the report flags any drift in the `winload.efi`/`bootmgfw.efi` hashes or a shrinking DBX — both are abnormal outside of a Windows update.

---

## Usage

```powershell
.\Check-Boot.ps1
```

### Parameters

| Parameter | Description |
|---|---|
| `-Silent` | No console output — for scheduled tasks. Reports are still generated. |
| `-SelfTest` | Runs 16 internal assertions against the script's core functions and exits (no system checks performed). |
| `-SkipSlowChecks` | Skips `SFC /verifyonly` and `DISM /CheckHealth`, the two slowest checks. |
| `-CreateRestorePoint` | Creates a System Restore point before the DISM checks. |
| `-Category <name(s)>` | Runs only the given category/categories (see the table above for valid names) plus the always-shown Summary. |

### Examples

```powershell
# Full run
.\Check-Boot.ps1

# Quick run, skipping SFC/DISM, no console output
.\Check-Boot.ps1 -Silent -SkipSlowChecks

# Only check Secure Boot and TPM
.\Check-Boot.ps1 -Category "Secure Boot","TPM"

# Verify the script's own logic
.\Check-Boot.ps1 -SelfTest
```

---

## Understanding the score

**Overall health score** (100 → 0, `-15` per error, `-5` per warning):

| Score | State |
|---|---|
| ≥ 90 | EXCELLENT |
| ≥ 75 | GOOD |
| ≥ 50 | FAIR |
| < 50 | CRITICAL |

**Per-category score**: each of the 22 categories starts at 100 and is deducted independently (`-30` per error, `-10` per warning in that category), then combined with a weight (BCD, Secure Boot, and System Integrity carry the most weight; Boot Order, Dual Boot, and Hackintosh the least) — so one weak category doesn't get lost in the overall average.

---

## Reports generated

Each run writes timestamped reports to `%USERPROFILE%\Desktop\Maintenance_Reports\Check-Boot\`:

- `Rapport_Boot_<timestamp>.csv`
- `Rapport_Boot_<timestamp>.json`
- `Rapport_Boot_<timestamp>.html` — a dark-theme dashboard with a score gauge, trend vs the previous run, a sparkline of score history, per-category tiles, a critical-findings section, and a filterable results table
- `Baseline_Boot.json` — persisted between runs to detect drift (binary hash changes, DBX shrinking, score trend)

---

## Why it's useful

- Catches a silently degraded boot chain (corrupted `bootmgfw.efi`, disabled Secure Boot, a DBX that has shrunk, an unsigned boot driver) long before it turns into a machine that won't start.
- Gives dual-boot and Hackintosh users visibility into how their setup interacts with the native Windows boot chain, without assuming a single-OS configuration is broken.
- Works identically on a French-language Windows install and an English one: every locale-dependent detection (`sfc`, `dism`) matches both languages, and the higher-risk detections (BCD entries, EFI GUIDs) are driven by literal file paths and GUIDs that are never translated by Windows.
- `-SelfTest` and `-Category` make it easy to fold into a larger maintenance suite or a scheduled task without re-running the entire (slower) check set every time.

---
*Part of Nephren's Windows 11 maintenance/security script suite.*
