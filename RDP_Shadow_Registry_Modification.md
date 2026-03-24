# RDP Shadow Registry Modification — Enabling Shadowing Without Consent

## Overview

Detects modification of the Terminal Services `Shadow` registry value to settings that allow remote session shadowing without user consent. Attackers can abuse RDP shadowing to silently observe or take full control of an active user session, enabling credential harvesting, lateral movement, or surveillance without triggering a new logon event.

This technique is particularly stealthy because the session hijack occurs within an existing authenticated session rather than creating a new one, and native Windows tools (`mstsc /shadow`) can be used — no additional tooling required.

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Lateral Movement |
| **Technique** | T1563.002 - Remote Service Session Hijacking: RDP Hijacking |

## Data Source

- `DeviceRegistryEvents` (Defender for Endpoint)

## Detection Logic

The query monitors for `RegistryValueSet` or `RegistryKeyCreated` events targeting the Terminal Services `Shadow` registry value, filtering specifically for values that enable shadowing without user consent.

### Shadow Registry Value Reference

| Value | Meaning | Risk |
|-------|---------|------|
| 0 | No remote control allowed | Safe |
| 1 | Full control with user permission | Safe |
| **2** | **Full control without user permission** | **Malicious** |
| 3 | View only with user permission | Safe |
| **4** | **View only without user permission** | **Malicious** |

## Query

```kql
// RDP Shadow Registry Modification - Enabling Shadowing Without Consent
// Detects modification of the Terminal Services Shadow registry value
// to settings that allow session shadowing without user consent.
//
// Shadow registry value meanings:
//   0 = No remote control allowed
//   1 = Full control with user permission
//   2 = Full control without user permission  <-- malicious
//   3 = View only with user permission
//   4 = View only without user permission     <-- malicious
//
// MITRE ATT&CK: T1563.002 - Remote Service Session Hijacking: RDP Hijacking
DeviceRegistryEvents
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has "Terminal Services"
| where RegistryValueName =~ "Shadow"
| where RegistryValueData in ("2", "4")
| extend ShadowSetting = case(
    RegistryValueData == "2", "Full control without consent",
    RegistryValueData == "4", "View only without consent",
    "Unknown"
)
| project
    Timestamp,
    DeviceName,
    ShadowSetting,
    RegistryKey,
    RegistryValueData,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    InitiatingProcessSHA256,
    ReportId
```
