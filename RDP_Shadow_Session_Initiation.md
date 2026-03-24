# RDP Shadow Session Initiation Without Consent

## Overview

Detects the use of `mstsc /shadow` with the `/noconsentprompt` flag, which allows an attacker to shadow an active RDP session without the target user being prompted for approval. This is a native Windows technique requiring no additional tooling — only local admin or SYSTEM privileges on the target host.

This query complements the [RDP Shadow Registry Modification](RDP_Shadow_Registry_Modification.md) detection. An attacker typically needs to both set the registry value to allow no-consent shadowing *and* execute the shadow command. Detecting both the registry change and the command execution provides layered coverage of this technique.

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Lateral Movement |
| **Technique** | T1563.002 - Remote Service Session Hijacking: RDP Hijacking |

## Data Source

- `DeviceProcessEvents` (Defender for Endpoint)

## Detection Logic

The query looks for process command lines containing both `shadow:` (specifying the target session ID) and `noconsentprompt` (suppressing the user approval dialog). The presence of both arguments together is a strong indicator of malicious intent, as legitimate remote assistance workflows typically require user consent.

## Query

```kql
DeviceProcessEvents
| where (ProcessCommandLine contains "noconsentprompt" and ProcessCommandLine contains "shadow:")
```
