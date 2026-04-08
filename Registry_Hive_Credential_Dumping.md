# Registry Hive Credential Dumping Detection

## Overview

Detects attempts to dump sensitive Windows registry hives (SAM, SYSTEM, SECURITY) which contain credential material. Attackers extract these hives to perform offline credential attacks — the SAM hive contains local account password hashes, the SYSTEM hive holds the boot key needed to decrypt them, and the SECURITY hive stores LSA secrets and cached domain credentials.

The most common method is `reg.exe save`, but the query also covers alternative techniques including `esentutl.exe` for raw file copy and access to hive files through Volume Shadow Copies. Dumping multiple hives in the same session is a particularly strong indicator, as extracting useful credentials typically requires at least both SAM and SYSTEM.

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Credential Access |
| **Techniques** | T1003.002 - OS Credential Dumping: Security Account Manager |
| | T1003.004 - OS Credential Dumping: LSA Secrets |
| | T1003.005 - OS Credential Dumping: Cached Domain Credentials |

## Data Source

- `DeviceProcessEvents` (Defender for Endpoint)

## Detection Logic

1. **Detect** `reg.exe` with `save` or `export` targeting SAM, SYSTEM, or SECURITY hives.
2. **Detect** alternative dumping methods — `esentutl.exe` copying hive files, and any process accessing hive files through Volume Shadow Copy paths.
3. **Exclude** known legitimate processes that may interact with registry hives (e.g., backup agents, compliance tools).
4. **Correlate** multiple hive dumps on the same device within a 15-minute window to identify the full credential extraction pattern (SAM + SYSTEM + SECURITY).
5. **Score** based on which hives were targeted — dumping multiple hives scores higher than a single hive operation.

## Customization

- **`ExcludedProcesses`** — Add legitimate backup or compliance agents that export registry hives in your environment.
- **`ExcludedAccounts`** — Add service accounts used by authorized tools that perform hive operations.
- **`CorrelationWindow`** — Time window for grouping multiple hive dumps on the same device. Default is 15 minutes.
- **Lookback window** — Default is 24 hours. Extend for broader hunting.

## Query

```kql
// ============================================================================
// Registry Hive Credential Dumping Detection
// Detects attempts to dump SAM, SYSTEM, and SECURITY registry hives for
// offline credential extraction. Covers reg.exe save/export, esentutl.exe
// raw copy, and Volume Shadow Copy access to hive files.
//
// Data source: DeviceProcessEvents (Defender for Endpoint)
//
// MITRE ATT&CK:
//   T1003.002 - OS Credential Dumping: Security Account Manager
//   T1003.004 - OS Credential Dumping: LSA Secrets
//   T1003.005 - OS Credential Dumping: Cached Domain Credentials
// ============================================================================
let LookbackWindow = 24h;
let CorrelationWindow = 15m;
// Legitimate processes that may interact with registry hives
let ExcludedProcesses = dynamic([
    // "backupagent.exe", "omsagent.exe"
]);
let ExcludedAccounts = dynamic([
    // "svc_backup"
]);
// Target hive patterns
let HivePatterns = dynamic([
    "hklm\\sam", "hklm\\system", "hklm\\security",
    "hkey_local_machine\\sam", "hkey_local_machine\\system", "hkey_local_machine\\security"
]);
let ShadowCopyHiveFiles = dynamic([
    "\\windows\\system32\\config\\sam",
    "\\windows\\system32\\config\\system",
    "\\windows\\system32\\config\\security"
]);
// --- Method 1: reg.exe save/export ---
// Use regex to match only the top-level hive (e.g., HKLM\SAM) and NOT
// deeper subkeys (e.g., HKLM\SYSTEM\CurrentControlSet\services\...)
let RegDump = DeviceProcessEvents
    | where Timestamp > ago(LookbackWindow)
    | where FileName =~ "reg.exe"
    | where ProcessCommandLine has_any ("save", "export")
    | where ProcessCommandLine matches regex @"(?i)(hklm|hkey_local_machine)\\(sam|system|security)(\s|""|$)"
    | extend Method = "reg.exe save/export";
// --- Method 2: esentutl.exe raw copy of hive files ---
let EsentutlDump = DeviceProcessEvents
    | where Timestamp > ago(LookbackWindow)
    | where FileName =~ "esentutl.exe"
    | where ProcessCommandLine has_any (ShadowCopyHiveFiles)
        or (ProcessCommandLine has "/y" and ProcessCommandLine has_any ("\\config\\sam", "\\config\\system", "\\config\\security"))
    | extend Method = "esentutl.exe copy";
// --- Method 3: Volume Shadow Copy access to hive files ---
let ShadowCopyDump = DeviceProcessEvents
    | where Timestamp > ago(LookbackWindow)
    | where ProcessCommandLine has "HarddiskVolumeShadowCopy"
    | where ProcessCommandLine has_any (ShadowCopyHiveFiles)
    | where FileName !~ "esentutl.exe" // Avoid overlap with Method 2
    | extend Method = "Volume Shadow Copy";
// --- Combine all methods ---
let AllDumps = union RegDump, EsentutlDump, ShadowCopyDump
    | where not(InitiatingProcessFileName has_any (ExcludedProcesses))
    | where not(InitiatingProcessAccountName has_any (ExcludedAccounts))
    // Identify which hive was targeted
    // For reg.exe: match top-level hive only (already filtered by regex)
    // For file-based methods: match on config file path
    | extend TargetHive = case(
        ProcessCommandLine matches regex @"(?i)(hklm|hkey_local_machine)\\sam(\s|""|$)"
            or ProcessCommandLine has "\\config\\sam", "SAM",
        ProcessCommandLine matches regex @"(?i)(hklm|hkey_local_machine)\\system(\s|""|$)"
            or ProcessCommandLine has "\\config\\system", "SYSTEM",
        ProcessCommandLine matches regex @"(?i)(hklm|hkey_local_machine)\\security(\s|""|$)"
            or ProcessCommandLine has "\\config\\security", "SECURITY",
        "Unknown"
    );
// --- Correlate: group hive dumps on the same device within the time window ---
let Correlated = AllDumps
    | summarize
        FirstSeen = min(Timestamp),
        LastSeen = max(Timestamp),
        HivesDumped = make_set(TargetHive),
        Methods = make_set(Method),
        Commands = make_set(ProcessCommandLine, 5),
        Processes = make_set(InitiatingProcessFileName),
        AccountName = take_any(InitiatingProcessAccountName)
        by DeviceName, DeviceId, bin(Timestamp, CorrelationWindow)
    | extend HiveCount = array_length(HivesDumped)
    | extend Severity = case(
        // SAM + SYSTEM (+ optionally SECURITY) = full credential extraction
        HiveCount >= 2 and set_has_element(HivesDumped, "SAM") and set_has_element(HivesDumped, "SYSTEM"), "High",
        // SECURITY alone = LSA secrets / cached creds
        HiveCount == 1 and set_has_element(HivesDumped, "SECURITY"), "Medium",
        // Single hive dump
        HiveCount == 1, "Medium",
        "Low"
    );
Correlated
| project
    FirstSeen,
    LastSeen,
    Severity,
    DeviceName,
    AccountName,
    HiveCount,
    HivesDumped,
    Methods,
    Processes,
    Commands
| sort by HiveCount desc, Severity asc, FirstSeen desc
```
