# DLL Sideloading Detection

## Overview

Detects DLL sideloading by correlating three stages of the attack chain: a DLL being dropped into a non-standard location by a suspicious process, the DLL lacking a trusted code signature, and the DLL subsequently being loaded into a process from that same location with low global prevalence.

DLL sideloading exploits the Windows DLL search order — when an application loads a DLL without specifying an absolute path, Windows searches several locations in a defined order. Attackers place a malicious DLL with the expected name next to a legitimate (often signed) executable, causing it to load the attacker's code instead of the legitimate library. This is particularly effective because the malicious code runs within the context of a trusted process, potentially inheriting its reputation and privileges.

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Defense Evasion, Persistence |
| **Techniques** | T1574.002 - Hijack Execution Flow: DLL Side-Loading |
| | T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking |

## Data Sources

- `DeviceFileEvents` (Defender for Endpoint)
- `DeviceFileCertificateInfo` (Defender for Endpoint)
- `DeviceImageLoadEvents` (Defender for Endpoint)
- `FileProfile` function (MDE cloud enrichment)

## Detection Logic

The query operates in three stages, each narrowing the result set significantly:

1. **Stage 1 — DLL drop detection:** Identifies DLL files created in non-standard locations by processes commonly used in attack delivery chains. Standard trusted paths (`Windows`, `Program Files`, `ProgramData\Microsoft`, WinSxS, driver store) are excluded. The delivery processes are split into two tiers — high-confidence script engines and a broader set of LOLBins.

2. **Stage 2 — Certificate validation:** Cross-references the dropped DLLs against `DeviceFileCertificateInfo` to filter down to only unsigned or untrusted DLLs. Legitimately installed DLLs from major vendors will almost always have a valid signature.

3. **Stage 3 — Load correlation:** Checks `DeviceImageLoadEvents` for cases where an untrusted DLL was actually loaded into a process, enriches with `FileProfile` to check global prevalence (< 100 devices globally), and confirms the load occurred from the same folder as the drop. This final stage produces the sideloading signal — a rare, unsigned DLL dropped and loaded from the same unusual location.

## Customization

- **`_ProductionDetectionModeOn`** — Set to `1` for production (1 hour detection window, 4 hour lookback for file drops). Set to `0` for tuning mode (30 days) to baseline your environment before deployment.
- **`IngestionBuffer`** — Small buffer (default 5 minutes) subtracted from "now" to account for table ingestion delay. Prevents missed events that haven't landed yet.
- **`PrevalenceThreshold`** — Maximum global prevalence for a DLL to be considered suspicious. Default is 100. Raise this if your environment has many unique internal DLLs, or lower it for stricter detection.
- **`ExcludedFolders`** — Add environment-specific trusted paths (e.g., internal deployment directories, build agent paths) to reduce false positives.
- **Delivery processes** — Review and extend the `DeliveryProcesses` list based on your threat model. The current list covers common script engines and LOLBins.

## Query

```kql
// ============================================================================
// DLL Sideloading Detection
// Correlates DLL file drops, certificate trust status, and image load events
// to detect DLL sideloading attacks. Filters by global prevalence to
// surface only rare, untrusted DLLs loaded from non-standard paths.
//
// Data sources:
//   DeviceFileEvents, DeviceFileCertificateInfo, DeviceImageLoadEvents
//
// MITRE ATT&CK:
//   T1574.002 - Hijack Execution Flow: DLL Side-Loading
//   T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking
// ============================================================================
let _ProductionDetectionModeOn = 1; // 1 = Production, 0 = Tuning
let IngestionBuffer = 5m;
let _stop = ago(IngestionBuffer);
let TimeFrame = iff(_ProductionDetectionModeOn == 1, _stop - 1h, ago(30d));
let LookBack = iff(_ProductionDetectionModeOn == 1, _stop - 4h, ago(30d));
let PrevalenceThreshold = 100;
// Processes commonly used to deliver/drop DLLs in attack chains
let DeliveryProcesses = dynamic([
    // Script engines
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "cscript.exe", "wscript.exe", "jscript.exe",
    "python.exe", "java.exe",
    // LOLBins that can drop or fetch files
    "certutil.exe", "mshta.exe", "msiexec.exe",
    "bitsadmin.exe", "regsvr32.exe", "rundll32.exe",
    // User-initiated (downloads, ZIP extraction, etc.)
    "explorer.exe"
]);
// Trusted paths to exclude — DLLs here are expected
let ExcludedFolders = dynamic([
    @":\Windows",
    @":\Program Files\",
    @":\Program Files (x86)\",
    @"ProgramData\Microsoft",
    @"WinSxS",
    @"DriverStore"
]);
// ============================================================================
// Stage 1: Find DLLs dropped into non-standard locations by delivery processes
// ============================================================================
let newDLL = DeviceFileEvents
    | where Timestamp between (LookBack .. _stop)
    | where FileName endswith ".dll"
    | where isnotempty(SHA1)
    | where InitiatingProcessFileName in~ (DeliveryProcesses)
    | where not(FolderPath has_any (ExcludedFolders))
    | where not(FolderPath startswith "/") // Exclude Linux/WSL paths
    // Additional filter for explorer.exe to reduce noise:
    // only flag if the DLL lands in a user-writable temp/download path
    | where InitiatingProcessFileName !~ "explorer.exe"
        or FolderPath has_any ("\\Temp\\", "\\Downloads\\", "\\AppData\\", "\\Desktop\\", "\\Public\\")
    | extend DropFolder = extract(@'^(.*)\\[^\\]*$', 1, FolderPath)
    | distinct SHA1, DropFolder, DeviceId;
// ============================================================================
// Stage 2: Filter to only unsigned / untrusted DLLs
// ============================================================================
let untrusted = DeviceFileCertificateInfo
    | where Timestamp between (LookBack .. _stop)
    | where SHA1 in ((newDLL | project SHA1))
    | summarize arg_max(Timestamp, IsTrusted, IsRootSignerMicrosoft) by SHA1
    | where IsTrusted != 1
    | distinct SHA1;
// ============================================================================
// Stage 3: Correlate with actual DLL loads + prevalence check
// ============================================================================
DeviceImageLoadEvents
| where Timestamp between (TimeFrame .. _stop)
| where not(FolderPath has_any (ExcludedFolders))
| where not(FolderPath startswith "/")
| where not(InitiatingProcessFolderPath has_any (ExcludedFolders))
| where SHA1 in (untrusted)
// Cloud enrichment: check global prevalence
| invoke FileProfile("SHA1", 500)
| where GlobalPrevalence < PrevalenceThreshold
// Extract the folder the DLL was loaded from
| extend LoadFolder = extract(@'^(.*)\\[^\\]*$', 1, FolderPath)
// Confirm the DLL was loaded from the same folder it was dropped in
| join kind=inner newDLL on SHA1, DeviceId
| where LoadFolder =~ DropFolder
// Deduplicate per DLL + device, keep first and last seen
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    LoadCount = count()
    by DeviceName,
       FileName,
       SHA1,
       SHA256,
       FolderPath,
       LoadedByProcess = InitiatingProcessFileName,
       LoadedByPath = InitiatingProcessFolderPath,
       DroppedByAccount = InitiatingProcessAccountName,
       GlobalPrevalence,
       GlobalFirstSeen
| extend DaysSinceGlobalFirstSeen = datetime_diff("day", now(), GlobalFirstSeen)
| project
    FirstSeen,
    LastSeen,
    LoadCount,
    DeviceName,
    FileName,
    FolderPath,
    LoadedByProcess,
    LoadedByPath,
    DroppedByAccount,
    SHA256,
    GlobalPrevalence,
    GlobalFirstSeen,
    DaysSinceGlobalFirstSeen
| sort by GlobalPrevalence asc, FirstSeen desc
```
