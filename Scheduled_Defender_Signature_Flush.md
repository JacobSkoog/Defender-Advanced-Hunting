# Scheduled Task Flushing Defender Signatures

## Overview

Detects scheduled tasks running as SYSTEM that invoke the built-in `MpCmdRun.exe -RemoveDefinitions` command to flush Microsoft Defender Antivirus signatures. This is a defense evasion technique that allows attackers to effectively blind Defender AV while it still appears enabled and healthy in management consoles — real-time protection stays on, but without signatures it cannot detect known malware.

The `MpCmdRun.exe` utility is a legitimate Defender component that supports removing signature definitions, typically used for troubleshooting. When abused through a scheduled task running as SYSTEM, an attacker can ensure signatures are repeatedly wiped, maintaining a persistent gap in detection coverage even after automatic signature updates restore them.

### Key commands

```
MpCmdRun.exe -RemoveDefinitions -All          // Removes all signatures
MpCmdRun.exe -RemoveDefinitions -DynamicSignatures  // Removes dynamic signatures only
```

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Defense Evasion |
| **Techniques** | T1562.001 - Impair Defenses: Disable or Modify Tools |
| | T1053.005 - Scheduled Task/Job: Scheduled Task |

## Data Sources

- `DeviceProcessEvents` (Defender for Endpoint)

## Detection Logic

1. **Direct execution** — Detects `MpCmdRun.exe` invoked with `-RemoveDefinitions` where the process chain indicates a scheduled task origin (`svchost.exe` hosting the Task Scheduler service, or `taskeng.exe` / `taskhostw.exe` as parent).
2. **Task creation** — Catches `schtasks.exe` or PowerShell `Register-ScheduledTask` / `New-ScheduledTask` creating a task that references `MpCmdRun` and `RemoveDefinitions`.
3. **Indirect via scripting engines** — Detects PowerShell, cmd, or other scripting engines spawned by the task scheduler that then invoke `MpCmdRun.exe -RemoveDefinitions`, covering cases where the scheduled task runs a wrapper script with the command inline.
4. **Bat/cmd file chain** — Detects the common real-world pattern where the scheduled task runs a `.bat` or `.cmd` file via `cmd.exe`, and the batch script contains the `MpCmdRun.exe -RemoveDefinitions` command. In this case `MpCmdRun.exe` has `cmd.exe` as its parent, and the `cmd.exe` command line references the batch file.

All three detections specifically look for SYSTEM-level execution context, as this is the privilege level required to modify Defender's signatures and the level at which a malicious scheduled task would operate.

## Customization

- **`ExcludedTasks`** — If your organization has legitimate automation that removes definitions for troubleshooting (rare, but possible), add the task name or command pattern here.
- **Lookback window** — Default is 30 days. Signature flushing tasks may run infrequently, so a wider window helps catch periodic executions.

## Query

```kql
// ============================================================================
// Scheduled Task Flushing Defender Signatures
// Detects scheduled tasks running as SYSTEM that invoke MpCmdRun.exe to
// remove Defender AV signature definitions, a defense evasion technique
// that blinds Defender while it still appears enabled.
//
// Data source: DeviceProcessEvents (Defender for Endpoint)
//
// MITRE ATT&CK:
//   T1562.001 - Impair Defenses: Disable or Modify Tools
//   T1053.005 - Scheduled Task/Job: Scheduled Task
// ============================================================================
let LookbackWindow = 30d;
// Legitimate task patterns to exclude (rare — review carefully before adding)
let ExcludedTasks = dynamic([
    // "Defender-Troubleshoot-Scheduled"
]);
// Processes that indicate task scheduler as the execution origin
let TaskSchedulerParents = dynamic([
    "svchost.exe",    // Hosts the Schedule service
    "taskeng.exe",    // Legacy task engine (pre-Win10)
    "taskhostw.exe"   // Modern task host
]);
// ============================================================================
// Detection 1: MpCmdRun -RemoveDefinitions spawned by task scheduler
// ============================================================================
let DirectExecution = DeviceProcessEvents
    | where Timestamp > ago(LookbackWindow)
    | where FileName =~ "MpCmdRun.exe"
    | where ProcessCommandLine has "RemoveDefinitions"
    | where InitiatingProcessFileName in~ (TaskSchedulerParents)
        or InitiatingProcessParentFileName in~ (TaskSchedulerParents)
    | where InitiatingProcessAccountName =~ "SYSTEM"
        or AccountName =~ "SYSTEM"
    | where not(ProcessCommandLine has_any (ExcludedTasks))
    | extend
        DetectionType = "ScheduledExecution",
        Severity = "High",
        RemovalScope = case(
            ProcessCommandLine has "-All", "All Signatures",
            ProcessCommandLine has "-DynamicSignatures", "Dynamic Signatures Only",
            "Unknown Scope"
        );
// ============================================================================
// Detection 2: Scheduled task creation referencing MpCmdRun + RemoveDefinitions
// ============================================================================
let TaskCreation = DeviceProcessEvents
    | where Timestamp > ago(LookbackWindow)
    | where (FileName =~ "schtasks.exe" and ProcessCommandLine has "/create")
        or ProcessCommandLine has_any (
            "Register-ScheduledTask",
            "New-ScheduledTask",
            "New-ScheduledTaskAction"
        )
    | where ProcessCommandLine has "MpCmdRun"
    | where ProcessCommandLine has "RemoveDefinitions"
    | where not(ProcessCommandLine has_any (ExcludedTasks))
    | extend
        DetectionType = "TaskCreation",
        Severity = "Critical",
        RemovalScope = case(
            ProcessCommandLine has "-All", "All Signatures",
            ProcessCommandLine has "-DynamicSignatures", "Dynamic Signatures Only",
            "Unknown Scope"
        );
// ============================================================================
// Detection 3: Script engine spawned by task scheduler invoking MpCmdRun
// ============================================================================
let IndirectExecution = DeviceProcessEvents
    | where Timestamp > ago(LookbackWindow)
    | where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe")
    | where ProcessCommandLine has "MpCmdRun" and ProcessCommandLine has "RemoveDefinitions"
    | where InitiatingProcessFileName in~ (TaskSchedulerParents)
        or InitiatingProcessParentFileName in~ (TaskSchedulerParents)
    | where InitiatingProcessAccountName =~ "SYSTEM"
        or AccountName =~ "SYSTEM"
    | where not(ProcessCommandLine has_any (ExcludedTasks))
    | extend
        DetectionType = "ScriptedScheduledExecution",
        Severity = "High",
        RemovalScope = case(
            ProcessCommandLine has "-All", "All Signatures",
            ProcessCommandLine has "-DynamicSignatures", "Dynamic Signatures Only",
            "Unknown Scope"
        );
// ============================================================================
// Detection 4: MpCmdRun spawned by a bat/cmd file in a scheduled task chain
// The scheduled task runs cmd.exe /c script.bat, and the bat file contains
// the MpCmdRun -RemoveDefinitions command. In this case the MpCmdRun process
// has cmd.exe as its parent, and cmd.exe has the task scheduler as its parent.
// ============================================================================
let BatFileChain = DeviceProcessEvents
    | where Timestamp > ago(LookbackWindow)
    | where FileName =~ "MpCmdRun.exe"
    | where ProcessCommandLine has "RemoveDefinitions"
    | where InitiatingProcessFileName =~ "cmd.exe"
    | where InitiatingProcessCommandLine has_any (".bat", ".cmd")
    // Verify SYSTEM context
    | where InitiatingProcessAccountName =~ "SYSTEM"
        or AccountName =~ "SYSTEM"
    | where not(ProcessCommandLine has_any (ExcludedTasks))
    | extend
        DetectionType = "BatFileScheduledExecution",
        Severity = "High",
        RemovalScope = case(
            ProcessCommandLine has "-All", "All Signatures",
            ProcessCommandLine has "-DynamicSignatures", "Dynamic Signatures Only",
            "Unknown Scope"
        );
// ============================================================================
// Combine all detections
// ============================================================================
union DirectExecution, TaskCreation, IndirectExecution, BatFileChain
| project
    Timestamp,
    DetectionType,
    Severity,
    RemovalScope,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    InitiatingProcessAccountName,
    ReportId
| sort by Severity asc, Timestamp desc
```
