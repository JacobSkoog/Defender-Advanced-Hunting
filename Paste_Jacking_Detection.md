# Paste Jacking Detection — Suspicious Commands via Run Dialog

## Overview

Detects potential paste jacking (also known as clipboard hijacking) attacks by identifying suspicious process executions spawned from `explorer.exe`, which is the parent process when a user runs commands via the Windows Run dialog (`Win+R`).

Paste jacking works by silently replacing clipboard contents when a user copies text from a malicious or compromised web page. The user believes they are copying something benign, but when they paste into a Run dialog or terminal, a hidden malicious command is executed instead. Since the clipboard substitution happens within the browser's DOM, endpoint agents have no visibility into the swap itself — but the resulting process creation is fully observable.

The key insight is that legitimate Run dialog usage almost exclusively consists of short, simple commands: launching applications (`calc`, `notepad`, `regedit`), opening paths, or running MMC snap-ins. A long, complex command line containing download cradles, encoded payloads, or chained commands originating from `explorer.exe` is highly anomalous.

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Execution |
| **Techniques** | T1204.001 - User Execution: Malicious Link |
| | T1059.001 - Command and Scripting Interpreter: PowerShell |
| | T1059.003 - Command and Scripting Interpreter: Windows Command Shell |

## Data Source

- `DeviceProcessEvents` (Defender for Endpoint)

## Detection Logic

1. **Filter** for processes where `explorer.exe` is the initiating (parent) process — this is the Run dialog execution chain.
2. **Scope** to child processes that are scripting engines or commonly abused LOLBins (`powershell.exe`, `cmd.exe`, `mshta.exe`, `wscript.exe`, `cscript.exe`, `certutil.exe`, `curl.exe`, `bitsadmin.exe`, `regsvr32.exe`).
3. **Measure** command line length — legitimate Run dialog commands are typically very short. Long command lines are anomalous in this context.
4. **Score** the command line for suspicious content: download cradles, encoded commands, chained execution, obfuscation patterns, and common paste jacking payload characteristics.
5. **Correlate** with `GetClipboardData` events from `DeviceEvents` on the same device within 5 minutes prior to execution. A clipboard read shortly before a suspicious Run dialog command is a strong paste jacking signal and boosts the score by 2.
6. **Exclude** known legitimate long commands from management tools or enterprise software.

## Customization

- **`MinCommandLineLength`** — Minimum command line length to evaluate. The default of 80 characters filters out normal Run dialog usage while catching most payloads. Lower it for stricter monitoring, raise it if too noisy.
- **`ClipboardWindowSeconds`** — Time window in seconds to look for a `GetClipboardData` event before the suspicious execution. Default is 300 seconds (5 minutes). Tighten it to reduce false correlations in busy environments, or widen it if users tend to paste with a delay.
- **`FPPatterns`** — Add legitimate software that may produce longer command lines via the Run dialog in your environment.
- **Lookback window** — Default is 24 hours. Extend for broader hunting sweeps.

## Query

```kql
// ============================================================================
// Paste Jacking Detection — Suspicious Commands via Run Dialog
// Detects anomalous process executions spawned from explorer.exe (Run dialog)
// that exhibit characteristics of paste jacking payloads: unusual length,
// download cradles, encoded commands, or chained execution.
//
// Data source: DeviceProcessEvents (Defender for Endpoint)
//
// MITRE ATT&CK:
//   T1204.001 - User Execution: Malicious Link
//   T1059.001 - Command and Scripting Interpreter: PowerShell
//   T1059.003 - Command and Scripting Interpreter: Windows Command Shell
// ============================================================================
let LookbackWindow = 24h;
let MinCommandLineLength = 80;
let ClipboardWindowSeconds = 300; // 5 minutes
// Known false positive patterns
let FPPatterns = dynamic([
    "visualstudiocode",
    "vscode",
    "microsoft.windowsterminal",
    "windowspackagemanager",
    "chocolatey"
]);
// Processes commonly abused in paste jacking payloads
let SuspiciousChildren = dynamic([
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "certutil.exe",
    "curl.exe",
    "bitsadmin.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "msdt.exe"
]);
let SuspiciousPatterns = dynamic([
    // Download cradles
    "downloadstring",
    "downloadfile",
    "downloaddata",
    "invoke-webrequest",
    "start-bitstransfer",
    "net.webclient",
    "xmlhttp",
    "curl ",
    "wget ",
    "certutil -urlcache",
    "bitsadmin /transfer",
    // Encoded / hidden execution
    "-enc ",
    "-encodedcommand",
    "-w hidden",
    "-windowstyle hidden",
    "-nop",
    "-noprofile",
    "-ep bypass",
    "-executionpolicy bypass",
    "frombase64string",
    // Chained execution (paste jacking hallmark)
    " && ",
    " ; ",
    " | iex",
    "| invoke-expression",
    // Common paste jacking patterns
    "invoke-expression",
    "iex(",
    "iex ",
    "start-process",
    "new-object",
    "[system.net",
    "[io.file]",
    // Obfuscation
    "-join",
    "[char]",
    "-bxor",
    "-replace",
    "gzipstream",
    "memorystream",
    // Reverse shells / C2
    "tcpclient",
    "system.net.sockets",
    "powercat",
    "nishang"
]);
// --- Step 1: Collect clipboard access events per device ---
let ClipboardEvents = DeviceEvents
    | where Timestamp > ago(LookbackWindow)
    | where ActionType == "GetClipboardData"
    | project ClipboardTimestamp = Timestamp, DeviceId, ClipboardProcess = InitiatingProcessFileName;
// --- Step 2: Detect suspicious Run dialog executions ---
DeviceProcessEvents
| where Timestamp > ago(LookbackWindow)
// Run dialog chain: explorer.exe spawns the process
| where InitiatingProcessFileName =~ "explorer.exe"
// Only look at scripting engines and commonly abused binaries
| where FileName in~ (SuspiciousChildren)
// Command line length threshold — legitimate Run dialog usage is short
| extend CmdLength = strlen(ProcessCommandLine)
| where CmdLength >= MinCommandLineLength
// Exclude known false positives
| where not(ProcessCommandLine has_any (FPPatterns))
// Score for suspicious content
| mv-apply Pattern = SuspiciousPatterns to typeof(string) on (
    summarize SuspiciousScore = countif(ProcessCommandLine has Pattern)
)
// Flag anything with a suspicious score OR an unusually long command line
| where SuspiciousScore >= 1 or CmdLength >= 250
// --- Step 3: Correlate with clipboard activity within 5 minutes prior ---
| join kind=leftouter ClipboardEvents on DeviceId
| where isnull(ClipboardTimestamp)
    or (ClipboardTimestamp between (ago(LookbackWindow) .. Timestamp)
        and (Timestamp - ClipboardTimestamp) between (0s .. ClipboardWindowSeconds * 1s))
// Deduplicate: keep the closest clipboard event per process execution
| summarize arg_min(iff(isnotnull(ClipboardTimestamp),
    Timestamp - ClipboardTimestamp, timespan(null)), *) by ReportId
| extend ClipboardPreceded = isnotnull(ClipboardTimestamp)
// Boost score if clipboard activity preceded execution
| extend AdjustedScore = SuspiciousScore + iff(ClipboardPreceded, 2, 0)
| extend Severity = case(
    AdjustedScore >= 4 or CmdLength >= 500, "High",
    AdjustedScore >= 2 or CmdLength >= 250, "Medium",
    "Low"
)
| project
    Timestamp,
    Severity,
    DeviceName,
    AccountName = InitiatingProcessAccountName,
    ChildProcess = FileName,
    CmdLength,
    SuspiciousScore,
    AdjustedScore,
    ClipboardPreceded,
    ClipboardProcess,
    ProcessCommandLine,
    SHA256,
    ReportId
| sort by AdjustedScore desc, CmdLength desc, Timestamp desc
```
