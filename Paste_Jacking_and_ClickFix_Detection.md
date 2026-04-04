# Paste Jacking Detection — Suspicious Commands via Run Dialog

## Overview

Detects potential paste jacking attacks, most commonly delivered today through fake CAPTCHA or "verify you are human" pages. The attack flow works as follows: a user lands on a malicious or compromised site that presents a convincing CAPTCHA dialog. When the user clicks "Verify" or "I'm not a robot", JavaScript silently copies a malicious command to their clipboard. The page then instructs the user to press Win+R, paste with Ctrl+V, and hit Enter — framed as a "verification step". The user believes they are completing a CAPTCHA, but they are actually executing a malicious payload through the Windows Run dialog.

This technique (also referred to as ClickFix) has become the most prevalent paste jacking variant, replacing older methods that relied on hidden clipboard replacement during copy operations. It is effective because it leverages social engineering to make the user perform the execution themselves, bypassing browser sandboxing and download protections entirely.

Since the clipboard manipulation and social engineering happen within the browser, endpoint agents have no visibility into those stages. However, the resulting process creation — explorer.exe spawning a scripting engine with a long, suspicious command line — is fully observable and highly anomalous. Legitimate Run dialog usage almost exclusively consists of short, simple commands like launching applications (calc, notepad, regedit) or opening paths. The query also correlates with GetClipboardData events to identify cases where clipboard content was read shortly before execution, further strengthening the signal.

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
