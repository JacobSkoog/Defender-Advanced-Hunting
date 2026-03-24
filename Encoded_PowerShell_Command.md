# Encoded PowerShell Command Detection

## Overview

Detects the use of Base64-encoded PowerShell commands, a widely used technique for obfuscating malicious payloads. Attackers encode commands to bypass command-line logging, evade static detection rules, and hide the true intent of their scripts from casual inspection.

PowerShell supports the `-EncodedCommand` parameter (and various abbreviations like `-enc`, `-ec`, `-en`) which accepts a Base64-encoded UTF-16LE string. While some legitimate tools and deployment frameworks use this feature, encoded commands in combination with certain patterns are strong indicators of malicious activity.

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Execution, Defense Evasion |
| **Techniques** | T1059.001 - Command and Scripting Interpreter: PowerShell |
| | T1027 - Obfuscated Files or Information |

## Data Source

- `DeviceProcessEvents` (Defender for Endpoint)

## Detection Logic

1. **Match** process events where the command line contains encoded command indicators (`-enc`, `-encodedcommand`, or the `FromBase64String` method).
2. **Extract** the Base64 payload from the command line.
3. **Decode** the payload from Base64 (UTF-16LE) to readable text.
4. **Filter out known false positives** from common legitimate sources such as ConfigMgr/SCCM, Intune, Windows Update, SyncAppvPublishingServer, and other management tools.
5. **Score** the decoded command for suspicious indicators — known offensive patterns, download cradles, credential access, persistence mechanisms, and obfuscation techniques.

## Customization

The false positive exclusions in `FPPatterns` should be reviewed and extended based on your environment. Common additions include vendor-specific management agents, deployment tools, or automation frameworks that use encoded PowerShell legitimately.

The `SuspiciousPatterns` scoring can be tuned — add patterns relevant to your threat landscape or adjust the minimum score threshold in the final filter.

## Query

```kql
// ============================================================================
// Encoded PowerShell Command Detection
// Detects Base64-encoded PowerShell execution and scores the decoded content
// for suspicious indicators. Filters out known legitimate sources to reduce
// false positives.
//
// Data source: DeviceProcessEvents (Defender for Endpoint)
//
// MITRE ATT&CK:
//   T1059.001 - Command and Scripting Interpreter: PowerShell
//   T1027    - Obfuscated Files or Information
// ============================================================================
let FPPatterns = dynamic([
    // ConfigMgr / SCCM / Intune
    "omsagent",
    "ccmexec",
    "sccm",
    "configurationmanager",
    "microsoft.management.services",
    "intunemanagementextension",
    // Windows native / update
    "syncappvpublishingserver",
    "windowsupdate",
    "pswindowsupdate",
    "windows.management",
    // Monitoring agents
    "omsagent",
    "microsoft monitoring agent",
    "healthservice",
    // Common automation
    "chocolatey",
    "nuget"
]);
let SuspiciousPatterns = dynamic([
    // Download cradles
    "downloadstring",
    "downloadfile",
    "downloaddata",
    "invoke-webrequest",
    "iwr ",
    "wget ",
    "curl ",
    "start-bitstransfer",
    "net.webclient",
    "net.sockets",
    // Execution & injection
    "invoke-expression",
    "iex(",
    "iex ",
    "invoke-command",
    "start-process",
    "invoke-mimikatz",
    "invoke-shellcode",
    "[system.reflection.assembly]::load",
    "add-type",
    "compileassemblyfroms",
    // Credential access
    "get-credential",
    "convertto-securestring",
    "networkCredential",
    "mimikatz",
    "lsass",
    "sam database",
    "securestringtotext",
    // Persistence
    "new-scheduledtask",
    "register-scheduledtask",
    "new-service",
    "set-itemproperty",
    "wmi ",
    "win32_",
    // Reconnaissance / enumeration
    "get-aduser",
    "get-adgroup",
    "get-adcomputer",
    "get-domaincontroller",
    "[adsisearcher]",
    "directoryservices",
    // Obfuscation / evasion
    "frombase64string",
    "tobase64string",
    "gzipstream",
    "deflatestream",
    "memorystream",
    "io.compression",
    "securestringtobstr",
    "-bxor",
    "char]0x",
    // Lateral movement
    "enter-pssession",
    "new-pssession",
    "invoke-wmimethod",
    "invoke-cimmethod"
]);
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("powershell.exe", "pwsh.exe")
    or InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-encodedcommand", "FromBase64String")
// Extract the Base64 payload
| extend Base64Payload = extract(
    @"(?i)-[eE][nN][cC][oO]?[dD]?[eE]?[dD]?[cC]?[oO]?[mM]?[mM]?[aA]?[nN]?[dD]?\s+([A-Za-z0-9+/=]{20,})",
    1,
    ProcessCommandLine
)
| where isnotempty(Base64Payload)
// Decode Base64 to readable text
| extend DecodedCommand = base64_decode_tostring(Base64Payload)
| where isnotempty(DecodedCommand)
// Filter out known false positive sources
| where not(ProcessCommandLine has_any (FPPatterns))
| where not(DecodedCommand has_any (FPPatterns))
| where not(InitiatingProcessFileName in~ (
    "ccmexec.exe",
    "svchost.exe",
    "intuneMDMAgent.exe",
    "microsoftEdgeUpdate.exe"
))
// Score for suspicious content
| mv-apply Pattern = SuspiciousPatterns to typeof(string) on (
    summarize SuspiciousScore = countif(DecodedCommand has Pattern)
)
| where SuspiciousScore > 0
| project
    Timestamp,
    DeviceName,
    AccountName = InitiatingProcessAccountName,
    SuspiciousScore,
    DecodedCommand,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    ReportId
| sort by SuspiciousScore desc, Timestamp desc
```
