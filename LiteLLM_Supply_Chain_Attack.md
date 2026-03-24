# LiteLLM Supply Chain Attack Detection (CVE Pending)

## Overview

On March 24, 2026, versions 1.82.7 and 1.82.8 of the popular Python package [LiteLLM](https://github.com/BerriAI/litellm) were published to PyPI containing a malicious `.pth` file (`litellm_init.pth`). The release was uploaded directly to PyPI — no corresponding tag or release exists in the legitimate GitHub repository.

The `.pth` file executes automatically on every Python interpreter startup when the package is installed — **no `import` statement is required**. The payload is a multi-stage credential stealer and lateral movement tool attributed to the **TeamPCP** threat actor, reusing the same encryption scheme and exfiltration patterns seen in the earlier Trivy/KICS supply chain attacks.

### Attack stages

1. **Collection** — Harvests SSH keys, `.env` files, AWS/GCP/Azure credentials, Kubernetes configs, database passwords, `.gitconfig`, shell history, crypto wallets, environment variables, and cloud metadata (IMDS).
2. **Exfiltration** — Data is encrypted with a hardcoded 4096-bit RSA public key using AES-256-CBC, bundled into a tar archive, and POSTed to `https://models.litellm[.]cloud/` (attacker-controlled, not part of legitimate LiteLLM infrastructure).
3. **Persistence & lateral movement** — Installs a backdoor at `~/.config/sysmon/sysmon.py` with a systemd user service (`sysmon.service`). In Kubernetes environments, reads cluster secrets and deploys privileged `alpine:latest` pods on every node in `kube-system` (pod names matching `node-setup-*`).

### References

- [FutureSearch disclosure](https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/)
- [GitHub Issue #24512](https://github.com/BerriAI/litellm/issues/24512)

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Execution, Credential Access, Persistence, Lateral Movement |
| **Techniques** | T1059.006 - Command and Scripting Interpreter: Python |
| | T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain |
| | T1555 - Credentials from Password Stores |
| | T1552.001 - Unsecured Credentials: Credentials in Files |
| | T1053 - Scheduled Task/Job (systemd persistence) |

## Data Sources

- `DeviceFileEvents` (Defender for Endpoint)
- `DeviceProcessEvents` (Defender for Endpoint)
- `DeviceNetworkEvents` (Defender for Endpoint)

## Indicators of Compromise

| Type | Value |
|------|-------|
| **File** | `litellm_init.pth` |
| **File (SHA256)** | `ceNa7wMJnNHy1kRnNCcwJaFjWX3pORLfMh7xGL8TUjg` (base64 from RECORD) |
| **Persistence path** | `~/.config/sysmon/sysmon.py` |
| **Persistence service** | `~/.config/systemd/user/sysmon.service` |
| **C2 domain** | `models.litellm[.]cloud` |
| **Package versions** | `litellm 1.82.7`, `litellm 1.82.8` |
| **K8s pod pattern** | `node-setup-*` in `kube-system` namespace |

## Query 1 — File and Process Indicators

Detects the presence of the malicious `.pth` file, the persistence backdoor, or `pip install` of the compromised versions.

```kql
// ============================================================================
// LiteLLM Supply Chain Attack — File and Process Indicators
// Detects the malicious .pth file, persistence artifacts, and installation
// of compromised package versions.
//
// Data source: DeviceFileEvents, DeviceProcessEvents (Defender for Endpoint)
//
// MITRE ATT&CK:
//   T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain
//   T1059.006 - Command and Scripting Interpreter: Python
// ============================================================================
let MaliciousFileNames = dynamic([
    "litellm_init.pth",
    "sysmon.py",
    "sysmon.service"
]);
let MaliciousPaths = dynamic([
    ".config/sysmon/",
    ".config/systemd/user/sysmon"
]);
// Detect malicious files being created or modified
let FileIndicators = DeviceFileEvents
    | where ActionType in ("FileCreated", "FileModified")
    | where FileName in~ (MaliciousFileNames)
        or FolderPath has_any (MaliciousPaths)
        or (FileName endswith ".pth" and FolderPath has "litellm")
    | extend DetectionType = "MaliciousFile"
    | project
        Timestamp,
        DetectionType,
        DeviceName,
        FileName,
        FolderPath,
        SHA256,
        InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        InitiatingProcessAccountName,
        ReportId;
// Detect pip/uv installing the compromised versions
let InstallIndicators = DeviceProcessEvents
    | where ProcessCommandLine has "litellm"
    | where ProcessCommandLine has_any ("1.82.7", "1.82.8")
    | where ProcessCommandLine has_any ("pip", "uv ", "pip3", "pipx")
    | extend DetectionType = "CompromisedInstall"
    | project
        Timestamp,
        DetectionType,
        DeviceName,
        FileName,
        FolderPath = "",
        SHA256 = "",
        InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        InitiatingProcessAccountName = InitiatingProcessAccountName,
        ReportId;
union FileIndicators, InstallIndicators
| sort by Timestamp desc
```

## Query 2 — Network Indicators (C2 Communication)

Detects outbound connections to the attacker-controlled exfiltration domain.

```kql
// ============================================================================
// LiteLLM Supply Chain Attack — C2 Network Indicators
// Detects outbound connections to the attacker-controlled exfiltration endpoint.
//
// Data source: DeviceNetworkEvents (Defender for Endpoint)
//
// MITRE ATT&CK:
//   T1041 - Exfiltration Over C2 Channel
// ============================================================================
DeviceNetworkEvents
| where RemoteUrl has "models.litellm.cloud"
    or RemoteUrl has "litellm.cloud"
| project
    Timestamp,
    DeviceName,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    ReportId
| sort by Timestamp desc
```

## Query 3 — Behavioral Detection (Credential Harvesting Pattern)

Detects the behavioral pattern of a Python process accessing multiple credential files and cloud metadata endpoints in a short time window, regardless of specific IOCs. This provides coverage against variants that may use different file names or domains.

```kql
// ============================================================================
// LiteLLM Supply Chain Attack — Behavioral Credential Harvesting
// Detects Python processes exhibiting the credential harvesting pattern
// used by the TeamPCP infostealer: rapid access to multiple secret files
// and cloud metadata endpoints.
//
// Data source: DeviceFileEvents, DeviceNetworkEvents (Defender for Endpoint)
//
// MITRE ATT&CK:
//   T1552.001 - Unsecured Credentials: Credentials in Files
//   T1555    - Credentials from Password Stores
// ============================================================================
let CredentialPaths = dynamic([
    ".ssh/",
    ".aws/",
    ".azure/",
    ".config/gcloud/",
    ".kube/config",
    ".env",
    ".gitconfig",
    ".bash_history",
    ".zsh_history",
    "credentials.json",
    "application_default_credentials"
]);
// Find Python processes accessing multiple credential files
let SuspiciousFileAccess = DeviceFileEvents
    | where InitiatingProcessFileName in~ ("python", "python3", "python.exe", "python3.exe", "pythonw.exe")
    | where FolderPath has_any (CredentialPaths)
    | summarize
        CredentialFilesAccessed = dcount(FolderPath),
        FileList = make_set(FolderPath, 20),
        FirstSeen = min(Timestamp),
        LastSeen = max(Timestamp)
        by DeviceName, InitiatingProcessId, InitiatingProcessCommandLine
    // Threshold: accessing 3+ distinct credential locations is suspicious
    | where CredentialFilesAccessed >= 3
    | extend TimeSpan = LastSeen - FirstSeen
    // Rapid access pattern: all within 5 minutes
    | where TimeSpan <= 5m;
// Optionally correlate with cloud metadata access
let MetadataAccess = DeviceNetworkEvents
    | where InitiatingProcessFileName in~ ("python", "python3", "python.exe", "python3.exe")
    | where RemoteUrl has_any (
        "169.254.169.254",      // AWS/Azure IMDS
        "metadata.google",       // GCP metadata
        "100.100.100.200"        // Alibaba Cloud metadata
    )
    | project
        Timestamp,
        DeviceName,
        InitiatingProcessId,
        MetadataTarget = RemoteUrl;
SuspiciousFileAccess
| join kind=leftouter MetadataAccess
    on DeviceName, InitiatingProcessId
| project
    FirstSeen,
    LastSeen,
    DeviceName,
    CredentialFilesAccessed,
    MetadataTarget,
    FileList,
    InitiatingProcessCommandLine
| sort by CredentialFilesAccessed desc
```

## Response Actions

If any of the above queries return results:

1. **Isolate** affected devices immediately via MDE device isolation.
2. **Verify** installed LiteLLM version: `pip show litellm` on the device.
3. **Check persistence** — look for `~/.config/sysmon/sysmon.py` and the associated systemd service.
4. **In Kubernetes environments** — audit `kube-system` for pods matching `node-setup-*` and review cluster secrets for unauthorized access.
5. **Rotate all credentials** that were present on the affected machine: SSH keys, cloud provider tokens, Kubernetes configs, API keys, and database passwords.
6. **Purge package caches** (`pip cache purge`, `rm -rf ~/.cache/uv`) to prevent reinstallation from cached wheels.
