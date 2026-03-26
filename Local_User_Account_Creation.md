# Local User Account Creation Detection

## Overview

Detects the creation of local user accounts on endpoints. While local account creation is sometimes legitimate (e.g., during software installation or by IT administrators), it is also a common persistence technique used by attackers after gaining initial access. A newly created local account can provide a backdoor that survives password resets of domain accounts and may go unnoticed if the environment relies primarily on centralized identity monitoring.

This is particularly suspicious on servers and workstations that are domain-joined, where local accounts are rarely created during normal operations. The query enriches results with the initiating process context, making it easy to distinguish between an admin running `net user` and malware spawning accounts programmatically.

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Persistence |
| **Technique** | T1136.001 - Create Account: Local Account |

## Data Source

- `DeviceEvents` (Defender for Endpoint)

## Detection Logic

1. **Filter** `DeviceEvents` for `ActionType == "UserAccountCreated"` which fires when a new local user is created on the endpoint.
2. **Optionally scope** to specific devices or exclude known service accounts using the configurable filter variables.
3. **Enrich** with initiating process details — the process, command line, and parent process that triggered the account creation reveal whether this was a manual admin action, a deployment script, or something suspicious.
4. **Flag** high-interest indicators such as creation by unexpected processes, accounts created outside business hours, or creation on servers where local accounts should not be provisioned.

## Customization

- **`ExcludedAccounts`** — Add known service accounts or accounts created by legitimate software installers to reduce noise.
- **`ExcludedProcesses`** — Add processes that legitimately create local accounts in your environment (e.g., deployment agents, provisioning tools).
- **`ExcludedDomains`** — Add account domains to filter out. Useful for excluding domain-managed account creation events and focusing strictly on local accounts, or for filtering out a specific domain in multi-domain environments.
- **Device scoping** — Uncomment and populate `TargetDevices` to focus on specific machines during investigations.
- **Business hours** — Adjust the `BusinessHoursStart` / `BusinessHoursEnd` and timezone to match your environment. Activity outside these hours is flagged.

## Query

```kql
// ============================================================================
// Local User Account Creation Detection
// Detects creation of local user accounts on endpoints. Enriches with
// process context and flags suspicious characteristics such as creation
// outside business hours or by unexpected processes.
//
// Data source: DeviceEvents (Defender for Endpoint)
//
// MITRE ATT&CK: T1136.001 - Create Account: Local Account
// ============================================================================
// Optional: scope to specific devices
// let TargetDevices = dynamic(["SERVER-01", "WORKSTATION-42"]);
// Accounts created by known legitimate processes or installers
let ExcludedAccounts = dynamic([
    // "svc_backup", "sqlservice"
]);
let ExcludedProcesses = dynamic([
    // "ccmexec.exe", "intuneMDMAgent.exe"
]);
// Domains to exclude (e.g., filter out domain-managed accounts to focus on local)
let ExcludedDomains = dynamic([
    // "CONTOSO", "AzureAD"
]);
// Business hours definition (used for flagging, not filtering)
let BusinessHoursStart = 7;
let BusinessHoursEnd = 18;
let Timezone = "Europe/Stockholm";
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "UserAccountCreated"
// Optional: scope to specific devices
// | where DeviceName in~ (TargetDevices)
// Filter out known legitimate accounts
| where not(AccountName has_any (ExcludedAccounts))
| where not(InitiatingProcessFileName has_any (ExcludedProcesses))
| where not(AccountDomain has_any (ExcludedDomains))
// Enrich with time-of-day context
| extend LocalTime = datetime_utc_to_local(Timestamp, Timezone)
| extend HourOfDay = hourofday(LocalTime)
| extend OutsideBusinessHours = HourOfDay < BusinessHoursStart or HourOfDay >= BusinessHoursEnd
| extend DayOfWeek = dayofweek(LocalTime) / 1d
| extend IsWeekend = DayOfWeek >= 5 // Saturday = 5, Sunday = 6
// Flag suspicious characteristics
| extend SuspiciousIndicators = array_concat(
    iff(OutsideBusinessHours, dynamic(["OutsideBusinessHours"]), dynamic([])),
    iff(IsWeekend, dynamic(["Weekend"]), dynamic([])),
    iff(InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"),
        dynamic(["ScriptingEngine"]), dynamic([])),
    iff(InitiatingProcessFileName in~ ("svchost.exe", "wmiprvse.exe"),
        dynamic(["SystemProcess"]), dynamic([]))
)
| project
    Timestamp,
    DeviceName,
    CreatedAccount = AccountName,
    CreatedAccountDomain = AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    InitiatingProcessParentFileName,
    OutsideBusinessHours,
    IsWeekend,
    SuspiciousIndicators,
    ReportId
| sort by Timestamp desc
```
