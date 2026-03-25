# AV / EDR Configuration Assessment

## Overview

Provides a consolidated view of the current Microsoft Defender Antivirus and EDR configuration state across one or more devices. This is a configuration hunting query rather than a threat detection — use it to identify devices with weakened security posture such as AV in passive mode, disabled real-time protection, outdated signatures, or missing tamper protection.

In environments transitioning from third-party AV solutions, Defender AV may silently enter passive mode. Similarly, misconfigurations or policy conflicts through Intune or GPO can leave tamper protection, cloud protection, or PUA protection disabled without generating alerts. This query surfaces all of that in a single view.

## Use Cases

- Validating Defender for Endpoint deployment health across a device fleet.
- Identifying devices where AV is in passive mode or EDR block mode due to third-party AV presence.
- Detecting devices with stale signature versions or disabled real-time protection.
- Verifying tamper protection status after policy changes.
- Scoping configuration state to specific devices or device groups during incident response.

## Data Sources

- `DeviceTvmSecureConfigurationAssessment` (Defender Vulnerability Management)
- `DeviceTvmSecureConfigurationAssessmentKB` (configuration metadata)

## Configuration IDs Reference

| SCID | Setting | Platform | Context Data |
|------|---------|----------|-------------|
| scid-2010 | AV Mode (Active/Passive/EDR Block) | Windows | `0`=Active, `1`=Passive, `4`=EDR Block |
| scid-2011 | AV Signature & Engine Version | Windows | SigVersion, EngineVersion, SigUpdateTime, ProductVersion |
| scid-2012 | Real-time Protection | Windows | — |
| scid-2013 | PUA Protection | Windows | — |
| scid-2003 | Tamper Protection | Windows | — |
| scid-2016 | Cloud-delivered Protection | Windows | — |
| scid-91 | Behavior Monitoring | Windows | — |
| scid-90 | Email Scanning | Windows | — |
| scid-5090 | Real-time Protection | macOS | — |
| scid-5091 | Behavior Monitoring | macOS | — |
| scid-5094 | PUA Protection | macOS | — |
| scid-5095 | AV Signature Version | macOS | — |
| scid-6090 | Real-time Protection | Linux | — |
| scid-6091 | Behavior Monitoring | Linux | — |
| scid-6094 | PUA Protection | Linux | — |
| scid-6095 | AV Signature Version | Linux | — |

## Customization

- **Device scoping:** Uncomment and modify the `TargetDevices` filter to scope the query to specific devices or use wildcards for device groups.
- **Platform focus:** The query covers Windows, macOS, and Linux. Remove platform-specific SCIDs if you only need one OS.
- **Signature age threshold:** Adjust the `SigAgeWarningDays` value to match your organization's patching SLA.

## Query

```kql
// ============================================================================
// AV / EDR Configuration Assessment
// Consolidated view of Microsoft Defender AV and EDR configuration state
// across devices. Covers AV mode, signature versions, real-time protection,
// tamper protection, cloud protection, PUA protection, and behavior monitoring
// for Windows, macOS, and Linux.
//
// Data source: DeviceTvmSecureConfigurationAssessment (Defender TVM)
//
// Usage: Uncomment the TargetDevices filter to scope to specific devices.
// ============================================================================
let SigAgeWarningDays = 7;
// Optional: scope to specific devices
// let TargetDevices = dynamic(["workstation01", "server-prod-01"]);
// --- Step 1: Get AV mode (Active / Passive / EDR Block / Disabled) ---
let AVMode = DeviceTvmSecureConfigurationAssessment
    | where ConfigurationId == "scid-2010"
    | where isnotempty(Context)
    | extend avdata = parse_json(Context)
    | extend AVMode = case(
        tostring(avdata[0][0]) == "0", "Active",
        tostring(avdata[0][0]) == "1", "Passive",
        tostring(avdata[0][0]) == "4", "EDR Block Mode",
        "Unknown"
    )
    | project DeviceId, DeviceName, OSPlatform, AVMode, IsCompliant;
// --- Step 2: Get AV signature and engine versions ---
let AVVersions = DeviceTvmSecureConfigurationAssessment
    | where ConfigurationId in ("scid-2011", "scid-5095", "scid-6095")
    | where isnotempty(Context)
    | extend avdata = parse_json(Context)
    | extend
        AVSigVersion = tostring(avdata[0][0]),
        AVEngineVersion = tostring(avdata[0][1]),
        AVSigLastUpdateTime = todatetime(avdata[0][2]),
        AVProductVersion = tostring(avdata[0][3])
    | extend SigAgeDays = datetime_diff("day", now(), AVSigLastUpdateTime)
    | extend SigStatus = case(
        SigAgeDays <= 1, "Current",
        SigAgeDays <= SigAgeWarningDays, "Acceptable",
        SigAgeDays <= 14, "Warning",
        "Critical"
    )
    | project DeviceId, AVSigVersion, AVEngineVersion, AVProductVersion,
        AVSigLastUpdateTime, SigAgeDays, SigStatus;
// --- Step 3: Get all security control compliance states ---
let SecurityControls = DeviceTvmSecureConfigurationAssessment
    | where ConfigurationId in (
        "scid-2012", "scid-5090", "scid-6090",  // Real-time protection
        "scid-2003",                              // Tamper protection
        "scid-2016",                              // Cloud-delivered protection
        "scid-2013", "scid-5094", "scid-6094",  // PUA protection
        "scid-91",   "scid-5091", "scid-6091",  // Behavior monitoring
        "scid-90"                                 // Email scanning (Windows)
    )
    | extend Setting = case(
        ConfigurationId in ("scid-2012", "scid-5090", "scid-6090"), "RealTimeProtection",
        ConfigurationId == "scid-2003", "TamperProtection",
        ConfigurationId == "scid-2016", "CloudProtection",
        ConfigurationId in ("scid-2013", "scid-5094", "scid-6094"), "PUAProtection",
        ConfigurationId in ("scid-91", "scid-5091", "scid-6091"), "BehaviorMonitoring",
        ConfigurationId == "scid-90", "EmailScanning",
        "Other"
    )
    | extend Status = iff(IsCompliant == 1, "Enabled", "Disabled")
    | summarize Settings = make_bag(bag_pack(Setting, Status)) by DeviceId;
// --- Step 4: Join everything together ---
AVMode
// Optional: uncomment to scope to specific devices
// | where DeviceName has_any (TargetDevices)
| join kind=leftouter AVVersions on DeviceId
| join kind=leftouter SecurityControls on DeviceId
| extend
    RealTimeProtection  = tostring(Settings["RealTimeProtection"]),
    TamperProtection    = tostring(Settings["TamperProtection"]),
    CloudProtection     = tostring(Settings["CloudProtection"]),
    PUAProtection       = tostring(Settings["PUAProtection"]),
    BehaviorMonitoring  = tostring(Settings["BehaviorMonitoring"]),
    EmailScanning       = tostring(Settings["EmailScanning"])
// Calculate an overall health score
| extend DisabledCount =
    iff(RealTimeProtection == "Disabled", 1, 0) +
    iff(TamperProtection == "Disabled", 1, 0) +
    iff(CloudProtection == "Disabled", 1, 0) +
    iff(PUAProtection == "Disabled", 1, 0) +
    iff(BehaviorMonitoring == "Disabled", 1, 0)
| extend HealthStatus = case(
    AVMode in ("Passive", "Unknown") or RealTimeProtection == "Disabled", "Critical",
    DisabledCount >= 2 or SigStatus == "Critical", "Warning",
    DisabledCount >= 1 or SigStatus == "Warning", "Review",
    "Healthy"
)
| project
    DeviceName,
    OSPlatform,
    HealthStatus,
    AVMode,
    RealTimeProtection,
    TamperProtection,
    CloudProtection,
    PUAProtection,
    BehaviorMonitoring,
    EmailScanning,
    AVSigVersion,
    AVEngineVersion,
    AVProductVersion,
    AVSigLastUpdateTime,
    SigAgeDays,
    SigStatus,
    DisabledCount
| sort by HealthStatus asc, DisabledCount desc, SigAgeDays desc
```
