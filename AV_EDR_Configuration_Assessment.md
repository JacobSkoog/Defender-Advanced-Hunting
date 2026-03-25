# AV / EDR Configuration Assessment

## Overview

Provides a consolidated single-row-per-device view of Microsoft Defender Antivirus and EDR configuration state. Use it to quickly identify devices with weakened security posture across your fleet — AV in passive mode, disabled real-time protection, outdated signatures, missing tamper protection, and more.

The query pivots all relevant TVM security configuration assessments into a flat table, then enriches it with the parsed AV mode (Active/Passive/EDR Block) and signature version details extracted from the Context field.

## Known Caveats

- The `IsCompliant` field for `scid-2012` (Real-time Protection) is known to occasionally report non-compliant even when the feature is enabled. Treat the `RealtimeProtection` column as an indicator to investigate rather than a definitive status — validate with `Get-MpComputerStatus` on the device when results look unexpected.
- The TVM assessment table refreshes periodically (not real-time), so there can be a lag of several hours between a configuration change and it appearing in results.

## Use Cases

- Validating Defender for Endpoint deployment health across a device fleet.
- Identifying devices where AV is in passive mode or EDR block mode.
- Detecting devices with stale signature versions or disabled security controls.
- Verifying tamper protection and cloud protection status after policy changes.
- Scoping to specific devices during incident response.

## Data Sources

- `DeviceTvmSecureConfigurationAssessment` (Defender Vulnerability Management)

## Configuration IDs Reference

| SCID | Setting | Description |
|------|---------|-------------|
| scid-2000 | SensorEnabled | MDE sensor is running |
| scid-2001 | SensorDataCollection | Sensor data collection is working |
| scid-2002 | ImpairedCommunications | Sensor communication is not impaired |
| scid-2003 | TamperProtection | Tamper protection is enabled |
| scid-2010 | AntivirusEnabled | Defender AV is enabled (Context: mode) |
| scid-2011 | AntivirusSignatureVersion | AV signatures are up to date (Context: versions) |
| scid-2012 | RealtimeProtection | Real-time protection is on (see caveats) |
| scid-2013 | PUAProtection | Potentially unwanted app blocking |
| scid-2014 | AntivirusReporting | AV reporting / MAPS is enabled |
| scid-2016 | CloudProtection | Cloud-delivered protection is enabled |
| scid-91 | BehaviorMonitoring | Behavior monitoring is enabled |

## AV Mode Values (scid-2010 Context)

| Value | Mode | Meaning |
|-------|------|---------|
| 0 | Active | Defender AV is the primary AV engine |
| 1 | Passive | Another AV is primary, Defender runs alongside |
| 4 | EDR Block Mode | AV is disabled but EDR can block malicious artifacts |

## Customization

- **Device scoping:** Add a `| where DeviceName in~ ("server01", "workstation02")` filter after the `bag_unpack` to scope to specific devices.
- **macOS / Linux:** This query covers Windows SCIDs. For cross-platform coverage, add the platform-specific SCIDs (`scid-5090`–`scid-5095` for macOS, `scid-6090`–`scid-6095` for Linux) with corresponding entries in the `Test` case statement.

## Query

```kql
// ============================================================================
// AV / EDR Configuration Assessment
// Consolidated single-row-per-device view of Defender AV and EDR settings.
// Pivots TVM security configuration assessments into a flat table, then
// enriches with parsed AV mode and signature version details.
//
// Data source: DeviceTvmSecureConfigurationAssessment (Defender TVM)
//
// NOTE: scid-2012 (RealtimeProtection) IsCompliant can report false negatives.
// Cross-reference with Get-MpComputerStatus on the device if needed.
// ============================================================================
// --- Step 1: Get AV mode from scid-2010 Context ---
let AVModeTable = DeviceTvmSecureConfigurationAssessment
    | where ConfigurationId == "scid-2010" and isnotnull(Context)
    | extend avdata = parse_json(Context)
    | extend AVMode = case(
        tostring(avdata[0][0]) == "0", "Active",
        tostring(avdata[0][0]) == "1", "Passive",
        tostring(avdata[0][0]) == "4", "EDR Block Mode",
        "Unknown"
    )
    | project DeviceId, AVMode;
// --- Step 2: Get AV signature and engine versions from scid-2011 Context ---
let AVVersionTable = DeviceTvmSecureConfigurationAssessment
    | where ConfigurationId == "scid-2011" and isnotnull(Context)
    | extend avdata = parse_json(Context)
    | extend
        AVSigVersion = tostring(avdata[0][0]),
        AVEngineVersion = tostring(avdata[0][1]),
        AVSigLastUpdateTime = tostring(avdata[0][2]),
        AVProductVersion = tostring(avdata[0][3])
    | project DeviceId, AVSigVersion, AVEngineVersion, AVSigLastUpdateTime, AVProductVersion;
// --- Step 3: Pivot all security controls into one row per device ---
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in (
    "scid-91", "scid-2000", "scid-2001", "scid-2002", "scid-2003",
    "scid-2010", "scid-2011", "scid-2012", "scid-2013", "scid-2014", "scid-2016"
)
| extend Test = case(
    ConfigurationId == "scid-2000", "SensorEnabled",
    ConfigurationId == "scid-2001", "SensorDataCollection",
    ConfigurationId == "scid-2002", "ImpairedCommunications",
    ConfigurationId == "scid-2003", "TamperProtection",
    ConfigurationId == "scid-2010", "AntivirusEnabled",
    ConfigurationId == "scid-2011", "AntivirusSignatureVersion",
    ConfigurationId == "scid-2012", "RealtimeProtection",
    ConfigurationId == "scid-91", "BehaviorMonitoring",
    ConfigurationId == "scid-2013", "PUAProtection",
    ConfigurationId == "scid-2014", "AntivirusReporting",
    ConfigurationId == "scid-2016", "CloudProtection",
    "N/A"
),
Result = case(
    IsApplicable == 0, "N/A",
    IsCompliant == 1, "GOOD",
    "BAD"
)
| extend packed = pack(Test, Result)
| summarize Tests = make_bag(packed), DeviceName = any(DeviceName), OSPlatform = any(OSPlatform) by DeviceId
| evaluate bag_unpack(Tests)
// --- Step 4: Enrich with AV mode and version details ---
| join kind=leftouter AVModeTable on DeviceId
| join kind=leftouter AVVersionTable on DeviceId
| project-away DeviceId1, DeviceId2
| project
    DeviceName,
    OSPlatform,
    AVMode,
    SensorEnabled,
    SensorDataCollection,
    ImpairedCommunications,
    TamperProtection,
    AntivirusEnabled,
    RealtimeProtection,
    CloudProtection,
    BehaviorMonitoring,
    PUAProtection,
    AntivirusReporting,
    AntivirusSignatureVersion,
    AVSigVersion,
    AVEngineVersion,
    AVProductVersion,
    AVSigLastUpdateTime
| sort by AVMode asc, AntivirusEnabled asc
```
