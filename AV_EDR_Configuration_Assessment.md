# AV / EDR Configuration Assessment

## Overview

Provides a consolidated single-row-per-device view of Microsoft Defender Antivirus and EDR configuration state across Windows, macOS and Linux. Mobile platforms are excluded. Use it to quickly identify devices with weakened security posture across your fleet, such as AV in passive mode, disabled real-time protection, outdated signatures, missing tamper protection, and more.

The query normalises the platform-specific TVM configuration IDs into a common set of column names, pivots them into a flat table, then enriches with the parsed AV mode and signature version details extracted from the Context field.

## Known Caveats

- The `IsCompliant` field for `scid-2012` (Real-time Protection) is known to occasionally report non-compliant even when the feature is enabled. Treat the `RealtimeProtection` column as an indicator to investigate rather than a definitive status. Validate with `Get-MpComputerStatus` on the device when results look unexpected. The same applies to the macOS and Linux equivalents (`scid-5090` / `scid-6090`), which can be validated with `mdatp health`.
- The TVM assessment table refreshes periodically (not real-time), so there can be a lag of several hours between a configuration change and it appearing in results.
- Not every control exists on every platform. Linux has no tamper protection assessment, and AV mode, behavior monitoring and AV reporting are Windows-only. Those cells report `N/A` rather than `BAD` so they do not skew a posture review.
- The `Context` payload for the macOS and Linux signature assessments (`scid-5095` / `scid-6095`) is not documented and does not carry the same four fields as the Windows equivalent. The query does a best-effort positional parse: `AVSigVersion` is reliable, `AVSigLastUpdateTime` is taken from the second element and should be spot checked against `mdatp health --field definitions_updated` before being trusted in a report. `AVEngineVersion` and `AVProductVersion` are left blank on non-Windows devices.

## Use Cases

- Validating Defender for Endpoint deployment health across a mixed-OS device fleet.
- Identifying devices where AV is in passive mode or EDR block mode.
- Detecting devices with stale signature versions or disabled security controls.
- Verifying tamper protection and cloud protection status after policy changes.
- Scoping to specific devices during incident response.

## Data Sources

- `DeviceTvmSecureConfigurationAssessment` (Defender Vulnerability Management)

## Configuration IDs Reference

| Setting                   | Windows   | macOS     | Linux     | Description                                      |
| ------------------------- | --------- | --------- | --------- | ------------------------------------------------ |
| SensorEnabled             | scid-2000 | -         | -         | MDE sensor is running                            |
| SensorDataCollection      | scid-2001 | scid-5001 | scid-6001 | Sensor data collection is working                |
| ImpairedCommunications    | scid-2002 | scid-5002 | scid-6002 | Sensor communication is not impaired             |
| TamperProtection          | scid-2003 | scid-5092 | -         | Tamper protection is enabled                     |
| AntivirusEnabled          | scid-2010 | -         | -         | Defender AV is enabled (Context: mode)           |
| AntivirusSignatureVersion | scid-2011 | scid-5095 | scid-6095 | AV signatures are up to date (Context: versions) |
| RealtimeProtection        | scid-2012 | scid-5090 | scid-6090 | Real-time protection is on (see caveats)         |
| PUAProtection             | scid-2013 | scid-5091 | scid-6091 | Potentially unwanted app blocking                |
| AntivirusReporting        | scid-2014 | -         | -         | AV reporting / MAPS is enabled                   |
| CloudProtection           | scid-2016 | scid-5094 | scid-6094 | Cloud-delivered protection is enabled            |
| BehaviorMonitoring        | scid-91   | -         | -         | Behavior monitoring is enabled                   |

## AV Mode Values (scid-2010 Context)

| Value | Mode           | Meaning                                              |
| ----- | -------------- | ---------------------------------------------------- |
| 0     | Active         | Defender AV is the primary AV engine                 |
| 1     | Passive        | Another AV is primary, Defender runs alongside       |
| 4     | EDR Block Mode | AV is disabled but EDR can block malicious artifacts |

`AVMode` is Windows-only and reports `N/A` for macOS and Linux devices. On those platforms, use `AntivirusEnabled` together with `RealtimeProtection` to judge whether Defender AV is actually doing the work.

## Design Notes

- Platform SCIDs are mapped to a shared `Test` name, so a device only ever contributes one value per control and the output keeps one column per setting regardless of OS.
- The pivot drops any assessment whose SCID does not belong to the device's own platform. MDE returns the Windows AV SCIDs against macOS and Linux devices with `IsApplicable == 0`, and because several SCIDs normalise to the same key, leaving them in means `make_bag` can keep the non-applicable Windows result instead of the real one. The filter relies on the numbering convention: `scid-5xxx` is macOS, `scid-6xxx` is Linux, everything else is Windows. If Microsoft ever breaks that convention, this is the line to revisit.
- Both enrichment tables are collapsed to one row per `DeviceId` before the join. `join kind=leftouter` multiplies the left row by every matching right row, so a device with two entries in a lookup table produces two output rows. Pinning each signature SCID to its own platform prevents the common case, and the `summarize` covers repeated snapshots in tenants where the table holds more than the current state.
- The platform filter is an allowlist rather than `!in~ ("Android", "iOS")`. An exclusion list silently admits any platform Microsoft adds later, which would then show up as a row of `N/A` values. Note that it runs before the pivot, so filtered devices never reach the `summarize`.
- `bag_merge` seeds every device with a default bag of `N/A` values before `bag_unpack`. Without it the final `project` breaks in tenants that have no devices of a given platform, because the column for a platform-specific control would never be created.

## Customization

- **Device scoping:** Add a `| where DeviceName in~ ("server01", "workstation02")` filter after the `bag_unpack` to scope to specific devices.
- **Single platform:** Add `| where OSPlatform has "Linux"` after the `bag_unpack` rather than filtering on ConfigurationId, so the normalised column set stays intact.
- **Non-compliant only:** Append `| where RealtimeProtection == "BAD" or CloudProtection == "BAD" or TamperProtection == "BAD"` to cut the result down to devices worth chasing.

## Query

```
// ============================================================================
// AV / EDR Configuration Assessment (Windows / macOS / Linux)
// Consolidated single-row-per-device view of Defender AV and EDR settings.
// Normalises the platform-specific TVM configuration IDs into a common set of
// columns, pivots them into a flat table, then enriches with parsed AV mode
// and signature version details.
//
// Data source: DeviceTvmSecureConfigurationAssessment (Defender TVM)
//
// NOTE: scid-2012 / 5090 / 6090 (RealtimeProtection) IsCompliant can report
// false negatives. Cross-reference with Get-MpComputerStatus (Windows) or
// mdatp health (macOS / Linux) on the device if needed.
//
// NOTE: the Context payload for scid-5095 / scid-6095 is undocumented and is
// parsed positionally on a best-effort basis. See Known Caveats.
// ============================================================================
// --- Step 0: Default result bag so every control gets a column ---
let DefaultTests = dynamic({
    "SensorEnabled": "N/A",
    "SensorDataCollection": "N/A",
    "ImpairedCommunications": "N/A",
    "TamperProtection": "N/A",
    "AntivirusEnabled": "N/A",
    "AntivirusSignatureVersion": "N/A",
    "RealtimeProtection": "N/A",
    "BehaviorMonitoring": "N/A",
    "PUAProtection": "N/A",
    "AntivirusReporting": "N/A",
    "CloudProtection": "N/A"
});
// --- Step 1: Get AV mode from scid-2010 Context (Windows only) ---
// Pinned to Windows and collapsed to one row per device so the leftouter
// join below cannot fan out.
let AVModeTable = DeviceTvmSecureConfigurationAssessment
    | where ConfigurationId == "scid-2010"
        and OSPlatform startswith "Windows"
        and isnotnull(Context)
    | extend avdata = parse_json(Context)
    | extend AVMode = case(
        tostring(avdata[0][0]) == "0", "Active",
        tostring(avdata[0][0]) == "1", "Passive",
        tostring(avdata[0][0]) == "4", "EDR Block Mode",
        "Unknown"
    )
    | summarize AVMode = take_any(AVMode) by DeviceId;
// --- Step 2: Get AV signature and engine versions from the signature SCIDs ---
// Each SCID is pinned to its own platform, so a device can only match one of
// them, then the result is collapsed to one row per device.
let AVVersionTable = DeviceTvmSecureConfigurationAssessment
    | where isnotnull(Context)
    | where (OSPlatform startswith "Windows" and ConfigurationId == "scid-2011")
        or (OSPlatform has "macOS" and ConfigurationId == "scid-5095")
        or (OSPlatform has "Linux" and ConfigurationId == "scid-6095")
    | extend avdata = parse_json(Context)
    | extend IsWindows = ConfigurationId == "scid-2011"
    | extend
        AVSigVersion = tostring(avdata[0][0]),
        AVEngineVersion = iff(IsWindows, tostring(avdata[0][1]), ""),
        AVSigLastUpdateTime = iff(IsWindows, tostring(avdata[0][2]), tostring(avdata[0][1])),
        AVProductVersion = iff(IsWindows, tostring(avdata[0][3]), "")
    | summarize
        AVSigVersion = take_any(AVSigVersion),
        AVEngineVersion = take_any(AVEngineVersion),
        AVSigLastUpdateTime = take_any(AVSigLastUpdateTime),
        AVProductVersion = take_any(AVProductVersion)
        by DeviceId;
// --- Step 3: Pivot all security controls into one row per device ---
DeviceTvmSecureConfigurationAssessment
// Allowlist the desktop and server platforms. Android and iOS are onboarded
// to MDE but have no AV configuration assessments, so they would otherwise
// surface as all-N/A rows.
| where OSPlatform startswith "Windows"
    or OSPlatform has "macOS"
    or OSPlatform has "Linux"
| where ConfigurationId in (
    "scid-91",
    "scid-2000", "scid-2001", "scid-2002", "scid-2003",
    "scid-2010", "scid-2011", "scid-2012", "scid-2013", "scid-2014", "scid-2016",
    "scid-5001", "scid-5002", "scid-5090", "scid-5091", "scid-5092",
    "scid-5094", "scid-5095",
    "scid-6001", "scid-6002", "scid-6090", "scid-6091", "scid-6094", "scid-6095"
)
| extend Test = case(
    ConfigurationId == "scid-2000", "SensorEnabled",
    ConfigurationId in ("scid-2001", "scid-5001", "scid-6001"), "SensorDataCollection",
    ConfigurationId in ("scid-2002", "scid-5002", "scid-6002"), "ImpairedCommunications",
    ConfigurationId in ("scid-2003", "scid-5092"), "TamperProtection",
    ConfigurationId == "scid-2010", "AntivirusEnabled",
    ConfigurationId in ("scid-2011", "scid-5095", "scid-6095"), "AntivirusSignatureVersion",
    ConfigurationId in ("scid-2012", "scid-5090", "scid-6090"), "RealtimeProtection",
    ConfigurationId == "scid-91", "BehaviorMonitoring",
    ConfigurationId in ("scid-2013", "scid-5091", "scid-6091"), "PUAProtection",
    ConfigurationId == "scid-2014", "AntivirusReporting",
    ConfigurationId in ("scid-2016", "scid-5094", "scid-6094"), "CloudProtection",
    "N/A"
),
Result = case(
    IsApplicable == 0, "N/A",
    IsCompliant == 1, "GOOD",
    "BAD"
)
| where Test != "N/A"
// Drop cross-platform noise. MDE reports Windows AV SCIDs against macOS and
// Linux devices as non-applicable, and those rows would otherwise compete for
// the same normalised key in the bag below.
| extend DevicePlatform = case(
    OSPlatform startswith "Windows", "Win",
    OSPlatform has "macOS", "Mac",
    "Lin"
),
ScidPlatform = case(
    ConfigurationId startswith "scid-5", "Mac",
    ConfigurationId startswith "scid-6", "Lin",
    "Win"
)
| where DevicePlatform == ScidPlatform
| extend packed = pack(Test, Result)
| summarize Tests = make_bag(packed), DeviceName = any(DeviceName), OSPlatform = any(OSPlatform) by DeviceId
| extend Tests = bag_merge(Tests, DefaultTests)
| evaluate bag_unpack(Tests)
// --- Step 4: Enrich with AV mode and version details ---
| join kind=leftouter AVModeTable on DeviceId
| join kind=leftouter AVVersionTable on DeviceId
| project-away DeviceId1, DeviceId2
| extend AVMode = iff(isempty(AVMode), "N/A", AVMode)
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
| sort by OSPlatform asc, AVMode asc, AntivirusEnabled asc
```
