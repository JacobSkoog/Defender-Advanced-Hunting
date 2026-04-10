# DNS C2 Traffic Detection — Anomalous TXT Records and Subdomain Queries

## Overview

Detects command and control communication tunneled through DNS by identifying two key patterns: TXT record responses containing encoded or anomalous data (used for C2 response/download channels) and high volumes of queries with long subdomains to the same domain (used for data exfiltration/beaconing channels).

DNS tunneling C2 frameworks like `dnscat2`, `iodine`, `DNSTT`, `Cobalt Strike DNS`, and custom implementations use DNS as a bidirectional transport channel. The upstream channel (client → attacker) encodes data in subdomain labels, while the downstream channel (attacker → client) typically uses TXT records which allow up to ~255 bytes per response. This creates a distinctive traffic pattern that is detectable through MDE telemetry.

This query complements the [DNS Beaconing Base64 Subdomains](DNS_Beaconing_Base64_Subdomains.md) detection by focusing on TXT response content analysis and stricter volumetric thresholds.

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Command and Control, Exfiltration |
| **Techniques** | T1071.004 - Application Layer Protocol: DNS |
| | T1048.001 - Exfiltration Over Alternative Protocol |
| | T1572 - Protocol Tunneling |

## Data Sources

- `DeviceEvents` (Defender for Endpoint) — TXT record response analysis
- `DeviceNetworkEvents` (Defender for Endpoint) — Subdomain query analysis

## Detection Logic

The query runs two parallel analyses and combines the results:

1. **TXT record content analysis** — Uses `DeviceEvents` where DNS query results contain TXT record responses. Parses the `AdditionalFields` JSON to extract the TXT result content and flags responses that contain Base64-encoded data, are unusually long, or contain high-entropy strings. Also tracks volume per device and destination domain — sustained TXT queries with encoded responses is a strong C2 signal.

2. **Subdomain volume anomaly (strict)** — Uses `DeviceNetworkEvents` to find devices making a high number of queries with long subdomains to the same registered domain. Uses strict thresholds (minimum 30 queries, average subdomain length >= 20) and requires a high ratio of unique subdomains to total queries, which differentiates tunneling from CDN cache key patterns.

## Customization

- **`MinTXTQueryCount`** — Minimum TXT queries with encoded content to a single domain. Default is 3 (TXT with encoded data is rare enough that even a few hits are suspicious).
- **`MinSubdomainQueryCount`** — Minimum long-subdomain queries before flagging. Default is 30.
- **`MinAvgSubdomainLength`** — Minimum average subdomain length. Default is 20 characters (stricter than the Base64 detection to reduce false positives).
- **`MinUniquenessRatio`** — Minimum ratio of unique subdomains to total queries. Default is 0.7. DNS tunneling produces mostly unique subdomains per query, while CDNs and telemetry reuse patterns.
- **`MaxDomainPrevalence`** — Maximum number of devices in the tenant that have queried the same registered domain. Domains queried by many devices are almost certainly legitimate services. Default is 3 — C2 domains are typically queried by only the compromised device.
- **`MinTotalScore`** — Minimum combined score from TXT and subdomain analyses to include in results. Default is 2. Raise to reduce noise at the cost of potentially missing weaker signals, or lower to 1 for broader hunting sweeps.
- **`AllowlistedDomains`** — Extend with services that generate legitimate long subdomain or TXT traffic.

## Query

```kql
// ============================================================================
// DNS C2 Traffic Detection — Anomalous TXT Records and Subdomain Queries
// Detects DNS tunneling C2 by analyzing TXT record response content from
// DeviceEvents and long-subdomain query patterns from DeviceNetworkEvents.
//
// Data sources: DeviceEvents, DeviceNetworkEvents (Defender for Endpoint)
//
// MITRE ATT&CK:
//   T1071.004 - Application Layer Protocol: DNS
//   T1048.001 - Exfiltration Over Alternative Protocol
//   T1572    - Protocol Tunneling
// ============================================================================
let LookbackWindow = 24h;
let MinTXTQueryCount = 3;
let MinSubdomainQueryCount = 30;
let MinAvgSubdomainLength = 20;
let MinUniquenessRatio = 0.7;
// Maximum number of devices querying the same domain before it's considered common
// C2 domains are typically queried by only 1-2 devices in the tenant
let MaxDomainPrevalence = 3;
// Minimum combined score (TXT + Subdomain) to include in results
let MinTotalScore = 2;
let AllowlistedDomains = dynamic([
    "windows.com",
    "microsoft.com",
    "windowsupdate.com",
    "azure.com",
    "azurewebsites.net",
    "googleapis.com",
    "gstatic.com",
    "akamaiedge.net",
    "akamai.net",
    "cloudflare.com",
    "cloudfront.net",
    "amazonaws.com",
    "trafficmanager.net",
    "msedge.net",
    "office.com",
    "office365.com",
    "outlook.com",
    "live.com",
    "sharepoint.com",
    "azureedge.net",
    "msftconnecttest.com",
    "digicert.com",
    "verisign.com",
    "letsencrypt.org",
    "in-addr.arpa"
]);
// ============================================================================
// Prevalence: Count how many devices query each registered domain
// Domains queried by many devices are likely legitimate services
// ============================================================================
let DomainPrevalence = DeviceNetworkEvents
    | where Timestamp > ago(LookbackWindow)
    | where isnotempty(RemoteUrl)
    | extend CleanHost = tolower(extract(@"^(?:https?://)?([^/:?#]+)", 1, RemoteUrl))
    | where isnotempty(CleanHost)
    | extend HostParts = split(CleanHost, ".")
    | extend HostPartCount = array_length(HostParts)
    | where HostPartCount >= 2
    | extend RegDomain = strcat(tostring(HostParts[HostPartCount - 2]), ".", tostring(HostParts[HostPartCount - 1]))
    | summarize DeviceCount = dcount(DeviceId) by RegDomain;
// ============================================================================
// Analysis 1: TXT record response content analysis (DeviceEvents)
// ============================================================================
let TXTAnalysis = DeviceEvents
    | where Timestamp > ago(LookbackWindow)
    | where ActionType == "DnsQueryResponse"
    | extend ParsedFields = parse_json(AdditionalFields)
    | extend
        DnsQueryString = tostring(ParsedFields.DnsQueryString),
        DnsQueryResult = tostring(ParsedFields.DnsQueryResult),
        ClientProcess = tostring(ParsedFields.ClientProcessName)
    // Filter for TXT record responses
    | where DnsQueryResult has "TEXT"
    | where not(DnsQueryString has_any (AllowlistedDomains))
    // Parse TXT result content
    // DnsQueryResult is an array of JSON strings — each element needs double-parsing
    | extend ResultParsed = parse_json(DnsQueryResult)
    | mv-expand SingleResult = ResultParsed
    | extend ResultObj = parse_json(tostring(SingleResult))
    | where tostring(ResultObj.DnsQueryType) == "TEXT"
    | extend TXTContent = tostring(ResultObj.Result)
    | where isnotempty(TXTContent)
    | extend TXTLength = strlen(TXTContent)
    // Score the TXT content for suspicious characteristics
    | extend
        // Base64 pattern: long alphanumeric string with optional padding
        IsBase64Like = TXTContent matches regex @"^[A-Za-z0-9+/=]{20,}$",
        // High ratio of Base64 characters
        Base64CharCount = countof(TXTContent, "[A-Za-z0-9+/=]", "regex"),
        HasPadding = TXTContent endswith "=" or TXTContent endswith "=="
    | extend Base64Ratio = round(1.0 * Base64CharCount / TXTLength, 2)
    | extend ContentSuspicious = IsBase64Like or (Base64Ratio > 0.9 and TXTLength > 30) or HasPadding
    | where ContentSuspicious
    // Extract registered domain for aggregation
    | extend DomainParts = split(DnsQueryString, ".")
    | extend PartCount = array_length(DomainParts)
    | extend RegisteredDomain = iff(PartCount >= 2,
        strcat(tostring(DomainParts[PartCount - 2]), ".", tostring(DomainParts[PartCount - 1])),
        DnsQueryString)
    // Aggregate per device + domain
    | summarize
        TXTQueryCount = count(),
        AvgTXTLength = round(avg(TXTLength), 0),
        MaxTXTLength = max(TXTLength),
        FirstSeen = min(Timestamp),
        LastSeen = max(Timestamp),
        ClientProcesses = make_set(ClientProcess, 5),
        SampleContent = make_set(substring(TXTContent, 0, 40), 3),
        SampleQueries = make_set(DnsQueryString, 5)
        by DeviceName, DeviceId, RegisteredDomain
    | where TXTQueryCount >= MinTXTQueryCount
    // Filter out domains queried by many devices (likely legitimate)
    | join kind=leftouter (DomainPrevalence) on $left.RegisteredDomain == $right.RegDomain
    | extend DomainDeviceCount = coalesce(DeviceCount, 1)
    | where DomainDeviceCount <= MaxDomainPrevalence
    | extend TXTScore = case(
        TXTQueryCount >= 20 and AvgTXTLength >= 100, 4,
        TXTQueryCount >= 10, 3,
        TXTQueryCount >= 5, 2,
        1
    );
// ============================================================================
// Analysis 2: Subdomain length and volume anomaly (DeviceNetworkEvents)
// Strict thresholds to minimize false positives
// ============================================================================
let SubdomainAnalysis = DeviceNetworkEvents
    | where Timestamp > ago(LookbackWindow)
    | where ActionType == "DnsQueryResponse" or ActionType == "ConnectionSuccess"
    | where isnotempty(RemoteUrl)
    // Strip protocol, paths, query parameters, and fragments to get clean hostname
    | extend CleanUrl = tolower(RemoteUrl)
    | extend CleanUrl = extract(@"^(?:https?://)?([^/:?#]+)", 1, CleanUrl)
    | where isnotempty(CleanUrl)
    // Skip entries that look like IP addresses
    | where not(CleanUrl matches regex @"^\d+\.\d+\.\d+\.\d+$")
    | extend FullDomain = CleanUrl
    | where not(FullDomain has_any (AllowlistedDomains))
    | extend DomainParts = split(FullDomain, ".")
    | extend PartCount = array_length(DomainParts)
    | where PartCount >= 3
    | extend RegisteredDomain = strcat(tostring(DomainParts[PartCount - 2]), ".", tostring(DomainParts[PartCount - 1]))
    | extend SubdomainPortion = substring(FullDomain, 0, strlen(FullDomain) - strlen(RegisteredDomain) - 1)
    | extend SubdomainLength = strlen(SubdomainPortion)
    // Only consider queries with meaningfully long subdomains
    | where SubdomainLength >= 15
    | summarize
        QueryCount = count(),
        AvgSubdomainLength = round(avg(SubdomainLength), 1),
        MaxSubdomainLength = max(SubdomainLength),
        UniqueSubdomains = dcount(SubdomainPortion),
        FirstSeen = min(Timestamp),
        LastSeen = max(Timestamp),
        SampleQueries = make_set(FullDomain, 5)
        by DeviceName, DeviceId, RegisteredDomain
    | where QueryCount >= MinSubdomainQueryCount
    | where AvgSubdomainLength >= MinAvgSubdomainLength
    // Filter out domains queried by many devices (likely legitimate)
    | join kind=leftouter (DomainPrevalence) on $left.RegisteredDomain == $right.RegDomain
    | extend DomainDeviceCount = coalesce(DeviceCount, 1)
    | where DomainDeviceCount <= MaxDomainPrevalence
    // Uniqueness ratio: tunneling produces mostly unique subdomains
    | extend UniquenessRatio = round(1.0 * UniqueSubdomains / QueryCount, 2)
    | where UniquenessRatio >= MinUniquenessRatio
    | extend SubdomainScore = case(
        AvgSubdomainLength >= 30 and QueryCount >= 100, 4,
        AvgSubdomainLength >= 25 and QueryCount >= 50, 3,
        AvgSubdomainLength >= 20 and QueryCount >= 30, 2,
        1
    );
// ============================================================================
// Combine both analyses
// ============================================================================
let Combined = SubdomainAnalysis
    | join kind=fullouter TXTAnalysis on DeviceName, RegisteredDomain
    | extend
        DeviceName = coalesce(DeviceName, DeviceName1),
        DeviceId = coalesce(DeviceId, DeviceId1),
        RegisteredDomain = coalesce(RegisteredDomain, RegisteredDomain1),
        FirstSeen = coalesce(FirstSeen, FirstSeen1),
        LastSeen = coalesce(LastSeen, LastSeen1),
        SampleQueries = coalesce(SampleQueries, SampleQueries1)
    | extend
        TXTQueryCount = coalesce(TXTQueryCount, 0),
        TXTScore = coalesce(TXTScore, 0),
        AvgTXTLength = coalesce(AvgTXTLength, real(0)),
        SubdomainQueryCount = coalesce(QueryCount, 0),
        SubdomainScore = coalesce(SubdomainScore, 0),
        AvgSubdomainLength = coalesce(AvgSubdomainLength, real(0)),
        MaxSubdomainLength = coalesce(MaxSubdomainLength, 0),
        UniqueSubdomains = coalesce(UniqueSubdomains, 0),
        UniquenessRatio = coalesce(UniquenessRatio, real(0)),
        ClientProcesses = coalesce(ClientProcesses, dynamic([])),
        SampleContent = coalesce(SampleContent, dynamic([]))
    // Get prevalence for the combined domain
    | join kind=leftouter (DomainPrevalence) on $left.RegisteredDomain == $right.RegDomain
    | extend DomainDeviceCount = coalesce(DeviceCount, 1)
    | extend TotalScore = TXTScore + SubdomainScore
    | extend Signals = array_concat(
        iff(TXTScore > 0, dynamic(["EncodedTXTResponses"]), dynamic([])),
        iff(SubdomainScore > 0, dynamic(["LongUniqueSubdomains"]), dynamic([]))
    );
Combined
| extend
    DurationMinutes = datetime_diff("minute", LastSeen, FirstSeen),
    TotalQueries = TXTQueryCount + SubdomainQueryCount
| extend AvgIntervalSeconds = iff(TotalQueries > 1 and DurationMinutes > 0,
    round(1.0 * DurationMinutes * 60 / (TotalQueries - 1), 0),
    real(0))
| extend Severity = case(
    TotalScore >= 5, "Critical",
    TotalScore >= 3, "High",
    TotalScore >= 2, "Medium",
    "Low"
)
| where TotalScore >= MinTotalScore
| project
    FirstSeen,
    LastSeen,
    Severity,
    TotalScore,
    Signals,
    DeviceName,
    RegisteredDomain,
    DomainDeviceCount,
    TXTQueryCount,
    AvgTXTLength,
    SampleContent,
    ClientProcesses,
    SubdomainQueryCount,
    UniqueSubdomains,
    UniquenessRatio,
    AvgSubdomainLength,
    MaxSubdomainLength,
    DurationMinutes,
    AvgIntervalSeconds,
    SampleQueries
| sort by TotalScore desc, Severity asc
```
