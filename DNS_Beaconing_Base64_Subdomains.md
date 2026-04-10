# DNS Beaconing Detection — Base64-Encoded Subdomain Patterns

## Overview

Detects DNS queries where the subdomain portion contains patterns consistent with Base64-encoded data, a hallmark of DNS-based command and control (C2) channels. DNS tunneling and beaconing malware encode exfiltrated data or C2 instructions into subdomain labels, exploiting the fact that DNS traffic is often allowed through firewalls and rarely inspected at depth.

A typical malicious DNS query looks like:

```
aGVsbG8gd29ybGQ.c2VjcmV0ZGF0YQ.attacker-domain.com
```

Where each subdomain label contains Base64-encoded payload data. This detection identifies these patterns by looking for subdomain labels that match Base64 character sets, have high entropy, unusual length, and lack the structure of legitimate hostnames.

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Command and Control, Exfiltration |
| **Techniques** | T1071.004 - Application Layer Protocol: DNS |
| | T1048.001 - Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol |
| | T1132.001 - Data Encoding: Standard Encoding |

## Data Source

- `DeviceNetworkEvents` (Defender for Endpoint)

## Detection Logic

1. **Extract** the subdomain portion from DNS queries by stripping the top-level domain and registered domain.
2. **Filter** for subdomain labels that match Base64 character patterns — alphanumeric strings with `+`, `/`, or `=` padding, or the URL-safe variant with `-` and `_`.
3. **Score** each query across multiple heuristics: label length, Base64 character ratio, presence of padding characters, entropy, absence of natural word patterns (consecutive vowels/consonants), and query volume per domain.
4. **Aggregate** per device and destination domain to surface sustained beaconing rather than isolated queries.

## Customization

- **`MinSubdomainLength`** — Minimum subdomain length to evaluate. Shorter subdomains generate too many false positives. Default is 12 characters.
- **`AllowlistedDomains`** — Add CDNs, cloud services, and other legitimate domains that use long random-looking subdomains (e.g., certificate validation, telemetry, CDN cache keys).
- **`MinBeaconCount`** — Minimum number of queries to a single domain before alerting. Higher values reduce noise but may miss low-and-slow beacons.
- **`MaxDomainPrevalence`** — Maximum number of devices in the tenant querying the same registered domain. C2 domains are typically only queried by the compromised device. Default is 3.

## Query

```kql
// ============================================================================
// DNS Beaconing Detection — Base64-Encoded Subdomain Patterns
// Detects DNS queries containing subdomain labels that resemble Base64-encoded
// data, indicating potential DNS tunneling or C2 beaconing.
//
// Data source: DeviceNetworkEvents (Defender for Endpoint)
//
// MITRE ATT&CK:
//   T1071.004 - Application Layer Protocol: DNS
//   T1048.001 - Exfiltration Over Alternative Protocol
//   T1132.001 - Data Encoding: Standard Encoding
// ============================================================================
let LookbackWindow = 24h;
let MinSubdomainLength = 12;
let MinBeaconCount = 5;
// Maximum number of devices querying the same domain — C2 domains are typically
// queried by only the compromised device
let MaxDomainPrevalence = 3;
// Domains known to use long random-looking subdomains legitimately
// UPDATE: extend this list based on your environment
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
    "letsencrypt.org"
]);
// Domain prevalence: count how many devices query each registered domain
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
DeviceNetworkEvents
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
// Skip allowlisted domains
| where not(FullDomain has_any (AllowlistedDomains))
// Extract the registered domain (last two labels) and subdomain portion
| extend DomainParts = split(FullDomain, ".")
| extend PartCount = array_length(DomainParts)
| where PartCount >= 3
// Registered domain = last 2 parts (handles .com, .net, etc.)
// For ccTLDs like .co.uk, you may need to adjust to last 3 parts
| extend RegisteredDomain = strcat(tostring(DomainParts[PartCount - 2]), ".", tostring(DomainParts[PartCount - 1]))
// Subdomain = everything before the registered domain
| extend SubdomainRaw = substring(FullDomain, 0, strlen(FullDomain) - strlen(RegisteredDomain) - 1)
// Use the longest subdomain label for analysis
| extend SubdomainLabels = split(SubdomainRaw, ".")
| mv-apply Label = SubdomainLabels to typeof(string) on (
    summarize LongestLabel = arg_max(strlen(Label), Label)
)
| extend SubdomainLabel = tostring(Label)
| extend LabelLength = strlen(SubdomainLabel)
| where LabelLength >= MinSubdomainLength
// --- Scoring heuristics ---
// 1. Base64 character pattern: mostly alphanumeric with optional +/= or URL-safe -/_
| extend Base64CharCount = countof(SubdomainLabel, "[A-Za-z0-9+/=_-]", "regex")
| extend Base64Ratio = round(1.0 * Base64CharCount / LabelLength, 2)
// 2. Has Base64 padding characters
| extend HasPadding = SubdomainLabel has "=" or SubdomainLabel endswith "=="
// 3. Lacks natural language patterns — no runs of vowels typical in real hostnames
| extend VowelCount = countof(SubdomainLabel, "[aeiou]", "regex")
| extend VowelRatio = round(1.0 * VowelCount / LabelLength, 2)
// Natural English text typically has 35-45% vowels
// Base64 encoded data typically has ~15-25% vowels (random distribution)
// 4. Digit density — Base64 has more digits than natural hostnames
| extend DigitCount = countof(SubdomainLabel, "[0-9]", "regex")
| extend DigitRatio = round(1.0 * DigitCount / LabelLength, 2)
// 5. Mixed case detection (if preserved) — Base64 mixes cases freely
| extend UpperCount = countof(SubdomainLabel, "[A-Z]", "regex")
| extend HasMixedCase = UpperCount > 0 and UpperCount < LabelLength
// Score each indicator
| extend Score =
    // High Base64 character ratio (> 95%)
    iff(Base64Ratio > 0.95, 1, 0) +
    // Low vowel ratio suggests encoded data, not words
    iff(VowelRatio < 0.25, 1, 0) +
    // Contains digits mixed in (common in Base64, rare in hostnames)
    iff(DigitRatio > 0.1, 1, 0) +
    // Long label (Base64 chunks tend to be long)
    iff(LabelLength >= 20, 1, 0) +
    // Has padding characters (strong Base64 signal)
    iff(HasPadding, 2, 0) +
    // Mixed case
    iff(HasMixedCase, 1, 0)
| where Score >= 3
// Aggregate per device + destination domain to find sustained beaconing
| summarize
    QueryCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    AvgScore = round(avg(Score), 1),
    MaxLabelLength = max(LabelLength),
    SampleSubdomains = make_set(SubdomainLabel, 5),
    SampleFullQueries = make_set(FullDomain, 5)
    by DeviceName, RegisteredDomain
| where QueryCount >= MinBeaconCount
// Filter out domains queried by many devices (likely legitimate)
| join kind=leftouter (DomainPrevalence) on $left.RegisteredDomain == $right.RegDomain
| extend DomainDeviceCount = coalesce(DeviceCount, 1)
| where DomainDeviceCount <= MaxDomainPrevalence
// Calculate beaconing interval regularity
| extend DurationMinutes = datetime_diff("minute", LastSeen, FirstSeen)
| extend AvgIntervalSeconds = iff(QueryCount > 1,
    round(1.0 * DurationMinutes * 60 / (QueryCount - 1), 0),
    real(0))
| project
    FirstSeen,
    LastSeen,
    DeviceName,
    RegisteredDomain,
    DomainDeviceCount,
    QueryCount,
    DurationMinutes,
    AvgIntervalSeconds,
    AvgScore,
    MaxLabelLength,
    SampleSubdomains,
    SampleFullQueries
| sort by QueryCount desc, AvgScore desc
```
