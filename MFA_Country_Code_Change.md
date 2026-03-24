# MFA Phone Number Country Code Change Detection

## Overview

Detects when a user's MFA phone number is changed to a number with an unexpected country code prefix. This may indicate an attacker replacing a legitimate phone number with one they control in a different country, a common persistence technique after initial account compromise.

The query tracks changes to both the primary `PhoneNumber` and `AlternativePhoneNumber` fields within `StrongAuthenticationUserDetails`, normalizes phone number formatting, and classifies each change by severity based on whether the old and new country codes match expected values.

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Credential Access, Persistence |
| **Technique** | T1556.006 - Modify Authentication Process: Multi-Factor Authentication |

## Data Source

- `CloudAppEvents` (Defender XDR)

## Detection Logic

1. **Extract** all `StrongAuthenticationUserDetails` modifications from `Update user.` events.
2. **Parse** old and new values from the modified properties JSON structure.
3. **Identify** actual changes by comparing matching keys between old and new values.
4. **Normalize** phone numbers by stripping whitespace, parentheses, and dashes, and ensuring a `+` prefix.
5. **Classify** severity based on country code transitions:
   - **High** — Changed from an expected to an unexpected country code, or between two unexpected codes.
   - **Medium** — Changed from an unexpected to an expected country code (possible remediation).
   - **Informational** (filtered out) — Both old and new numbers use expected country codes.

## Customization

Update the `ExpectedCountryCodes` list to match your client's environment. For example, for a Nordic organization:

```kql
let ExpectedCountryCodes = dynamic(["+46", "+47", "+45", "+358"]);
```

## Query

```kql
// ============================================================================
// StrongAuthenticationUserDetails Country Code Change Detection
// Detects when a user's MFA phone number is changed to a number with an
// unexpected country code prefix. This may indicate an attacker replacing
// a legitimate phone number with one they control in another country.
//
// Data source: CloudAppEvents (Defender XDR)
//
// Monitored fields:
//   PhoneNumber             - primary MFA phone
//   AlternativePhoneNumber  - backup MFA phone
//
// Detection logic:
//   Flags changes where the phone number country code changes to or from
//   an unexpected country. Expected country codes are maintained in a list
//   for easy per-client customization.
//
// MITRE ATT&CK: T1556.006 - Modify Authentication Process: Multi-Factor Authentication
// ============================================================================
// Update per client environment
// Example: dynamic(["+46", "+47", "+45", "+358"]) for Nordics
let ExpectedCountryCodes = dynamic(["+46"]);
// Step 1: Get all StrongAuthenticationUserDetails modifications
let AuthDetailChanges =
    CloudAppEvents
    | where ActionType == "Update user."
    | where RawEventData has "StrongAuthenticationUserDetails"
    | extend
        Target = tostring(RawEventData.ObjectId),
        Actor = tostring(RawEventData.UserId)
    | mv-expand ModifiedProperties = parse_json(RawEventData.ModifiedProperties)
    | where ModifiedProperties.Name == "StrongAuthenticationUserDetails";
// Step 2: Parse old and new values from modified properties
let ParsedChanges = AuthDetailChanges
    | extend
        NewValueRaw = parse_json(
            replace_string(replace_string(tostring(ModifiedProperties.NewValue), "[", ""), "]", "")
        ),
        OldValueRaw = parse_json(
            replace_string(replace_string(tostring(ModifiedProperties.OldValue), "[", ""), "]", "")
        )
    | mv-expand NewValueRaw
    | mv-expand OldValueRaw;
// Step 3: Identify actual changes by comparing matching keys
let IdentifiedChanges = ParsedChanges
    | where (tostring(bag_keys(OldValueRaw)) == tostring(bag_keys(NewValueRaw)))
        or (isempty(OldValueRaw) and tostring(NewValueRaw) !contains ":null")
        or (isempty(NewValueRaw) and tostring(OldValueRaw) !contains ":null")
    | extend ChangedField = tostring(bag_keys(NewValueRaw)[0])
    | extend
        OldValue = tostring(parse_json(OldValueRaw)[ChangedField]),
        NewValue = tostring(parse_json(NewValueRaw)[ChangedField]);
// Step 4: Normalize phone numbers and filter to actual changes
let NormalizedChanges = IdentifiedChanges
    | extend OldValue = case(
        ChangedField in ("PhoneNumber", "AlternativePhoneNumber"),
            replace_strings(OldValue, dynamic([" ", "(", ")"]), dynamic(["", "", ""])),
        OldValue
    )
    | extend NewValue = case(
        ChangedField in ("PhoneNumber", "AlternativePhoneNumber"),
            replace_strings(NewValue, dynamic([" ", "(", ")"]), dynamic(["", "", ""])),
        NewValue
    )
    | where OldValue != NewValue;
// Step 5: Classify change type
let ClassifiedChanges = NormalizedChanges
    | extend Action = case(
        isempty(OldValue), strcat("Added new ", ChangedField),
        isempty(NewValue), strcat("Removed ", ChangedField),
        strcat("Changed ", ChangedField)
    )
    | project Timestamp, Action, Actor, Target, ChangedField, OldValue, NewValue;
// Step 6: Flag phone number changes involving unexpected country codes
ClassifiedChanges
| where ChangedField in ("PhoneNumber", "AlternativePhoneNumber")
| where isnotempty(OldValue) and isnotempty(NewValue)
// Normalize: strip remaining formatting, ensure + prefix
| extend
    OldNormalized = replace_regex(OldValue, @"[\s\-\(\)]", ""),
    NewNormalized = replace_regex(NewValue, @"[\s\-\(\)]", "")
| extend
    OldNormalized = iff(not(OldNormalized startswith "+"), strcat("+", OldNormalized), OldNormalized),
    NewNormalized = iff(not(NewNormalized startswith "+"), strcat("+", NewNormalized), NewNormalized)
// Check each number against expected country codes
| mv-apply ExpectedCode = ExpectedCountryCodes to typeof(string) on (
    summarize
        OldMatchCount = countif(OldNormalized startswith ExpectedCode),
        NewMatchCount = countif(NewNormalized startswith ExpectedCode)
)
| extend
    OldIsExpected = OldMatchCount > 0,
    NewIsExpected = NewMatchCount > 0
| extend Severity = case(
    // Changed from expected to unexpected country code
    OldIsExpected and not(NewIsExpected), "High",
    // Changed from unexpected to unexpected
    not(OldIsExpected) and not(NewIsExpected), "High",
    // Changed from unexpected to expected - possible remediation
    not(OldIsExpected) and NewIsExpected, "Medium",
    // Both expected country codes
    "Informational"
)
| where Severity != "Informational"
| project
    Timestamp,
    Severity,
    Action,
    Actor,
    Target,
    ChangedField,
    OldValue = OldNormalized,
    NewValue = NewNormalized,
    OldIsExpected,
    NewIsExpected
| sort by Severity asc, Timestamp desc
```
