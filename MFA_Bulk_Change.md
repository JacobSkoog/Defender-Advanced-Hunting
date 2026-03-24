# MFA Bulk Change Detection — Same Value Across Multiple Accounts

## Overview

Detects when the same authentication detail value (e.g., phone number or email) is registered across multiple user accounts. This is a strong indicator that an attacker has compromised several accounts and is enrolling their own contact information for MFA persistence, ensuring continued access even if passwords are reset.

The query monitors changes to `PhoneNumber`, `AlternativePhoneNumber`, and `Email` fields within `StrongAuthenticationUserDetails`, then aggregates by the new value to identify duplicates across accounts.

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Credential Access, Persistence |
| **Technique** | T1556.006 - Modify Authentication Process: Multi-Factor Authentication |

## Data Source

- `CloudAppEvents` (Defender XDR)

## Detection Logic

1. **Extract** all `StrongAuthenticationUserDetails` modifications from `Update user.` events.
2. **Parse** old and new values and identify actual field-level changes.
3. **Normalize** phone numbers by stripping formatting characters.
4. **Aggregate** by the new value to find the same value appearing on multiple accounts.
5. **Exclude expected pairs** — in many environments, users have both a regular account and an admin account. The query filters out cases where exactly two accounts share a value and one matches the admin account naming convention. This avoids false positives from legitimate admin/user account pairings.

## Customization

Update the admin account regex pattern to match your environment's naming convention. The default placeholder matches accounts starting with `adm` followed by digits (e.g., `adm12345`):

```kql
// Example patterns:
// @"(?i)adm\d+"        — matches adm12345, ADM001, etc.
// @"(?i)a\d{5}"        — matches a00001, A12345, etc.
// @"(?i)admin[-_]"     — matches admin-jsmith, admin_jdoe, etc.
```

## Query

```kql
// ============================================================================
// StrongAuthenticationUserDetails Bulk Change Detection
// Detects when the same authentication detail value (e.g. phone number)
// is registered across multiple user accounts, which may indicate an attacker
// enrolling their own phone number on compromised accounts for MFA persistence.
//
// Monitored fields:
//   PhoneNumber             - primary MFA phone
//   AlternativePhoneNumber  - backup MFA phone
//   Email                   - MFA email address
//
// MITRE ATT&CK: T1556.006 - Modify Authentication Process: Multi-Factor Authentication
// ============================================================================
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
// Step 2: Parse old and new values from the modified properties
// The raw format wraps key-value pairs in brackets that need stripping
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
// Step 4: Normalize phone numbers by stripping formatting characters
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
    | where OldValue != NewValue
    | where isnotempty(NewValue);
// Step 5: Classify the type of change
let ClassifiedChanges = NormalizedChanges
    | extend Action = case(
        isempty(OldValue), strcat("Added new ", ChangedField),
        isempty(NewValue), strcat("Removed ", ChangedField),
        strcat("Changed ", ChangedField)
    )
    | project Timestamp, Action, Actor, Target, ChangedField, OldValue, NewValue;
// Step 6: Flag values registered across multiple accounts
// Exclude expected pattern: same number on exactly 2 accounts where
// one is a regular account and one is an admin account
// UPDATE: Set AdminAccountPattern to match your admin account naming convention
let AdminAccountPattern = @"(?i)adm\d+";
ClassifiedChanges
| summarize 
    FirstSeen = min(Timestamp), 
    LastSeen = max(Timestamp), 
    AffectedUsers = make_set(Target) 
    by NewValue
| extend UserCount = array_length(AffectedUsers)
| where UserCount > 1
// Count how many of the affected accounts are admin accounts
| mv-apply User = AffectedUsers to typeof(string) on (
    summarize AdminCount = countif(User matches regex AdminAccountPattern)
)
| extend RegularCount = UserCount - AdminCount
// Allow: exactly 2 accounts where one is admin and one is regular
// Flag everything else
| where not(UserCount == 2 and AdminCount == 1 and RegularCount == 1)
| project
    FirstSeen,
    LastSeen,
    NewValue,
    UserCount,
    AdminCount,
    RegularCount,
    AffectedUsers
| sort by UserCount desc, LastSeen desc
```
