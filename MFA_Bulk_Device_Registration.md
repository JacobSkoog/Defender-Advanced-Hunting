# Authenticator App Bulk Device Registration Detection

## Overview

Detects when the same Authenticator app device (identified by `DeviceToken`) is registered across multiple user accounts. This may indicate an attacker enrolling their own device on compromised accounts to maintain MFA persistence — even if passwords are reset, the attacker's Authenticator app can still approve sign-in requests.

Unlike phone number-based MFA manipulation, this targets the `StrongAuthenticationPhoneAppDetail` property, covering Microsoft Authenticator and similar TOTP/push-notification apps.

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Credential Access, Persistence |
| **Technique** | T1556.006 - Modify Authentication Process: Multi-Factor Authentication |

## Data Source

- `CloudAppEvents` (Defender XDR)

## Detection Logic

1. **Extract** all `StrongAuthenticationPhoneAppDetail` modifications from `Update user.` events.
2. **Parse** the `DeviceToken` and `DeviceName` from the new value.
3. **Aggregate** by `DeviceToken` to find the same device registered on multiple accounts.
4. **Deduplicate identities** — the same user may exist across multiple domains (e.g., `jdoe@contoso.com` and `jdoe@fabrikam.com`). The query uses the UPN prefix to count unique identities rather than raw account count.
5. **Exclude expected pairs** — a device shared between exactly two unique identities where one is an admin account and one is regular is treated as expected (admin/user account pairing).

## Customization

Update the admin account regex pattern to match your environment's naming convention:

```kql
// Example patterns:
// @"(?i)adm\d+"        — matches adm12345, ADM001, etc.
// @"(?i)a\d{5}"        — matches a00001, A12345, etc.
// @"(?i)admin[-_]"     — matches admin-jsmith, admin_jdoe, etc.
```

## Query

```kql
// ============================================================================
// StrongAuthenticationPhoneAppDetail Bulk Device Registration Detection
// Detects when the same Authenticator app device (identified by DeviceToken)
// is registered across multiple user accounts. This may indicate an attacker
// enrolling their own device on compromised accounts for MFA persistence.
//
// Data source: CloudAppEvents (Defender XDR)
//
// Exclusion logic:
//   - Same user across multiple domains (same prefix before @) is expected
//   - A device shared between exactly 2 unique identities where one is an
//     admin account and one is regular is expected
//
// MITRE ATT&CK: T1556.006 - Modify Authentication Process: Multi-Factor Authentication
// ============================================================================
// UPDATE: Set AdminAccountPattern to match your admin account naming convention
let AdminAccountPattern = @"(?i)adm\d+";
CloudAppEvents
| where ActionType == "Update user."
| where RawEventData has "StrongAuthenticationPhoneAppDetail"
| extend
    Target = tostring(RawEventData.ObjectId),
    Actor = tostring(RawEventData.UserId)
| mv-expand ModifiedProperties = parse_json(RawEventData.ModifiedProperties)
| where ModifiedProperties.Name == "StrongAuthenticationPhoneAppDetail"
| extend NewValue = parse_json(tostring(ModifiedProperties.NewValue))
| mv-apply NewValue on (
    extend
        DeviceName = tostring(NewValue.DeviceName),
        DeviceToken = tostring(NewValue.DeviceToken)
)
| where isnotempty(DeviceToken) and DeviceToken != "NO_DEVICE_TOKEN"
// Aggregate: find tokens registered to multiple users
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    AffectedUsers = make_set(Target)
    by DeviceToken, DeviceName
| extend UserCount = array_length(AffectedUsers)
| where UserCount > 1
// Count unique user identities (prefix before @) and admin accounts
| mv-apply User = AffectedUsers to typeof(string) on (
    extend
        UserPrefix = tolower(extract(@"^([^@]+)", 1, User)),
        IsAdmin = User matches regex AdminAccountPattern
    | summarize
        UniqueIdentities = dcount(UserPrefix),
        AdminCount = countif(IsAdmin)
)
| extend RegularCount = UserCount - AdminCount
// Only flag if there are multiple distinct identities after deduplication
// This handles both:
//   - same person across domain1.com and domain2.com (same prefix = 1 identity)
//   - admin + regular account pair (2 accounts, but expected)
| where not(UniqueIdentities == 1)
| where not(UniqueIdentities == 2 and AdminCount == 1 and RegularCount == 1)
| project
    FirstSeen,
    LastSeen,
    DeviceName,
    DeviceToken,
    UserCount,
    UniqueIdentities,
    AdminCount,
    AffectedUsers
| sort by UniqueIdentities desc, LastSeen desc
```
