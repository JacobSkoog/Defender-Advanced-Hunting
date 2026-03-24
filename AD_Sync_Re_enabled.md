# AD Sync Re-enabled Detection

## Overview

Detects when Azure AD Connect (DirSync) is re-enabled for a user account. Re-enabling directory synchronization can indicate that an attacker is attempting to establish persistence by linking an on-premises Active Directory identity with a cloud account, or that a previously disabled sync configuration has been tampered with.

This is particularly relevant in hybrid environments where AD Connect is used to synchronize identities between on-premises AD and Entra ID. Unexpected changes to the `DirSyncEnabled` property should be investigated promptly.

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Persistence |
| **Technique** | T1098 - Account Manipulation |

## Data Source

- `CloudAppEvents` (Defender XDR)

## Detection Logic

The query monitors `CloudAppEvents` for `Update user.` actions where the `DirSyncEnabled` property is changed to `true`. A regex filter on `ObjectId` should be customized to match your tenant's UPN pattern, scoping the detection to relevant accounts.

## Customization

- Replace the regex pattern `[regex here :)]` with a pattern matching your environment's UPN format (e.g., `@contoso\\.com$`).

## Query

```kql
CloudAppEvents
| where RawEventData contains "DirSyncEnabled"
| where tostring(RawEventData.ObjectId) matches regex @"[regex here :)]" and ActionType == "Update user."
| mv-expand red = RawEventData.ModifiedProperties
| where tostring(red.Name) == "DirSyncEnabled" and tostring(red.NewValue) contains "true"
| extend accountupn = tostring(RawEventData.ObjectId)
| project Timestamp, ReportId, AccountDisplayName, accountupn, red
```
