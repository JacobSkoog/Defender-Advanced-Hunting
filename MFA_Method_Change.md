# MFA Method Change Detection

## Overview

Detects modifications to a user's MFA authentication methods in Entra ID, including additions, removals, and default method changes. This is useful for identifying unauthorized MFA downgrades (e.g., switching from PhoneAppNotification to SMS) or persistence through method manipulation after account compromise.

The query compares old and new `StrongAuthenticationMethod` arrays to determine exactly which methods were added or removed and whether the default method changed, providing clear human-readable output.

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Credential Access, Persistence |
| **Technique** | T1556.006 - Modify Authentication Process: Multi-Factor Authentication |

## Data Source

- `CloudAppEvents` (Defender XDR)

## Detection Logic

1. **Collect** all `Update user.` events containing `StrongAuthenticationMethod` modifications.
2. **Parse** old and new method arrays from the modified properties.
3. **Summarize** each set of methods and identify the default method per event.
4. **Compare** old vs. new method sets using `set_difference()` to find added and removed methods.
5. **Classify** the action (added, removed, or default changed) with human-readable method names.

## Authentication Method Reference

| Type ID | Method |
|---------|--------|
| 0 | TwoWayVoiceMobile |
| 1 | TwoWaySms |
| 2 | TwoWayVoiceOffice |
| 3 | TwoWayVoiceOtherMobile |
| 4 | TwoWaySmsOtherMobile |
| 5 | OneWaySms |
| 6 | PhoneAppNotification |
| 7 | PhoneAppOTP |

## Query

```kql
// ============================================================================
// StrongAuthenticationMethod Change Detection
// Detects modifications to user MFA methods in Entra ID, including additions,
// removals, and default method changes. Useful for identifying unauthorized
// MFA downgrades or persistence via method manipulation.
//
// Tracked authentication method types:
//   0 = TwoWayVoiceMobile
//   1 = TwoWaySms
//   2 = TwoWayVoiceOffice
//   3 = TwoWayVoiceOtherMobile
//   4 = TwoWaySmsOtherMobile
//   5 = OneWaySms
//   6 = PhoneAppNotification
//   7 = PhoneAppOTP
//
// MITRE ATT&CK: T1556.006 - Modify Authentication Process: Multi-Factor Authentication
// ============================================================================
let MethodName = (methodType: string) {
    case(
        methodType == "0", "TwoWayVoiceMobile",
        methodType == "1", "TwoWaySms",
        methodType == "2", "TwoWayVoiceOffice",
        methodType == "3", "TwoWayVoiceOtherMobile",
        methodType == "4", "TwoWaySmsOtherMobile",
        methodType == "5", "OneWaySms",
        methodType == "6", "PhoneAppNotification",
        methodType == "7", "PhoneAppOTP",
        strcat("Unknown(", methodType, ")")
    )
};
let BaseEvents = materialize(
    CloudAppEvents
    | where ActionType == "Update user."
    | where RawEventData has "StrongAuthenticationMethod"
    | extend Target = tostring(RawEventData.ObjectId)
    | extend Actor = tostring(RawEventData.UserId)
    | mv-expand ModifiedProperties = parse_json(RawEventData.ModifiedProperties)
    | where ModifiedProperties.Name == "StrongAuthenticationMethod"
    | extend 
        OldMethods = parse_json(tostring(ModifiedProperties.OldValue)),
        NewMethods = parse_json(tostring(ModifiedProperties.NewValue))
    | project Timestamp, Actor, Target, OldMethods, NewMethods, ReportId
);
let OldSummary = BaseEvents
    | mv-apply OldMethods on (
        extend MethodType = tostring(OldMethods.MethodType),
               IsDefault = tobool(OldMethods.Default)
    )
    | summarize 
        OldMethodSet = make_set(MethodType),
        OldDefault = maxif(MethodType, IsDefault)
        by ReportId, Timestamp, Actor, Target;
let NewSummary = BaseEvents
    | mv-apply NewMethods on (
        extend MethodType = tostring(NewMethods.MethodType),
               IsDefault = tobool(NewMethods.Default)
    )
    | summarize 
        NewMethodSet = make_set(MethodType),
        NewDefault = maxif(MethodType, IsDefault)
        by ReportId, Timestamp, Actor, Target;
OldSummary
| join kind=inner NewSummary on ReportId
| extend
    RemovedMethods = set_difference(OldMethodSet, NewMethodSet),
    AddedMethods = set_difference(NewMethodSet, OldMethodSet),
    DefaultChanged = OldDefault != NewDefault
// Expand removed methods to individual rows
| mv-expand RemovedMethod = iff(array_length(RemovedMethods) > 0, RemovedMethods, dynamic([null]))
| mv-expand AddedMethod = iff(array_length(AddedMethods) > 0, AddedMethods, dynamic([null]))
| extend Action = case(
    isnotnull(RemovedMethod) and isnotnull(AddedMethod),
        strcat("Removed: ", MethodName(tostring(RemovedMethod)), 
               " | Added: ", MethodName(tostring(AddedMethod))),
    isnotnull(RemovedMethod),
        strcat("Removed: ", MethodName(tostring(RemovedMethod))),
    isnotnull(AddedMethod),
        strcat("Added: ", MethodName(tostring(AddedMethod))),
    DefaultChanged,
        strcat("Default changed from ", MethodName(OldDefault), 
               " to ", MethodName(NewDefault)),
    "No change detected"
)
| where Action != "No change detected"
| project
    Timestamp,
    Action,
    Actor = Actor,
    Target = Target,
    DefaultChanged,
    OldDefault = MethodName(OldDefault),
    NewDefault = MethodName(NewDefault),
    ReportId
| sort by Timestamp desc
```
