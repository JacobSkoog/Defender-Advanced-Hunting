# Double File Extension Detection

## Overview

Detects files with double extensions where the final extension is executable (e.g., `invoice.pdf.exe`, `report.docx.scr`, `photo.jpg.bat`). This is a common social engineering technique that exploits the Windows default behavior of hiding known file extensions — the user sees `invoice.pdf` in Explorer while the actual file is `invoice.pdf.exe`.

This technique is frequently used in phishing campaigns and often delivered via email attachments, browser downloads, or shared drives. It requires no exploitation or vulnerability — just a user double-clicking what appears to be a document, image, or archive.

## MITRE ATT&CK

| Field | Value |
|-------|-------|
| **Tactic** | Defense Evasion, Execution |
| **Techniques** | T1036.007 - Masquerading: Double File Extension |
| | T1204.002 - User Execution: Malicious File |

## Data Sources

- `DeviceFileEvents` (Defender for Endpoint)
- `DeviceProcessEvents` (Defender for Endpoint)

## Detection Logic

The query runs two parallel detections:

1. **File creation** — Identifies files written to disk that have a double extension pattern where the decoy extension mimics a benign file type (`.pdf`, `.doc`, `.jpg`, `.png`, etc.) and the real extension is executable (`.exe`, `.scr`, `.bat`, `.cmd`, `.pif`, `.com`, `.vbs`, `.js`, `.wsf`, `.msi`, `.hta`).

2. **Process execution** — Catches the case where a double-extension file is actually executed. This may detect files that were created before the lookback window or that were delivered through channels not captured by `DeviceFileEvents`.

Both detections exclude standard trusted paths and known legitimate patterns to reduce false positives.

## Customization

- **`DecoyExtensions`** — Extensions used as the fake "first" extension. Extend if attackers in your environment use less common decoy types.
- **`ExecutableExtensions`** — The real (final) extensions that make the file dangerous. Add any additional executable types relevant to your environment.
- **`ExcludedFolders`** — Trusted paths where double extensions may occur legitimately (e.g., development build directories, package caches).
- **`ExcludedProcesses`** — Processes that legitimately create files with double extension patterns (e.g., archive extractors, download managers).
- **`ExcludedFilePatterns`** — Filename patterns to exclude. The default excludes PowerShell's `__PSScriptPolicyTest_` files, which create temporary double-extension files during execution policy checks.

## Query

```kql
// ============================================================================
// Double File Extension Detection
// Detects files with double extensions where a benign decoy extension is
// followed by an executable extension (e.g., invoice.pdf.exe), a common
// social engineering technique exploiting hidden file extensions in Windows.
//
// Data sources: DeviceFileEvents, DeviceProcessEvents (Defender for Endpoint)
//
// MITRE ATT&CK:
//   T1036.007 - Masquerading: Double File Extension
//   T1204.002 - User Execution: Malicious File
// ============================================================================
let LookbackWindow = 24h;
// Decoy extensions: benign-looking first extensions used to trick users
let DecoyExtensions = dynamic([
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".txt", ".csv", ".rtf", ".htm", ".html",
    ".iso", ".img"
]);
// Executable extensions: the real (dangerous) final extension
let ExecutableExtensions = dynamic([
    ".exe", ".scr", ".bat", ".cmd", ".pif", ".com",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".msi", ".msp", ".hta", ".cpl", ".ps1"
]);
// Patterns that legitimately produce double-extension files
let ExcludedFilePatterns = dynamic([
    "__PSScriptPolicyTest_"  // PowerShell execution policy test files
]);
// Paths to exclude
let ExcludedFolders = dynamic([
    ":\\Windows\\",
    ":\\Program Files\\",
    ":\\Program Files (x86)\\",
    "ProgramData\\Microsoft",
    "\\node_modules\\",
    "\\site-packages\\",
    "\\.nuget\\"
]);
// Processes that may legitimately create double-extension files
let ExcludedProcesses = dynamic([
    // "7zFM.exe", "winrar.exe"
]);
// --- Detection 1: File creation with double extension ---
let FileCreation = DeviceFileEvents
    | where Timestamp > ago(LookbackWindow)
    | where ActionType in ("FileCreated", "FileRenamed", "FileModified")
    | where isnotempty(FileName)
    // Extract the two extensions: e.g., "invoice.pdf.exe" -> ".pdf" and ".exe"
    | extend RealExtension = strcat(".", tolower(extract(@'\.([^.]+)$', 1, FileName)))
    | extend FileWithoutRealExt = extract(@'^(.+)\.[^.]+$', 1, FileName)
    | extend DecoyExtension = strcat(".", tolower(extract(@'\.([^.]+)$', 1, FileWithoutRealExt)))
    // Must have both a decoy and a real extension
    | where isnotempty(DecoyExtension) and DecoyExtension != "."
    | where isnotempty(RealExtension) and RealExtension != "."
    // Decoy must look benign, real must be executable
    | where DecoyExtension in (DecoyExtensions)
    | where RealExtension in (ExecutableExtensions)
    // Exclude trusted paths and known processes
    | where not(FolderPath has_any (ExcludedFolders))
    | where not(InitiatingProcessFileName has_any (ExcludedProcesses))
    | where not(FileName has_any (ExcludedFilePatterns))
    | extend DetectionType = "FileCreated"
    | project
        Timestamp,
        DetectionType,
        DeviceName,
        FileName,
        DecoyExtension,
        RealExtension,
        FolderPath,
        SHA256,
        InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        InitiatingProcessAccountName,
        ReportId;
// --- Detection 2: Execution of a double-extension file ---
let FileExecution = DeviceProcessEvents
    | where Timestamp > ago(LookbackWindow)
    | where isnotempty(FileName)
    | extend RealExtension = strcat(".", tolower(extract(@'\.([^.]+)$', 1, FileName)))
    | extend FileWithoutRealExt = extract(@'^(.+)\.[^.]+$', 1, FileName)
    | extend DecoyExtension = strcat(".", tolower(extract(@'\.([^.]+)$', 1, FileWithoutRealExt)))
    | where isnotempty(DecoyExtension) and DecoyExtension != "."
    | where isnotempty(RealExtension) and RealExtension != "."
    | where DecoyExtension in (DecoyExtensions)
    | where RealExtension in (ExecutableExtensions)
    | where not(FolderPath has_any (ExcludedFolders))
    | where not(FileName has_any (ExcludedFilePatterns))
    | extend DetectionType = "FileExecuted"
    | project
        Timestamp,
        DetectionType,
        DeviceName,
        FileName,
        DecoyExtension,
        RealExtension,
        FolderPath,
        SHA256,
        InitiatingProcessFileName = InitiatingProcessFileName,
        InitiatingProcessCommandLine = InitiatingProcessCommandLine,
        InitiatingProcessAccountName = InitiatingProcessAccountName,
        ReportId;
// --- Combine both detections ---
union FileCreation, FileExecution
| sort by Timestamp desc
```
