# WSL Backup Manager v4.1
# Description: Windows PowerShell / WSL2 backup and restore utility.
# Environment: Windows 10/11 (PowerShell 5.1 & Core 7+)
# Collaboration: Claude Opus 4.7 and GPT-5.5.
# Release date: 2026-05-11
# Runtime version is defined by Get-WSLBMScriptVersion.
#
# Current Version Summary (v4.01 -> v4.1):
#   - Static review driven hardening on the git-tracked v4.01 baseline.
#   - Strengthens FULL overwrite restore safeguards with Safety Net manifest
#     tracking, rollback confirmation, and improved disk/UNC preflight checks.
#   - Consolidates WSL / 7-Zip native process handling with safer argument
#     passing, timeout, cancel, and separated stdout/stderr capture.
#   - Improves archive/manifest verification, logging, UTF-8 text output,
#     lock-file cleanup reporting, backup table visibility, 7z PATH handling,
#     Close-VSCodeSafely matching, read-only WSL probes, DryRun behavior, and
#     real command path handling.
#
# Historical Baseline:
#   - v4.01 was the safety-hardened candidate derived from the v3.23 Windows-side
#     WSL2 backup script and v4.00 safety hardening baseline.
#
# Known Limitations:
#   - USER/CUSTOM backups remain convenience directory backups via WSL UNC paths
#     and Windows 7-Zip; they do not guarantee full Linux metadata fidelity.
#   - FULL overwrite restore is always destructive even with Safety Net. Prefer
#     clone restore validation before relying on overwrite recovery.

param(
    [switch]$DryRun
)

# =============================================================================
# 0. Global State & Initialization
# =============================================================================

$ErrorActionPreference = "Stop"

$Global:DryRun = [bool]$DryRun

$Global:BackupState = @{
    IsActive           = $false
    IsRunning          = $false
    Operation          = $null
    ActiveProcess      = $null
    CurrentFile        = $null
    CurrentDir         = $null
    LockFile           = $null
    StartTime          = $null
    SelectedBackupRoot = $null
    CleanupAllowedRoot = $null
}

$Global:ConfigPath = Join-Path $PSScriptRoot "wsl-backup-config.json"
$Global:LogRoot = Join-Path $PSScriptRoot "logs"
$Script:WSLBMScriptVersion = "v4.1"
$Script:WSLBMScriptDate = "2026-05-11"
$Script:CurrentDistro = $null
$Script:WSLPathPrefix = "\\wsl.localhost"
$Script:DefaultWSLCommandTimeoutSeconds = 14400
$Script:RestoreExtractTimeoutSeconds = 14400
$Script:ReadOnlyWSLProbeTimeoutSeconds = 30
$Script:SevenZipIntegrityTimeoutSeconds = 14400
$Script:MinimumSafetyNetArchiveBytes = 16MB
$Script:MinimumSafetyNetFreeSpaceBytes = 5GB

$Global:Config = @{
    GlobalBackupRoot = (Join-Path $PSScriptRoot "Backups")
    InstallRoot      = (Join-Path $PSScriptRoot "Instances")
    SevenZipPath     = ""
    CompressionLevel = 9
    DiskThresholds   = @{ Full = 10; User = 2; Custom = 1 }
    Instances        = @{}
}

# =============================================================================
# 1. Security Functions
# =============================================================================

function Test-SafeDistroName {
    <#
    .SYNOPSIS
        Validate WSL distribution names before native command use.
    .DESCRIPTION
        Reject cmd.exe and PowerShell metacharacters.
    .PARAMETER Name
        Distribution name to validate.
    .OUTPUTS
        [bool] True when the name is accepted.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $dangerousChars = '[&|<>^%"''`$;!()@#\[\]{}]'

    if ($Name -match $dangerousChars) {
        return $false
    }

    if ($Name -match '^\s' -or $Name -match '\s$') {
        return $false
    }

    if ($Name -match '\s{2,}') {
        return $false
    }

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }

    return $true
}

# =============================================================================
# 1b. Path Validation Helpers
#     Text, boundary, overlap, and audit-display helpers for Windows paths.
# =============================================================================

function Test-WSLBMPathTextSafety {
    <#
    .SYNOPSIS
        Reject empty paths, control characters, and double quotes.
    .OUTPUTS
        PSCustomObject: @{ IsValid=[bool]; Errors=[string[]] }
    #>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Path,

        [string]$Label = "Path"
    )

    $errors = @()

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $errors += "$Label is empty or whitespace."
        return [PSCustomObject]@{ IsValid = $false; Errors = $errors }
    }

    $trimmed = $Path.Trim()

    if ($trimmed -match '[\x00-\x1F\x7F]') {
        $errors += "$Label contains control characters."
    }

    if ($trimmed.Contains('"')) {
        $errors += "$Label contains double quote characters."
    }

    return [PSCustomObject]@{ IsValid = ($errors.Count -eq 0); Errors = $errors }
}

function Test-WSLBMDirectoryBoundary {
    <#
    .SYNOPSIS
        Validate high-risk directory boundaries.
    .PARAMETER Policy
        Strict is used for install roots; Relaxed is used for backup roots.
    .OUTPUTS
        PSCustomObject: @{ IsValid=[bool]; Warnings=[string[]]; Errors=[string[]] }
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [ValidateSet("Strict", "Relaxed")]
        [string]$Policy = "Relaxed",

        [string]$Label = "Path"
    )

    $errors = @()
    $warnings = @()

    $trimmed = $Path.Trim()

    # Normalize for comparison
    try {
        $fullPath = [System.IO.Path]::GetFullPath($trimmed)
        $pathRoot = [System.IO.Path]::GetPathRoot($fullPath)
    }
    catch {
        $errors += "$Label cannot be normalized: $($_.Exception.Message)"
        return [PSCustomObject]@{ IsValid = $false; Warnings = $warnings; Errors = $errors }
    }

    # Check: drive root (e.g. C:\)
    $separators = [char[]]@('\', '/')
    $normalizedRoot = $pathRoot.TrimEnd($separators)
    $normalizedFullPath = $fullPath.TrimEnd($separators)
    if ($normalizedFullPath -ieq $normalizedRoot) {
        $errors += "$Label points to a drive root ($normalizedRoot). This is not allowed."
    }

    # Check: UNC / network path
    $isUnc = $trimmed.StartsWith("\\", [System.StringComparison]::OrdinalIgnoreCase)
    if ($isUnc) {
        if ($Policy -eq "Strict") {
            $errors += "$Label is a UNC/network path. Install root requires a local fixed drive."
        }
        else {
            $warnings += "$Label is a UNC/network path. Performance and reliability may be affected."
        }
    }

    # Check: system directories
    $systemDirs = @(
        $env:SystemRoot,
        "$env:SystemRoot\System32",
        "$env:SystemRoot\SysWOW64",
        "$env:ProgramFiles",
        "${env:ProgramFiles(x86)}",
        "$env:ProgramData"
    )
    foreach ($sysDir in $systemDirs) {
        if (-not [string]::IsNullOrWhiteSpace($sysDir) -and (Test-PathIsSameOrChild -ChildPath $trimmed -ParentPath $sysDir)) {
            $errors += "$Label is inside a system directory ($sysDir). This is not allowed."
            break
        }
    }

    # Check: user profile root (exact match)
    $userProfile = $env:USERPROFILE
    if (-not [string]::IsNullOrWhiteSpace($userProfile)) {
        $normalizedUserProfile = [System.IO.Path]::GetFullPath($userProfile).TrimEnd($separators)
        if ($normalizedFullPath -ieq $normalizedUserProfile) {
            $errors += "$Label points to the user profile root ($userProfile). This is not allowed."
        }
    }

    # Check: OneDrive / sync folders
    $dropboxPath = if (Test-Path "$env:USERPROFILE\Dropbox" -ErrorAction SilentlyContinue) { "$env:USERPROFILE\Dropbox" } else { "" }
    $syncFolderPatterns = @(
        @{ Name = "OneDrive"; Path = $env:OneDrive },
        @{ Name = "OneDrive Commercial"; Path = $env:OneDriveCommercial },
        @{ Name = "Dropbox"; Path = $dropboxPath }
    )
    foreach ($sync in $syncFolderPatterns) {
        if (-not [string]::IsNullOrWhiteSpace($sync.Path)) {
            if (Test-PathIsSameOrChild -ChildPath $trimmed -ParentPath $sync.Path) {
                if ($Policy -eq "Strict") {
                    $errors += "$Label is inside a $($sync.Name) folder ($($sync.Path)). Sync folders are not allowed for install root."
                }
                else {
                    $warnings += "$Label is inside a $($sync.Name) folder ($($sync.Path)). Sync folders may cause backup corruption."
                }
                break
            }
        }
    }

    return [PSCustomObject]@{
        IsValid  = ($errors.Count -eq 0)
        Warnings = $warnings
        Errors   = $errors
    }
}

function Test-WSLBMRootOverlap {
    <#
    .SYNOPSIS
        Check whether two configured roots overlap.
    .OUTPUTS
        PSCustomObject: @{ IsValid=[bool]; Errors=[string[]] }
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path1,

        [Parameter(Mandatory = $true)]
        [string]$Path2,

        [string]$Label1 = "Path 1",

        [string]$Label2 = "Path 2"
    )

    $errors = @()

    $isChild12 = Test-PathIsSameOrChild -ChildPath $Path1 -ParentPath $Path2
    $isChild21 = Test-PathIsSameOrChild -ChildPath $Path2 -ParentPath $Path1

    if ($isChild12) {
        $errors += "$Label1 cannot be inside $Label2."
    }
    if ($isChild21) {
        $errors += "$Label2 cannot be inside $Label1."
    }

    return [PSCustomObject]@{ IsValid = ($errors.Count -eq 0); Errors = $errors }
}

function Assert-WSLBMBackupRootPath {
    <#
    .SYNOPSIS
        Validate backup root paths with relaxed boundary checks.
    .OUTPUTS
        PSCustomObject: @{ IsValid=[bool]; Errors=[string[]]; Warnings=[string[]] }
    #>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Path,

        [string]$Label = "Backup Root"
    )

    $allErrors = @()
    $allWarnings = @()

    # 1. Text safety
    $textResult = Test-WSLBMPathTextSafety -Path $Path -Label $Label
    if (-not $textResult.IsValid) { $allErrors += $textResult.Errors }

    if (-not $textResult.IsValid) {
        return [PSCustomObject]@{ IsValid = $false; Errors = $allErrors; Warnings = $allWarnings }
    }

    # 2. Must be absolute path
    if (-not [System.IO.Path]::IsPathRooted($Path.Trim())) {
        $allErrors += "$Label must be an absolute path."
        return [PSCustomObject]@{ IsValid = $false; Errors = $allErrors; Warnings = $allWarnings }
    }

    # 3. Directory boundary (Relaxed)
    $boundaryResult = Test-WSLBMDirectoryBoundary -Path $Path -Policy "Relaxed" -Label $Label
    if (-not $boundaryResult.IsValid) { $allErrors += $boundaryResult.Errors }
    $allWarnings += $boundaryResult.Warnings

    return [PSCustomObject]@{
        IsValid  = ($allErrors.Count -eq 0)
        Errors   = $allErrors
        Warnings = $allWarnings
    }
}

function Assert-WSLBMInstallRootPath {
    <#
    .SYNOPSIS
        Validate install root paths with strict boundary checks.
    .OUTPUTS
        PSCustomObject: @{ IsValid=[bool]; Errors=[string[]]; Warnings=[string[]] }
    #>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Path,

        [string]$Label = "Install Root"
    )

    $allErrors = @()
    $allWarnings = @()

    # 1. Text safety
    $textResult = Test-WSLBMPathTextSafety -Path $Path -Label $Label
    if (-not $textResult.IsValid) { $allErrors += $textResult.Errors }

    if (-not $textResult.IsValid) {
        return [PSCustomObject]@{ IsValid = $false; Errors = $allErrors; Warnings = $allWarnings }
    }

    # 2. Must be absolute path
    if (-not [System.IO.Path]::IsPathRooted($Path.Trim())) {
        $allErrors += "$Label must be an absolute path."
        return [PSCustomObject]@{ IsValid = $false; Errors = $allErrors; Warnings = $allWarnings }
    }

    # 3. Directory boundary (Strict)
    $boundaryResult = Test-WSLBMDirectoryBoundary -Path $Path -Policy "Strict" -Label $Label
    if (-not $boundaryResult.IsValid) { $allErrors += $boundaryResult.Errors }
    $allWarnings += $boundaryResult.Warnings

    # 4. Overlap with backup root
    if ($allErrors.Count -eq 0) {
        $overlapResult = Test-WSLBMRootOverlap -Path1 $Path -Path2 $Global:Config.GlobalBackupRoot -Label1 $Label -Label2 "Backup Root"
        if (-not $overlapResult.IsValid) { $allErrors += $overlapResult.Errors }
    }

    return [PSCustomObject]@{
        IsValid  = ($allErrors.Count -eq 0)
        Errors   = $allErrors
        Warnings = $allWarnings
    }
}

function Write-WSLBMPathValidationResult {
    <#
    .SYNOPSIS
        Display path validation warnings and errors.
    #>
    param(
        [PSCustomObject]$Result,

        [string]$Label = "Path"
    )

    # Compatibility parameter retained for existing call sites.
    $null = $Label

    foreach ($w in $Result.Warnings) {
        Write-Host "[WARN] $w" -ForegroundColor Yellow
    }
    foreach ($e in $Result.Errors) {
        Write-Host "[REJECTED] $e" -ForegroundColor Red
    }
}

# =============================================================================
# 2. Dynamic Resource Scheduler
# =============================================================================

function Get-Optimal7zThreads {
    <#
    .SYNOPSIS
        Calculate a conservative 7-Zip thread count.
    .DESCRIPTION
        Reserve memory for Windows, WSL2 Vmmem growth, and compression overhead.
    .PARAMETER Level
        Compression level (1-9).
    .OUTPUTS
        [int] Recommended thread count.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 9)]
        [int]$Level
    )

    Write-Host "`n[Pre-Flight Resource Check] $(Get-WSLBMScriptVersion) Conservative Model" -ForegroundColor Cyan

    try {
        $os = Get-CimInstance Win32_OperatingSystem | Select-Object -First 1

        $totalRamMB = [math]::Round([double]$os.TotalVisibleMemorySize / 1KB)
        $freeRamMB = [math]::Round([double]$os.FreePhysicalMemory / 1KB)
        $cpuCores = [int]$env:NUMBER_OF_PROCESSORS

        if ($totalRamMB -le 0 -or $freeRamMB -le 0) {
            throw "Invalid memory values"
        }
    }
    catch {
        Write-Host "[WARN] Could not query WMI. Defaulting to safe mode (2threads)." -ForegroundColor Yellow
        return 2
    }

    # Reserve the larger of 15% total RAM or 2.5GB for Windows and apps.
    $reservePercent = $totalRamMB * 0.15
    $reserveFixed = 2560 # 2.5GB
    $baseReserveMB = [math]::Max($reservePercent, $reserveFixed)

    # Reserve for WSL2 Vmmem growth during export.
    $vmmemReserveMB = 3072  # 3GB for Vmmem expansion

    $totalReserveMB = $baseReserveMB + $vmmemReserveMB
    $availableFor7zMB = $freeRamMB - $totalReserveMB

    if ($availableFor7zMB -lt 1024) {
        Write-Host "[WARN] Very low available memory. Using minimum safe mode." -ForegroundColor Yellow
        $availableFor7zMB = 1024
    }

    # Per-thread memory cost includes observed streaming growth.
    $memCostPerThread = switch ($Level) {
        { $_ -ge 9 } { 1800; break }
        { $_ -ge 7 } { 1200; break }  # mx7-8: ~1.0-1.2GB
        { $_ -ge 5 } { 600; break }   # mx5-6: ~500-600MB
        { $_ -ge 3 } { 300; break }   # mx3-4: ~200-300MB
        Default { 150 }   # mx1-2: ~100-150MB
    }

    $ramLimitThreads = [math]::Floor($availableFor7zMB / $memCostPerThread)
    if ($ramLimitThreads -lt 1) { $ramLimitThreads = 1 }

    # Keep CPU headroom for Windows and WSL.
    $cpuLimitThreads = $cpuCores - 2
    if ($cpuLimitThreads -lt 1) { $cpuLimitThreads = 1 }

    # Hard cap keeps the system responsive even on large machines.
    $hardMaxThreads = switch ($Level) {
        { $_ -ge 9 } { 4; break }
        { $_ -ge 7 } { 6; break }
        { $_ -ge 5 } { 8; break }
        Default { 12 }
    }

    $finalThreads = [math]::Min($ramLimitThreads, $cpuLimitThreads)
    $finalThreads = [math]::Min($finalThreads, $hardMaxThreads)
    if ($finalThreads -lt 1) { $finalThreads = 1 }

    Write-Host ("  System RAM: {0} (Free: {1})" -f (Format-Bytes ($totalRamMB * 1MB)), (Format-Bytes ($freeRamMB * 1MB))) -ForegroundColor Gray
    Write-Host ("  Base Reserve  : {0} (OS/Apps)" -f (Format-Bytes ($baseReserveMB * 1MB))) -ForegroundColor Gray
    Write-Host ("  Vmmem Reserve : {0} (WSL2 Dynamic)" -f (Format-Bytes ($vmmemReserveMB * 1MB))) -ForegroundColor Gray
    Write-Host ("  Available     : {0} for 7-Zip" -f (Format-Bytes ($availableFor7zMB * 1MB))) -ForegroundColor Gray
    Write-Host ("  Thread Cost   : ~{0} MB/thread (mx{1}, includes growth)" -f $memCostPerThread, $Level) -ForegroundColor Gray
    Write-Host ("  Limits        : RAM={0} | CPU={1} | Hard={2}" -f $ramLimitThreads, $cpuLimitThreads, $hardMaxThreads) -ForegroundColor Gray

    $bottleneck = "Balanced"
    if ($finalThreads -eq $ramLimitThreads -and $ramLimitThreads -lt $cpuLimitThreads -and $ramLimitThreads -lt $hardMaxThreads) {
        $bottleneck = "RAM-Limited"
        Write-Host ("  Decision: {0}. Using {1} thread(s)." -f $bottleneck, $finalThreads) -ForegroundColor Yellow
    }
    elseif ($finalThreads -eq $hardMaxThreads) {
        $bottleneck = "Safety-Capped"
        Write-Host ("  Decision      : {0}. Using {1} thread(s)." -f $bottleneck, $finalThreads) -ForegroundColor Cyan
    }
    else {
        Write-Host ("  Decision      : {0}. Using {1} thread(s)." -f $bottleneck, $finalThreads) -ForegroundColor Green
    }
    Write-Host "------------------------------------------------" -ForegroundColor DarkGray

    return [int]$finalThreads
}

# =============================================================================
# 3. Core Helper Functions
# =============================================================================

function Get-WSLPathing {
    if (Test-Path "\\wsl.localhost" -ErrorAction SilentlyContinue) {
        $Script:WSLPathPrefix = "\\wsl.localhost"
    }
    elseif (Test-Path "\\wsl$" -ErrorAction SilentlyContinue) {
        $Script:WSLPathPrefix = "\\wsl$"
    }
    else {
        $Script:WSLPathPrefix = "\\wsl.localhost"
    }
}

function Format-Bytes {
    param(
        [AllowNull()]
        [object]$Bytes
    )

    try {
        if ($null -eq $Bytes -or [string]::IsNullOrWhiteSpace([string]$Bytes)) {
            $byteValue = [double]0
        }
        else {
            $byteValue = [double]$Bytes
        }
    }
    catch {
        $byteValue = [double]0
    }

    if ($byteValue -lt 0) { $byteValue = [double]0 }

    if ($byteValue -gt 1GB) { return "{0:N2} GB" -f ($byteValue / 1GB) }
    elseif ($byteValue -gt 1MB) { return "{0:N2} MB" -f ($byteValue / 1MB) }
    else { return "{0:N2} KB" -f ($byteValue / 1KB) }
}

function Format-OptionalByteCount {
    param(
        [AllowNull()]
        [object]$Value,

        [string]$InvalidText = "invalid"
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return ""
    }

    try {
        return Format-Bytes ([long]$Value)
    }
    catch {
        return $InvalidText
    }
}

# =============================================================================
# 2b. Manifest Helpers
#     Read, display, and validate backup manifest metadata without changing flows.
# =============================================================================

function Read-BackupManifest {
    <#
    .SYNOPSIS
        Read manifest.json from a backup directory.
    .DESCRIPTION
        Failures return a legacy fallback object instead of throwing.
    .OUTPUTS
        PSCustomObject, always non-null.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupDirPath
    )

    $fallback = [PSCustomObject]@{
        HasManifest          = $false
        ManifestStatus       = "not_found"
        BackupStatus         = $null
        SevenZipExitCode     = $null
        WarningSummary       = $null
        BackupType           = $null
        SourceDistro         = $null
        CreatedAt            = $null
        ArchiveName          = $null
        ArchiveSizeBytes     = $null
        ArchiveSha256        = $null
        BackupMode           = $null
        WslUser              = $null
        CustomRelativePath   = $null
        MetadataWarning      = $null
        OperationId          = $null
    }

    $manifestPath = Join-Path $BackupDirPath "manifest.json"

    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        return $fallback
    }

    try {
        $raw = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 -ErrorAction Stop
        $json = $raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $fallback.ManifestStatus = "parse_error"
        return $fallback
    }

    if ($null -eq $json -or $null -eq $json.BackupType) {
        $fallback.ManifestStatus = "field_missing"
        return $fallback
    }

    return [PSCustomObject]@{
        HasManifest          = $true
        ManifestStatus       = "ok"
        BackupStatus         = $json.BackupStatus
        SevenZipExitCode     = $json.SevenZipExitCode
        WarningSummary       = $json.WarningSummary
        BackupType           = $json.BackupType
        SourceDistro         = $json.SourceDistro
        CreatedAt            = $json.CreatedAt
        ArchiveName          = $json.ArchiveName
        ArchiveSizeBytes     = $json.ArchiveSizeBytes
        ArchiveSha256        = $json.ArchiveSha256
        BackupMode           = $json.BackupMode
        WslUser              = $json.WslUser
        CustomRelativePath   = $json.CustomRelativePath
        MetadataWarning      = $json.MetadataWarning
        OperationId          = $json.OperationId
    }
}

function Get-BackupManifestStatusText {
    <#
    .SYNOPSIS
        Build shared manifest status display data.
    .DESCRIPTION
        Returns status text, color, operation ID prefix, hash prefix, source, and type.
    .PARAMETER ManifestInfo
        PSCustomObject returned by Read-BackupManifest.
    .OUTPUTS
        PSCustomObject: @{
            StatusText   = "OK" / "legacy" / "corrupted" / "incomplete" / "unavailable"
            Color        = ConsoleColor
            OpIdPrefix   = OperationId prefix or "-"
            HashPrefix   = ArchiveSha256 prefix or "-"
            SourceDistro = Source distro or "-"
            BackupType   = Backup type or "-"
        }
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$ManifestInfo
    )

    $mf = $ManifestInfo

    # Map ManifestStatus to unified display text
    $statusText = "unavailable"
    $color      = [ConsoleColor]::DarkGray

    if ($mf.HasManifest -and $mf.ManifestStatus -eq "ok") {
        if ($mf.BackupStatus -eq "Warning") {
            $statusText = "warning"
            $color      = [ConsoleColor]::Yellow
        }
        else {
            $statusText = "OK"
            $color      = [ConsoleColor]::Green
        }
    }
    else {
        switch ($mf.ManifestStatus) {
            "not_found"    { $statusText = "legacy";     $color = [ConsoleColor]::DarkGray }
            "parse_error"  { $statusText = "corrupted";  $color = [ConsoleColor]::Red }
            "field_missing"{ $statusText = "incomplete"; $color = [ConsoleColor]::Yellow }
            default        { $statusText = "unavailable"; $color = [ConsoleColor]::DarkGray }
        }
    }

    # OpId prefix (first 8 chars)
    $opIdPrefix = "-"
    $operationIdText = if ($null -ne $mf.OperationId) { [string]$mf.OperationId } else { "" }
    if (-not [string]::IsNullOrWhiteSpace($operationIdText) -and $operationIdText.Length -ge 8) {
        $opIdPrefix = $operationIdText.Substring(0, 8)
    } elseif (-not [string]::IsNullOrWhiteSpace($operationIdText)) {
        $opIdPrefix = $operationIdText
    }

    # Hash prefix (first 12 chars)
    $hashPrefix = "-"
    $archiveHashText = if ($null -ne $mf.ArchiveSha256) { [string]$mf.ArchiveSha256 } else { "" }
    if (-not [string]::IsNullOrWhiteSpace($archiveHashText) -and $archiveHashText.Length -ge 12) {
        $hashPrefix = $archiveHashText.Substring(0, 12)
    } elseif (-not [string]::IsNullOrWhiteSpace($archiveHashText)) {
        $hashPrefix = $archiveHashText
    }

    # Source distro / BackupType
    $sourceDistro = if ($mf.SourceDistro) { $mf.SourceDistro } else { "-" }
    $backupType   = if ($mf.BackupType)   { $mf.BackupType }   else { "-" }

    return [PSCustomObject]@{
        StatusText   = $statusText
        Color        = $color
        OpIdPrefix   = $opIdPrefix
        HashPrefix   = $hashPrefix
        SourceDistro = $sourceDistro
        BackupType   = $backupType
    }
}

function Write-ManifestLegacyCompatibilityWarning {
    Write-Host "[WARN] Manifest status: legacy. Proceeding with legacy backup compatibility." -ForegroundColor Yellow
}

function Write-ManifestAuditField {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ShownFields,

        [Parameter(Mandatory = $true)]
        [string]$FieldName,

        [AllowNull()]
        [object]$Value,

        [ConsoleColor]$ForegroundColor = [ConsoleColor]::DarkGray,

        [int]$Indent = 2,

        [int]$Width = 18,

        [string]$Label = ""
    )

    if ($null -eq $Value) { return }
    $valueText = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($valueText)) { return }
    if ($ShownFields.ContainsKey($FieldName)) { return }

    $ShownFields[$FieldName] = $true
    $labelText = if ([string]::IsNullOrWhiteSpace($Label)) { $FieldName } else { $Label }
    $format = "{0}{1,-$Width}: {2}"
    Write-Host ($format -f (" " * $Indent), $labelText, $valueText) -ForegroundColor $ForegroundColor
}

function Show-ManifestAuditInfo {
    <#
    .SYNOPSIS
        Display manifest audit information before restore confirmation.
    .DESCRIPTION
        Missing or damaged manifest data falls back to legacy compatibility.
    .PARAMETER BackupDirPath
        Backup directory path.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupDirPath
    )

    $mf = Read-BackupManifest -BackupDirPath $BackupDirPath

    $manifestStatus = Get-BackupManifestStatusText -ManifestInfo $mf

    if (-not $mf.HasManifest -or $mf.ManifestStatus -ne "ok") {
        Write-Host "  [Manifest] $($manifestStatus.StatusText)" -ForegroundColor $manifestStatus.Color
        Write-Host "    Manifest is unavailable or not trusted; legacy compatibility path remains in use." -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    Write-Host ""
    Write-Host "[Manifest Audit]" -ForegroundColor Cyan
    Write-Host "  Status            : $($manifestStatus.StatusText)" -ForegroundColor $manifestStatus.Color

    $shownManifestFields = @{}
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "BackupStatus" -Value $mf.BackupStatus -ForegroundColor $manifestStatus.Color
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "SevenZipExitCode" -Value $mf.SevenZipExitCode
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "WarningSummary" -Value $mf.WarningSummary -ForegroundColor Yellow
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "BackupType" -Value $mf.BackupType
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "SourceDistro" -Value $mf.SourceDistro
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "CreatedAt" -Value $mf.CreatedAt
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "ArchiveName" -Value $mf.ArchiveName
    $archiveSizeText = Format-OptionalByteCount -Value $mf.ArchiveSizeBytes
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "ArchiveSize" -Value $archiveSizeText
    if ($manifestStatus.HashPrefix -ne "-") {
        Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "ArchiveSha256" -Value "$($manifestStatus.HashPrefix)..."
    }
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "BackupMode" -Value $mf.BackupMode
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "WslUser" -Value $mf.WslUser
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "CustomRelativePath" -Value $mf.CustomRelativePath
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "MetadataWarning" -Value $mf.MetadataWarning -ForegroundColor Yellow
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "OperationId" -Value $mf.OperationId

    Write-Host ""
}

function Get-WSLBMFileSha256WithProgress {
    param(
        [Parameter(Mandatory = $true)]
        [Alias("Path")]
        [string]$LiteralPath,

        [string]$Activity = "Computing SHA256",

        [bool]$AllowCancel = $true,

        [int]$ProgressId = 4101
    )

    $item = Get-Item -LiteralPath $LiteralPath -ErrorAction Stop
    if ($item.PSIsContainer) {
        throw "SHA256 input is a directory: $LiteralPath"
    }
    if ($item.Length -le 0) {
        throw "SHA256 input is empty: $LiteralPath"
    }

    $sha256 = $null
    $stream = $null
    $bufferSize = 4MB
    $buffer = New-Object byte[] $bufferSize
    $emptyBuffer = New-Object byte[] 0
    $totalBytes = [long]$item.Length
    $readBytes = [long]0
    $cancelStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $stream = [System.IO.File]::OpenRead($item.FullName)

        while ($true) {
            $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
            if ($bytesRead -le 0) {
                break
            }

            $null = $sha256.TransformBlock($buffer, 0, $bytesRead, $buffer, 0)
            $readBytes += [long]$bytesRead
            $percent = [math]::Min(99, [int](($readBytes * 100.0) / $totalBytes))
            $status = "{0} / {1}" -f (Format-Bytes $readBytes), (Format-Bytes $totalBytes)
            Write-Progress -Id $ProgressId -Activity $Activity -Status $status -PercentComplete $percent

            if ($AllowCancel -and $cancelStopwatch.ElapsedMilliseconds -ge 500) {
                $cancelStopwatch.Restart()
                if (Test-WSLBMUserCancelRequested) {
                    throw "Archive hash verification cancelled by user."
                }
            }
        }

        $null = $sha256.TransformFinalBlock($emptyBuffer, 0, 0)
        Write-Progress -Id $ProgressId -Activity $Activity -Status "Completed" -PercentComplete 100
        return ([System.BitConverter]::ToString($sha256.Hash) -replace "-", "").ToLowerInvariant()
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        if ($null -ne $sha256) {
            $sha256.Dispose()
        }
        if ($null -ne $cancelStopwatch) {
            $cancelStopwatch.Stop()
        }
        Write-Progress -Id $ProgressId -Activity $Activity -Completed
    }
}

function Test-BackupManifestArchiveConsistency {
    <#
    .SYNOPSIS
        Validate manifest/archive consistency.
    .DESCRIPTION
        Valid manifests fail closed on mismatch; legacy backups remain compatible.
    .PARAMETER BackupDirPath
        Backup directory path.
    .PARAMETER ArchiveFilePath
        Archive file path.
    .PARAMETER ExpectedBackupType
        Expected restore entry type: FULL, USER, or CUSTOM.
    .OUTPUTS
        PSCustomObject: @{ IsLegacy=[bool]; IsConsistent=[bool]; Errors=[string[]] }
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupDirPath,

        [Parameter(Mandatory = $true)]
        [string]$ArchiveFilePath,

        [Parameter(Mandatory = $true)]
        [ValidateSet("FULL", "USER", "CUSTOM")]
        [string]$ExpectedBackupType
    )

    $errors = @()

    $mf = Read-BackupManifest -BackupDirPath $BackupDirPath

    # No valid manifest: legacy fallback.
    if (-not $mf.HasManifest -or $mf.ManifestStatus -ne "ok") {
        return [PSCustomObject]@{
            IsLegacy     = $true
            IsConsistent = $true
            Errors       = @()
        }
    }

    # BackupType check.
    if ($ExpectedBackupType -eq "FULL") {
        if ($mf.BackupType -ne "FULL") {
            $errors += "BackupType mismatch: expected FULL, manifest says '$($mf.BackupType)'"
        }
    }
    else {
        # USER or CUSTOM entry: accept both USER and CUSTOM
        if ($mf.BackupType -notin @("USER", "CUSTOM")) {
            $errors += "BackupType mismatch: expected USER or CUSTOM, manifest says '$($mf.BackupType)'"
        }
    }

    # ArchiveName check.
    $actualFileName = Split-Path $ArchiveFilePath -Leaf
    if ($mf.ArchiveName -and $mf.ArchiveName -ne $actualFileName) {
        $errors += "ArchiveName mismatch: manifest='$($mf.ArchiveName)', actual='$actualFileName'"
    }

    # ArchiveSizeBytes check.
    if ($null -ne $mf.ArchiveSizeBytes -and $mf.ArchiveSizeBytes -gt 0) {
        try {
            $actualItem = Get-Item -LiteralPath $ArchiveFilePath -ErrorAction Stop
            if ($actualItem.Length -ne [long]$mf.ArchiveSizeBytes) {
                $errors += "ArchiveSizeBytes mismatch: manifest=$($mf.ArchiveSizeBytes), actual=$($actualItem.Length)"
            }
        }
        catch {
            $errors += "Cannot read archive file for size check: $($_.Exception.Message)"
        }
    }

    # ArchiveSha256 check.
    if ($mf.ArchiveSha256) {
        Write-Host "  [Manifest] Verifying archive hash; large backups may take time. Press Q to cancel." -ForegroundColor Cyan
        try {
            $actualHash = Get-WSLBMFileSha256WithProgress `
                -LiteralPath $ArchiveFilePath `
                -Activity "Verifying manifest archive SHA256" `
                -AllowCancel $true `
                -ProgressId 4101
            $expectedHash = ([string]$mf.ArchiveSha256).ToLowerInvariant()
            if ($actualHash -ne $expectedHash) {
                $errors += "ArchiveSha256 mismatch: manifest=$($mf.ArchiveSha256), actual=$actualHash"
            }
            else {
                Write-Host "  [Manifest] SHA256 verified" -ForegroundColor Green
            }
        }
        catch {
            if ($_.Exception.Message -like "*cancelled by user*") {
                Write-Host "  [Manifest] SHA256 verification cancelled by user." -ForegroundColor Yellow
                Write-LogEntry "WARN" "Restore-Manifest" "Archive SHA256 verification cancelled by user. Archive=$ArchiveFilePath" -Distro $Script:CurrentDistro
            }
            else {
                Write-Host "  [Manifest] SHA256 verification failed: $($_.Exception.Message)" -ForegroundColor Red
                Write-LogEntry "ERROR" "Restore-Manifest" "Archive SHA256 verification failed. Archive=$ArchiveFilePath | Error=$($_.Exception.Message)" -Distro $Script:CurrentDistro
            }
            $errors += "Cannot compute archive hash: $($_.Exception.Message)"
        }
    }

    if ($errors.Count -gt 0) {
        return [PSCustomObject]@{
            IsLegacy     = $false
            IsConsistent = $false
            Errors       = $errors
        }
    }

    return [PSCustomObject]@{
        IsLegacy     = $false
        IsConsistent = $true
        Errors       = @()
    }
}

function Get-DisplayedBackupCount {
    param(
        [AllowNull()]
        $Backups,

        [int]$MaxCount = 20
    )

    if ($null -eq $Backups) {
        return 0
    }

    return [math]::Min(@($Backups).Count, $MaxCount)
}

function Show-BackupTable {
    param(
        $Backups,

        [switch]$ShowAll
    )

    Write-Host "----------------------------------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host("{0,-4} {1,-11} {2,-20} {3,-12} {4,-15} {5,-16} {6}" -f "#", "Status", "Date", "Size", "Type", "Source", "Note") -ForegroundColor Gray
    Write-Host "----------------------------------------------------------------------------------------------" -ForegroundColor DarkGray

    $limit = if ($ShowAll) { @($Backups).Count } else { Get-DisplayedBackupCount -Backups $Backups }
    for ($i = 0; $i -lt $limit; $i++) {
        $b = $Backups[$i]

        # Read manifest (always returns object, never throws)
        $mf = Read-BackupManifest -BackupDirPath $b.FullName

        # Date: prefer manifest CreatedAt, fallback to filesystem
        $date = if ($mf.HasManifest -and $mf.CreatedAt) {
            try { ([DateTime]$mf.CreatedAt).ToString("yyyy-MM-dd HH:mm") } catch { $b.CreationTime.ToString("yyyy-MM-dd HH:mm") }
        } else {
            $b.CreationTime.ToString("yyyy-MM-dd HH:mm")
        }

        # Note from note.txt
        $note = ""
        $notePath = Join-Path $b.FullName "note.txt"
        if (Test-Path -LiteralPath $notePath -PathType Leaf) {
            $note = (Get-Content -LiteralPath $notePath -ErrorAction SilentlyContinue | Select-Object -First 1)
        }

        # Size: prefer manifest ArchiveSizeBytes, fallback to scanning *.7z
        $sizeStr = "0 KB"
        if ($mf.HasManifest -and $mf.ArchiveSizeBytes) {
            $manifestSizeText = Format-OptionalByteCount -Value $mf.ArchiveSizeBytes
            if ($manifestSizeText) { $sizeStr = $manifestSizeText }
        } else {
            $f = Get-ChildItem $b.FullName -File -Filter "*.7z" -ErrorAction SilentlyContinue
            if ($f) { $sizeStr = Format-Bytes ($f | Measure-Object -Property Length -Sum).Sum }
        }

        # Type: prefer manifest BackupType, fallback to name regex
        $type = "Unknown"
        if ($mf.HasManifest -and $mf.BackupType) {
            $type = switch ($mf.BackupType) {
                "FULL"    { "FULL SYSTEM" }
                "USER"    { "USER HOME" }
                "CUSTOM"  { "CUSTOM" }
                default   { $mf.BackupType }
            }
        } else {
            if ($b.Name -match "FULL") { $type = "FULL SYSTEM" }
            elseif ($b.Name -match "USER") { $type = "USER HOME" }
            elseif ($b.Name -match "CUSTOM") { $type = "CUSTOM" }
        }

        # Unified manifest status via helper
        $st = Get-BackupManifestStatusText -ManifestInfo $mf

        # Source distro from manifest
        $source = if ($mf.SourceDistro) { $mf.SourceDistro } else { "-" }

        # Keep USER/CUSTOM notes compact so warning rows do not overflow the table.
        $noteTags = @()
        if ($type -match "USER|CUSTOM") {
            if ($mf.HasManifest -and $mf.BackupStatus -eq "Warning") {
                $noteTags += "warn"
            }
            if ($mf.HasManifest -and $mf.BackupMode) {
                $modeTag = switch ($mf.BackupMode) {
                    "unc-windows-7zip" { "UNC" }
                    "wsl-export"       { "FULL" }
                    default            { $mf.BackupMode }
                }
                $noteTags += $modeTag
            } elseif (-not $mf.HasManifest) {
                $noteTags += "no-manifest"
            }
        }

        if ($st.OpIdPrefix -ne "-") { $noteTags += $st.OpIdPrefix }
        if ($noteTags.Count -gt 0) {
            $note = ("[{0}] {1}" -f ($noteTags -join " "), $note).Trim()
        }

        Write-Host ("[{0,2}] " -f ($i + 1)) -NoNewline -ForegroundColor Cyan
        Write-Host ("{0,-11}" -f $st.StatusText) -NoNewline -ForegroundColor $st.Color
        Write-Host ("{0,-20} {1,-12} {2,-15} {3,-16} {4}" -f $date, $sizeStr, $type, $source, $note)
    }
    Write-Host "----------------------------------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Status: " -NoNewline -ForegroundColor DarkGray
    Write-Host "OK" -NoNewline -ForegroundColor Green
    Write-Host " | " -NoNewline -ForegroundColor DarkGray
    Write-Host "warning" -NoNewline -ForegroundColor Yellow
    Write-Host " | " -NoNewline -ForegroundColor DarkGray
    Write-Host "legacy" -NoNewline -ForegroundColor DarkGray
    Write-Host " | " -NoNewline -ForegroundColor DarkGray
    Write-Host "corrupted" -NoNewline -ForegroundColor Red
    Write-Host " | " -NoNewline -ForegroundColor DarkGray
    Write-Host "incomplete" -NoNewline -ForegroundColor Yellow
    Write-Host " | " -NoNewline -ForegroundColor DarkGray
    Write-Host "unavailable" -ForegroundColor DarkGray
    if ($Backups.Count -gt $limit) {
        Write-Host ("  Showing only the most recent {0} of {1} backups. Restore/Delete selection is limited to visible entries." -f $limit, $Backups.Count) -ForegroundColor Yellow
        Write-Host "  Enter A at the selection prompt to show all recognized backups." -ForegroundColor Yellow
    }
    elseif ($ShowAll -and $Backups.Count -gt 20) {
        Write-Host ("  Showing all {0} recognized backups. Selection remains limited to listed entries." -f $Backups.Count) -ForegroundColor Yellow
    }
}

# =============================================================================
# 2c. OperationId Helpers
#     Short operation IDs used in console banners and audit logs.
# =============================================================================
$Script:CurrentOperationId = ""

function New-OperationId {
    <#
    .SYNOPSIS
        Generate a short, unique operation ID (timestamp + 4-char random suffix).
    .OUTPUTS
        string, e.g. "20260502-145700-a3f2"
    #>
    $ts = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $suffix = -join ((48..57) + (97..102) | Get-Random -Count 4 | ForEach-Object { [char]$_ })
    return "${ts}-${suffix}"
}

function Write-OperationIdBanner {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OperationId
    )

    Write-Host "[OperationId: $OperationId]" -ForegroundColor Cyan
}

function Write-OverwriteRestoreDestructiveWarning {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$InstallPath,

        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [Parameter(Mandatory = $true)]
        [string]$RequiredPhrase,

        [string]$RestoreTempRoot = "",

        [string]$SafetyNetPath = "",

        [object]$OverwritePathInfo = $null
    )

    $detectedBasePath = "<unavailable>"
    $configInstallPath = "<unavailable>"
    $manualInstallPath = ""
    $manualPathUsed = $false
    if ($null -ne $OverwritePathInfo) {
        if (-not [string]::IsNullOrWhiteSpace([string]$OverwritePathInfo.DetectedBasePath)) {
            $detectedBasePath = [string]$OverwritePathInfo.DetectedBasePath
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$OverwritePathInfo.ConfigInstallPath)) {
            $configInstallPath = [string]$OverwritePathInfo.ConfigInstallPath
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$OverwritePathInfo.ManualInstallPath)) {
            $manualInstallPath = [string]$OverwritePathInfo.ManualInstallPath
        }
        $manualPathUsed = [bool]$OverwritePathInfo.ManualPathUsed
    }
    $restoreTempRootDisplay = if ([string]::IsNullOrWhiteSpace($RestoreTempRoot)) { "<unavailable>" } else { $RestoreTempRoot }
    $safetyNetPathDisplay = if ([string]::IsNullOrWhiteSpace($SafetyNetPath)) { "<unavailable>" } else { $SafetyNetPath }

    Write-Host ""
    Write-Host "[FINAL WARNING] FULL overwrite restore will unregister the existing WSL distro." -ForegroundColor Red
    Write-Host "Target distro                             : $DistroName" -ForegroundColor Yellow
    Write-Host "Existing BasePath detected from registry : $detectedBasePath" -ForegroundColor Yellow
    Write-Host "Config/default install path              : $configInstallPath" -ForegroundColor Yellow
    if ($detectedBasePath -ne "<unavailable>" -and
        $configInstallPath -ne "<unavailable>" -and
        -not [string]::Equals($detectedBasePath, $configInstallPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Host "[WARN] Detected existing WSL BasePath differs from configured InstallRoot default; overwrite restore will use the existing BasePath." -ForegroundColor Yellow
    }
    if ($manualPathUsed) {
        Write-Host "Manual installPath                       : $manualInstallPath" -ForegroundColor Yellow
        Write-Host "Manual path was used because registry BasePath was unavailable." -ForegroundColor Yellow
    }
    Write-Host "Actual installPath to be used after unregister/import: $InstallPath" -ForegroundColor Yellow
    Write-Host "Restore temp root                        : $restoreTempRootDisplay" -ForegroundColor Yellow
    Write-Host "Safety Net path                          : $safetyNetPathDisplay" -ForegroundColor Yellow
    Write-Host "Backup archive                           : $BackupFile" -ForegroundColor Yellow
    Write-Host "Safety Net, manifest, and integrity checks should already have passed; this is still destructive." -ForegroundColor Red
    Write-Host "The current distro can be removed before import is attempted." -ForegroundColor Red
    Write-Host "Type the exact phrase below to continue, or Q/CANCEL to abort:" -ForegroundColor Yellow
    Write-Host "  $RequiredPhrase" -ForegroundColor Cyan
}

function Write-LogEntry {
    param(
        [string]$Level,
        [string]$Action,
        [string]$Message,
        [string]$Distro = $Script:CurrentDistro
    )

    if (-not (Test-Path $Global:LogRoot)) {
        New-Item -ItemType Directory -Path $Global:LogRoot -Force | Out-Null
    }

    $ym = (Get-Date).ToString('yyyy-MM')
    $opsLog = Join-Path $Global:LogRoot "ops-$ym.log"
    $errLog = Join-Path $Global:LogRoot "error-$ym.log"
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
    $durationStr = ""
    if (($Level -eq "SUCCESS" -or $Level -eq "ERROR") -and $Global:BackupState.StartTime) {
        $elapsed = New-TimeSpan -Start $Global:BackupState.StartTime -End (Get-Date)
        $durationStr = "[{0:mm}m {0:ss}s]" -f $elapsed
        $Global:BackupState.StartTime = $null
    }

    $logLine = "$timestamp | $Level | $Distro | $Action | $durationStr $Message"
    try { Add-Content -Path $opsLog -Value $logLine -Encoding UTF8 } catch {
        # Logging failures are intentionally non-fatal for backup/restore flows.
        $null = $_
    }
    if ($Level -eq "ERROR") {
        try { Add-Content -Path $errLog -Value $logLine -Encoding UTF8 } catch {
            # Logging failures are intentionally non-fatal for backup/restore flows.
            $null = $_
        }
    }
}

function Write-WSLBMTextFileUtf8NoBom {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [AllowNull()]
        [string]$Content = ""
    )

    $encoding = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($LiteralPath, $Content, $encoding)
}

function New-BackupDirectory {
    param([string]$path)
    if (-not (Test-Path $path)) {
        try {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
            return $true
        }
        catch {
            Write-Host "[ERROR] Failed to create directory: $path" -ForegroundColor Red
            return $false
        }
    }
    return $true
}

function Write-WSLBMConfigPathValidationResult {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Result,

        [string]$Label = "Configured path",

        [string]$InvalidAction = "The path will not be used until it is reconfigured."
    )

    if (-not $Result.IsValid) {
        Write-Host "[CONFIG ERROR] $Label is invalid. $InvalidAction" -ForegroundColor Red
    }
    foreach ($e in $Result.Errors) {
        Write-Host "[CONFIG ERROR] $e" -ForegroundColor Red
    }
    foreach ($w in $Result.Warnings) {
        Write-Host "[CONFIG WARN] $w" -ForegroundColor Yellow
    }
}

function Test-WSLBMBackupRootReady {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Path,

        [string]$Label = "Backup Root",

        [string]$InvalidAction = "Backup, restore, and delete flows that depend on this path are blocked."
    )

    $pathText = if ($null -eq $Path) { "" } else { [string]$Path }
    $check = Assert-WSLBMBackupRootPath -Path $pathText -Label $Label
    Write-WSLBMConfigPathValidationResult -Result $check -Label $Label -InvalidAction $InvalidAction
    return $check.IsValid
}

function Test-WSLBMInstallRootReady {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Path,

        [string]$Label = "Install Root",

        [string]$InvalidAction = "Restore flows that depend on this path are blocked."
    )

    $pathText = if ($null -eq $Path) { "" } else { [string]$Path }
    $check = Assert-WSLBMInstallRootPath -Path $pathText -Label $Label
    Write-WSLBMConfigPathValidationResult -Result $check -Label $Label -InvalidAction $InvalidAction
    return $check.IsValid
}

function Get-ValidatedBackupScanPath {
    $scanPath = Get-InstanceBackupPath
    $label = "Instance backup path"
    if (-not $scanPath) {
        $scanPath = $Global:Config.GlobalBackupRoot
        $label = "Configured Backup Root"
    }

    $invalidAction = "Backup list, restore, and delete scanning are blocked. Reconfigure Settings or choose a valid custom backup location."
    if (-not (Test-WSLBMBackupRootReady -Path $scanPath -Label $label -InvalidAction $invalidAction)) {
        return $null
    }

    return $scanPath
}

function Import-Config {
    if (Test-Path $Global:ConfigPath) {
        try {
            $json = Get-Content $Global:ConfigPath -Raw | ConvertFrom-Json
            if ($json.GlobalBackupRoot) { $Global:Config.GlobalBackupRoot = $json.GlobalBackupRoot }
            if ($json.InstallRoot) { $Global:Config.InstallRoot = $json.InstallRoot }
            if ($json.SevenZipPath) { $Global:Config.SevenZipPath = $json.SevenZipPath }
            if ($json.CompressionLevel) { $Global:Config.CompressionLevel = $json.CompressionLevel }
            if ($json.DiskThresholds) {
                if ($json.DiskThresholds.Full) { $Global:Config.DiskThresholds.Full = $json.DiskThresholds.Full }
                if ($json.DiskThresholds.User) { $Global:Config.DiskThresholds.User = $json.DiskThresholds.User }
                if ($json.DiskThresholds.Custom) { $Global:Config.DiskThresholds.Custom = $json.DiskThresholds.Custom }
            }
            if ($json.Instances) {
                $Global:Config.Instances = @{}
                $json.Instances.PSObject.Properties | ForEach-Object {
                    $Global:Config.Instances[$_.Name] = @{ BackupPath = $_.Value.BackupPath }
                }
            }
        }
        catch {
            Write-Host "[WARN] Config file malformed. Using defaults." -ForegroundColor Yellow
        }
    }

    $backupRootReady = Test-WSLBMBackupRootReady `
        -Path $Global:Config.GlobalBackupRoot `
        -Label "Configured Backup Root" `
        -InvalidAction "It will not be created or used until Settings is corrected."
    if ($backupRootReady) {
        New-BackupDirectory $Global:Config.GlobalBackupRoot | Out-Null
    }

    $installRootReady = Test-WSLBMInstallRootReady `
        -Path $Global:Config.InstallRoot `
        -Label "Configured Install Root" `
        -InvalidAction "It will not be created or used by default clone restore until Settings is corrected."
    if ($installRootReady) {
        New-BackupDirectory $Global:Config.InstallRoot | Out-Null
    }

    if (-not [string]::IsNullOrWhiteSpace($Global:Config.SevenZipPath)) {
        if (-not (Test-Path -LiteralPath $Global:Config.SevenZipPath -PathType Leaf)) {
            Write-Host "[CONFIG WARN] Configured 7-Zip path not found: $($Global:Config.SevenZipPath). Will fall back to PATH." -ForegroundColor Yellow
        }
    }
}

function Save-Config {
    try {
        $Global:Config | ConvertTo-Json -Depth 5 | Set-Content -Path $Global:ConfigPath -Encoding UTF8
    }
    catch {
        Write-Host "[ERROR] Saving config failed." -ForegroundColor Red
    }
}

# =============================================================================
# 2d. 7z Helpers
#     Resolve configured 7-Zip path and validate archive inputs before use.
# =============================================================================

function Resolve-WSLBMSevenZipPath {
    $sevenZipExe = $Global:Config.SevenZipPath
    if ([string]::IsNullOrWhiteSpace($sevenZipExe)) {
        return "7z"
    }

    if (-not (Test-Path -LiteralPath $sevenZipExe -PathType Leaf)) {
        Write-Host "[WARN] Configured 7-Zip path not found: $sevenZipExe. Falling back to PATH." -ForegroundColor Yellow
        return "7z"
    }

    return $sevenZipExe
}

function Assert-WSLBMSevenZipArchiveInput {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ArchivePath,

        [string]$Context = "7z archive"
    )

    if ([string]::IsNullOrWhiteSpace($ArchivePath)) {
        throw "$Context path is empty."
    }

    if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
        throw "$Context not found or is not a file: $ArchivePath"
    }

    try {
        $archiveItem = Get-Item -LiteralPath $ArchivePath -ErrorAction Stop
    }
    catch {
        throw "$Context cannot be inspected: $ArchivePath ($($_.Exception.Message))"
    }

    if ($archiveItem.Length -le 0) {
        throw "$Context is empty (0 bytes): $ArchivePath"
    }

    return $archiveItem
}

# =============================================================================
# 2e. Read-Only Diagnostics Helpers
#     Environment self-checks only; no backup, restore, delete, WSL mutation, or 7z execution.
# =============================================================================

function ConvertTo-WSLBMDiagnosticsText {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ""
    }

    $parts = @()
    foreach ($part in @($Value)) {
        if ($null -ne $part) {
            $parts += [string]$part
        }
    }

    return (($parts -join [Environment]::NewLine).Trim())
}

function Get-WSLBMFirstDiagnosticsLine {
    param(
        [AllowNull()]
        [object]$Value
    )

    $text = ConvertTo-WSLBMDiagnosticsText -Value $Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return ""
    }

    $lines = @($text -split "\r\n|\n|\r")
    foreach ($line in $lines) {
        $lineText = ([string]$line).Trim()
        if (-not [string]::IsNullOrWhiteSpace($lineText)) {
            return $lineText
        }
    }

    return ""
}

function ConvertTo-WSLBMCleanDiagnosticsText {
    param(
        [AllowNull()]
        [object]$Value
    )

    $text = ConvertTo-WSLBMDiagnosticsText -Value $Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return ""
    }

    $lines = @()
    foreach ($line in @($text -split "\r\n|\n|\r")) {
        $lineText = ([string]$line).Trim()
        if (-not [string]::IsNullOrWhiteSpace($lineText)) {
            $lines += $lineText
        }
    }

    return (($lines -join [Environment]::NewLine).Trim())
}

function Get-WSLBMProbeEncodingCandidates {
    $encodings = @()
    $seenCodePages = @{}

    foreach ($candidate in @(
        { [System.Text.Encoding]::UTF8 },
        { [Console]::OutputEncoding },
        { [System.Text.Encoding]::Default },
        { [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage) },
        { [System.Text.Encoding]::Unicode }
    )) {
        try {
            $encoding = & $candidate
            if ($null -ne $encoding -and -not $seenCodePages.ContainsKey($encoding.CodePage)) {
                $seenCodePages[$encoding.CodePage] = $true
                $encodings += $encoding
            }
        }
        catch {
            $null = $_
        }
    }

    if ($encodings.Count -eq 0) {
        $encodings += [System.Text.Encoding]::UTF8
    }

    return @($encodings)
}

function Get-WSLBMDecodedTextScore {
    param(
        [AllowNull()]
        [string]$Text
    )

    if ([string]::IsNullOrEmpty($Text)) {
        return 0
    }

    $score = 0
    foreach ($ch in $Text.ToCharArray()) {
        $code = [int][char]$ch
        if ($code -eq 0xFFFD) {
            $score += 1000
        }
        elseif ($code -eq 0) {
            $score += 500
        }
        elseif ([char]::IsControl($ch) -and $ch -notin @("`r", "`n", "`t")) {
            $score += 100
        }
    }

    return $score
}

function ConvertFrom-WSLBMProbeBytes {
    param(
        [AllowNull()]
        [byte[]]$Bytes
    )

    if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
        return [PSCustomObject]@{
            Text          = ""
            DecodeWarning = $false
            EncodingName  = ""
        }
    }

    $bestText = ""
    $bestScore = [int]::MaxValue
    $bestEncodingName = ""

    foreach ($encoding in Get-WSLBMProbeEncodingCandidates) {
        try {
            $decoded = $encoding.GetString($Bytes)
            $cleanText = ConvertTo-WSLBMCleanDiagnosticsText -Value $decoded
            $score = Get-WSLBMDecodedTextScore -Text $cleanText
            if ($score -lt $bestScore) {
                $bestScore = $score
                $bestText = $cleanText
                $bestEncodingName = $encoding.WebName
            }
        }
        catch {
            $null = $_
        }
    }

    $decodeWarning = ($bestScore -gt 0)
    if ([string]::IsNullOrWhiteSpace($bestText) -and $Bytes.Length -gt 0) {
        $decodeWarning = $true
    }

    return [PSCustomObject]@{
        Text          = $bestText
        DecodeWarning = $decodeWarning
        EncodingName  = $bestEncodingName
    }
}

function Get-WSLBMReadOnlyWslProbeDisplay {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ProbeResult,

        [Parameter(Mandatory = $true)]
        [string]$CommandText
    )

    $exitCode = $ProbeResult.ExitCode
    $outputLine = Get-WSLBMFirstDiagnosticsLine -Value $ProbeResult.Output
    $errorLine = Get-WSLBMFirstDiagnosticsLine -Value $ProbeResult.Error
    $decodeWarning = [bool]$ProbeResult.DecodeWarning
    $captureException = [bool]$ProbeResult.CaptureException
    $timedOut = [bool]$ProbeResult.TimedOut
    $skippedBecauseDryRun = [bool]$ProbeResult.SkippedBecauseDryRun

    if ($skippedBecauseDryRun) {
        return [PSCustomObject]@{ Status = "WARN"; Detail = "$CommandText skipped because DryRun does not call wsl.exe." }
    }

    if ($timedOut) {
        return [PSCustomObject]@{ Status = "FAIL"; Detail = "$CommandText timed out." }
    }

    if ($captureException) {
        $detail = if ([string]::IsNullOrWhiteSpace($errorLine)) { "$CommandText capture failed." } else { $errorLine }
        return [PSCustomObject]@{ Status = "FAIL"; Detail = $detail }
    }

    if ($null -eq $exitCode) {
        $detail = if ([string]::IsNullOrWhiteSpace($errorLine)) { $outputLine } else { $errorLine }
        if ([string]::IsNullOrWhiteSpace($detail)) {
            $detail = "$CommandText failed without reporting an exit code."
        }
        return [PSCustomObject]@{ Status = "FAIL"; Detail = $detail }
    }

    if ($null -ne $exitCode -and $exitCode -ne 0) {
        $detail = if ([string]::IsNullOrWhiteSpace($errorLine)) { $outputLine } else { $errorLine }
        if ([string]::IsNullOrWhiteSpace($detail) -or $decodeWarning) {
            $detail = "$CommandText failed with exit code $exitCode."
        }
        return [PSCustomObject]@{ Status = "FAIL"; Detail = $detail }
    }

    if ($decodeWarning) {
        return [PSCustomObject]@{ Status = "WARN"; Detail = "WSL probe completed but output could not be decoded cleanly." }
    }

    if ([string]::IsNullOrWhiteSpace($outputLine)) {
        return [PSCustomObject]@{ Status = "WARN"; Detail = "$CommandText completed but returned no readable output." }
    }

    return [PSCustomObject]@{ Status = "OK"; Detail = $outputLine }
}

function New-WSLBMDiagnosticsItem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet("OK", "WARN", "FAIL", "SKIP", "UNKNOWN")]
        [string]$Status,

        [AllowNull()]
        [object]$Detail = "",

        [AllowNull()]
        [object]$Hint = ""
    )

    $itemName = ConvertTo-WSLBMDiagnosticsText -Value $Name
    $itemStatus = ConvertTo-WSLBMDiagnosticsText -Value $Status
    $itemDetail = ConvertTo-WSLBMDiagnosticsText -Value $Detail
    $itemHint = ConvertTo-WSLBMDiagnosticsText -Value $Hint

    $properties = [ordered]@{}
    $properties["Name"] = $itemName
    $properties["Status"] = $itemStatus
    $properties["Detail"] = $itemDetail
    $properties["Hint"] = $itemHint

    return [PSCustomObject]$properties
}

function Test-WSLBMDiagnosticsItem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Probe
    )

    try {
        $probeOutput = & $Probe
        $selectedItem = $null
        foreach ($candidate in @($probeOutput)) {
            if ($null -eq $candidate) {
                continue
            }
            if ($candidate.PSObject.Properties["Name"] -and $candidate.PSObject.Properties["Status"]) {
                $selectedItem = $candidate
                break
            }
        }

        if ($null -eq $selectedItem) {
            return New-WSLBMDiagnosticsItem -Name $Name -Status "UNKNOWN" -Detail "Probe returned no result."
        }

        $statusText = ConvertTo-WSLBMDiagnosticsText -Value $selectedItem.Status
        if ($statusText -notin @("OK", "WARN", "FAIL", "SKIP", "UNKNOWN")) {
            $statusText = "UNKNOWN"
        }

        return New-WSLBMDiagnosticsItem `
            -Name (ConvertTo-WSLBMDiagnosticsText -Value $selectedItem.Name) `
            -Status $statusText `
            -Detail (ConvertTo-WSLBMDiagnosticsText -Value $selectedItem.Detail) `
            -Hint (ConvertTo-WSLBMDiagnosticsText -Value $selectedItem.Hint)
    }
    catch {
        return New-WSLBMDiagnosticsItem -Name $Name -Status "WARN" -Detail $_.Exception.Message -Hint "Diagnostics continued after this warning."
    }
}

function Invoke-WSLBMReadOnlyWslProbe {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("status", "version", "list-verbose", "list-quiet", "list", "whoami")]
        [string]$Probe,

        [string]$Distro = $Script:CurrentDistro,

        [int]$TimeoutSeconds = $Script:ReadOnlyWSLProbeTimeoutSeconds
    )

    $arguments = @(switch ($Probe) {
        "status"       { @("--status") }
        "version"      { @("--version") }
        "list-verbose" { @("--list", "--verbose") }
        "list-quiet"   { @("--list", "--quiet") }
        "list"         { @("--list") }
        "whoami"       { @("-d", $Distro, "whoami") }
    })

    $exitCode = $null
    $outputText = ""
    $errorText = ""
    $decodeWarning = $false
    $captureException = $false
    $timedOut = $false
    $outputEncodingName = ""
    $errorEncodingName = ""

    if ($Global:DryRun) {
        $outputText = switch ($Probe) {
            "list-quiet" { "DRY-RUN-DISTRO" }
            "list"       { "DRY-RUN-DISTRO" }
            "whoami"     { "dryrun" }
            default      { "" }
        }
        $errorText = "DRY RUN: read-only WSL probe skipped; real run still requires WSL."
        Write-LogEntry "WARN" "WSL-Probe-DryRun" "Skipped read-only WSL probe '$Probe'; real run still requires WSL." -Distro $Distro

        return [PSCustomObject]@{
            Probe                = [string]$Probe
            Args                 = @($arguments)
            ExitCode             = 0
            Output               = $outputText
            Error                = $errorText
            DecodeWarning        = $false
            CaptureException     = $false
            TimedOut             = $false
            SkippedBecauseDryRun = $true
            OutputEncoding       = ""
            ErrorEncoding        = ""
        }
    }

    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = "wsl.exe"
        $null = Set-WSLBMProcessStartInfoArguments -StartInfo $startInfo -Arguments $arguments
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.CreateNoWindow = $true

        $process = New-Object System.Diagnostics.Process
        $stdoutBuffer = New-Object System.IO.MemoryStream
        $stderrBuffer = New-Object System.IO.MemoryStream

        try {
            $process.StartInfo = $startInfo
            $null = $process.Start()
            $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdoutBuffer)
            $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderrBuffer)
            if ($TimeoutSeconds -gt 0) {
                $exited = $process.WaitForExit($TimeoutSeconds * 1000)
                if (-not $exited) {
                    $timedOut = $true
                    Stop-WSLBMProcessTree -Process $process -OperationName "WSL-Probe"
                }
            }
            else {
                $process.WaitForExit()
            }

            $null = $process.WaitForExit(5000)
            $null = $stdoutTask.Wait(5000)
            $null = $stderrTask.Wait(5000)
            $exitCode = if ($process.HasExited) { $process.ExitCode } else { $null }

            $stdoutDecoded = ConvertFrom-WSLBMProbeBytes -Bytes $stdoutBuffer.ToArray()
            $stderrDecoded = ConvertFrom-WSLBMProbeBytes -Bytes $stderrBuffer.ToArray()
            $outputText = $stdoutDecoded.Text
            $errorText = $stderrDecoded.Text
            if ($timedOut -and [string]::IsNullOrWhiteSpace($errorText)) {
                $errorText = "Timed out after $TimeoutSeconds seconds."
            }
            $decodeWarning = [bool]($stdoutDecoded.DecodeWarning -or $stderrDecoded.DecodeWarning)
            $outputEncodingName = $stdoutDecoded.EncodingName
            $errorEncodingName = $stderrDecoded.EncodingName
        }
        finally {
            if ($null -ne $stdoutBuffer) { $stdoutBuffer.Dispose() }
            if ($null -ne $stderrBuffer) { $stderrBuffer.Dispose() }
            if ($null -ne $process) { $process.Dispose() }
        }
    }
    catch {
        $captureException = $true
        $errorText = ConvertTo-WSLBMDiagnosticsText -Value $_.Exception.Message
    }

    $properties = [ordered]@{}
    $properties["Probe"] = [string]$Probe
    $properties["Args"] = @($arguments)
    $properties["ExitCode"] = $exitCode
    $properties["Output"] = $outputText
    $properties["Error"] = $errorText
    $properties["DecodeWarning"] = $decodeWarning
    $properties["CaptureException"] = $captureException
    $properties["TimedOut"] = $timedOut
    $properties["SkippedBecauseDryRun"] = $false
    $properties["OutputEncoding"] = $outputEncodingName
    $properties["ErrorEncoding"] = $errorEncodingName

    return [PSCustomObject]$properties
}

function Get-WSLBMSevenZipDiagnostics {
    try {
        $configuredPath = [string]$Global:Config.SevenZipPath
        $configuredText = "(not configured)"
        if (-not [string]::IsNullOrWhiteSpace($configuredPath)) {
            $configuredText = $configuredPath
        }

        $pathCommand = Get-Command "7z" -ErrorAction SilentlyContinue
        $pathSource = ""
        if ($pathCommand) {
            $pathSource = ConvertTo-WSLBMDiagnosticsText -Value $pathCommand.Source
        }

        if (-not [string]::IsNullOrWhiteSpace($configuredPath)) {
            $configuredExists = Test-Path -LiteralPath $configuredPath -PathType Leaf -ErrorAction SilentlyContinue
            if ($configuredExists) {
                $detail = "Configured path exists: $configuredPath"
                return New-WSLBMDiagnosticsItem -Name "7z Path" -Status "OK" -Detail $detail
            }
            if (-not [string]::IsNullOrWhiteSpace($pathSource)) {
                $detail = "Configured path missing: $configuredPath"
                $hint = "PATH fallback available: $pathSource"
                return New-WSLBMDiagnosticsItem -Name "7z Path" -Status "WARN" -Detail $detail -Hint $hint
            }
            $detail = "Configured path missing: $configuredPath"
            return New-WSLBMDiagnosticsItem -Name "7z Path" -Status "FAIL" -Detail $detail -Hint "No PATH fallback found."
        }

        if (-not [string]::IsNullOrWhiteSpace($pathSource)) {
            $detail = "Configured: $configuredText; PATH fallback: $pathSource"
            return New-WSLBMDiagnosticsItem -Name "7z Path" -Status "OK" -Detail $detail
        }

        $detail = "Configured: $configuredText; PATH fallback not found."
        return New-WSLBMDiagnosticsItem -Name "7z Path" -Status "WARN" -Detail $detail -Hint "Install 7-Zip or set an explicit 7z.exe path."
    }
    catch {
        return New-WSLBMDiagnosticsItem -Name "7z Path" -Status "WARN" -Detail $_.Exception.Message -Hint "Diagnostics continued after this warning."
    }
}

function Get-WSLBMPathingDiagnostics {
    $distroName = ConvertTo-WSLBMDiagnosticsText -Value $Script:CurrentDistro
    if ([string]::IsNullOrWhiteSpace($distroName)) {
        return New-WSLBMDiagnosticsItem `
            -Name "WSL UNC Pathing" `
            -Status "UNKNOWN" `
            -Detail "Cannot determine current distro name for UNC path check." `
            -Hint "Select a distro first; diagnostics checks concrete paths like \\wsl.localhost\<DistroName>."
    }

    $candidatePaths = @(
        ("\\wsl.localhost\{0}" -f $distroName),
        ("\\wsl`$\{0}" -f $distroName)
    )

    foreach ($candidatePath in $candidatePaths) {
        try {
            if (Test-Path -LiteralPath $candidatePath -PathType Container -ErrorAction SilentlyContinue) {
                return New-WSLBMDiagnosticsItem -Name "WSL UNC Pathing" -Status "OK" -Detail "$candidatePath is reachable."
            }
        }
        catch {
            $null = $_
        }
    }

    $detail = "Distro UNC path was not reachable: $($candidatePaths -join ' ; ')"
    $hint = "WSL may be stopped, the distro name may not match the UNC provider, permissions may block access, or the WSL UNC provider may not be ready."
    return New-WSLBMDiagnosticsItem -Name "WSL UNC Pathing" -Status "WARN" -Detail $detail -Hint $hint
}

function Add-WSLBMDiagnosticsSnapshotItem {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [System.Collections.Generic.List[object]]$Items,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Probe
    )

    if ($null -eq $Items) { return }

    try {
        $item = Test-WSLBMDiagnosticsItem -Name $Name -Probe $Probe
        if ($null -eq $item) {
            $item = New-WSLBMDiagnosticsItem -Name $Name -Status "UNKNOWN" -Detail "Probe returned no diagnostics item."
        }
        [void]$Items.Add([object]$item)
    }
    catch {
        try {
            $fallbackItem = New-WSLBMDiagnosticsItem -Name $Name -Status "WARN" -Detail $_.Exception.Message -Hint "Diagnostics continued after this warning."
            [void]$Items.Add([object]$fallbackItem)
        }
        catch {
            $null = $_
        }
    }
}

function Get-WSLBMDiagnosticsSnapshot {
    $items = New-Object System.Collections.Generic.List[object]

    Add-WSLBMDiagnosticsSnapshotItem -Items $items -Name "PowerShell" -Probe {
        $edition = ConvertTo-WSLBMDiagnosticsText -Value $PSVersionTable.PSEdition
        $version = ConvertTo-WSLBMDiagnosticsText -Value $PSVersionTable.PSVersion
        $detail = "$edition $version".Trim()
        New-WSLBMDiagnosticsItem -Name "PowerShell" -Status "OK" -Detail $detail
    }

    Add-WSLBMDiagnosticsSnapshotItem -Items $items -Name "Windows / OS" -Probe {
        $osList = @(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop)
        $os = $osList[0]
        if ($null -eq $os) {
            New-WSLBMDiagnosticsItem -Name "Windows / OS" -Status "UNKNOWN" -Detail "Operating system information was not returned."
        }
        else {
            $caption = ConvertTo-WSLBMDiagnosticsText -Value $os.Caption
            $buildNumber = ConvertTo-WSLBMDiagnosticsText -Value $os.BuildNumber
            $detail = "$caption build $buildNumber"
            New-WSLBMDiagnosticsItem -Name "Windows / OS" -Status "OK" -Detail $detail
        }
    }

    Add-WSLBMDiagnosticsSnapshotItem -Items $items -Name "Script Version" -Probe {
        $scriptVersion = Get-WSLBMScriptVersion
        New-WSLBMDiagnosticsItem -Name "Script Version" -Status "OK" -Detail $scriptVersion
    }

    Add-WSLBMDiagnosticsSnapshotItem -Items $items -Name "DryRun" -Probe {
        $status = if ($Global:DryRun) { "OK" } else { "SKIP" }
        $detail = ([bool]$Global:DryRun).ToString()
        New-WSLBMDiagnosticsItem -Name "DryRun" -Status $status -Detail $detail
    }

    Add-WSLBMDiagnosticsSnapshotItem -Items $items -Name "Current OperationId" -Probe {
        $operationId = ConvertTo-WSLBMDiagnosticsText -Value $Script:CurrentOperationId
        if ([string]::IsNullOrWhiteSpace($operationId)) {
            New-WSLBMDiagnosticsItem -Name "Current OperationId" -Status "SKIP" -Detail "No active operation."
        }
        else {
            New-WSLBMDiagnosticsItem -Name "Current OperationId" -Status "OK" -Detail $operationId
        }
    }

    Add-WSLBMDiagnosticsSnapshotItem -Items $items -Name "Backup Root" -Probe {
        $path = ConvertTo-WSLBMDiagnosticsText -Value $Global:Config.GlobalBackupRoot
        $check = Assert-WSLBMBackupRootPath -Path $path -Label "Backup Root"
        $pathExists = Test-Path -LiteralPath $path -PathType Container -ErrorAction SilentlyContinue
        $existsText = if ($pathExists) { "exists" } else { "missing" }
        $detail = "$path ($existsText)"
        if (-not $check.IsValid) {
            $hint = @($check.Errors) -join "; "
            New-WSLBMDiagnosticsItem -Name "Backup Root" -Status "FAIL" -Detail $detail -Hint $hint
        }
        elseif (@($check.Warnings).Count -gt 0) {
            $hint = @($check.Warnings) -join "; "
            New-WSLBMDiagnosticsItem -Name "Backup Root" -Status "WARN" -Detail $detail -Hint $hint
        }
        else {
            New-WSLBMDiagnosticsItem -Name "Backup Root" -Status "OK" -Detail $detail
        }
    }

    Add-WSLBMDiagnosticsSnapshotItem -Items $items -Name "Install Root" -Probe {
        $path = ConvertTo-WSLBMDiagnosticsText -Value $Global:Config.InstallRoot
        $check = Assert-WSLBMInstallRootPath -Path $path -Label "Install Root"
        $pathExists = Test-Path -LiteralPath $path -PathType Container -ErrorAction SilentlyContinue
        $existsText = if ($pathExists) { "exists" } else { "missing" }
        $detail = "$path ($existsText)"
        if (-not $check.IsValid) {
            $hint = @($check.Errors) -join "; "
            New-WSLBMDiagnosticsItem -Name "Install Root" -Status "FAIL" -Detail $detail -Hint $hint
        }
        elseif (@($check.Warnings).Count -gt 0) {
            $hint = @($check.Warnings) -join "; "
            New-WSLBMDiagnosticsItem -Name "Install Root" -Status "WARN" -Detail $detail -Hint $hint
        }
        else {
            New-WSLBMDiagnosticsItem -Name "Install Root" -Status "OK" -Detail $detail
        }
    }

    Add-WSLBMDiagnosticsSnapshotItem -Items $items -Name "7z Path" -Probe {
        Get-WSLBMSevenZipDiagnostics
    }

    Add-WSLBMDiagnosticsSnapshotItem -Items $items -Name "WSL Status" -Probe {
        $statusProbe = Invoke-WSLBMReadOnlyWslProbe -Probe "status"
        $display = Get-WSLBMReadOnlyWslProbeDisplay -ProbeResult $statusProbe -CommandText "wsl.exe --status"
        New-WSLBMDiagnosticsItem -Name "WSL Status" -Status $display.Status -Detail $display.Detail -Hint "Read-only probe: wsl.exe --status"
    }

    Add-WSLBMDiagnosticsSnapshotItem -Items $items -Name "WSL Version" -Probe {
        $versionProbe = Invoke-WSLBMReadOnlyWslProbe -Probe "version"
        $display = Get-WSLBMReadOnlyWslProbeDisplay -ProbeResult $versionProbe -CommandText "wsl.exe --version"
        New-WSLBMDiagnosticsItem -Name "WSL Version" -Status $display.Status -Detail $display.Detail -Hint "Read-only probe: wsl.exe --version"
    }

    Add-WSLBMDiagnosticsSnapshotItem -Items $items -Name "WSL Distros" -Probe {
        $listProbe = Invoke-WSLBMReadOnlyWslProbe -Probe "list-verbose"
        $display = Get-WSLBMReadOnlyWslProbeDisplay -ProbeResult $listProbe -CommandText "wsl.exe --list --verbose"
        $status = $display.Status
        $detail = $display.Detail
        if ($status -eq "OK") {
            $lines = @()
            $outputText = ConvertTo-WSLBMCleanDiagnosticsText -Value $listProbe.Output
            if (-not [string]::IsNullOrWhiteSpace($outputText)) {
                foreach ($rawLine in @($outputText -split "\r\n|\n|\r")) {
                    $lineText = ([string]$rawLine).Trim()
                    if (-not [string]::IsNullOrWhiteSpace($lineText)) {
                        $lines += $lineText
                    }
                }
            }
            if ($lines.Count -gt 1) {
                $detail = "$($lines.Count - 1) distro row(s) reported."
            }
            elseif ($lines.Count -eq 1) {
                $detail = "Only header/output line reported."
            }
        }
        New-WSLBMDiagnosticsItem -Name "WSL Distros" -Status $status -Detail $detail -Hint "Read-only probe: wsl.exe --list --verbose"
    }

    Add-WSLBMDiagnosticsSnapshotItem -Items $items -Name "WSL UNC Pathing" -Probe {
        Get-WSLBMPathingDiagnostics
    }

    Add-WSLBMDiagnosticsSnapshotItem -Items $items -Name "PSScriptAnalyzer" -Probe {
        $pssa = Get-Command Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue
        if ($pssa) {
            $source = ConvertTo-WSLBMDiagnosticsText -Value $pssa.Source
            $detail = "Installed: $source"
            New-WSLBMDiagnosticsItem -Name "PSScriptAnalyzer" -Status "OK" -Detail $detail
        }
        else {
            New-WSLBMDiagnosticsItem -Name "PSScriptAnalyzer" -Status "SKIP" -Detail "Not installed or not available in PATH." -Hint "Diagnostics does not run script analysis."
        }
    }

    Add-WSLBMDiagnosticsSnapshotItem -Items $items -Name "Log Directory" -Probe {
        $logRoot = ConvertTo-WSLBMDiagnosticsText -Value $Global:LogRoot
        $pathExists = Test-Path -LiteralPath $logRoot -PathType Container -ErrorAction SilentlyContinue
        $existsText = if ($pathExists) { "exists" } else { "missing" }
        $status = if ($existsText -eq "exists") { "OK" } else { "WARN" }
        $detail = "$logRoot ($existsText)"
        New-WSLBMDiagnosticsItem -Name "Log Directory" -Status $status -Detail $detail -Hint "Diagnostics does not create log directories."
    }

    $generatedAt = Get-Date
    $itemArray = @($items.ToArray())
    if ($itemArray.Count -eq 0) {
        $itemArray = @(
            New-WSLBMDiagnosticsItem `
                -Name "Diagnostics" `
                -Status "UNKNOWN" `
                -Detail "No diagnostics items were collected." `
                -Hint "Diagnostics completed with an empty snapshot fallback."
        )
    }

    $properties = [ordered]@{}
    $properties["GeneratedAt"] = $generatedAt
    $properties["Items"] = $itemArray

    return [PSCustomObject]$properties
}

function Show-WSLBMDiagnostics {
    Clear-Host
    Write-Host "=== Diagnostics / Environment Self-Check (Read-Only) ===" -ForegroundColor Cyan
    Write-Host "No backup, restore, delete, WSL mutation, or 7z archive operation is performed." -ForegroundColor DarkGray
    Write-Host ""

    try {
        $snapshot = Get-WSLBMDiagnosticsSnapshot
    }
    catch {
        $fallbackItem = New-WSLBMDiagnosticsItem -Name "Diagnostics" -Status "WARN" -Detail $_.Exception.Message -Hint "Diagnostics snapshot failed before all items could be collected."
        $properties = [ordered]@{}
        $properties["GeneratedAt"] = Get-Date
        $properties["Items"] = @($fallbackItem)
        $snapshot = [PSCustomObject]$properties
    }

    try {
        $generatedText = ([datetime]$snapshot.GeneratedAt).ToString("yyyy-MM-dd HH:mm:ss")
    }
    catch {
        $generatedText = ConvertTo-WSLBMDiagnosticsText -Value $snapshot.GeneratedAt
    }
    Write-Host ("Generated: {0}" -f $generatedText) -ForegroundColor DarkGray
    Write-Host ""

    $displayItems = @()
    if ($null -ne $snapshot -and $snapshot.PSObject.Properties["Items"] -and $null -ne $snapshot.Items) {
        foreach ($candidate in @($snapshot.Items)) {
            if ($null -ne $candidate) {
                $displayItems += $candidate
            }
        }
    }
    if ($displayItems.Count -eq 0) {
        $displayItems = @(
            New-WSLBMDiagnosticsItem `
                -Name "Diagnostics" `
                -Status "UNKNOWN" `
                -Detail "Diagnostics snapshot contained no items." `
                -Hint "Empty diagnostics output was replaced with this fallback item."
        )
    }

    foreach ($item in $displayItems) {
        $itemStatus = ConvertTo-WSLBMDiagnosticsText -Value $item.Status
        if ([string]::IsNullOrWhiteSpace($itemStatus)) { $itemStatus = "UNKNOWN" }
        $itemName = ConvertTo-WSLBMDiagnosticsText -Value $item.Name
        $itemDetail = ConvertTo-WSLBMDiagnosticsText -Value $item.Detail
        $itemHint = ConvertTo-WSLBMDiagnosticsText -Value $item.Hint

        $color = switch ($itemStatus) {
            "OK"      { [ConsoleColor]::Green }
            "WARN"    { [ConsoleColor]::Yellow }
            "FAIL"    { [ConsoleColor]::Red }
            "SKIP"    { [ConsoleColor]::DarkGray }
            default   { [ConsoleColor]::DarkGray }
        }

        Write-Host ("[{0,-7}] " -f $itemStatus) -NoNewline -ForegroundColor $color
        Write-Host ("{0,-22} {1}" -f $itemName, $itemDetail)
        if (-not [string]::IsNullOrWhiteSpace($itemHint)) {
            Write-Host ("          {0}" -f $itemHint) -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    Read-Host "Press Enter..."
}

function Test-7zInstalled {
    $foundPath = ""
    if ($Global:Config.SevenZipPath -and (Test-Path -LiteralPath $Global:Config.SevenZipPath -PathType Leaf)) {
        $foundPath = $Global:Config.SevenZipPath
    }
    elseif ((Get-Command "7z" -ErrorAction SilentlyContinue).Source) {
        $foundPath = (Get-Command "7z").Source
    }
    else {
        $paths = @(
            "$env:ProgramFiles\7-Zip\7z.exe",
            "${env:ProgramFiles(x86)}\7-Zip\7z.exe",
            "D:\Tools\7-Zip\7z.exe"
        )
        foreach ($p in $paths) {
            if (Test-Path -LiteralPath $p -PathType Leaf) {
                $foundPath = $p
                break
            }
        }
    }

    if ($foundPath) {
        $Global:Config.SevenZipPath = $foundPath
        Save-Config
        Write-Host "Found 7-Zip: " -NoNewline
        Write-Host $foundPath -ForegroundColor Green
        return $true
    }

    Write-Host "[WARNING] 7-Zip (7z.exe) not found." -ForegroundColor Yellow
    $userPath = Read-Host "Enter full path to 7z.exe"
    $szTextCheck = Test-WSLBMPathTextSafety -Path $userPath -Label "7-Zip path"
    if (-not $szTextCheck.IsValid) {
        Write-WSLBMPathValidationResult -Result $szTextCheck -Label "7-Zip path"
        return $false
    }
    if (Test-Path -LiteralPath $userPath -PathType Leaf) {
        $Global:Config.SevenZipPath = $userPath
        Save-Config
        return $true
    }
    return $false
}

function Test-WSLAvailability {
    if ($Global:DryRun) {
        Write-Host "[WARN] DryRun: WSL availability check skipped; real runs still require WSL." -ForegroundColor Yellow
        Write-LogEntry "WARN" "WSL-Availability" "DryRun skipped WSL availability check; real runs still require WSL."
        return
    }

    $probe = Invoke-WSLBMReadOnlyWslProbe -Probe "status" -TimeoutSeconds $Script:ReadOnlyWSLProbeTimeoutSeconds
    $output = @($probe.Output, $probe.Error)
    $exitCode = $probe.ExitCode

    if ($null -eq $exitCode -or $exitCode -ne 0) {
        $exitText = if ($null -eq $exitCode) { "unknown exit code" } else { "exit code $exitCode" }
        Write-Host "[CRITICAL] WSL availability check failed ($exitText)." -ForegroundColor Red
        $detail = ($output | ForEach-Object { ([string]$_).Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 3) -join " | "
        if (-not [string]::IsNullOrWhiteSpace($detail)) {
            Write-Host "  $detail" -ForegroundColor Yellow
        }
        Write-Host "WSL Backup Manager cannot continue without a successful read-only WSL status check." -ForegroundColor Yellow
        exit 1
    }
}

function Get-WSLUser {
    if ([string]::IsNullOrWhiteSpace($Script:CurrentDistro)) {
        throw "Cannot resolve WSL user: no current distro is selected."
    }

    if (-not (Test-SafeDistroName -Name $Script:CurrentDistro)) {
        throw "Cannot resolve WSL user: current distro name is unsafe."
    }

    $probe = Invoke-WSLBMReadOnlyWslProbe -Probe "whoami" -Distro $Script:CurrentDistro -TimeoutSeconds $Script:ReadOnlyWSLProbeTimeoutSeconds
    $output = @(([string]$probe.Output) -split "\r?\n")
    if (-not $probe.SkippedBecauseDryRun) {
        $output += @(([string]$probe.Error) -split "\r?\n")
    }
    $exitCode = $probe.ExitCode

    $lines = @()
    foreach ($item in $output) {
        $text = ([string]$item).Trim()
        if (-not [string]::IsNullOrWhiteSpace($text)) {
            $lines += $text
        }
    }

    $combinedOutput = ($lines -join " | ")
    if ($null -eq $exitCode -or $exitCode -ne 0) {
        if ([string]::IsNullOrWhiteSpace($combinedOutput)) {
            $combinedOutput = "no output"
        }
        throw "Cannot resolve WSL user for '$Script:CurrentDistro': wsl.exe whoami failed with exit code $exitCode ($combinedOutput)."
    }

    if ($lines.Count -ne 1) {
        throw "Cannot resolve WSL user for '$Script:CurrentDistro': expected one output line, got $($lines.Count)."
    }

    $userName = $lines[0].Trim()
    if ([string]::IsNullOrWhiteSpace($userName)) {
        throw "Cannot resolve WSL user for '$Script:CurrentDistro': whoami returned empty output."
    }

    if ($userName -match "[\r\n]" -or $userName -match "(?i)(^error[:\s]|^failed\b|failure\b|not found|invalid|^usage:|wsl_e_|0x[0-9a-f]{8}|the system cannot|access is denied|specified distribution)") {
        throw "Cannot resolve WSL user for '$Script:CurrentDistro': whoami returned error-like output."
    }

    if ($userName -notmatch '^[A-Za-z_][A-Za-z0-9_-]*[$]?$') {
        throw "Cannot resolve WSL user for '$Script:CurrentDistro': whoami returned an unexpected username '$userName'."
    }

    return $userName
}

function Format-QuotedArgs {
    # Legacy display/fallback helper only. Prefer native process ArgumentList paths
    # for new code; use this only when a legacy preview/fallback cannot accept arrays.
    # This is not a general shell escaping guarantee and must not be used as the
    # default path for real process execution.
    param([string[]]$Arguments)
    $safeArgs = @()
    foreach ($arg in $Arguments) {
        if ($null -eq $arg -or $arg.Length -eq 0 -or $arg -match '[\s`"$%&<>|^]') {
            $safeArgs += (ConvertTo-WSLBMNativeArgumentString -Arguments @($arg))
        }
        else {
            $safeArgs += $arg
        }
    }
    return $safeArgs -join " "
}

function ConvertTo-WSLBMNativeArgumentString {
    # Fallback only: used when ProcessStartInfo.ArgumentList is unavailable.
    param(
        [AllowNull()]
        [string[]]$Arguments = @()
    )

    $quoted = @()
    foreach ($argument in $Arguments) {
        $arg = if ($null -eq $argument) { "" } else { [string]$argument }
        if ($arg.Length -eq 0) {
            $quoted += '""'
            continue
        }

        if ($arg -notmatch '[\s`"$%&<>|^]') {
            $quoted += $arg
            continue
        }

        $builder = New-Object System.Text.StringBuilder
        [void]$builder.Append('"')
        $backslashes = 0
        foreach ($ch in $arg.ToCharArray()) {
            if ($ch -eq '\') {
                $backslashes++
                continue
            }

            if ($ch -eq '"') {
                [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
                [void]$builder.Append('"')
                $backslashes = 0
                continue
            }

            if ($backslashes -gt 0) {
                [void]$builder.Append(('\' * $backslashes))
                $backslashes = 0
            }
            [void]$builder.Append($ch)
        }

        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * ($backslashes * 2)))
        }
        [void]$builder.Append('"')
        $quoted += $builder.ToString()
    }

    return ($quoted -join " ")
}

function Set-WSLBMProcessStartInfoArguments {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.ProcessStartInfo]$StartInfo,

        [AllowNull()]
        [string[]]$Arguments = @()
    )

    $argumentListProperty = $StartInfo.GetType().GetProperty("ArgumentList")
    if ($null -ne $argumentListProperty -and $null -ne $StartInfo.ArgumentList) {
        foreach ($argument in $Arguments) {
            $arg = if ($null -eq $argument) { "" } else { [string]$argument }
            $StartInfo.ArgumentList.Add($arg)
        }
        return "ArgumentList"
    }

    $StartInfo.Arguments = ConvertTo-WSLBMNativeArgumentString -Arguments $Arguments
    return "ArgumentsFallback"
}

function Get-WSLBMProcessTreeIds {
    param(
        [Parameter(Mandatory = $true)]
        [int]$RootProcessId
    )

    $orderedIds = New-Object System.Collections.Generic.List[int]
    $pending = New-Object System.Collections.Generic.Queue[int]
    $pending.Enqueue($RootProcessId)

    while ($pending.Count -gt 0) {
        $currentProcessId = $pending.Dequeue()
        if ($orderedIds.Contains($currentProcessId)) {
            continue
        }

        $orderedIds.Add($currentProcessId)
        try {
            $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$currentProcessId" -ErrorAction Stop)
        }
        catch {
            $children = @()
        }

        foreach ($child in $children) {
            if ($null -ne $child.ProcessId) {
                $pending.Enqueue([int]$child.ProcessId)
            }
        }
    }

    return @($orderedIds.ToArray())
}

function Stop-WSLBMProcessTree {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process]$Process,

        [string]$OperationName = "NativeProcess"
    )

    if ($null -eq $Process) {
        return
    }

    try {
        if ($Process.HasExited) {
            return
        }

        $pidToKill = $Process.Id
        try {
            $taskKill = Start-Process "taskkill" `
                -ArgumentList "/F", "/T", "/PID", $pidToKill `
                -NoNewWindow -Wait -PassThru -ErrorAction Stop
            $null = $taskKill
            $null = $Process.WaitForExit(5000)
        }
        catch {
            try {
                # Fallback mirrors taskkill /T by stopping child PIDs before the root PID.
                $fallbackProcessIds = @(Get-WSLBMProcessTreeIds -RootProcessId $pidToKill)
                [array]::Reverse($fallbackProcessIds)
                foreach ($fallbackProcessId in $fallbackProcessIds) {
                    Stop-Process -Id $fallbackProcessId -Force -ErrorAction SilentlyContinue
                }
                $null = $Process.WaitForExit(5000)
            }
            catch {
                $null = $_
            }
        }
    }
    catch {
        Write-LogEntry "WARN" $OperationName "Failed to stop process tree: $($_.Exception.Message)"
    }
}

function Test-WSLBMUserCancelRequested {
    try {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            return ($key.Key -eq "Q")
        }
    }
    catch {
        return $false
    }

    return $false
}

function Invoke-WSLBMNativeProcessChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [AllowNull()]
        [string[]]$Arguments = @(),

        [string]$OperationName = "NativeProcess",

        [string]$Description = "",

        [int]$TimeoutSeconds = 0,

        [switch]$AllowCancel,

        [switch]$RegisterActiveProcess,

        [string]$WorkingDirectory = "",

        [string]$Distro = $Script:CurrentDistro
    )

    $argumentString = ConvertTo-WSLBMNativeArgumentString -Arguments $Arguments
    $commandPreview = if ([string]::IsNullOrWhiteSpace($argumentString)) { $FilePath } else { "$FilePath $argumentString" }
    $argumentMode = "Unknown"
    $process = $null
    $stdOutTask = $null
    $stdErrTask = $null
    $processId = $null
    $timedOut = $false
    $cancelled = $false
    $errorMessage = ""
    $startedAt = Get-Date

    $previousActiveProcess = $Global:BackupState.ActiveProcess
    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $FilePath
        $argumentMode = Set-WSLBMProcessStartInfoArguments -StartInfo $startInfo -Arguments $Arguments
        if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
            $startInfo.WorkingDirectory = $WorkingDirectory
        }
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.CreateNoWindow = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo

        Write-LogEntry "INFO" $OperationName "$Description | ArgumentMode=$argumentMode | $commandPreview" -Distro $Distro
        if (-not $process.Start()) {
            throw "Process did not start."
        }

        $processId = $process.Id
        if ($RegisterActiveProcess) {
            $Global:BackupState.ActiveProcess = $process
        }

        $stdOutTask = $process.StandardOutput.ReadToEndAsync()
        $stdErrTask = $process.StandardError.ReadToEndAsync()

        while (-not $process.HasExited) {
            if ($TimeoutSeconds -gt 0) {
                $elapsedSeconds = ((Get-Date) - $startedAt).TotalSeconds
                if ($elapsedSeconds -ge $TimeoutSeconds) {
                    $timedOut = $true
                    $errorMessage = "Timed out after $TimeoutSeconds seconds."
                    Write-Host "[ERROR] $Description timed out after $TimeoutSeconds seconds." -ForegroundColor Red
                    Write-LogEntry "ERROR" $OperationName "$Description timed out after $TimeoutSeconds seconds. PID=$processId" -Distro $Distro
                    Stop-WSLBMProcessTree -Process $process -OperationName $OperationName
                    break
                }
            }

            if ($AllowCancel -and (Test-WSLBMUserCancelRequested)) {
                $cancelled = $true
                $errorMessage = "Cancelled by user."
                Write-Host "`n[Abort] User requested cancel..." -ForegroundColor Yellow
                Write-LogEntry "WARN" $OperationName "$Description cancelled by user. PID=$processId" -Distro $Distro
                Stop-WSLBMProcessTree -Process $process -OperationName $OperationName
                break
            }

            Start-Sleep -Milliseconds 200
        }

        $null = $process.WaitForExit(5000)
        if ($null -ne $stdOutTask) {
            $null = $stdOutTask.Wait(5000)
        }
        if ($null -ne $stdErrTask) {
            $null = $stdErrTask.Wait(5000)
        }

        $stdOut = if ($null -ne $stdOutTask -and $stdOutTask.IsCompleted) { [string]$stdOutTask.Result } else { "" }
        $stdErr = if ($null -ne $stdErrTask -and $stdErrTask.IsCompleted) { [string]$stdErrTask.Result } else { "" }
        $combined = (($stdOut, $stdErr) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join [Environment]::NewLine
        $exitCode = if ($process.HasExited) { $process.ExitCode } else { $null }

        if ($timedOut -or $cancelled) {
            return [pscustomobject]@{
                Success              = $false
                ExitCode             = $exitCode
                TimedOut             = $timedOut
                Cancelled            = $cancelled
                StdOut               = $stdOut
                StdErr               = $stdErr
                Output               = $combined
                CombinedOutput       = $combined
                ErrorMessage         = $errorMessage
                ProcessId            = $processId
                ArgumentMode         = $argumentMode
                SkippedBecauseDryRun = $false
                Description          = $Description
            }
        }

        if ($null -eq $exitCode) {
            $errorMessage = "Process did not report an exit code."
        }
        elseif ($exitCode -ne 0) {
            $errorMessage = "Process exited with code $exitCode."
        }

        return [pscustomobject]@{
            Success              = ($null -ne $exitCode -and $exitCode -eq 0)
            ExitCode             = $exitCode
            TimedOut             = $false
            Cancelled            = $false
            StdOut               = $stdOut
            StdErr               = $stdErr
            Output               = $combined
            CombinedOutput       = $combined
            ErrorMessage         = $errorMessage
            ProcessId            = $processId
            ArgumentMode         = $argumentMode
            SkippedBecauseDryRun = $false
            Description          = $Description
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-LogEntry "ERROR" $OperationName "$Description failed to start or monitor: $errorMessage" -Distro $Distro
        return [pscustomobject]@{
            Success              = $false
            ExitCode             = $null
            TimedOut             = $timedOut
            Cancelled            = $cancelled
            StdOut               = ""
            StdErr               = ""
            Output               = ""
            CombinedOutput       = ""
            ErrorMessage         = $errorMessage
            ProcessId            = $processId
            ArgumentMode         = $argumentMode
            SkippedBecauseDryRun = $false
            Description          = $Description
        }
    }
    finally {
        if ($RegisterActiveProcess) {
            $Global:BackupState.ActiveProcess = $previousActiveProcess
        }
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}

function Close-VSCodeSafely {
    $ideProcessNames = @("Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf")
    if (Get-Process -Name $ideProcessNames -ErrorAction SilentlyContinue) {
        Write-Host "[WARN] VS Code is running. It might lock WSL files." -ForegroundColor Yellow
        $ans = Read-Host "Press [Enter] to continue anyway, or [Q] to cancel"
        if ($ans -eq "Q" -or $ans -eq "q") { return $false }
    }
    return $true
}

function Get-WSLBMUncShareRoot {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ""
    }

    if ($Path -match '^(\\\\[^\\]+\\[^\\]+)') {
        return $Matches[1]
    }

    return ""
}

function Resolve-WSLBMSpaceCheckPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    if ([string]::IsNullOrWhiteSpace($expanded)) {
        throw "Path is empty."
    }

    if (Test-Path -LiteralPath $expanded -ErrorAction SilentlyContinue) {
        return [System.IO.Path]::GetFullPath($expanded)
    }

    $candidate = $expanded
    while (-not [string]::IsNullOrWhiteSpace($candidate)) {
        $parent = Split-Path -Path $candidate -Parent -ErrorAction SilentlyContinue
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $candidate) {
            break
        }

        if (Test-Path -LiteralPath $parent -ErrorAction SilentlyContinue) {
            return [System.IO.Path]::GetFullPath($parent)
        }

        $candidate = $parent
    }

    $root = [System.IO.Path]::GetPathRoot($expanded)
    if (-not [string]::IsNullOrWhiteSpace($root)) {
        if ($root -match '^\\\\') {
            $shareRoot = Get-WSLBMUncShareRoot -Path $expanded
            if (-not [string]::IsNullOrWhiteSpace($shareRoot)) {
                return $shareRoot
            }
        }
        return $root
    }

    throw "Cannot determine a space check path for '$Path'."
}

function Get-WSLBMPathFreeSpaceInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$Label = "Path",

        [string]$LogAction = "Space",

        [string]$Distro = $Script:CurrentDistro
    )

    $tempDriveName = $null
    try {
        $checkPath = Resolve-WSLBMSpaceCheckPath -Path $Path
        $fullPath = [System.IO.Path]::GetFullPath($checkPath)
        $root = [System.IO.Path]::GetPathRoot($fullPath)
        $availableBytes = $null
        $sourceKey = ""
        $sourceType = ""

        if (-not [string]::IsNullOrWhiteSpace($root) -and $root -match '^[A-Za-z]:\\') {
            $driveInfo = New-Object -TypeName System.IO.DriveInfo -ArgumentList $root
            if (-not $driveInfo.IsReady) {
                throw "Drive '$root' is not ready."
            }
            $availableBytes = [long]$driveInfo.AvailableFreeSpace
            $sourceKey = $driveInfo.Name
            $sourceType = if ($driveInfo.DriveType -eq [System.IO.DriveType]::Network) { "MappedDrive" } else { "LocalDrive" }
        }

        if ($null -eq $availableBytes) {
            $matchedDrive = $null
            foreach ($drive in (Get-PSDrive -PSProvider FileSystem -ErrorAction Stop)) {
                if ($null -eq $drive.Free -or [string]::IsNullOrWhiteSpace($drive.Root)) {
                    continue
                }

                if ($fullPath.StartsWith($drive.Root, [System.StringComparison]::OrdinalIgnoreCase)) {
                    if ($null -eq $matchedDrive -or $drive.Root.Length -gt $matchedDrive.Root.Length) {
                        $matchedDrive = $drive
                    }
                }
            }

            if ($null -ne $matchedDrive) {
                $availableBytes = [long]$matchedDrive.Free
                $sourceKey = $matchedDrive.Root
                $sourceType = if ($matchedDrive.Root -match '^\\\\') { "MappedUNCPSDrive" } else { "FileSystemPSDrive" }
            }
        }

        if ($null -eq $availableBytes -and $fullPath -match '^\\\\') {
            $shareRoot = Get-WSLBMUncShareRoot -Path $fullPath
            if ([string]::IsNullOrWhiteSpace($shareRoot)) {
                throw "Cannot parse UNC share root for $fullPath"
            }

            $tempDriveName = "WSLBM" + (Get-Random -Minimum 100000 -Maximum 999999)
            $null = New-PSDrive -Name $tempDriveName -PSProvider FileSystem -Root $shareRoot -ErrorAction Stop
            $tempDrive = Get-PSDrive -Name $tempDriveName -ErrorAction Stop
            if ($null -eq $tempDrive.Free) {
                throw "Temporary UNC PSDrive did not report free space."
            }

            $availableBytes = [long]$tempDrive.Free
            $sourceKey = $shareRoot
            $sourceType = "TemporaryUNCPSDrive"
        }

        if ($null -eq $availableBytes) {
            throw "Cannot determine available free space for ${Label}: $Path"
        }

        Write-LogEntry "INFO" $LogAction "Space source=$sourceType | Label=$Label | Target=$Path | CheckPath=$checkPath | Source=$sourceKey | Available=$(Format-Bytes $availableBytes)" -Distro $Distro
        return [pscustomobject]@{
            Success        = $true
            TargetPath     = $Path
            CheckPath      = $checkPath
            FullPath       = $fullPath
            AvailableBytes = $availableBytes
            SourceKey      = $sourceKey
            SourceType     = $sourceType
            Reason         = ""
        }
    }
    catch {
        $message = $_.Exception.Message
        Write-LogEntry "ERROR" $LogAction "Unable to determine free space. Label=$Label | Target=$Path | Reason=$message" -Distro $Distro
        return [pscustomobject]@{
            Success        = $false
            TargetPath     = $Path
            CheckPath      = $null
            FullPath       = $Path
            AvailableBytes = $null
            SourceKey      = ""
            SourceType     = "Unknown"
            Reason         = $message
        }
    }
    finally {
        if (-not [string]::IsNullOrWhiteSpace($tempDriveName)) {
            Remove-PSDrive -Name $tempDriveName -ErrorAction SilentlyContinue
        }
    }
}

function Test-DiskSpace {
    param($gb)
    $path = if (Get-InstanceBackupPath) { Get-InstanceBackupPath } else { $Global:Config.GlobalBackupRoot }
    $requiredBytes = [long]([double]$gb * 1GB)
    $space = Get-WSLBMPathFreeSpaceInfo -Path $path -Label "Backup destination" -LogAction "Backup-Space" -Distro $Script:CurrentDistro
    if (-not $space.Success) {
        Write-Host "[ERROR] Cannot verify disk space for backup destination: $($space.Reason)" -ForegroundColor Red
        return $false
    }

    if ($space.AvailableBytes -lt $requiredBytes) {
        Write-Host "Low Disk Space on $($space.SourceKey)! Need $gb GB, only $(Format-Bytes $space.AvailableBytes) free." -ForegroundColor Red
        Write-LogEntry "ERROR" "Backup-Space" "Insufficient space. Required=$(Format-Bytes $requiredBytes) | Available=$(Format-Bytes $space.AvailableBytes) | Path=$path | Source=$($space.SourceType)" -Distro $Script:CurrentDistro
        return $false
    }

    Write-LogEntry "INFO" "Backup-Space" "Disk space check passed. Required=$(Format-Bytes $requiredBytes) | Available=$(Format-Bytes $space.AvailableBytes) | Path=$path | Source=$($space.SourceType)" -Distro $Script:CurrentDistro
    return $true
}

# =============================================================================
# 4. Lock, Monitor & Cleanup
# =============================================================================

function New-LockFile {
    param(
        [string]$OperationType,
        [string]$TargetDir
    )
    $lockPath = Join-Path $TargetDir ".backup-in-progress"
    if (Test-Path $lockPath) {
        Remove-Item $lockPath -Force -ErrorAction SilentlyContinue
    }
    $lockContent = @"
Start: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Operation: $OperationType
User: $env:USERNAME
PID: $PID
Distro: $Script:CurrentDistro
"@
    Set-Content -Path $lockPath -Value $lockContent -Encoding UTF8
    $Global:BackupState.LockFile = $lockPath
    $Global:BackupState.StartTime = Get-Date
}

function Remove-LockFile {
    try {
        if ($Global:BackupState.LockFile -and (Test-Path -LiteralPath $Global:BackupState.LockFile)) {
            Remove-Item -LiteralPath $Global:BackupState.LockFile -Force -ErrorAction Stop
        }
    }
    catch {
        Write-LogEntry "WARN" "Lock-Remove" "Failed to remove lock file '$($Global:BackupState.LockFile)': $($_.Exception.Message)"
    }
    finally {
        $Global:BackupState.LockFile = $null
    }
}

function Stop-ActiveBackupProcesses {
    <#
    .SYNOPSIS
        Stop the active backup process tree.
    .DESCRIPTION
        Uses taskkill with retries, then falls back to recursive Stop-Process.
    #>
    if ($null -eq $Global:BackupState.ActiveProcess) {
        return
    }

    if ($Global:BackupState.ActiveProcess.HasExited) {
        $Global:BackupState.ActiveProcess = $null
        return
    }

    $pidToKill = $Global:BackupState.ActiveProcess.Id
    Write-Host "  [Cleanup] Terminating process tree (PID: $pidToKill)..." -NoNewline -ForegroundColor DarkGray

    $maxAttempts = 3
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $null = Start-Process "taskkill" `
                -ArgumentList "/F", "/T", "/PID", $pidToKill `
                -NoNewWindow -Wait -PassThru -ErrorAction Stop

            # Wait up to 5 seconds for process exit.
            $waitResult = $Global:BackupState.ActiveProcess.WaitForExit(5000)

            if ($waitResult -or $Global:BackupState.ActiveProcess.HasExited) {
                Write-Host " Done." -ForegroundColor DarkGray
                $Global:BackupState.ActiveProcess = $null
                return
            }
        }
        catch {
            # Fallback mirrors taskkill /T by stopping child PIDs before the root PID.
            try {
                $fallbackProcessIds = @(Get-WSLBMProcessTreeIds -RootProcessId $pidToKill)
                [array]::Reverse($fallbackProcessIds)
                foreach ($fallbackProcessId in $fallbackProcessIds) {
                    Stop-Process -Id $fallbackProcessId -Force -ErrorAction SilentlyContinue
                }
                Start-Sleep -Milliseconds 500
                if ($Global:BackupState.ActiveProcess.HasExited) {
                    Write-Host " Done (fallback)." -ForegroundColor DarkGray
                    $Global:BackupState.ActiveProcess = $null
                    return
                }
            }
            catch {
                $null = $_
            }
        }
        if ($attempt -lt $maxAttempts) {
            Start-Sleep -Milliseconds 1000
        }
    }

    Write-Host " Warning: Process may still be running." -ForegroundColor Yellow
    $Global:BackupState.ActiveProcess = $null
}

function Set-BackupCleanupAllowedRootFromDestination {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$BackupDir
    )

    $Global:BackupState.SelectedBackupRoot = $null
    $Global:BackupState.CleanupAllowedRoot = $null

    if ([string]::IsNullOrWhiteSpace($BackupDir)) {
        return
    }

    try {
        $selectedRoot = Split-Path -Path $BackupDir -Parent
        if (-not [string]::IsNullOrWhiteSpace($selectedRoot)) {
            $Global:BackupState.SelectedBackupRoot = $selectedRoot
            $Global:BackupState.CleanupAllowedRoot = $selectedRoot
        }
    }
    catch {
        $Global:BackupState.SelectedBackupRoot = $null
        $Global:BackupState.CleanupAllowedRoot = $null
    }
}

function Clear-BackupCleanupAllowedRoot {
    $Global:BackupState.SelectedBackupRoot = $null
    $Global:BackupState.CleanupAllowedRoot = $null
}

function Remove-FailedBackupDir {
    <#
    .SYNOPSIS
        Clean up a failed backup directory.
    .DESCRIPTION
        Requires the in-progress lock and the recorded cleanup root.
    #>
    $dir = $Global:BackupState.CurrentDir
    if (-not $dir -or -not (Test-Path $dir)) {
        return
    }

    $lockFile = Join-Path $dir ".backup-in-progress"
    if (-not (Test-Path $lockFile)) {
        return
    }

    $allowedRoot = $Global:BackupState.CleanupAllowedRoot
    if ([string]::IsNullOrWhiteSpace($allowedRoot)) {
        Write-Host "  [Cleanup] Skipped failed backup folder cleanup: no selected backup root is recorded for this operation." -ForegroundColor Yellow
        Write-LogEntry "WARN" "Backup-Cleanup" "Skipped failed backup cleanup because CleanupAllowedRoot is empty. Dir=$dir"
        return
    }

    if ($Global:DryRun) {
        Write-Host "  [Cleanup] DryRun preview for failed backup folder cleanup..." -NoNewline -ForegroundColor DarkGray
    }
    else {
        Write-Host "  [Cleanup] Removing failed backup folder..." -NoNewline -ForegroundColor DarkGray
    }

    # Retry protected cleanup up to 3 times.
    $lastDeleteResult = $null
    for ($i = 1; $i -le 3; $i++) {
        $deleteResult = Invoke-ProtectedBackupPathDelete `
            -Path $dir `
            -Mode "FailedBackupCleanup" `
            -Reason "Failed backup cleanup" `
            -AllowedRoot $allowedRoot `
            -RequireInProgressLock
        $lastDeleteResult = $deleteResult

        if ($deleteResult.Success) {
            if ($deleteResult.SkippedBecauseDryRun) {
                Write-Host " Previewed." -ForegroundColor DarkGray
            }
            else {
                Write-Host " Done." -ForegroundColor DarkGray
            }
            return
        }

        if ($i -lt 3) {
            Start-Sleep -Milliseconds 1500
        }
    }

    Write-Host " Failed (files may be locked)." -ForegroundColor Yellow
    if ($lastDeleteResult -and -not [string]::IsNullOrWhiteSpace($lastDeleteResult.Reason)) {
        Write-Host "  Reason: $($lastDeleteResult.Reason)" -ForegroundColor Yellow
    }
    Write-Host "  Please manually delete: $dir" -ForegroundColor Yellow
}

function Watch-Process-With-Monitor {
    <#
    .SYNOPSIS
        Monitor a process and support user cancellation.
    #>
    param(
        $Process,
        $MonitoredFile
    )

    # Compatibility parameter retained for older monitor call sites.
    $null = $MonitoredFile

    while (-not $Process.HasExited) {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq "Q") {
                Write-Host "`n[Abort] User requested cancel..." -ForegroundColor Yellow
                Stop-ActiveBackupProcesses
                throw "UserCancelled"
            }
        }
        Start-Sleep -Milliseconds 200
    }
    Write-Host ""
}

# =============================================================================
# 5. Interactive Helpers
# =============================================================================

function Select-Compression-Interactive {
    $current = $Global:Config.CompressionLevel
    Write-Host "Compression Level: " -NoNewline
    Write-Host "mx$current" -ForegroundColor Green

    while ($true) {
        Write-Host "Press [1-9] to change, or [Enter] to keep current." -ForegroundColor DarkGray
        $userLevel = Read-Host "Selection"

        if ([string]::IsNullOrWhiteSpace($userLevel)) {
            return
        }
        if ($userLevel -in @("q", "Q")) { return }

        if ($userLevel -match '^[1-9]$') {
            $Global:Config.CompressionLevel = [int]$userLevel
            Save-Config
            Write-Host " -> Set to mx$userLevel" -ForegroundColor Yellow
            return
        }

        Write-Host "Invalid level. Please enter 1-9." -ForegroundColor Red
    }
}

# =============================================================================
# 6. Path Logic & Selection
# =============================================================================

function Select-WSLDistro {
    param([switch]$Force)

    if ($Force) { $Script:CurrentDistro = $null }

    try {
        $quietProbe = Invoke-WSLBMReadOnlyWslProbe -Probe "list-quiet" -TimeoutSeconds $Script:ReadOnlyWSLProbeTimeoutSeconds
        $raw = @(([string]$quietProbe.Output) -split "\r?\n")
        if (-not $quietProbe.SkippedBecauseDryRun) {
            $raw += @(([string]$quietProbe.Error) -split "\r?\n")
        }
        $quietExitCode = $quietProbe.ExitCode
        if ($null -eq $quietExitCode -or $quietExitCode -ne 0) {
            $exitText = if ($null -eq $quietExitCode) { "unknown exit code" } else { "exit code $quietExitCode" }
            $detail = ($raw | ForEach-Object { ([string]$_).Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 3) -join " | "
            Write-Host "[ERROR] Failed to list WSL distributions with wsl.exe --list --quiet ($exitText)." -ForegroundColor Red
            if (-not [string]::IsNullOrWhiteSpace($detail)) {
                Write-Host "  $detail" -ForegroundColor Yellow
            }
            exit 1
        }

        if (-not $raw) {
            $listProbe = Invoke-WSLBMReadOnlyWslProbe -Probe "list" -TimeoutSeconds $Script:ReadOnlyWSLProbeTimeoutSeconds
            $rawList = @(([string]$listProbe.Output) -split "\r?\n")
            if (-not $listProbe.SkippedBecauseDryRun) {
                $rawList += @(([string]$listProbe.Error) -split "\r?\n")
            }
            $listExitCode = $listProbe.ExitCode
            if ($null -eq $listExitCode -or $listExitCode -ne 0) {
                $exitText = if ($null -eq $listExitCode) { "unknown exit code" } else { "exit code $listExitCode" }
                $detail = ($rawList | ForEach-Object { ([string]$_).Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 3) -join " | "
                Write-Host "[ERROR] Failed to list WSL distributions with wsl.exe --list ($exitText)." -ForegroundColor Red
                if (-not [string]::IsNullOrWhiteSpace($detail)) {
                    Write-Host "  $detail" -ForegroundColor Yellow
                }
                exit 1
            }

            $raw = @()
            foreach ($line in $rawList) {
                $clean = $line -replace " \(Default\)", "" -replace " \(默认\)", "" -replace "`0", ""
                $clean = $clean.Trim()
                if ($clean -and $clean -notmatch "Windows Subsystem" -and $clean -notmatch "^The default") {
                    $raw += $clean
                }
            }
        }
    }
    catch {
        Write-Host "[ERROR] Failed to list distributions." -ForegroundColor Red
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Yellow
        exit 1
    }

    $distros = @()
    foreach ($r in $raw) {
        $t = $r -replace "[\x00-\x1F\x7F]", ""
        $t = $t.Trim()
        if ($t) { $distros += $t }
    }

    if ($distros.Count -eq 0) {
        Write-Host "[ERROR] No WSL distributions found." -ForegroundColor Red
        exit
    }

    if ($Script:CurrentDistro -and -not $Force) { return }

    while ($true) {
        Clear-Host
        Write-Host "=== Select Target Distribution ===" -ForegroundColor Cyan

        for ($i = 0; $i -lt $distros.Count; $i++) {
            $d = $distros[$i]
            $safetyIcon = if (Test-SafeDistroName -Name $d) { "[OK]" } else { "[!]" }
            Write-Host ("[$($i+1)] {0} {1}" -f $d, $safetyIcon)
        }
        Write-Host "[0] Exit/Cancel" -ForegroundColor Gray

        $sel = Read-Host "Select Number"

        if ($sel -eq "0" -or $sel -eq "q" -or $sel -eq "Q") {
            if ($Force) { return }
            exit
        }

        if ($sel -match '^\d+$') {
            $selNum = [int]$sel
            if ($selNum -gt 0 -and $selNum -le $distros.Count) {
                $selectedDistro = $distros[$selNum - 1]

                if (-not (Test-SafeDistroName -Name $selectedDistro)) {
                    Write-Host "[SECURITY WARNING] This distro name contains unsafe characters!" -ForegroundColor Red
                    Write-Host "Name: '$selectedDistro'" -ForegroundColor Yellow
                    Write-Host "For security reasons, please rename this distro before using this tool." -ForegroundColor Yellow
                    Read-Host "Press Enter to select another..."
                    continue
                }

                $Script:CurrentDistro = $selectedDistro
                Write-Host "Target set to: $Script:CurrentDistro" -ForegroundColor Green
                Start-Sleep -Milliseconds 500
                return
            }
        }

        Write-Host "Invalid selection. Please try again." -ForegroundColor Red
        Start-Sleep -Milliseconds 500
    }
}

function Get-InstanceBackupPath {
    if ($Global:Config.Instances.ContainsKey($Script:CurrentDistro)) {
        return $Global:Config.Instances[$Script:CurrentDistro].BackupPath
    }
    return $null
}

function Set-InstanceBackupPath {
    param($newPath)
    if (-not $Global:Config.Instances.ContainsKey($Script:CurrentDistro)) {
        $Global:Config.Instances[$Script:CurrentDistro] = @{}
    }
    $Global:Config.Instances[$Script:CurrentDistro].BackupPath = $newPath
    Save-Config
}

function Clear-InstanceBackupPath {
    if ($Global:Config.Instances.ContainsKey($Script:CurrentDistro)) {
        $Global:Config.Instances[$Script:CurrentDistro].BackupPath = $null
        Save-Config
        Write-LogEntry "INFO" "Config" "Cleared saved backup destination for distro '$Script:CurrentDistro'." -Distro $Script:CurrentDistro
    }
}

function Get-BackupDestination {
    param(
        [string]$defaultName,
        [switch]$PreviewOnly
    )
    $savedPath = Get-InstanceBackupPath
    Write-Host ""
    Write-Host "Select Destination:"
    if ($PreviewOnly) {
        Write-Host "  DRY RUN: destination selection will not create directories or save defaults." -ForegroundColor Yellow
    }
    $globalPath = $Global:Config.GlobalBackupRoot
    if ($savedPath) {
        Write-Host "  [1] Instance Default ($savedPath)" -ForegroundColor Green
        Write-Host "  [2] Global Default   ($globalPath)" -ForegroundColor Gray
        Write-Host "  [3] Custom Location  (Save As...)" -ForegroundColor Yellow
        $valid = @("1", "2", "3")
    }
    else {
        Write-Host "  [1] Global Default   ($globalPath)" -ForegroundColor Green
        Write-Host "  [2] Custom Location  (Save As...)" -ForegroundColor Yellow
        $valid = @("1", "2")
    }

    while ($true) {
        $sel = Read-Host "Choose (or Q to cancel)"
        if ($sel -in @("q", "Q")) { return $null }
        if ($sel -in $valid) { break }
        Write-Host "Invalid option." -ForegroundColor Red
    }

    $finalPath = ""
    if ($savedPath) {
        switch ($sel) {
            "1" { $finalPath = $savedPath }
            "2" { $finalPath = $globalPath }
            "3" { $finalPath = "CUSTOM" }
        }
    }
    else {
        switch ($sel) {
            "1" { $finalPath = $globalPath }
            "2" { $finalPath = "CUSTOM" }
        }
    }

    $usingSavedInstanceDefault = ($savedPath -and $sel -eq "1")
    if ($usingSavedInstanceDefault -and $finalPath -ne "CUSTOM" -and -not (Test-Path -LiteralPath $finalPath -ErrorAction SilentlyContinue)) {
        $savedValidation = Assert-WSLBMBackupRootPath -Path $finalPath -Label "Saved instance default destination"
        Write-WSLBMPathValidationResult -Result $savedValidation -Label "Saved instance default destination"
        if (-not $savedValidation.IsValid) {
            Write-Host "[CONFIG ERROR] Saved instance default destination is blocked. Choose a new path or clear the saved default in Settings." -ForegroundColor Red
            return $null
        }

        Write-Host "[WARN] Saved instance default path does not exist: $finalPath" -ForegroundColor Yellow
        Write-LogEntry "WARN" "Config" "Saved instance backup destination does not exist: $finalPath" -Distro $Script:CurrentDistro

        if ($PreviewOnly) {
            Write-Host "  DRY RUN: would offer to create this directory, choose a new path, clear the saved default, or cancel." -ForegroundColor Yellow
            Write-Host "  DRY RUN: would clear only this distro's saved default if selected and confirmed." -ForegroundColor Yellow
            Write-Host "  DRY RUN: would not create directory or write config." -ForegroundColor Yellow
        }
        else {
            while ($true) {
                Write-Host "  [C] Create this directory and continue"
                Write-Host "  [N] Choose a new path"
                Write-Host "  [R] Clear this saved default"
                Write-Host "  [Q] Cancel"
                $missingChoice = Read-Host "Saved default action"

                if ($missingChoice -in @("q", "Q")) {
                    return $null
                }
                if ($missingChoice -in @("n", "N")) {
                    $finalPath = "CUSTOM"
                    break
                }
                if ($missingChoice -in @("r", "R")) {
                    $clearConfirm = Read-Host "Clear saved default for '$Script:CurrentDistro'? Type CLEAR to confirm"
                    if ($clearConfirm -ceq "CLEAR") {
                        Clear-InstanceBackupPath
                        Write-Host "Saved instance default cleared. Choose a destination again." -ForegroundColor Green
                        return (Get-BackupDestination -defaultName $defaultName)
                    }
                    Write-Host "Saved default was not cleared." -ForegroundColor Yellow
                    continue
                }
                if ($missingChoice -in @("c", "C")) {
                    $createAns = Read-Host "Create saved default directory now? [Y/N/Q]"
                    if ($createAns -eq "Y" -or $createAns -eq "y") {
                        if (-not (New-BackupDirectory $finalPath)) { return $null }
                        break
                    }
                    if ($createAns -in @("q", "Q")) {
                        return $null
                    }
                    continue
                }

                Write-Host "Invalid option." -ForegroundColor Red
            }
        }
    }

    if ($finalPath -eq "CUSTOM") {
        $finalPath = Read-Host "Enter full path (e.g. D:\Backups\Specific)"
        if ([string]::IsNullOrWhiteSpace($finalPath)) { return $null }
        $customValidation = Assert-WSLBMBackupRootPath -Path $finalPath -Label "Custom backup path"
        Write-WSLBMPathValidationResult -Result $customValidation -Label "Custom backup path"
        if (-not $customValidation.IsValid) { return $null }
        $finalPath = $finalPath.TrimEnd('\')
        if (Test-Path -LiteralPath $finalPath -PathType Leaf) {
            Write-Host "[ERROR] Custom backup path points to a file. Choose a directory." -ForegroundColor Red
            return $null
        }
        if (-not (Test-Path -LiteralPath $finalPath -PathType Container)) {
            if ($PreviewOnly) {
                Write-Host "  DRY RUN: custom destination root does not exist; would create: $finalPath" -ForegroundColor Yellow
            }
            else {
                $createAns = Read-Host "Directory not found. Create? [Y/N/Q]"
                if ($createAns -eq "Y" -or $createAns -eq "y") {
                    if (-not (New-BackupDirectory $finalPath)) { return $null }
                }
                else {
                    return $null
                }
            }
        }
        if ($PreviewOnly) {
            Write-Host "  DRY RUN: custom destination root was not saved as an instance default." -ForegroundColor Yellow
        }
        else {
            $saveAns = Read-Host "Save as default for[$Script:CurrentDistro]? [Y/N/Q]"
            if ($saveAns -eq "Y" -or $saveAns -eq "y") {
                Set-InstanceBackupPath -newPath $finalPath
            }
        }
    }
    else {
        $selectedValidation = Assert-WSLBMBackupRootPath -Path $finalPath -Label "Selected backup destination"
        Write-WSLBMPathValidationResult -Result $selectedValidation -Label "Selected backup destination"
        if (-not $selectedValidation.IsValid) {
            Write-Host "[CONFIG ERROR] Selected backup destination is blocked. Reconfigure Settings or choose Custom Location." -ForegroundColor Red
            return $null
        }

        if (Test-Path -LiteralPath $finalPath -PathType Leaf) {
            Write-Host "[CONFIG ERROR] Selected backup destination points to a file. Reconfigure Settings or choose Custom Location." -ForegroundColor Red
            return $null
        }

        if (-not (Test-Path -LiteralPath $finalPath -PathType Container)) {
            if ($PreviewOnly) {
                Write-Host "  DRY RUN: selected destination root does not exist; would create: $finalPath" -ForegroundColor Yellow
            }
            else {
                $createAns = Read-Host "Selected backup root not found. Create? [Y/N/Q]"
                if ($createAns -eq "Y" -or $createAns -eq "y") {
                    if (-not (New-BackupDirectory $finalPath)) { return $null }
                }
                else {
                    return $null
                }
            }
        }
    }

    return (Join-Path $finalPath $defaultName)
}

function Test-BackupIntegrity {
    param(
        [string]$backupFile,
        [string]$backupType,
        [long]$MinimumSizeBytes = -1
    )

    Write-Host "[Backup Verification]" -ForegroundColor Cyan

    $archiveItem = Assert-WSLBMSevenZipArchiveInput -ArchivePath $backupFile -Context "Backup archive"
    $fileSize = $archiveItem.Length
    $readableSize = Format-Bytes $fileSize

    $minSize = if ($MinimumSizeBytes -ge 0) {
        $MinimumSizeBytes
    }
    else {
        switch ($backupType) {
            "FULL" { 100MB }
            "USER-FULL" { 1KB }
            default { 100 }
        }
    }

    if ($fileSize -lt $minSize) {
        throw "File too small ($fileSize bytes). Expected at least $minSize bytes."
    }
    Write-Host "  [OK] Size Check: $readableSize" -ForegroundColor Green

    $sevenZipExe = Resolve-WSLBMSevenZipPath

    $argList = @("t", $backupFile, "-y")
    $checkResult = Invoke-WSLBMNativeProcessChecked `
        -FilePath $sevenZipExe `
        -Arguments $argList `
        -OperationName "Backup-Integrity" `
        -Description "7z integrity check" `
        -TimeoutSeconds $Script:SevenZipIntegrityTimeoutSeconds `
        -Distro $Script:CurrentDistro
    $exitCode = $checkResult.ExitCode

    if ($checkResult.TimedOut) {
        throw "7z integrity check failed: timed out after $Script:SevenZipIntegrityTimeoutSeconds seconds."
    }
    if ($checkResult.Cancelled) {
        throw "7z integrity check failed: cancelled by user."
    }
    if ($null -eq $exitCode) {
        throw "7z integrity check failed: process did not report an exit code."
    }
    if ($exitCode -ne 0) {
        $detail = Get-WSLBMFirstDiagnosticsLine -Value $checkResult.CombinedOutput
        if ([string]::IsNullOrWhiteSpace($detail)) {
            throw "CRC Integrity Check Failed (7z exit code $exitCode)"
        }
        throw "CRC Integrity Check Failed (7z exit code $exitCode): $detail"
    }
    Write-Host "  [OK] Integrity Check" -ForegroundColor Green
}

function Get-WSLBMScriptVersion {
    return $Script:WSLBMScriptVersion
}

function Assert-WSLBMManifestPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupDir,

        [Parameter(Mandatory = $true)]
        [string]$ManifestPath
    )

    $backupDirFull = [System.IO.Path]::GetFullPath($BackupDir)
    $manifestFull = [System.IO.Path]::GetFullPath($ManifestPath)
    $manifestParent = [System.IO.Path]::GetDirectoryName($manifestFull)
    $manifestName = [System.IO.Path]::GetFileName($manifestFull)

    if (-not $manifestParent.Equals($backupDirFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Manifest path must be directly under the current backup directory."
    }
    if ($manifestName -ne "manifest.json") {
        throw "Manifest file name must be manifest.json."
    }
}

function Write-BackupManifest {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("FULL", "USER", "CUSTOM")]
        [string]$BackupType,

        [Parameter(Mandatory = $true)]
        [string]$BackupDir,

        [Parameter(Mandatory = $true)]
        [string]$ArchivePath,

        [Parameter(Mandatory = $true)]
        [string]$SourceDistro,

        [string]$WslUser = "",

        [string]$CustomRelativePath = "",

        [ValidateSet("Success", "Warning")]
        [string]$BackupStatus = "Success",

        [AllowNull()]
        [object]$SevenZipExitCode = $null,

        [string]$WarningSummary = ""
    )

    if (-not (Test-Path -LiteralPath $BackupDir -PathType Container)) {
        throw "Backup directory does not exist: $BackupDir"
    }

    $archiveItem = Get-Item -LiteralPath $ArchivePath -ErrorAction Stop
    if (-not $archiveItem.PSIsContainer) {
        $manifestPath = Join-Path $BackupDir "manifest.json"
        Assert-WSLBMManifestPath -BackupDir $BackupDir -ManifestPath $manifestPath

        $archiveHash = Get-FileHash -LiteralPath $archiveItem.FullName -Algorithm SHA256 -ErrorAction Stop
        $scriptVersion = Get-WSLBMScriptVersion
        $createdAt = (Get-Date).ToString("o")
        $archiveName = [string]$archiveItem.Name
        $archiveSizeBytes = [long]$archiveItem.Length
        $archiveSha256 = [string]$archiveHash.Hash
        $backupMode = if ($BackupType -eq "FULL") { "wsl-export" } else { "unc-windows-7zip" }
        $wslUserValue = if ([string]::IsNullOrWhiteSpace($WslUser)) { $null } else { $WslUser }
        $customRelativePathValue = if ([string]::IsNullOrWhiteSpace($CustomRelativePath)) { $null } else { $CustomRelativePath }
        $sevenZipExitCodeValue = if ($null -eq $SevenZipExitCode -or [string]::IsNullOrWhiteSpace([string]$SevenZipExitCode)) {
            $null
        }
        else {
            [int]$SevenZipExitCode
        }
        $warningSummaryValue = if ([string]::IsNullOrWhiteSpace($WarningSummary)) { $null } else { $WarningSummary }
        $metadataWarning = if ($BackupType -in @("USER", "CUSTOM")) {
            "USER/CUSTOM backup via WSL UNC path and Windows 7-Zip does not guarantee full Linux metadata fidelity."
        }
        else {
            $null
        }

        $manifest = [ordered]@{
            SchemaVersion      = 1
            Tool               = "WSL Backup Manager"
            ScriptVersion      = $scriptVersion
            CreatedAt          = $createdAt
            BackupStatus       = $BackupStatus
            SevenZipExitCode   = $sevenZipExitCodeValue
            WarningSummary     = $warningSummaryValue
            BackupType         = $BackupType
            SourceDistro       = $SourceDistro
            ArchiveName        = $archiveName
            ArchiveSizeBytes   = $archiveSizeBytes
            ArchiveSha256      = $archiveSha256
            BackupMode         = $backupMode
            WslUser            = $wslUserValue
            CustomRelativePath = $customRelativePathValue
            MetadataWarning    = $metadataWarning
        }

        if (-not [string]::IsNullOrWhiteSpace($Script:CurrentOperationId)) {
            $manifest.OperationId = $Script:CurrentOperationId
        }

        Write-WSLBMTextFileUtf8NoBom -LiteralPath $manifestPath -Content ($manifest | ConvertTo-Json -Depth 4)
        Write-Host "  [OK] Manifest written: manifest.json" -ForegroundColor Green
        Write-LogEntry "INFO" "Backup-Manifest" "Manifest written: $manifestPath" -Distro $SourceDistro
        return $manifestPath
    }

    throw "Backup archive path is not a file: $ArchivePath"
}

function Write-BackupManifestBestEffort {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("FULL", "USER", "CUSTOM")]
        [string]$BackupType,

        [Parameter(Mandatory = $true)]
        [string]$BackupDir,

        [Parameter(Mandatory = $true)]
        [string]$ArchivePath,

        [Parameter(Mandatory = $true)]
        [string]$SourceDistro,

        [string]$WslUser = "",

        [string]$CustomRelativePath = "",

        [ValidateSet("Success", "Warning")]
        [string]$BackupStatus = "Success",

        [AllowNull()]
        [object]$SevenZipExitCode = $null,

        [string]$WarningSummary = ""
    )

    try {
        $null = Write-BackupManifest `
            -BackupType $BackupType `
            -BackupDir $BackupDir `
            -ArchivePath $ArchivePath `
            -SourceDistro $SourceDistro `
            -WslUser $WslUser `
            -CustomRelativePath $CustomRelativePath `
            -BackupStatus $BackupStatus `
            -SevenZipExitCode $SevenZipExitCode `
            -WarningSummary $WarningSummary
    }
    catch {
        $warning = "Manifest write failed: $($_.Exception.Message). Backup archive has already been created and was not deleted."
        Write-Host "[WARN] $warning" -ForegroundColor Yellow
        Write-LogEntry "WARN" "Backup-Manifest" $warning -Distro $SourceDistro
    }
}

function Test-RestoreArchiveIntegrity {
    param([string]$backupFile)

    Write-Host "  -> Restore Pre-flight: Running full archive integrity check (slower, safer)..." -ForegroundColor Cyan
    try {
        Test-BackupIntegrity -backupFile $backupFile -backupType "FULL"
        return $true
    }
    catch {
        Write-Host "  [FAILED] Restore archive integrity check failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-SafetyNetArchive {
    param([string]$safetyFile)

    Write-Host "  -> Safety Net Check: Verifying exported tar readability..." -ForegroundColor Cyan
    try {
        $safetyItem = Get-Item -LiteralPath $safetyFile -ErrorAction Stop
        if ($safetyItem.Length -lt $Script:MinimumSafetyNetArchiveBytes) {
            Write-LogEntry "ERROR" "Restore-SafetyNet" "Safety Net archive below minimum threshold. Path=$safetyFile | Actual=$($safetyItem.Length) | Minimum=$Script:MinimumSafetyNetArchiveBytes" -Distro $Script:CurrentDistro
            throw "Safety Net archive is too small. Actual=$(Format-Bytes $safetyItem.Length), minimum=$(Format-Bytes $Script:MinimumSafetyNetArchiveBytes). Path=$safetyFile"
        }

        Test-BackupIntegrity -backupFile $safetyFile -backupType "SAFETY-NET" -MinimumSizeBytes $Script:MinimumSafetyNetArchiveBytes
        return $true
    }
    catch {
        Write-Host "  [FAILED] Safety Net validation failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-RestoreSafetyNetExportSpace {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$SafetyNetPath
    )

    $estimatedBytes = $null
    $estimateSource = ""
    $registryInfo = Get-WSLDistroRegistryInfo -DistroName $DistroName
    if ($registryInfo.Success) {
        $vhdxPath = Join-Path $registryInfo.BasePath "ext4.vhdx"
        try {
            if (Test-Path -LiteralPath $vhdxPath -PathType Leaf) {
                $vhdxItem = Get-Item -LiteralPath $vhdxPath -ErrorAction Stop
                $estimatedBytes = [long]$vhdxItem.Length
                $estimateSource = "ext4.vhdx"
            }
            else {
                Write-Host "[WARN] Cannot find ext4.vhdx for precise Safety Net size estimate: $vhdxPath" -ForegroundColor Yellow
                Write-LogEntry "WARN" "Restore-SafetyNet-Space" "ext4.vhdx not found for precise estimate. Distro=$DistroName | Path=$vhdxPath" -Distro $DistroName
            }
        }
        catch {
            Write-Host "[WARN] Cannot read ext4.vhdx size for precise Safety Net estimate: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-LogEntry "WARN" "Restore-SafetyNet-Space" "Cannot read ext4.vhdx size for estimate: $($_.Exception.Message)" -Distro $DistroName
        }
    }
    else {
        Write-Host "[WARN] Cannot read WSL registry BasePath for precise Safety Net estimate: $($registryInfo.Reason)" -ForegroundColor Yellow
        Write-LogEntry "WARN" "Restore-SafetyNet-Space" "Cannot read registry BasePath for estimate: $($registryInfo.Reason)" -Distro $DistroName
    }

    $requiredBytes = $Script:MinimumSafetyNetFreeSpaceBytes
    if ($null -ne $estimatedBytes -and $estimatedBytes -gt 0) {
        $bufferBytes = [long][math]::Max([math]::Ceiling([double]$estimatedBytes * 0.10), [double]1GB)
        $requiredBytes = [long]($estimatedBytes + $bufferBytes)
    }

    if ($Global:DryRun) {
        Write-Host "DRY RUN: would check Safety Net export free space at $SafetyNetPath" -ForegroundColor Yellow
        if ($null -ne $estimatedBytes -and $estimatedBytes -gt 0) {
            Write-Host "  DRY RUN: estimated Safety Net size from ${estimateSource}: $(Format-Bytes $estimatedBytes)" -ForegroundColor Yellow
            Write-Host "  DRY RUN: required with buffer: $(Format-Bytes $requiredBytes)" -ForegroundColor Yellow
        }
        else {
            Write-Host "  DRY RUN: precise estimate unavailable; would require at least $(Format-Bytes $requiredBytes)" -ForegroundColor Yellow
        }
        Write-LogEntry "INFO" "Restore-SafetyNet-Space" "DryRun would check Safety Net space. Path=$SafetyNetPath | Estimate=$estimatedBytes | Required=$requiredBytes" -Distro $DistroName
        return $true
    }

    $space = Get-WSLBMPathFreeSpaceInfo -Path $SafetyNetPath -Label "Safety Net export target" -LogAction "Restore-SafetyNet-Space" -Distro $DistroName
    if (-not $space.Success) {
        Write-Host "[ERROR] Safety Net export blocked because destination free space cannot be verified: $($space.Reason)" -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-SafetyNet-Space" "Cannot verify Safety Net export space. Path=$SafetyNetPath | Reason=$($space.Reason)" -Distro $DistroName
        return $false
    }

    Write-Host "  -> Safety Net Space Check" -ForegroundColor Cyan
    Write-Host "     Target   : $SafetyNetPath" -ForegroundColor DarkGray
    if ($null -ne $estimatedBytes -and $estimatedBytes -gt 0) {
        Write-Host "     Estimate : $(Format-Bytes $estimatedBytes) ($estimateSource)" -ForegroundColor DarkGray
    }
    else {
        Write-Host "     Estimate : unavailable; using minimum free-space guard" -ForegroundColor Yellow
        Write-LogEntry "WARN" "Restore-SafetyNet-Space" "Precise Safety Net size estimate unavailable; using minimum guard $(Format-Bytes $requiredBytes). Path=$SafetyNetPath" -Distro $DistroName
    }
    Write-Host "     Required : $(Format-Bytes $requiredBytes)" -ForegroundColor DarkGray
    Write-Host "     Available: $(Format-Bytes $space.AvailableBytes)" -ForegroundColor DarkGray
    Write-LogEntry "INFO" "Restore-SafetyNet-Space" "Target=$SafetyNetPath | Estimate=$estimatedBytes | Required=$(Format-Bytes $requiredBytes) | Available=$(Format-Bytes $space.AvailableBytes) | Source=$($space.SourceType):$($space.SourceKey)" -Distro $DistroName

    if ($space.AvailableBytes -lt $requiredBytes) {
        Write-Host "[ERROR] Not enough free space for Safety Net export." -ForegroundColor Red
        Write-Host "  Required : $(Format-Bytes $requiredBytes)" -ForegroundColor Yellow
        Write-Host "  Available: $(Format-Bytes $space.AvailableBytes)" -ForegroundColor Yellow
        Write-LogEntry "ERROR" "Restore-SafetyNet-Space" "Insufficient Safety Net export space. Required=$(Format-Bytes $requiredBytes) | Available=$(Format-Bytes $space.AvailableBytes) | Path=$SafetyNetPath" -Distro $DistroName
        return $false
    }

    Write-Host "  [OK] Safety Net export space check passed." -ForegroundColor Green
    return $true
}

function Invoke-GuardedWSLCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [string]$Distro = $Script:CurrentDistro,

        [int]$TimeoutSeconds = $Script:DefaultWSLCommandTimeoutSeconds,

        [bool]$AllowCancel = $true
    )

    $commandPreview = "wsl.exe " + ($Arguments -join " ")

    if ($Global:DryRun) {
        Write-Host "DRY RUN: would run $commandPreview" -ForegroundColor Yellow
        Write-LogEntry "INFO" "WSL-DryRun" "$Description | $commandPreview" -Distro $Distro
        return [pscustomobject]@{
            Success              = $true
            ExitCode             = $null
            SkippedBecauseDryRun = $true
            Description          = $Description
            TimedOut             = $false
            Cancelled            = $false
            StdOut               = ""
            StdErr               = ""
            Output               = ""
            CombinedOutput       = ""
            ErrorMessage         = ""
            ProcessId            = $null
        }
    }

    $runnerResult = Invoke-WSLBMNativeProcessChecked `
        -FilePath "wsl.exe" `
        -Arguments $Arguments `
        -OperationName "WSL-Command" `
        -Description $Description `
        -TimeoutSeconds $TimeoutSeconds `
        -Distro $Distro `
        -RegisterActiveProcess `
        -AllowCancel:([bool]$AllowCancel)

    $outputText = [string]$runnerResult.CombinedOutput

    if (-not $runnerResult.Success) {
        if ($runnerResult.TimedOut) {
            Write-Host "[ERROR] $Description timed out after $TimeoutSeconds seconds." -ForegroundColor Red
            Write-LogEntry "ERROR" "WSL-Command" "$Description timed out after $TimeoutSeconds seconds" -Distro $Distro
        }
        elseif ($runnerResult.Cancelled) {
            Write-Host "[WARN] $Description cancelled by user." -ForegroundColor Yellow
            Write-LogEntry "WARN" "WSL-Command" "$Description cancelled by user" -Distro $Distro
        }
        elseif ($null -eq $runnerResult.ExitCode) {
            Write-Host "[ERROR] $Description failed: WSL command did not report an exit code." -ForegroundColor Red
            Write-LogEntry "ERROR" "WSL-Command" "$Description failed: WSL command did not report an exit code" -Distro $Distro
        }
        else {
            Write-Host "[ERROR] $Description failed (wsl.exe exit code $($runnerResult.ExitCode))." -ForegroundColor Red
            Write-LogEntry "ERROR" "WSL-Command" "$Description failed with exit code $($runnerResult.ExitCode)" -Distro $Distro
        }
        if ($outputText) {
            Write-Host $outputText -ForegroundColor DarkGray
        }
        return [pscustomobject]@{
            Success              = $false
            ExitCode             = $runnerResult.ExitCode
            SkippedBecauseDryRun = $false
            Description          = $Description
            TimedOut             = $runnerResult.TimedOut
            Cancelled            = $runnerResult.Cancelled
            StdOut               = $runnerResult.StdOut
            StdErr               = $runnerResult.StdErr
            Output               = $outputText
            CombinedOutput       = $outputText
            ErrorMessage         = $runnerResult.ErrorMessage
            ProcessId            = $runnerResult.ProcessId
        }
    }

    return [pscustomobject]@{
        Success              = $true
        ExitCode             = $runnerResult.ExitCode
        SkippedBecauseDryRun = $false
        Description          = $Description
        TimedOut             = $false
        Cancelled            = $false
        StdOut               = $runnerResult.StdOut
        StdErr               = $runnerResult.StdErr
        Output               = $outputText
        CombinedOutput       = $outputText
        ErrorMessage         = ""
        ProcessId            = $runnerResult.ProcessId
    }
}

function Test-RestoreTarEntryPathMatch {
    param(
        [AllowNull()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$EntryName
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    if ([string]::Equals($Path, $EntryName, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    $leaf = Split-Path -Path $Path -Leaf -ErrorAction SilentlyContinue
    if ([string]::Equals($leaf, $EntryName, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    $normalizedPath = $Path -replace '\\', '/'
    $normalizedEntry = $EntryName -replace '\\', '/'
    return $normalizedPath.EndsWith("/$normalizedEntry", [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-RestoreTarSizeFromArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [string]$EntryName = "wsl-export.tar",

        [string]$Distro = $Script:CurrentDistro
    )

    $null = Assert-WSLBMSevenZipArchiveInput -ArchivePath $BackupFile -Context "Restore archive"
    $sevenZipExe = Resolve-WSLBMSevenZipPath

    Write-Host "  -> Restore Pre-flight: Reading restore tar size from archive..." -ForegroundColor Cyan
    Write-LogEntry "INFO" "Restore-TempSpace" "Reading $EntryName size from $BackupFile" -Distro $Distro

    $argList = @("l", "-slt", $BackupFile, $EntryName)
    $listResult = Invoke-WSLBMNativeProcessChecked `
        -FilePath $sevenZipExe `
        -Arguments $argList `
        -OperationName "Restore-TempSpace" `
        -Description "List restore tar entry metadata" `
        -TimeoutSeconds $Script:RestoreExtractTimeoutSeconds `
        -Distro $Distro
    $exitCode = $listResult.ExitCode

    if ($listResult.TimedOut) {
        throw "7z list failed while reading restore tar size: timed out after $Script:RestoreExtractTimeoutSeconds seconds."
    }
    if ($listResult.Cancelled) {
        throw "7z list failed while reading restore tar size: cancelled by user."
    }
    if ($null -eq $exitCode) {
        throw "7z list failed while reading restore tar size: process did not report an exit code."
    }
    if ($exitCode -ne 0) {
        throw "7z list failed while reading restore tar size (exit code $exitCode)."
    }

    $outputText = [string]$listResult.StdOut
    if ([string]::IsNullOrWhiteSpace($outputText)) {
        # Some native tools/environments do not keep metadata listing text solely on stdout.
        # Use combined output only as a compatibility fallback after exit-code success.
        $outputText = [string]$listResult.CombinedOutput
    }
    $output = @($outputText -split "\r?\n")
    $currentPath = $null
    $currentSize = $null
    foreach ($line in $output) {
        $text = [string]$line
        if ($text -match '^Path = (.+)$') {
            if ((Test-RestoreTarEntryPathMatch -Path $currentPath -EntryName $EntryName) -and $null -ne $currentSize) {
                return [long]$currentSize
            }
            $currentPath = $Matches[1].Trim()
            $currentSize = $null
            continue
        }

        if ($text -match '^Size = (\d+)$') {
            if ($null -ne $currentPath) {
                $currentSize = [long]$Matches[1]
            }
        }
    }

    if ((Test-RestoreTarEntryPathMatch -Path $currentPath -EntryName $EntryName) -and $null -ne $currentSize) {
        return [long]$currentSize
    }

    throw "Archive entry '$EntryName' was not found or its uncompressed size could not be parsed."
}

function Resolve-RestoreSpaceCheckPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$Label = "Restore path",

        [string]$Distro = $Script:CurrentDistro
    )

    try {
        if ([string]::IsNullOrWhiteSpace($Path)) {
            throw "$Label is empty."
        }

        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $candidate = $fullPath

        while (-not [string]::IsNullOrWhiteSpace($candidate)) {
            if (Test-Path $candidate -PathType Container) {
                return [pscustomobject]@{
                    Success   = $true
                    CheckPath = $candidate
                    FullPath  = $fullPath
                    Reason    = ""
                }
            }

            $parent = Split-Path $candidate -Parent
            if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $candidate) {
                break
            }
            $candidate = $parent
        }

        $root = [System.IO.Path]::GetPathRoot($fullPath)
        if (-not [string]::IsNullOrWhiteSpace($root) -and (Test-Path $root -PathType Container)) {
            return [pscustomobject]@{
                Success   = $true
                CheckPath = $root
                FullPath  = $fullPath
                Reason    = ""
            }
        }

        throw "Cannot find an existing parent directory or ready root for ${Label}: $Path"
    }
    catch {
        $message = $_.Exception.Message
        Write-Host "[ERROR] Cannot determine space check location for ${Label}: $message" -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-Space" "Cannot determine space check location for ${Label}: $message" -Distro $Distro
        return [pscustomobject]@{
            Success   = $false
            CheckPath = $null
            FullPath  = $Path
            Reason    = $message
        }
    }
}

function New-RestorePathSafetyResult {
    param(
        [bool]$Success,
        [string]$NormalizedPath = "",
        [string]$Reason = ""
    )

    return [pscustomobject]@{
        Success        = $Success
        NormalizedPath = $NormalizedPath
        Reason         = $Reason
    }
}

function Get-NormalizedWindowsPathForComparison {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Path,

        [string]$Label = "Path"
    )

    try {
        if ([string]::IsNullOrWhiteSpace($Path)) {
            return New-RestorePathSafetyResult -Success $false -Reason "$Label is empty."
        }

        $trimmedPath = $Path.Trim()
        if ($trimmedPath -match '[\x00-\x1F\x7F]') {
            return New-RestorePathSafetyResult -Success $false -Reason "$Label contains control characters."
        }
        if ($trimmedPath.Contains('"')) {
            return New-RestorePathSafetyResult -Success $false -Reason "$Label contains double quote characters."
        }
        if (-not [System.IO.Path]::IsPathRooted($trimmedPath)) {
            return New-RestorePathSafetyResult -Success $false -Reason "$Label must be an absolute local Windows path."
        }

        $fullPath = [System.IO.Path]::GetFullPath($trimmedPath)
        $root = [System.IO.Path]::GetPathRoot($fullPath)
        if ([string]::IsNullOrWhiteSpace($root)) {
            return New-RestorePathSafetyResult -Success $false -Reason "Cannot determine root for $Label."
        }

        $separators = [char[]]@('\', '/')
        $normalizedPath = $fullPath.TrimEnd($separators)
        $normalizedRoot = $root.TrimEnd($separators)
        if ($normalizedPath -eq $normalizedRoot) {
            $normalizedPath = $root
        }

        return New-RestorePathSafetyResult -Success $true -NormalizedPath $normalizedPath
    }
    catch {
        return New-RestorePathSafetyResult -Success $false -Reason "Cannot normalize ${Label}: $($_.Exception.Message)"
    }
}

function Test-PathIsSameOrChild {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ChildPath,

        [Parameter(Mandatory = $true)]
        [string]$ParentPath
    )

    $childResolved = Get-NormalizedWindowsPathForComparison -Path $ChildPath -Label "Child path"
    $parentResolved = Get-NormalizedWindowsPathForComparison -Path $ParentPath -Label "Parent path"
    if (-not $childResolved.Success -or -not $parentResolved.Success) {
        return $false
    }

    $comparison = [System.StringComparison]::OrdinalIgnoreCase
    $child = $childResolved.NormalizedPath
    $parent = $parentResolved.NormalizedPath

    if ($child.Equals($parent, $comparison)) {
        return $true
    }

    $separators = [char[]]@('\', '/')
    $parentWithSeparator = $parent.TrimEnd($separators)
    if (-not $parentWithSeparator.EndsWith('\') -and -not $parentWithSeparator.EndsWith('/')) {
        $parentWithSeparator = "$parentWithSeparator\"
    }

    return $child.StartsWith($parentWithSeparator, $comparison)
}

function Get-WSLDistroRegistryInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName
    )

    $lxssRoot = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss"
    if ([string]::IsNullOrWhiteSpace($DistroName)) {
        return [pscustomobject]@{
            Success          = $false
            DistroName       = $DistroName
            RegistryKey      = ""
            DistributionName = ""
            BasePathRaw      = ""
            BasePath         = ""
            Reason           = "Distro name is empty."
        }
    }

    try {
        if (-not (Test-Path -LiteralPath $lxssRoot -PathType Container)) {
            return [pscustomobject]@{
                Success          = $false
                DistroName       = $DistroName
                RegistryKey      = ""
                DistributionName = ""
                BasePathRaw      = ""
                BasePath         = ""
                Reason           = "WSL Lxss registry root was not found."
            }
        }

        foreach ($key in (Get-ChildItem -LiteralPath $lxssRoot -ErrorAction Stop)) {
            $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
            $name = [string]$props.DistributionName
            if (-not [string]::Equals($name, $DistroName, [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }

            $basePathRaw = [string]$props.BasePath
            if ([string]::IsNullOrWhiteSpace($basePathRaw)) {
                return [pscustomobject]@{
                    Success          = $false
                    DistroName       = $DistroName
                    RegistryKey      = $key.Name
                    DistributionName = $name
                    BasePathRaw      = ""
                    BasePath         = ""
                    Reason           = "Registry entry was found, but BasePath is empty."
                }
            }

            $expandedBasePath = [Environment]::ExpandEnvironmentVariables($basePathRaw)
            $basePathResolved = Get-NormalizedWindowsPathForComparison -Path $expandedBasePath -Label "WSL registry BasePath"
            if (-not $basePathResolved.Success) {
                return [pscustomobject]@{
                    Success          = $false
                    DistroName       = $DistroName
                    RegistryKey      = $key.Name
                    DistributionName = $name
                    BasePathRaw      = $basePathRaw
                    BasePath         = ""
                    Reason           = $basePathResolved.Reason
                }
            }

            return [pscustomobject]@{
                Success          = $true
                DistroName       = $DistroName
                RegistryKey      = $key.Name
                DistributionName = $name
                BasePathRaw      = $basePathRaw
                BasePath         = $basePathResolved.NormalizedPath
                Reason           = ""
            }
        }

        return [pscustomobject]@{
            Success          = $false
            DistroName       = $DistroName
            RegistryKey      = ""
            DistributionName = ""
            BasePathRaw      = ""
            BasePath         = ""
            Reason           = "No WSL registry entry matched distro '$DistroName'."
        }
    }
    catch {
        return [pscustomobject]@{
            Success          = $false
            DistroName       = $DistroName
            RegistryKey      = ""
            DistributionName = ""
            BasePathRaw      = ""
            BasePath         = ""
            Reason           = $_.Exception.Message
        }
    }
}

function Resolve-OverwriteRestoreInstallPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$BackupFile
    )

    $configInstallPathRaw = ""
    $configInstallPath = ""
    if (-not [string]::IsNullOrWhiteSpace($Global:Config.InstallRoot)) {
        $configInstallPathRaw = Join-Path $Global:Config.InstallRoot $DistroName
        $configInstallPathResolved = Get-NormalizedWindowsPathForComparison -Path $configInstallPathRaw -Label "Configured/default install path"
        $configInstallPath = if ($configInstallPathResolved.Success) { $configInstallPathResolved.NormalizedPath } else { $configInstallPathRaw }
    }

    $registryInfo = Get-WSLDistroRegistryInfo -DistroName $DistroName
    if ($registryInfo.Success) {
        $selectedPath = $registryInfo.BasePath
        Write-Host ""
        Write-Host "[Overwrite Restore Install Path]" -ForegroundColor Cyan
        Write-Host "  Current distro name       : $DistroName" -ForegroundColor Yellow
        Write-Host "  Detected current BasePath : $($registryInfo.BasePath)" -ForegroundColor Yellow
        Write-Host "  Config/default install path: $configInstallPath" -ForegroundColor Yellow
        Write-Host "  Actual installPath to use : $selectedPath" -ForegroundColor Yellow

        if (-not [string]::IsNullOrWhiteSpace($configInstallPath) -and
            -not [string]::Equals($registryInfo.BasePath, $configInstallPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            $warning = "Detected existing WSL BasePath differs from configured InstallRoot default; overwrite restore will use the existing BasePath."
            Write-Host "[WARN] $warning" -ForegroundColor Yellow
            Write-LogEntry "WARN" "Restore-InstallPath" $warning -Distro $DistroName
        }

        $installPathSafety = Test-RestoreInstallPathSafety -InstallPath $selectedPath -BackupFile $BackupFile -DistroName $DistroName -Mode "Overwrite"
        if (-not $installPathSafety.Success) {
            return [pscustomobject]@{
                Success                   = $false
                InstallPath               = $selectedPath
                DetectedBasePath          = $registryInfo.BasePath
                ConfigInstallPath         = $configInstallPath
                RegistryBasePathAvailable = $true
                ManualPathUsed            = $false
                ManualInstallPath         = ""
                Reason                    = $installPathSafety.Reason
            }
        }

        return [pscustomobject]@{
            Success                   = $true
            InstallPath               = $installPathSafety.NormalizedPath
            DetectedBasePath          = $registryInfo.BasePath
            ConfigInstallPath         = $configInstallPath
            RegistryBasePathAvailable = $true
            ManualPathUsed            = $false
            ManualInstallPath         = ""
            Reason                    = ""
        }
    }

    Write-Host ""
    Write-Host "[WARN] Could not detect the current WSL BasePath from registry: $($registryInfo.Reason)" -ForegroundColor Yellow
    Write-Host "[WARN] Overwrite restore will not silently use the configured/default InstallRoot path." -ForegroundColor Yellow
    Write-Host "Enter the existing install path for the current distro, or Q/CANCEL to abort." -ForegroundColor Yellow
    Write-LogEntry "WARN" "Restore-InstallPath" "Registry BasePath unavailable: $($registryInfo.Reason)" -Distro $DistroName

    while ($true) {
        $manualPath = Read-Host "Existing install path for '$DistroName'"
        if ([string]::IsNullOrWhiteSpace($manualPath) -or $manualPath -in @("q", "Q", "cancel", "CANCEL")) {
            return [pscustomobject]@{
                Success                   = $false
                InstallPath               = ""
                DetectedBasePath          = ""
                ConfigInstallPath         = $configInstallPath
                RegistryBasePathAvailable = $false
                ManualPathUsed            = $false
                ManualInstallPath         = ""
                Reason                    = "User cancelled manual overwrite restore install path entry."
            }
        }

        $installPathSafety = Test-RestoreInstallPathSafety -InstallPath $manualPath -BackupFile $BackupFile -DistroName $DistroName -Mode "Overwrite"
        if ($installPathSafety.Success) {
            Write-Host "Manual installPath accepted because registry BasePath was unavailable." -ForegroundColor Yellow
            Write-LogEntry "WARN" "Restore-InstallPath" "Manual overwrite restore install path accepted because registry BasePath was unavailable: $($installPathSafety.NormalizedPath)" -Distro $DistroName
            return [pscustomobject]@{
                Success                   = $true
                InstallPath               = $installPathSafety.NormalizedPath
                DetectedBasePath          = ""
                ConfigInstallPath         = $configInstallPath
                RegistryBasePathAvailable = $false
                ManualPathUsed            = $true
                ManualInstallPath         = $installPathSafety.NormalizedPath
                Reason                    = ""
            }
        }

        Write-Host "Enter a safe existing install path, or Q/CANCEL to abort." -ForegroundColor Yellow
    }
}

# =============================================================================
# 6b. Delete Safety Helpers
#     Guard backup directory deletion with boundary, shape, and reparse checks.
# =============================================================================

function New-ProtectedBackupPathDeleteResult {
    param(
        [bool]$Success,
        [bool]$SkippedBecauseDryRun = $false,
        [string]$DeletedPath = "",
        [string]$Reason = "",
        [string]$BackupType = "Unknown",
        [bool]$HasInProgressLock = $false,
        [bool]$RequireInProgressLock = $false,
        [bool]$FromRecognizedBackupList = $false,
        [object]$ReparsePointScan = $null
    )

    return [pscustomobject]@{
        Success                  = $Success
        SkippedBecauseDryRun     = $SkippedBecauseDryRun
        DeletedPath              = $DeletedPath
        Reason                   = $Reason
        BackupType               = $BackupType
        HasInProgressLock        = $HasInProgressLock
        RequireInProgressLock    = $RequireInProgressLock
        FromRecognizedBackupList = $FromRecognizedBackupList
        ReparsePointScan         = $ReparsePointScan
    }
}

function Test-WSLBMBackupDirectoryShape {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [switch]$RequireInProgressLock,

        [switch]$FromRecognizedBackupList
    )

    function New-BackupDirectoryShapeResult {
        param(
            [bool]$Success,
            [string]$Reason = "",
            [string]$BackupType = "Unknown",
            [bool]$HasInProgressLock = $false
        )

        return New-ProtectedBackupPathDeleteResult `
            -Success $Success `
            -DeletedPath $Path `
            -Reason $Reason `
            -BackupType $BackupType `
            -HasInProgressLock $HasInProgressLock `
            -RequireInProgressLock ([bool]$RequireInProgressLock) `
            -FromRecognizedBackupList ([bool]$FromRecognizedBackupList)
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return New-BackupDirectoryShapeResult -Success $false -Reason "Target is not an existing directory."
    }

    $name = Split-Path -Path $Path -Leaf
    if ($name -notmatch '^\d{4}-\d{2}-\d{2}_\d{4}-(FULL|USER|CUSTOM)$') {
        return New-BackupDirectoryShapeResult -Success $false -Reason "Directory name does not match a WSLBM generated backup name."
    }

    $backupType = $Matches[1]
    $lockPath = Join-Path $Path ".backup-in-progress"
    $hasLock = Test-Path -LiteralPath $lockPath -PathType Leaf

    if ($RequireInProgressLock -and (-not $hasLock)) {
        return New-BackupDirectoryShapeResult -Success $false -Reason "Failed backup cleanup requires .backup-in-progress." -BackupType $backupType -HasInProgressLock $hasLock
    }

    if ($hasLock) {
        return New-BackupDirectoryShapeResult -Success $true -BackupType $backupType -HasInProgressLock $hasLock
    }

    if (-not $FromRecognizedBackupList) {
        return New-BackupDirectoryShapeResult -Success $false -Reason "Directory was not marked as coming from the recognized backup list." -BackupType $backupType -HasInProgressLock $hasLock
    }

    switch ($backupType) {
        "FULL" {
            if (Test-Path -LiteralPath (Join-Path $Path "wsl-full.7z") -PathType Leaf) {
                return New-BackupDirectoryShapeResult -Success $true -BackupType $backupType -HasInProgressLock $hasLock
            }
            return New-BackupDirectoryShapeResult -Success $false -Reason "FULL backup directory does not contain wsl-full.7z." -BackupType $backupType -HasInProgressLock $hasLock
        }
        "USER" {
            if (Test-Path -LiteralPath (Join-Path $Path "home.7z") -PathType Leaf) {
                return New-BackupDirectoryShapeResult -Success $true -BackupType $backupType -HasInProgressLock $hasLock
            }
            return New-BackupDirectoryShapeResult -Success $false -Reason "USER backup directory does not contain home.7z." -BackupType $backupType -HasInProgressLock $hasLock
        }
        "CUSTOM" {
            $archive = Get-ChildItem -LiteralPath $Path -Filter "*.7z" -File -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($null -ne $archive) {
                return New-BackupDirectoryShapeResult -Success $true -BackupType $backupType -HasInProgressLock $hasLock
            }
            return New-BackupDirectoryShapeResult -Success $false -Reason "CUSTOM backup directory does not contain a .7z archive." -BackupType $backupType -HasInProgressLock $hasLock
        }
    }

    return New-BackupDirectoryShapeResult -Success $false -Reason "Unknown WSLBM backup directory type." -BackupType $backupType -HasInProgressLock $hasLock
}

function Test-BackupDirectoryReparsePointSafety {
    # This scan targets ReparsePoint entries such as junctions, directory symlinks, and mount points.
    # It does not expand ordinary hard link files and is only a backup-delete boundary check,
    # not a general proof that arbitrary directory deletion is safe.
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [int]$MaxReportedPaths = 10
    )

    function New-BackupDirectoryReparsePointSafetyResult {
        param(
            [bool]$Success,
            [bool]$HasReparsePoint = $false,
            [string[]]$ReparsePointPaths = @(),
            [int]$ScannedDirectories = 0,
            [int]$ScannedItems = 0,
            [string]$Reason = ""
        )

        return [pscustomobject]@{
            Success            = $Success
            HasReparsePoint    = $HasReparsePoint
            ReparsePointPaths  = @($ReparsePointPaths)
            ScannedDirectories = $ScannedDirectories
            ScannedItems       = $ScannedItems
            Reason             = $Reason
        }
    }

    $pendingDirectories = New-Object System.Collections.ArrayList
    $reparsePointPaths = New-Object System.Collections.ArrayList
    $scannedDirectories = 0
    $scannedItems = 0

    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
            return New-BackupDirectoryReparsePointSafetyResult -Success $false -Reason "Target is not an existing directory."
        }

        $rootItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            [void]$reparsePointPaths.Add($rootItem.FullName)
            return New-BackupDirectoryReparsePointSafetyResult `
                -Success $false `
                -HasReparsePoint $true `
                -ReparsePointPaths @($reparsePointPaths) `
                -ScannedDirectories $scannedDirectories `
                -ScannedItems $scannedItems `
                -Reason "Backup delete target is a reparse point, junction, or symlink."
        }

        [void]$pendingDirectories.Add($rootItem.FullName)

        while ($pendingDirectories.Count -gt 0) {
            $lastIndex = $pendingDirectories.Count - 1
            $currentDirectory = [string]$pendingDirectories[$lastIndex]
            $pendingDirectories.RemoveAt($lastIndex)
            $scannedDirectories++

            try {
                $children = @(Get-ChildItem -LiteralPath $currentDirectory -Force -ErrorAction Stop)
            }
            catch {
                return New-BackupDirectoryReparsePointSafetyResult `
                    -Success $false `
                    -HasReparsePoint ($reparsePointPaths.Count -gt 0) `
                    -ReparsePointPaths @($reparsePointPaths) `
                    -ScannedDirectories $scannedDirectories `
                    -ScannedItems $scannedItems `
                    -Reason "Cannot enumerate backup directory child items under '$currentDirectory': $($_.Exception.Message)"
            }

            foreach ($child in $children) {
                $scannedItems++

                try {
                    $isReparsePoint = (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
                }
                catch {
                    return New-BackupDirectoryReparsePointSafetyResult `
                        -Success $false `
                        -HasReparsePoint ($reparsePointPaths.Count -gt 0) `
                        -ReparsePointPaths @($reparsePointPaths) `
                        -ScannedDirectories $scannedDirectories `
                        -ScannedItems $scannedItems `
                        -Reason "Cannot inspect child item attributes under '$currentDirectory': $($_.Exception.Message)"
                }

                if ($isReparsePoint) {
                    if ($reparsePointPaths.Count -lt $MaxReportedPaths) {
                        [void]$reparsePointPaths.Add($child.FullName)
                    }

                    return New-BackupDirectoryReparsePointSafetyResult `
                        -Success $false `
                        -HasReparsePoint $true `
                        -ReparsePointPaths @($reparsePointPaths) `
                        -ScannedDirectories $scannedDirectories `
                        -ScannedItems $scannedItems `
                        -Reason "Backup directory contains a reparse point, junction, or symlink child: $($child.FullName)"
                }

                if ($child.PSIsContainer) {
                    [void]$pendingDirectories.Add($child.FullName)
                }
            }
        }

        return New-BackupDirectoryReparsePointSafetyResult `
            -Success $true `
            -ScannedDirectories $scannedDirectories `
            -ScannedItems $scannedItems
    }
    catch {
        return New-BackupDirectoryReparsePointSafetyResult `
            -Success $false `
            -HasReparsePoint ($reparsePointPaths.Count -gt 0) `
            -ReparsePointPaths @($reparsePointPaths) `
            -ScannedDirectories $scannedDirectories `
            -ScannedItems $scannedItems `
            -Reason "Backup directory reparse point scan failed: $($_.Exception.Message)"
    }
}

function Invoke-ProtectedBackupPathDelete {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet("FailedBackupCleanup", "BatchBackupDelete")]
        [string]$Mode,

        [string]$Reason = "",

        [string]$AllowedRoot = "",

        [switch]$RequireInProgressLock,

        [switch]$FromRecognizedBackupList,

        [string]$Distro = $Script:CurrentDistro
    )

    function Deny-ProtectedBackupPathDelete {
        param(
            [string]$Message,
            [string]$NormalizedPath = $Path,
            [string]$BackupType = "Unknown",
            [bool]$HasInProgressLock = $false,
            [object]$ReparsePointScan = $null
        )

        Write-Host "[WARN] Backup directory delete blocked: $Message" -ForegroundColor Yellow
        Write-LogEntry "WARN" "Delete-Blocked" "Mode=$Mode | $Message | Path=$NormalizedPath | Reason=$Reason" -Distro $Distro
        return New-ProtectedBackupPathDeleteResult `
            -Success $false `
            -DeletedPath $NormalizedPath `
            -Reason $Message `
            -BackupType $BackupType `
            -HasInProgressLock $HasInProgressLock `
            -RequireInProgressLock ([bool]$RequireInProgressLock) `
            -FromRecognizedBackupList ([bool]$FromRecognizedBackupList) `
            -ReparsePointScan $ReparsePointScan
    }

    function Write-ProtectedBackupPathDeleteAudit {
        param(
            [Parameter(Mandatory = $true)]
            [string]$TargetPath,

            [Parameter(Mandatory = $true)]
            [object]$Shape,

            [Parameter(Mandatory = $true)]
            [object]$ReparsePointScan
        )

        $scanStatus = if ($ReparsePointScan.Success) { "Passed" } else { "Blocked" }
        $scanReason = if ([string]::IsNullOrWhiteSpace($ReparsePointScan.Reason)) { "None" } else { $ReparsePointScan.Reason }
        $firstReparsePath = "None"
        if ($ReparsePointScan.HasReparsePoint -and $ReparsePointScan.ReparsePointPaths.Count -gt 0) {
            $firstReparsePath = [string]$ReparsePointScan.ReparsePointPaths[0]
        }

        Write-Host "  [Delete Audit] Backup directory delete pre-flight:" -ForegroundColor Cyan
        Write-Host ("     Target path              : {0}" -f $TargetPath) -ForegroundColor DarkGray
        Write-Host ("     Mode                     : {0}" -f $Mode) -ForegroundColor DarkGray
        Write-Host ("     DryRun                   : {0}" -f ([bool]$Global:DryRun)) -ForegroundColor DarkGray
        Write-Host ("     From recognized list     : {0}" -f ([bool]$FromRecognizedBackupList)) -ForegroundColor DarkGray
        Write-Host ("     Requires in-progress lock: {0}" -f ([bool]$RequireInProgressLock)) -ForegroundColor DarkGray
        Write-Host ("     Backup type              : {0}" -f $Shape.BackupType) -ForegroundColor DarkGray
        Write-Host ("     Has .backup-in-progress  : {0}" -f $Shape.HasInProgressLock) -ForegroundColor DarkGray
        Write-Host ("     Directory shape          : Passed" ) -ForegroundColor DarkGray
        Write-Host ("     Reparse scan             : {0}" -f $scanStatus) -ForegroundColor DarkGray
        Write-Host "     Reparse scan scope       : ReparsePoint-only; hard link files are not expanded." -ForegroundColor DarkGray
        Write-Host ("     Reparse point found      : {0}" -f $ReparsePointScan.HasReparsePoint) -ForegroundColor DarkGray
        Write-Host ("     Scanned directories      : {0}" -f $ReparsePointScan.ScannedDirectories) -ForegroundColor DarkGray
        Write-Host ("     Scanned items            : {0}" -f $ReparsePointScan.ScannedItems) -ForegroundColor DarkGray
        Write-Host ("     First reparse path       : {0}" -f $firstReparsePath) -ForegroundColor DarkGray
        Write-Host ("     Scan reason              : {0}" -f $scanReason) -ForegroundColor DarkGray

        Write-LogEntry "INFO" "Delete-Audit" "Mode=$Mode | Target=$TargetPath | DryRun=$([bool]$Global:DryRun) | FromRecognizedBackupList=$([bool]$FromRecognizedBackupList) | RequireInProgressLock=$([bool]$RequireInProgressLock) | BackupType=$($Shape.BackupType) | HasInProgressLock=$($Shape.HasInProgressLock) | ReparseScan=$scanStatus | ReparseScanScope=ReparsePoint-only; hard link files are not expanded. | HasReparsePoint=$($ReparsePointScan.HasReparsePoint) | ScannedDirectories=$($ReparsePointScan.ScannedDirectories) | ScannedItems=$($ReparsePointScan.ScannedItems) | FirstReparsePath=$firstReparsePath | ScanReason=$scanReason | Reason=$Reason" -Distro $Distro
    }

    $targetResolved = Get-NormalizedWindowsPathForComparison -Path $Path -Label "Backup delete target"
    if (-not $targetResolved.Success) {
        return Deny-ProtectedBackupPathDelete -Message $targetResolved.Reason
    }

    $target = $targetResolved.NormalizedPath
    $comparison = [System.StringComparison]::OrdinalIgnoreCase

    if (-not (Test-Path -LiteralPath $target -PathType Container)) {
        return Deny-ProtectedBackupPathDelete -Message "Target is not an existing directory." -NormalizedPath $target
    }

    if ($target.StartsWith('\\', $comparison)) {
        return Deny-ProtectedBackupPathDelete -Message "UNC or network backup deletion targets are not allowed." -NormalizedPath $target
    }

    $root = [System.IO.Path]::GetPathRoot($target)
    if ([string]::IsNullOrWhiteSpace($root) -or $root -notmatch '^[A-Za-z]:\\') {
        return Deny-ProtectedBackupPathDelete -Message "Target must be on a local drive path." -NormalizedPath $target
    }

    $rootResolved = Get-NormalizedWindowsPathForComparison -Path $root -Label "Backup delete target root"
    if (-not $rootResolved.Success -or $target.Equals($rootResolved.NormalizedPath, $comparison)) {
        return Deny-ProtectedBackupPathDelete -Message "Drive root deletion is not allowed." -NormalizedPath $target
    }

    try {
        $driveInfo = New-Object -TypeName System.IO.DriveInfo -ArgumentList $root
        if ($driveInfo.DriveType -eq [System.IO.DriveType]::Network) {
            return Deny-ProtectedBackupPathDelete -Message "Mapped network drives are not allowed for backup deletion." -NormalizedPath $target
        }
    }
    catch {
        return Deny-ProtectedBackupPathDelete -Message "Cannot determine drive safety for backup delete target: $($_.Exception.Message)" -NormalizedPath $target
    }

    try {
        $targetItem = Get-Item -LiteralPath $target -Force -ErrorAction Stop
        if (($targetItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            return Deny-ProtectedBackupPathDelete -Message "Backup delete target is a reparse point, junction, or symlink." -NormalizedPath $target
        }
    }
    catch {
        return Deny-ProtectedBackupPathDelete -Message "Cannot inspect backup delete target attributes: $($_.Exception.Message)" -NormalizedPath $target
    }

    $candidateAllowedRoots = if ($Mode -eq "FailedBackupCleanup") {
        @($AllowedRoot)
    }
    else {
        @($Global:Config.GlobalBackupRoot, (Get-InstanceBackupPath), $AllowedRoot)
    }

    $allowedRoots = @()
    foreach ($candidateRoot in $candidateAllowedRoots) {
        if ([string]::IsNullOrWhiteSpace($candidateRoot)) { continue }
        $rootCandidateResolved = Get-NormalizedWindowsPathForComparison -Path $candidateRoot -Label "Allowed backup deletion root"
        if ($rootCandidateResolved.Success) {
            $allowedRoots += $rootCandidateResolved.NormalizedPath
        }
    }
    $allowedRoots = @($allowedRoots | Select-Object -Unique)
    if ($allowedRoots.Count -eq 0) {
        return Deny-ProtectedBackupPathDelete -Message "No safe backup deletion root could be determined." -NormalizedPath $target
    }

    $underAllowedRoot = $false
    foreach ($allowed in $allowedRoots) {
        if ($target.Equals($allowed, $comparison)) {
            return Deny-ProtectedBackupPathDelete -Message "Refusing to delete a backup root itself: $allowed" -NormalizedPath $target
        }
        if (Test-PathIsSameOrChild -ChildPath $target -ParentPath $allowed) {
            $underAllowedRoot = $true
            break
        }
    }
    if (-not $underAllowedRoot) {
        return Deny-ProtectedBackupPathDelete -Message "Target is outside allowed backup deletion roots." -NormalizedPath $target
    }

    $forbiddenExactPaths = @()
    foreach ($forbiddenRaw in @(
            $env:USERPROFILE,
            $PSScriptRoot,
            $Global:Config.InstallRoot,
            $Global:Config.GlobalBackupRoot,
            (Get-InstanceBackupPath),
            $AllowedRoot,
            [System.IO.Path]::GetTempPath()
        )) {
        if ([string]::IsNullOrWhiteSpace($forbiddenRaw)) { continue }
        $forbiddenResolved = Get-NormalizedWindowsPathForComparison -Path $forbiddenRaw -Label "Forbidden backup deletion boundary"
        if ($forbiddenResolved.Success) {
            $forbiddenExactPaths += $forbiddenResolved.NormalizedPath
        }
    }

    $windowsRootRaw = $env:WINDIR
    if ([string]::IsNullOrWhiteSpace($windowsRootRaw)) { $windowsRootRaw = $env:SystemRoot }
    if (-not [string]::IsNullOrWhiteSpace($windowsRootRaw)) {
        $windowsRootResolved = Get-NormalizedWindowsPathForComparison -Path $windowsRootRaw -Label "Windows system directory"
        if ($windowsRootResolved.Success) {
            $forbiddenExactPaths += $windowsRootResolved.NormalizedPath
            if (Test-PathIsSameOrChild -ChildPath $target -ParentPath $windowsRootResolved.NormalizedPath) {
                return Deny-ProtectedBackupPathDelete -Message "Target is under the Windows system directory." -NormalizedPath $target
            }

            $system32Path = Join-Path $windowsRootResolved.NormalizedPath "System32"
            $system32Resolved = Get-NormalizedWindowsPathForComparison -Path $system32Path -Label "Windows System32 directory"
            if ($system32Resolved.Success) {
                $forbiddenExactPaths += $system32Resolved.NormalizedPath
                if (Test-PathIsSameOrChild -ChildPath $target -ParentPath $system32Resolved.NormalizedPath) {
                    return Deny-ProtectedBackupPathDelete -Message "Target is under the Windows System32 directory." -NormalizedPath $target
                }
            }
        }
    }

    $forbiddenExactPaths = @($forbiddenExactPaths | Select-Object -Unique)
    foreach ($forbidden in $forbiddenExactPaths) {
        if ($target.Equals($forbidden, $comparison)) {
            return Deny-ProtectedBackupPathDelete -Message "Target equals a protected boundary path: $forbidden" -NormalizedPath $target
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($Global:Config.InstallRoot)) {
        $installRootResolved = Get-NormalizedWindowsPathForComparison -Path $Global:Config.InstallRoot -Label "Configured install root"
        if ($installRootResolved.Success -and (Test-PathIsSameOrChild -ChildPath $target -ParentPath $installRootResolved.NormalizedPath)) {
            return Deny-ProtectedBackupPathDelete -Message "Target is under the configured install root." -NormalizedPath $target
        }
    }

    $tempRootResolved = Get-NormalizedWindowsPathForComparison -Path ([System.IO.Path]::GetTempPath()) -Label "TEMP root"
    if ($tempRootResolved.Success -and (Test-PathIsSameOrChild -ChildPath $target -ParentPath $tempRootResolved.NormalizedPath)) {
        return Deny-ProtectedBackupPathDelete -Message "Target is under the TEMP root." -NormalizedPath $target
    }

    $pathSegments = $target -split '[\\/]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    foreach ($segment in $pathSegments) {
        if ($segment -match '^(OneDrive( - .+)?|Dropbox|Google Drive|GoogleDrive|iCloudDrive|Box)$') {
            return Deny-ProtectedBackupPathDelete -Message "Target appears to be under a sync folder segment: $segment" -NormalizedPath $target
        }
    }

    $shape = Test-WSLBMBackupDirectoryShape -Path $target -RequireInProgressLock:$RequireInProgressLock -FromRecognizedBackupList:$FromRecognizedBackupList
    if (-not $shape.Success) {
        return Deny-ProtectedBackupPathDelete -Message $shape.Reason -NormalizedPath $target
    }

    $reparsePointScan = Test-BackupDirectoryReparsePointSafety -Path $target
    Write-ProtectedBackupPathDeleteAudit -TargetPath $target -Shape $shape -ReparsePointScan $reparsePointScan
    if (-not $reparsePointScan.Success) {
        return Deny-ProtectedBackupPathDelete `
            -Message $reparsePointScan.Reason `
            -NormalizedPath $target `
            -BackupType $shape.BackupType `
            -HasInProgressLock $shape.HasInProgressLock `
            -ReparsePointScan $reparsePointScan
    }

    if ($Global:DryRun) {
        Write-Host "DRY RUN: would delete backup directory: $target" -ForegroundColor Yellow
        Write-LogEntry "INFO" "Delete-DryRun" "Mode=$Mode | Would delete backup directory: $target | BackupType=$($shape.BackupType) | HasInProgressLock=$($shape.HasInProgressLock) | ReparseScan=Passed | Reason=$Reason" -Distro $Distro
        return New-ProtectedBackupPathDeleteResult `
            -Success $true `
            -SkippedBecauseDryRun $true `
            -DeletedPath $target `
            -BackupType $shape.BackupType `
            -HasInProgressLock $shape.HasInProgressLock `
            -RequireInProgressLock ([bool]$RequireInProgressLock) `
            -FromRecognizedBackupList ([bool]$FromRecognizedBackupList) `
            -ReparsePointScan $reparsePointScan
    }

    Write-Host "  Deleting backup directory: $target" -ForegroundColor DarkGray
    Write-LogEntry "WARN" "Delete" "Mode=$Mode | Deleting backup directory: $target | BackupType=$($shape.BackupType) | HasInProgressLock=$($shape.HasInProgressLock) | ReparseScan=Passed | Reason=$Reason" -Distro $Distro

    try {
        Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop
        Write-LogEntry "INFO" "Delete" "Mode=$Mode | Removed backup directory: $target" -Distro $Distro
        return New-ProtectedBackupPathDeleteResult `
            -Success $true `
            -DeletedPath $target `
            -BackupType $shape.BackupType `
            -HasInProgressLock $shape.HasInProgressLock `
            -RequireInProgressLock ([bool]$RequireInProgressLock) `
            -FromRecognizedBackupList ([bool]$FromRecognizedBackupList) `
            -ReparsePointScan $reparsePointScan
    }
    catch {
        $message = "Failed to delete backup directory: $($_.Exception.Message)"
        Write-LogEntry "ERROR" "Delete" "Mode=$Mode | $message | Path=$target" -Distro $Distro
        return New-ProtectedBackupPathDeleteResult `
            -Success $false `
            -DeletedPath $target `
            -Reason $message `
            -BackupType $shape.BackupType `
            -HasInProgressLock $shape.HasInProgressLock `
            -RequireInProgressLock ([bool]$RequireInProgressLock) `
            -FromRecognizedBackupList ([bool]$FromRecognizedBackupList) `
            -ReparsePointScan $reparsePointScan
    }
}

function Test-RestoreInstallPathSafety {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$InstallPath,

        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [string]$DistroName = $Script:CurrentDistro,

        [string]$Mode = "Restore"
    )

    function New-InstallPathFailure {
        param([string]$Reason)

        $modeLabel = if ([string]::IsNullOrWhiteSpace($Mode)) { "Restore" } else { $Mode }
        Write-Host "[ERROR] Unsafe $modeLabel restore install path: $Reason" -ForegroundColor Red
        Write-Host "  Install path: $InstallPath" -ForegroundColor Yellow
        Write-LogEntry "ERROR" "Restore-PathSafety" "Mode=$modeLabel | $Reason | InstallPath=$InstallPath | BackupFile=$BackupFile" -Distro $DistroName
        return New-RestorePathSafetyResult -Success $false -Reason $Reason
    }

    $installResolved = Get-NormalizedWindowsPathForComparison -Path $InstallPath -Label "Install path"
    if (-not $installResolved.Success) {
        return New-InstallPathFailure -Reason $installResolved.Reason
    }

    $install = $installResolved.NormalizedPath
    $comparison = [System.StringComparison]::OrdinalIgnoreCase
    $root = [System.IO.Path]::GetPathRoot($install)

    if ($install.StartsWith('\\', $comparison)) {
        return New-InstallPathFailure -Reason "UNC or network restore targets are not allowed."
    }

    if ([string]::IsNullOrWhiteSpace($root) -or $root -notmatch '^[A-Za-z]:\\') {
        return New-InstallPathFailure -Reason "Install path must be on a local drive path such as D:\\WSL\\Instance."
    }

    try {
        $driveInfo = New-Object -TypeName System.IO.DriveInfo -ArgumentList $root
        if ($driveInfo.DriveType -eq [System.IO.DriveType]::Network) {
            return New-InstallPathFailure -Reason "Mapped network drives are not allowed for restore install paths."
        }
    }
    catch {
        return New-InstallPathFailure -Reason "Cannot determine drive safety for install path root '$root': $($_.Exception.Message)"
    }

    $rootResolved = Get-NormalizedWindowsPathForComparison -Path $root -Label "Install path root"
    if (-not $rootResolved.Success -or $install.Equals($rootResolved.NormalizedPath, $comparison)) {
        return New-InstallPathFailure -Reason "Drive root restore targets are not allowed."
    }

    $windowsRootRaw = $env:WINDIR
    if ([string]::IsNullOrWhiteSpace($windowsRootRaw)) {
        $windowsRootRaw = $env:SystemRoot
    }
    if ([string]::IsNullOrWhiteSpace($windowsRootRaw)) {
        return New-InstallPathFailure -Reason "Cannot determine Windows system directory boundary for restore install path."
    }
    $windowsRootResolved = Get-NormalizedWindowsPathForComparison -Path $windowsRootRaw -Label "Windows system directory"
    if (-not $windowsRootResolved.Success) {
        return New-InstallPathFailure -Reason "Cannot normalize Windows system directory boundary: $($windowsRootResolved.Reason)"
    }
    if (Test-PathIsSameOrChild -ChildPath $install -ParentPath $windowsRootResolved.NormalizedPath) {
        return New-InstallPathFailure -Reason "Restore install path cannot be the Windows system directory or one of its subdirectories."
    }

    $system32Path = Join-Path $windowsRootResolved.NormalizedPath "System32"
    if (Test-PathIsSameOrChild -ChildPath $install -ParentPath $system32Path) {
        return New-InstallPathFailure -Reason "Restore install path cannot be the Windows System32 directory or one of its subdirectories."
    }

    $tempRootRaw = [System.IO.Path]::GetTempPath()
    if ([string]::IsNullOrWhiteSpace($tempRootRaw)) {
        return New-InstallPathFailure -Reason "Cannot determine TEMP boundary for restore install path."
    }
    $tempRootResolved = Get-NormalizedWindowsPathForComparison -Path $tempRootRaw -Label "TEMP root"
    if (-not $tempRootResolved.Success) {
        return New-InstallPathFailure -Reason "Cannot normalize TEMP boundary: $($tempRootResolved.Reason)"
    }
    if (Test-PathIsSameOrChild -ChildPath $install -ParentPath $tempRootResolved.NormalizedPath) {
        return New-InstallPathFailure -Reason "Restore install path cannot be the TEMP directory or one of its subdirectories."
    }

    if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        return New-InstallPathFailure -Reason "Cannot determine USERPROFILE boundary for restore install path."
    }
    $userProfileResolved = Get-NormalizedWindowsPathForComparison -Path $env:USERPROFILE -Label "USERPROFILE"
    if (-not $userProfileResolved.Success) {
        return New-InstallPathFailure -Reason "Cannot normalize USERPROFILE boundary: $($userProfileResolved.Reason)"
    }
    if ($install.Equals($userProfileResolved.NormalizedPath, $comparison)) {
        return New-InstallPathFailure -Reason "USERPROFILE and the .wslconfig directory are not allowed as restore install targets."
    }

    foreach ($highRiskUserDir in @("Desktop", "Documents", "Downloads")) {
        $highRiskPath = Join-Path $userProfileResolved.NormalizedPath $highRiskUserDir
        if (Test-PathIsSameOrChild -ChildPath $install -ParentPath $highRiskPath) {
            return New-InstallPathFailure -Reason "Restore install path cannot be under USERPROFILE\$highRiskUserDir."
        }
    }

    if (Test-PathIsSameOrChild -ChildPath $install -ParentPath $userProfileResolved.NormalizedPath) {
        Write-Host "[WARN] Restore install path is under USERPROFILE; ensure it is not synced, redirected, or used for personal files." -ForegroundColor Yellow
        Write-LogEntry "WARN" "Restore-PathSafety" "Mode=$Mode | InstallPath under USERPROFILE allowed with warning: $install" -Distro $DistroName
    }

    if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        return New-InstallPathFailure -Reason "Cannot determine script directory boundary for restore install path."
    }
    $scriptRootResolved = Get-NormalizedWindowsPathForComparison -Path $PSScriptRoot -Label "Script directory"
    if (-not $scriptRootResolved.Success) {
        return New-InstallPathFailure -Reason "Cannot normalize script directory boundary: $($scriptRootResolved.Reason)"
    }

    $installUnderConfiguredInstallRoot = $false
    if (-not [string]::IsNullOrWhiteSpace($Global:Config.InstallRoot)) {
        $installRootResolved = Get-NormalizedWindowsPathForComparison -Path $Global:Config.InstallRoot -Label "Configured install root"
        if (-not $installRootResolved.Success) {
            return New-InstallPathFailure -Reason "Cannot normalize configured install root boundary: $($installRootResolved.Reason)"
        }
        $installUnderConfiguredInstallRoot = Test-PathIsSameOrChild -ChildPath $install -ParentPath $installRootResolved.NormalizedPath
    }

    if ($install.Equals($scriptRootResolved.NormalizedPath, $comparison)) {
        return New-InstallPathFailure -Reason "Restore install path cannot be the script directory itself."
    }
    if (Test-PathIsSameOrChild -ChildPath $scriptRootResolved.NormalizedPath -ParentPath $install) {
        return New-InstallPathFailure -Reason "Restore install path cannot contain the script directory."
    }
    if ((Test-PathIsSameOrChild -ChildPath $install -ParentPath $scriptRootResolved.NormalizedPath) -and (-not $installUnderConfiguredInstallRoot)) {
        return New-InstallPathFailure -Reason "Restore install path cannot be under the script directory unless it is under the configured install root."
    }

    if ([string]::IsNullOrWhiteSpace($Global:Config.GlobalBackupRoot)) {
        return New-InstallPathFailure -Reason "Cannot determine configured backup root boundary for restore install path."
    }
    $backupRootResolved = Get-NormalizedWindowsPathForComparison -Path $Global:Config.GlobalBackupRoot -Label "Global backup root"
    if (-not $backupRootResolved.Success) {
        return New-InstallPathFailure -Reason "Cannot normalize configured backup root: $($backupRootResolved.Reason)"
    }
    if (Test-PathIsSameOrChild -ChildPath $install -ParentPath $backupRootResolved.NormalizedPath) {
        return New-InstallPathFailure -Reason "Restore install path cannot be under the configured backup root."
    }
    if (Test-PathIsSameOrChild -ChildPath $backupRootResolved.NormalizedPath -ParentPath $install) {
        return New-InstallPathFailure -Reason "Restore install path cannot contain the configured backup root."
    }

    $backupDir = Split-Path -Path $BackupFile -Parent
    if ([string]::IsNullOrWhiteSpace($backupDir)) {
        return New-InstallPathFailure -Reason "Cannot determine backup file directory for restore path safety check."
    }
    $backupDirResolved = Get-NormalizedWindowsPathForComparison -Path $backupDir -Label "Backup file directory"
    if (-not $backupDirResolved.Success) {
        return New-InstallPathFailure -Reason "Cannot normalize backup file directory: $($backupDirResolved.Reason)"
    }
    if (Test-PathIsSameOrChild -ChildPath $install -ParentPath $backupDirResolved.NormalizedPath) {
        return New-InstallPathFailure -Reason "Restore install path cannot be the backup file directory or one of its subdirectories."
    }
    if (Test-PathIsSameOrChild -ChildPath $backupDirResolved.NormalizedPath -ParentPath $install) {
        return New-InstallPathFailure -Reason "Restore install path cannot contain the backup file directory."
    }

    $pathSegments = $install -split '[\\/]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    foreach ($segment in $pathSegments) {
        if ($segment -match '^(OneDrive( - .+)?|Dropbox|Google Drive|GoogleDrive|iCloudDrive|Box)$') {
            return New-InstallPathFailure -Reason "Restore install path appears to be under a sync folder segment: $segment."
        }
    }

    Write-Host "  [OK] Restore install path safety check passed." -ForegroundColor Green
    Write-Host "     Install path: $install" -ForegroundColor DarkGray
    Write-LogEntry "INFO" "Restore-PathSafety" "Mode=$Mode | InstallPath=$install passed safety pre-flight" -Distro $DistroName
    return New-RestorePathSafetyResult -Success $true -NormalizedPath $install
}

function Test-RestoreTempRootWritable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        if ([string]::IsNullOrWhiteSpace($Path)) {
            return $false
        }
        if (-not (Test-Path -LiteralPath $Path -PathType Container -ErrorAction SilentlyContinue)) {
            return $false
        }

        $null = Get-Item -LiteralPath $Path -Force -ErrorAction Stop

        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principals = New-Object System.Collections.Generic.List[string]
        $principals.Add($identity.Name)
        if ($null -ne $identity.User) {
            $principals.Add($identity.User.Value)
        }
        foreach ($group in $identity.Groups) {
            $principals.Add($group.Value)
            try {
                $principals.Add($group.Translate([Security.Principal.NTAccount]).Value)
            }
            catch {
                $null = $_
            }
        }

        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $allowWrite = $false
        foreach ($rule in $acl.Access) {
            $identityValue = [string]$rule.IdentityReference.Value
            $principalMatches = $false
            foreach ($principal in $principals) {
                if ([string]::Equals($principal, $identityValue, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $principalMatches = $true
                    break
                }
            }
            if (-not $principalMatches) {
                continue
            }

            $rights = $rule.FileSystemRights
            $hasWriteRight =
                ([int]($rights -band [System.Security.AccessControl.FileSystemRights]::Write)) -ne 0 -or
                ([int]($rights -band [System.Security.AccessControl.FileSystemRights]::Modify)) -ne 0 -or
                ([int]($rights -band [System.Security.AccessControl.FileSystemRights]::FullControl)) -ne 0 -or
                ([int]($rights -band [System.Security.AccessControl.FileSystemRights]::CreateDirectories)) -ne 0 -or
                ([int]($rights -band [System.Security.AccessControl.FileSystemRights]::WriteData)) -ne 0
            if (-not $hasWriteRight) {
                continue
            }

            if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                return $false
            }
            if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
                $allowWrite = $true
            }
        }

        return $allowWrite
    }
    catch {
        return $false
    }
}

function Resolve-RestoreTempRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [Parameter(Mandatory = $true)]
        [string]$InstallPath,

        [string]$Distro = $Script:CurrentDistro
    )

    $installResolved = Get-NormalizedWindowsPathForComparison -Path $InstallPath -Label "Restore install path"
    if (-not $installResolved.Success) {
        throw "Cannot determine restore temp root because install path is unsafe: $($installResolved.Reason)"
    }

    $candidates = @()
    $backupDirRaw = Split-Path -Path $BackupFile -Parent
    if (-not [string]::IsNullOrWhiteSpace($backupDirRaw)) {
        $backupDirResolved = Get-NormalizedWindowsPathForComparison -Path $backupDirRaw -Label "Backup archive directory"
        if ($backupDirResolved.Success) {
            $candidates += [pscustomobject]@{
                ParentRoot = $backupDirResolved.NormalizedPath
                Source     = "BackupDir"
                Warning    = ""
            }
        }
    }

    $installParentRaw = Split-Path -Path $installResolved.NormalizedPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($installParentRaw)) {
        $installParentResolved = Get-NormalizedWindowsPathForComparison -Path $installParentRaw -Label "Install path parent"
        if ($installParentResolved.Success) {
            $candidates += [pscustomobject]@{
                ParentRoot = $installParentResolved.NormalizedPath
                Source     = "InstallPathParent"
                Warning    = ""
            }
        }
    }

    $systemTempWarning = "Falling back to system TEMP on C:; large restore may consume system drive space."
    $tempRootRaw = [System.IO.Path]::GetTempPath()
    if (-not [string]::IsNullOrWhiteSpace($tempRootRaw)) {
        $tempRootResolved = Get-NormalizedWindowsPathForComparison -Path $tempRootRaw -Label "System TEMP root"
        if ($tempRootResolved.Success) {
            $candidates += [pscustomobject]@{
                ParentRoot = $tempRootResolved.NormalizedPath
                Source     = "SystemTemp"
                Warning    = $systemTempWarning
            }
        }
    }

    foreach ($candidate in $candidates) {
        if (-not (Test-RestoreTempRootWritable -Path $candidate.ParentRoot)) {
            Write-LogEntry "WARN" "Restore-TempRoot" "Skipping restore temp parent because it is not writable: $($candidate.ParentRoot)" -Distro $Distro
            continue
        }

        if (Test-PathIsSameOrChild -ChildPath $candidate.ParentRoot -ParentPath $installResolved.NormalizedPath) {
            Write-LogEntry "WARN" "Restore-TempRoot" "Skipping restore temp parent because it is inside the target install path: $($candidate.ParentRoot)" -Distro $Distro
            continue
        }

        return [pscustomobject]@{
            ParentRoot       = $candidate.ParentRoot
            Source           = $candidate.Source
            Warning          = $candidate.Warning
            InstallPath      = $installResolved.NormalizedPath
            UsedSystemTemp   = ($candidate.Source -eq "SystemTemp")
        }
    }

    throw "Cannot find a writable restore temp root outside the target install path."
}

function New-RestoreTempPathInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [Parameter(Mandatory = $true)]
        [string]$InstallPath,

        [string]$Distro = $Script:CurrentDistro
    )

    $tempRootInfo = Resolve-RestoreTempRoot -BackupFile $BackupFile -InstallPath $InstallPath -Distro $Distro

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $tempDirName = "WSLBM-RestoreTemp-{0}" -f ([guid]::NewGuid().ToString('N'))
        $tempDir = Join-Path $tempRootInfo.ParentRoot $tempDirName
        $tempDirResolved = Get-NormalizedWindowsPathForComparison -Path $tempDir -Label "Restore temp directory"
        if (-not $tempDirResolved.Success) {
            continue
        }
        if (-not (Test-PathIsSameOrChild -ChildPath $tempDirResolved.NormalizedPath -ParentPath $tempRootInfo.ParentRoot)) {
            continue
        }
        if (Test-PathIsSameOrChild -ChildPath $tempDirResolved.NormalizedPath -ParentPath $tempRootInfo.InstallPath) {
            continue
        }
        if (Test-Path -LiteralPath $tempDirResolved.NormalizedPath -ErrorAction SilentlyContinue) {
            continue
        }

        $tempTar = Join-Path $tempDirResolved.NormalizedPath "wsl-export.tar"
        if (-not [string]::IsNullOrWhiteSpace($tempRootInfo.Warning)) {
            Write-Host "[WARN] $($tempRootInfo.Warning)" -ForegroundColor Yellow
            Write-LogEntry "WARN" "Restore-TempRoot" $tempRootInfo.Warning -Distro $Distro
        }
        Write-Host "  Restore temp root: $($tempDirResolved.NormalizedPath)" -ForegroundColor DarkGray
        Write-LogEntry "INFO" "Restore-TempRoot" "Source=$($tempRootInfo.Source) | TempRoot=$($tempDirResolved.NormalizedPath) | Parent=$($tempRootInfo.ParentRoot)" -Distro $Distro
        return [pscustomobject]@{
            TempRoot       = $tempDirResolved.NormalizedPath
            TempDir        = $tempDirResolved.NormalizedPath
            TempTar        = $tempTar
            ParentRoot     = $tempRootInfo.ParentRoot
            Source         = $tempRootInfo.Source
            UsedSystemTemp = $tempRootInfo.UsedSystemTemp
        }
    }

    throw "Cannot allocate a unique restore temp directory under $($tempRootInfo.ParentRoot)."
}

function Clear-RestoreTempArtifacts {
    param(
        [string]$TempDir,
        [string]$TempTar,
        [string]$Distro = $Script:CurrentDistro
    )

    # Compatibility parameter retained for restore cleanup audit context.
    $null = $Distro

    if ($Global:DryRun) {
        return
    }

    function Write-RestoreCleanupWarning {
        param([string]$Message)

        Write-Host "[WARN] Restore temp cleanup skipped or incomplete: $Message" -ForegroundColor Yellow
        Write-LogEntry "WARN" "Restore-Cleanup" $Message -Distro $Distro
    }

    if ([string]::IsNullOrWhiteSpace($TempDir) -and [string]::IsNullOrWhiteSpace($TempTar)) {
        return
    }
    if ([string]::IsNullOrWhiteSpace($TempDir) -or [string]::IsNullOrWhiteSpace($TempTar)) {
        Write-RestoreCleanupWarning "Restore temp cleanup requires both TempDir and TempTar. TempDir=$TempDir | TempTar=$TempTar"
        return
    }

    $tempDirResolved = Get-NormalizedWindowsPathForComparison -Path $TempDir -Label "Restore temp directory"
    $tempTarResolved = Get-NormalizedWindowsPathForComparison -Path $TempTar -Label "Restore temp tar"

    if (-not $tempDirResolved.Success -or -not $tempTarResolved.Success) {
        Write-RestoreCleanupWarning "Cannot normalize restore temp paths safely. TempDir=$TempDir | TempTar=$TempTar"
        return
    }

    $tempDirName = Split-Path -Path $tempDirResolved.NormalizedPath -Leaf
    if ($tempDirName -notmatch '^WSLBM-RestoreTemp-[0-9a-fA-F]{32}$') {
        Write-RestoreCleanupWarning "Restore temp directory name does not match controlled prefix: $($tempDirResolved.NormalizedPath)"
        return
    }
    $tempDirParent = Split-Path -Path $tempDirResolved.NormalizedPath -Parent
    if ([string]::IsNullOrWhiteSpace($tempDirParent) -or $tempDirParent -eq $tempDirResolved.NormalizedPath) {
        Write-RestoreCleanupWarning "Restore temp directory has no safe parent boundary: $($tempDirResolved.NormalizedPath)"
        return
    }

    $tarParent = Split-Path -Path $tempTarResolved.NormalizedPath -Parent
    $tarName = Split-Path -Path $tempTarResolved.NormalizedPath -Leaf
    if (-not $tarParent.Equals($tempDirResolved.NormalizedPath, [System.StringComparison]::OrdinalIgnoreCase) -or $tarName -ne "wsl-export.tar") {
        Write-RestoreCleanupWarning "Restore temp tar is not the expected file under the controlled temp directory: $($tempTarResolved.NormalizedPath)"
        return
    }

    try {
        if (Test-Path -LiteralPath $tempTarResolved.NormalizedPath -PathType Leaf) {
            Remove-Item -LiteralPath $tempTarResolved.NormalizedPath -Force -ErrorAction Stop
        }
    }
    catch {
        Write-RestoreCleanupWarning "Failed to remove restore temp tar $($tempTarResolved.NormalizedPath): $($_.Exception.Message)"
    }

    try {
        if (Test-Path -LiteralPath $tempDirResolved.NormalizedPath -PathType Container) {
            $remainingItem = Get-ChildItem -LiteralPath $tempDirResolved.NormalizedPath -Force -ErrorAction Stop | Select-Object -First 1
            if ($null -eq $remainingItem) {
                Remove-Item -LiteralPath $tempDirResolved.NormalizedPath -Force -ErrorAction Stop
            }
            else {
                Write-RestoreCleanupWarning "Restore temp directory is not empty; leaving it for manual review: $($tempDirResolved.NormalizedPath)"
            }
        }
    }
    catch {
        Write-RestoreCleanupWarning "Failed to remove empty restore temp directory $($tempDirResolved.NormalizedPath): $($_.Exception.Message)"
    }
}

function Test-PathFreeSpaceForRestorePayload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [long]$TarSizeBytes,

        [string]$Label = "Restore path",

        [string]$Distro = $Script:CurrentDistro
    )

    if ($TarSizeBytes -le 0) {
        Write-Host "[ERROR] Restore tar size is invalid: $TarSizeBytes bytes." -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-Space" "Invalid restore tar size: $TarSizeBytes bytes" -Distro $Distro
        return $false
    }

    $bufferBytes = [long][math]::Max([math]::Ceiling([double]$TarSizeBytes * 0.10), [double]1GB)
    $requiredBytes = [long]($TarSizeBytes + $bufferBytes)
    $availableBytes = $null
    $spaceSource = ""

    try {
        $resolvedPath = Resolve-RestoreSpaceCheckPath -Path $Path -Label $Label -Distro $Distro
        if (-not $resolvedPath.Success) {
            return $false
        }

        $space = Get-WSLBMPathFreeSpaceInfo -Path $resolvedPath.CheckPath -Label $Label -LogAction "Restore-Space" -Distro $Distro
        if (-not $space.Success) {
            throw $space.Reason
        }
        $availableBytes = [long]$space.AvailableBytes
        $spaceSource = "$($space.SourceType):$($space.SourceKey)"

        Write-Host "  -> Restore Space Check: $Label" -ForegroundColor Cyan
        Write-Host ("     Target    : {0}" -f $Path) -ForegroundColor DarkGray
        Write-Host ("     Check path: {0}" -f $resolvedPath.CheckPath) -ForegroundColor DarkGray
        Write-Host ("     Tar size  : {0}" -f (Format-Bytes $TarSizeBytes)) -ForegroundColor DarkGray
        Write-Host ("     Buffer    : {0}" -f (Format-Bytes $bufferBytes)) -ForegroundColor DarkGray
        Write-Host ("     Required  : {0}" -f (Format-Bytes $requiredBytes)) -ForegroundColor DarkGray
        Write-Host ("     Available : {0}" -f (Format-Bytes $availableBytes)) -ForegroundColor DarkGray
        Write-LogEntry "INFO" "Restore-Space" "Label=$Label | Target=$Path | CheckPath=$($resolvedPath.CheckPath) | Source=$spaceSource | Tar=$(Format-Bytes $TarSizeBytes) | Required=$(Format-Bytes $requiredBytes) | Available=$(Format-Bytes $availableBytes)" -Distro $Distro

        if ($availableBytes -lt $requiredBytes) {
            Write-Host "[ERROR] Not enough free space for restore payload." -ForegroundColor Red
            Write-Host "  Target    : $Path" -ForegroundColor Yellow
            Write-Host "  Check path: $($resolvedPath.CheckPath)" -ForegroundColor Yellow
            Write-Host "  Required  : $(Format-Bytes $requiredBytes)" -ForegroundColor Yellow
            Write-Host "  Available : $(Format-Bytes $availableBytes)" -ForegroundColor Yellow
            Write-LogEntry "ERROR" "Restore-Space" "Insufficient space. Label=$Label | Target=$Path | CheckPath=$($resolvedPath.CheckPath) | Required=$(Format-Bytes $requiredBytes) | Available=$(Format-Bytes $availableBytes)" -Distro $Distro
            return $false
        }

        Write-Host "  [OK] Restore space check passed for $Label." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Cannot verify free space for ${Label}: $($_.Exception.Message)" -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-Space" "Cannot verify free space for ${Label}: $($_.Exception.Message)" -Distro $Distro
        return $false
    }
}

function Test-PathFreeSpaceForRestoreTar {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TempPath,

        [Parameter(Mandatory = $true)]
        [long]$TarSizeBytes,

        [string]$Distro = $Script:CurrentDistro
    )

    return Test-PathFreeSpaceForRestorePayload -Path $TempPath -TarSizeBytes $TarSizeBytes -Label "Restore temp root" -Distro $Distro
}

function Test-RestoreImportPreflight {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [Parameter(Mandatory = $true)]
        [string]$InstallPath,

        [string]$Distro = $Script:CurrentDistro,

        [string]$Mode = "Restore"
    )

    $tarEntryName = "wsl-export.tar"
    $minimumTarSizeBytes = 1KB

    $installPathSafety = Test-RestoreInstallPathSafety -InstallPath $InstallPath -BackupFile $BackupFile -DistroName $Distro -Mode $Mode
    if (-not $installPathSafety.Success) {
        Write-Host "[ERROR] Restore aborted before any WSL changes because install path safety pre-flight failed." -ForegroundColor Red
        return [pscustomobject]@{
            Success              = $false
            TarSizeBytes         = -1
            SkippedBecauseDryRun = $Global:DryRun
            InstallPath          = $InstallPath
            InstallPathSafety    = $installPathSafety
            TempPathInfo         = $null
        }
    }

    try {
        $tempPathInfo = New-RestoreTempPathInfo -BackupFile $BackupFile -InstallPath $installPathSafety.NormalizedPath -Distro $Distro
    }
    catch {
        Write-Host "[ERROR] Restore aborted before any WSL changes because restore temp root could not be selected: $($_.Exception.Message)" -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-Preflight" "Cannot select restore temp root: $($_.Exception.Message)" -Distro $Distro
        return [pscustomobject]@{
            Success              = $false
            TarSizeBytes         = -1
            SkippedBecauseDryRun = $Global:DryRun
            InstallPath          = $installPathSafety.NormalizedPath
            InstallPathSafety    = $installPathSafety
            TempPathInfo         = $null
        }
    }

    if ($Global:DryRun) {
        Write-Host "DRY RUN: restore install path safety check passed for $($installPathSafety.NormalizedPath)" -ForegroundColor Yellow
        Write-Host "DRY RUN: would use restore temp root $($tempPathInfo.TempRoot)" -ForegroundColor Yellow
        Write-Host "DRY RUN: would run full restore archive integrity check for $BackupFile" -ForegroundColor Yellow
        Write-Host "DRY RUN: would read uncompressed size of $tarEntryName from $BackupFile" -ForegroundColor Yellow
        Write-Host "DRY RUN: would check restore temp root free space for restore payload at $($tempPathInfo.TempRoot)" -ForegroundColor Yellow
        Write-Host "DRY RUN: would check install path free space for restore payload at $InstallPath" -ForegroundColor Yellow
        Write-LogEntry "INFO" "Restore-Preflight-DryRun" "Mode=$Mode | Would validate install path safety, archive, read $tarEntryName size, and check restore temp/install path space. Backup=$BackupFile | InstallPath=$InstallPath | TempRoot=$($tempPathInfo.TempRoot)" -Distro $Distro
        return [pscustomobject]@{
            Success              = $true
            TarSizeBytes         = -1
            SkippedBecauseDryRun = $true
            InstallPath          = $installPathSafety.NormalizedPath
            InstallPathSafety    = $installPathSafety
            TempPathInfo         = $tempPathInfo
        }
    }

    if (-not (Test-RestoreArchiveIntegrity -backupFile $BackupFile)) {
        Write-LogEntry "ERROR" "Restore-Preflight" "Archive integrity check failed: $BackupFile" -Distro $Distro
        Write-Host "[ERROR] Restore aborted before any WSL changes." -ForegroundColor Red
        return [pscustomobject]@{
            Success              = $false
            TarSizeBytes         = -1
            SkippedBecauseDryRun = $false
            TempPathInfo         = $tempPathInfo
        }
    }

    try {
        $tarSizeBytes = Get-RestoreTarSizeFromArchive -BackupFile $BackupFile -EntryName $tarEntryName -Distro $Distro
    }
    catch {
        Write-Host "[ERROR] Restore pre-flight failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-Preflight" "Failed to read $tarEntryName size: $($_.Exception.Message)" -Distro $Distro
        return [pscustomobject]@{
            Success              = $false
            TarSizeBytes         = -1
            SkippedBecauseDryRun = $false
            TempPathInfo         = $tempPathInfo
        }
    }

    if ($tarSizeBytes -lt $minimumTarSizeBytes) {
        Write-Host "[ERROR] Restore tar entry is too small ($(Format-Bytes $tarSizeBytes))." -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-Preflight" "Archive tar entry too small: $tarSizeBytes bytes" -Distro $Distro
        return [pscustomobject]@{
            Success              = $false
            TarSizeBytes         = $tarSizeBytes
            SkippedBecauseDryRun = $false
            TempPathInfo         = $tempPathInfo
        }
    }

    $bufferBytes = [long][math]::Max([math]::Ceiling([double]$tarSizeBytes * 0.10), [double]1GB)
    $requiredBytes = [long]($tarSizeBytes + $bufferBytes)
    Write-LogEntry "INFO" "Restore-Preflight" "Restore payload size=$(Format-Bytes $tarSizeBytes) | Required per target=$(Format-Bytes $requiredBytes)" -Distro $Distro

    if (-not (Test-PathFreeSpaceForRestorePayload -Path $tempPathInfo.TempRoot -TarSizeBytes $tarSizeBytes -Label "Restore temp root" -Distro $Distro)) {
        Write-Host "[ERROR] Restore aborted before any WSL changes because restore temp root space pre-flight failed." -ForegroundColor Red
        return [pscustomobject]@{
            Success              = $false
            TarSizeBytes         = $tarSizeBytes
            SkippedBecauseDryRun = $false
            TempPathInfo         = $tempPathInfo
        }
    }

    if (-not (Test-PathFreeSpaceForRestorePayload -Path $installPathSafety.NormalizedPath -TarSizeBytes $tarSizeBytes -Label "Install path" -Distro $Distro)) {
        Write-Host "[ERROR] Restore aborted before any WSL changes because install path space pre-flight failed." -ForegroundColor Red
        return [pscustomobject]@{
            Success              = $false
            TarSizeBytes         = $tarSizeBytes
            SkippedBecauseDryRun = $false
            TempPathInfo         = $tempPathInfo
        }
    }

    return [pscustomobject]@{
        Success              = $true
        TarSizeBytes         = $tarSizeBytes
        RequiredBytes        = $requiredBytes
        BufferBytes          = $bufferBytes
        SkippedBecauseDryRun = $false
        InstallPath          = $installPathSafety.NormalizedPath
        InstallPathSafety    = $installPathSafety
        TempPathInfo         = $tempPathInfo
    }
}

function Expand-RestoreArchiveToTempTar {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [string]$Distro = $Script:CurrentDistro,

        [long]$TarSizeBytes = -1,

        [object]$TempPathInfo = $null,

        [string]$InstallPath = ""
    )

    $tarEntryName = "wsl-export.tar"
    $minimumTarSizeBytes = 1KB
    try {
        $tempPathInfo = $TempPathInfo
        if ($null -eq $tempPathInfo) {
            if ([string]::IsNullOrWhiteSpace($InstallPath)) {
                throw "Restore temp path requires the target install path."
            }
            $tempPathInfo = New-RestoreTempPathInfo -BackupFile $BackupFile -InstallPath $InstallPath -Distro $Distro
        }
        $tempDir = $tempPathInfo.TempDir
        $tempTar = $tempPathInfo.TempTar
    }
    catch {
        Write-Host "[ERROR] Restore tar extraction failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-Extract" "Cannot allocate controlled temp path: $($_.Exception.Message)" -Distro $Distro
        return [pscustomobject]@{
            Success              = $false
            ExitCode             = $null
            SkippedBecauseDryRun = $Global:DryRun
            TempDir              = $null
            TempTar              = $null
        }
    }

    if ($Global:DryRun) {
        Write-Host "DRY RUN: would read uncompressed size of $tarEntryName from $BackupFile" -ForegroundColor Yellow
        Write-Host "DRY RUN: would check restore temp root free space for restore tar plus safety buffer at $tempDir" -ForegroundColor Yellow
        Write-Host "DRY RUN: would extract $tarEntryName from $BackupFile to $tempTar" -ForegroundColor Yellow
        Write-Host "DRY RUN: would validate extracted tar exists and is at least $(Format-Bytes $minimumTarSizeBytes)" -ForegroundColor Yellow
        Write-LogEntry "INFO" "Restore-Extract-DryRun" "Would read $tarEntryName size, check restore temp root space, and extract to $tempTar" -Distro $Distro
        return [pscustomobject]@{
            Success              = $true
            ExitCode             = $null
            SkippedBecauseDryRun = $true
            TempDir              = $tempDir
            TempTar              = $tempTar
        }
    }

    try {
        $null = Assert-WSLBMSevenZipArchiveInput -ArchivePath $BackupFile -Context "Restore archive"
        $sevenZipExe = Resolve-WSLBMSevenZipPath

        $tarSizeBytes = $TarSizeBytes
        if ($tarSizeBytes -le 0) {
            $tarSizeBytes = Get-RestoreTarSizeFromArchive -BackupFile $BackupFile -EntryName $tarEntryName -Distro $Distro
        }
        if ($tarSizeBytes -lt $minimumTarSizeBytes) {
            Write-Host "[ERROR] Restore tar entry is too small ($(Format-Bytes $tarSizeBytes))." -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-TempSpace" "Archive tar entry too small: $tarSizeBytes bytes" -Distro $Distro
            return [pscustomobject]@{
                Success              = $false
                ExitCode             = $null
                SkippedBecauseDryRun = $false
                TempDir              = $tempDir
                TempTar              = $tempTar
            }
        }

        if (-not (Test-PathFreeSpaceForRestoreTar -TempPath $tempDir -TarSizeBytes $tarSizeBytes -Distro $Distro)) {
            return [pscustomobject]@{
                Success              = $false
                ExitCode             = $null
                SkippedBecauseDryRun = $false
                TempDir              = $tempDir
                TempTar              = $tempTar
            }
        }

        if (Test-Path -LiteralPath $tempDir -ErrorAction SilentlyContinue) {
            throw "Controlled restore TEMP directory already exists: $tempDir"
        }
        New-Item -ItemType Directory -Path $tempDir | Out-Null

        Write-Host "Extracting restore tar to temporary file..." -ForegroundColor Cyan
        Write-Host "  Temp: $tempTar" -ForegroundColor DarkGray
        Write-LogEntry "INFO" "Restore-Extract" "Extracting $tarEntryName to $tempTar" -Distro $Distro

        $argList = @("e", $BackupFile, $tarEntryName, "-o$tempDir", "-y", "-bd")
        $previousIsActive = $Global:BackupState.IsActive
        $previousIsRunning = $Global:BackupState.IsRunning
        $previousOperation = $Global:BackupState.Operation
        $previousCurrentFile = $Global:BackupState.CurrentFile
        $previousCurrentDir = $Global:BackupState.CurrentDir
        try {
            $Global:BackupState.IsActive = $true
            $Global:BackupState.IsRunning = $true
            $Global:BackupState.Operation = "Restore-Extract"
            $Global:BackupState.CurrentFile = $BackupFile
            $Global:BackupState.CurrentDir = $tempDir
            $extractProcess = Invoke-WSLBMNativeProcessChecked `
                -FilePath $sevenZipExe `
                -Arguments $argList `
                -OperationName "Restore-Extract" `
                -Description "Extract restore tar from archive" `
                -TimeoutSeconds $Script:RestoreExtractTimeoutSeconds `
                -AllowCancel `
                -RegisterActiveProcess `
                -Distro $Distro
            $exitCode = $extractProcess.ExitCode
        }
        finally {
            $Global:BackupState.IsActive = $previousIsActive
            $Global:BackupState.IsRunning = $previousIsRunning
            $Global:BackupState.Operation = $previousOperation
            $Global:BackupState.CurrentFile = $previousCurrentFile
            $Global:BackupState.CurrentDir = $previousCurrentDir
        }
        if ($extractProcess.TimedOut) {
            Write-Host "[ERROR] Failed to extract restore tar: 7z timed out." -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-Extract" "7z timed out after $Script:RestoreExtractTimeoutSeconds seconds" -Distro $Distro
            return [pscustomobject]@{
                Success              = $false
                ExitCode             = $exitCode
                SkippedBecauseDryRun = $false
                TimedOut             = $true
                Cancelled            = $false
                TempDir              = $tempDir
                TempTar              = $tempTar
            }
        }
        if ($extractProcess.Cancelled) {
            Write-Host "[WARN] Restore tar extraction cancelled by user." -ForegroundColor Yellow
            Write-LogEntry "WARN" "Restore-Extract" "7z extraction cancelled by user" -Distro $Distro
            return [pscustomobject]@{
                Success              = $false
                ExitCode             = $exitCode
                SkippedBecauseDryRun = $false
                TimedOut             = $false
                Cancelled            = $true
                TempDir              = $tempDir
                TempTar              = $tempTar
            }
        }
        if ($null -eq $exitCode) {
            Write-Host "[ERROR] Failed to extract restore tar: 7z did not report an exit code." -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-Extract" "7z failed without reporting an exit code" -Distro $Distro
            return [pscustomobject]@{
                Success              = $false
                ExitCode             = $null
                SkippedBecauseDryRun = $false
                TimedOut             = $false
                Cancelled            = $false
                TempDir              = $tempDir
                TempTar              = $tempTar
            }
        }
        if ($exitCode -ne 0) {
            Write-Host "[ERROR] Failed to extract restore tar (7z exit code $exitCode)." -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-Extract" "7z failed with exit code $exitCode" -Distro $Distro
            return [pscustomobject]@{
                Success              = $false
                ExitCode             = $exitCode
                SkippedBecauseDryRun = $false
                TimedOut             = $false
                Cancelled            = $false
                TempDir              = $tempDir
                TempTar              = $tempTar
            }
        }

        if (-not (Test-Path $tempTar -PathType Leaf)) {
            Write-Host "[ERROR] Restore tar extraction failed: $tempTar was not created." -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-Extract" "Extracted tar missing: $tempTar" -Distro $Distro
            return [pscustomobject]@{
                Success              = $false
                ExitCode             = $exitCode
                SkippedBecauseDryRun = $false
                TempDir              = $tempDir
                TempTar              = $tempTar
            }
        }

        $tarItem = Get-Item $tempTar
        if ($tarItem.Length -lt $minimumTarSizeBytes) {
            Write-Host "[ERROR] Restore tar extraction failed: file is too small ($(Format-Bytes $tarItem.Length))." -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-Extract" "Extracted tar too small: $($tarItem.Length) bytes" -Distro $Distro
            return [pscustomobject]@{
                Success              = $false
                ExitCode             = $exitCode
                SkippedBecauseDryRun = $false
                TempDir              = $tempDir
                TempTar              = $tempTar
            }
        }

        Write-Host "  [OK] Restore tar extracted: $(Format-Bytes $tarItem.Length)" -ForegroundColor Green
        Write-LogEntry "INFO" "Restore-Extract" "Extracted $tarEntryName ($(Format-Bytes $tarItem.Length))" -Distro $Distro
        return [pscustomobject]@{
            Success              = $true
            ExitCode             = $exitCode
            SkippedBecauseDryRun = $false
            TempDir              = $tempDir
            TempTar              = $tempTar
        }
    }
    catch {
        Write-Host "[ERROR] Restore tar extraction failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-Extract" "Exception: $($_.Exception.Message)" -Distro $Distro
        return [pscustomobject]@{
            Success              = $false
            ExitCode             = $null
            SkippedBecauseDryRun = $false
            TempDir              = $tempDir
            TempTar              = $tempTar
        }
    }
}

function Invoke-RestoreImportFromTar {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$InstallPath,

        [Parameter(Mandatory = $true)]
        [string]$TempTar
    )

    # WSL high-risk boundary: import is routed through Invoke-GuardedWSLCommand (DryRun + exit-code check).
    $importResult = Invoke-GuardedWSLCommand `
        -Description "Import restored distro from extracted tar" `
        -Arguments @("--import", $DistroName, $InstallPath, $TempTar) `
        -Distro $DistroName

    if (-not $importResult.Success) {
        Write-LogEntry "ERROR" "Restore-Import" "WSL import failed for $DistroName" -Distro $DistroName
        return $importResult
    }

    Write-LogEntry "INFO" "Restore-Import" "WSL import completed for $DistroName" -Distro $DistroName
    return $importResult
}

function Get-RestoreSafetyNetManifestPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SafetyNetPath
    )

    $parent = [System.IO.Path]::GetDirectoryName($SafetyNetPath)
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($SafetyNetPath)
    return (Join-Path $parent "$baseName.manifest.json")
}

function Write-RestoreSafetyNetManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$SafetyNetPath
    )

    $safetyItem = Get-Item -LiteralPath $SafetyNetPath -ErrorAction Stop
    $safetyHash = Get-FileHash -LiteralPath $safetyItem.FullName -Algorithm SHA256 -ErrorAction Stop
    $manifestPath = Get-RestoreSafetyNetManifestPath -SafetyNetPath $safetyItem.FullName

    $manifest = [ordered]@{
        SchemaVersion     = 1
        ManifestType      = "SafetyNet"
        OperationId       = $Script:CurrentOperationId
        CreatedAt         = (Get-Date).ToString("o")
        SourceDistro      = $DistroName
        SafetyNetPath     = $safetyItem.FullName
        SafetyNetFileName = $safetyItem.Name
        ArchiveSizeBytes  = [long]$safetyItem.Length
        ArchiveSha256     = [string]$safetyHash.Hash
        Purpose           = "FULL overwrite restore safety net"
        ScriptVersion     = Get-WSLBMScriptVersion
    }

    Write-WSLBMTextFileUtf8NoBom -LiteralPath $manifestPath -Content ($manifest | ConvertTo-Json -Depth 4)
    return $manifestPath
}

function New-RestoreSafetyNetBackup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName
    )

    if ([string]::IsNullOrWhiteSpace($DistroName)) {
        Write-Host "[ERROR] Safety Net failed: distro name is empty." -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-SafetyNet" "Distro name is empty"
        return $null
    }

    if (-not (Test-SafeDistroName -Name $DistroName)) {
        Write-Host "[ERROR] Safety Net failed: distro name contains unsafe characters." -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-SafetyNet" "Unsafe distro name: $DistroName"
        return $null
    }

    if (-not (Test-WSLBMBackupRootReady `
            -Path $Global:Config.GlobalBackupRoot `
            -Label "Configured Backup Root" `
            -InvalidAction "Safety Net creation is blocked until Settings is corrected.")) {
        Write-LogEntry "ERROR" "Restore-SafetyNet" "Invalid configured backup root: $($Global:Config.GlobalBackupRoot)" -Distro $DistroName
        return $null
    }

    $safeFileNameDistro = $DistroName -replace '[\\/:*?"<>|]', '_'
    $safetyFile = Join-Path $Global:Config.GlobalBackupRoot "SAFETY-NET-$safeFileNameDistro-$(Get-Date -Format 'yyyyMMdd-HHmmss').tar"

    Write-Host "Creating Safety Net..." -ForegroundColor Cyan
    Write-LogEntry "INFO" "Restore-SafetyNet" "Creating Safety Net: $safetyFile" -Distro $DistroName

    try {
        if (-not (Test-RestoreSafetyNetExportSpace -DistroName $DistroName -SafetyNetPath $safetyFile)) {
            Write-Host "[ERROR] Safety Net export blocked before any WSL export because space pre-flight failed." -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-SafetyNet" "Safety Net export blocked by space pre-flight: $safetyFile" -Distro $DistroName
            return $null
        }

        if ($Global:DryRun) {
            # WSL high-risk boundary: Safety Net preview still uses the guarded wrapper, which short-circuits in DryRun.
            $null = Invoke-GuardedWSLCommand -Description "Shutdown WSL for Safety Net" -Arguments @("--shutdown") -Distro $DistroName
            $null = Invoke-GuardedWSLCommand -Description "Export Safety Net" -Arguments @("--export", $DistroName, $safetyFile) -Distro $DistroName
            Write-Host "DRY RUN: would validate Safety Net file $safetyFile" -ForegroundColor Yellow
            Write-LogEntry "INFO" "Restore-SafetyNet" "DryRun Safety Net export simulated: $safetyFile" -Distro $DistroName
            return $safetyFile
        }

        if (-not (New-BackupDirectory $Global:Config.GlobalBackupRoot)) {
            Write-Host "[ERROR] Safety Net failed: cannot access backup root." -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-SafetyNet" "Cannot access backup root: $($Global:Config.GlobalBackupRoot)" -Distro $DistroName
            return $null
        }

        # WSL high-risk boundary: Safety Net shutdown/export use guarded wrapper after backup-root preflight.
        $shutdownResult = Invoke-GuardedWSLCommand -Description "Shutdown WSL for Safety Net" -Arguments @("--shutdown") -Distro $DistroName
        if (-not $shutdownResult.Success) {
            Write-LogEntry "ERROR" "Restore-SafetyNet" "WSL shutdown failed before Safety Net export" -Distro $DistroName
            return $null
        }
        Start-Sleep -Seconds 1

        $exportResult = Invoke-GuardedWSLCommand -Description "Export Safety Net" -Arguments @("--export", $DistroName, $safetyFile) -Distro $DistroName
        if (-not $exportResult.Success) {
            Write-LogEntry "ERROR" "Restore-SafetyNet" "Safety Net export failed" -Distro $DistroName
            return $null
        }

        if (-not (Test-Path -LiteralPath $safetyFile -PathType Leaf)) {
            Write-Host "[ERROR] Safety Net export failed: file was not created." -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-SafetyNet" "Safety Net file missing: $safetyFile" -Distro $DistroName
            return $null
        }

        $safetyItem = Get-Item -LiteralPath $safetyFile -ErrorAction Stop
        if ($safetyItem.Length -lt $Script:MinimumSafetyNetArchiveBytes) {
            Write-Host "[ERROR] Safety Net export failed: file is too small ($(Format-Bytes $safetyItem.Length); minimum $(Format-Bytes $Script:MinimumSafetyNetArchiveBytes))." -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-SafetyNet" "Safety Net file too small. Path=$safetyFile | Actual=$($safetyItem.Length) | Minimum=$Script:MinimumSafetyNetArchiveBytes" -Distro $DistroName
            return $null
        }

        if (-not (Test-SafetyNetArchive -safetyFile $safetyFile)) {
            Write-LogEntry "ERROR" "Restore-SafetyNet" "Safety Net archive validation failed: $safetyFile" -Distro $DistroName
            return $null
        }

        try {
            $manifestPath = Write-RestoreSafetyNetManifest -DistroName $DistroName -SafetyNetPath $safetyFile
            Write-Host "Safety Net manifest written: $manifestPath" -ForegroundColor Green
            Write-LogEntry "INFO" "Restore-SafetyNet-Manifest" "Safety Net manifest written: $manifestPath" -Distro $DistroName
        }
        catch {
            Write-Host "[WARN] Safety Net tar exists and passed validation, but manifest write failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-LogEntry "WARN" "Restore-SafetyNet-Manifest" "Safety Net manifest write failed for ${safetyFile}: $($_.Exception.Message)" -Distro $DistroName
        }

        $safetySize = Format-Bytes $safetyItem.Length
        Write-Host "Safety Net saved and verified: $safetyFile ($safetySize)" -ForegroundColor Green
        Write-LogEntry "SUCCESS" "Restore-SafetyNet" "Safety Net verified: $safetyFile ($safetySize)" -Distro $DistroName
        return $safetyFile
    }
    catch {
        Write-Host "[ERROR] Safety Net failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-SafetyNet" "Exception: $($_.Exception.Message)" -Distro $DistroName
        return $null
    }
}

function Confirm-RestoreSafetyNetCreation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName
    )

    $requiredPhrase = "CREATE SAFETY NET FOR $DistroName"

    Write-Host ""
    Write-Host "[Safety Net Creation Confirmation]" -ForegroundColor Yellow
    Write-Host "This step only creates and verifies a Safety Net backup tar." -ForegroundColor Yellow
    Write-Host "It will run wsl --export for distro '$DistroName' to generate the Safety Net tar." -ForegroundColor Yellow
    Write-Host "It will not unregister the existing distro." -ForegroundColor Yellow
    Write-Host "It will not run restore import." -ForegroundColor Yellow
    Write-Host "Type the exact phrase below to create the Safety Net, or Q/CANCEL to abort:" -ForegroundColor Yellow
    Write-Host "  $requiredPhrase" -ForegroundColor Cyan

    $confirm = Read-Host "Safety Net confirmation"
    if ([string]::IsNullOrWhiteSpace($confirm) -or $confirm -in @("q", "Q", "cancel", "CANCEL")) {
        Write-LogEntry "WARN" "Restore-SafetyNet-Confirm" "Safety Net creation cancelled before export confirmation" -Distro $DistroName
        return $false
    }

    if ($confirm -cne $requiredPhrase) {
        Write-LogEntry "WARN" "Restore-SafetyNet-Confirm" "Safety Net creation confirmation phrase mismatch" -Distro $DistroName
        Write-Host "[ERROR] Safety Net confirmation phrase did not match. Safety Net creation cancelled before export." -ForegroundColor Red
        return $false
    }

    Write-LogEntry "WARN" "Restore-SafetyNet-Confirm" "Safety Net creation confirmed with exact phrase" -Distro $DistroName
    return $true
}

function Read-RestoreSafetyNetManifestBestEffort {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SafetyNetPath,

        [Parameter(Mandatory = $true)]
        [string]$DistroName
    )

    $manifestPath = Get-RestoreSafetyNetManifestPath -SafetyNetPath $SafetyNetPath
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        Write-LogEntry "WARN" "Restore-SafetyNet-Manifest" "Safety Net manifest unavailable: $manifestPath" -Distro $DistroName
        return [pscustomobject]@{
            Success      = $false
            ManifestPath = $manifestPath
            Manifest     = $null
            Reason       = "Manifest file was not found."
        }
    }

    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        return [pscustomobject]@{
            Success      = $true
            ManifestPath = $manifestPath
            Manifest     = $manifest
            Reason       = ""
        }
    }
    catch {
        Write-LogEntry "WARN" "Restore-SafetyNet-Manifest" "Safety Net manifest read failed: $manifestPath | $($_.Exception.Message)" -Distro $DistroName
        return [pscustomobject]@{
            Success      = $false
            ManifestPath = $manifestPath
            Manifest     = $null
            Reason       = $_.Exception.Message
        }
    }
}

function Invoke-RestoreSafetyNetRollbackPrompt {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$InstallPath,

        [Parameter(Mandatory = $true)]
        [string]$SafetyNetPath,

        [object]$OverwritePathInfo = $null
    )

    $detectedBasePath = "<unavailable>"
    if ($null -ne $OverwritePathInfo -and
        -not [string]::IsNullOrWhiteSpace([string]$OverwritePathInfo.DetectedBasePath)) {
        $detectedBasePath = [string]$OverwritePathInfo.DetectedBasePath
    }

    $manifestInfo = Read-RestoreSafetyNetManifestBestEffort -SafetyNetPath $SafetyNetPath -DistroName $DistroName
    Write-Host ""
    Write-Host "[Safety Net Rollback Available]" -ForegroundColor Yellow
    Write-Host "Target distro        : $DistroName" -ForegroundColor Yellow
    Write-Host "Original install path: $detectedBasePath" -ForegroundColor Yellow
    Write-Host "Rollback import path : $InstallPath" -ForegroundColor Yellow
    Write-Host "Safety Net tar       : $SafetyNetPath" -ForegroundColor Yellow

    if ($manifestInfo.Success) {
        $manifest = $manifestInfo.Manifest
        $hash = [string]$manifest.ArchiveSha256
        $hashPrefix = if ($hash.Length -gt 12) { $hash.Substring(0, 12) } else { $hash }
        Write-Host "Safety Net manifest  : $($manifestInfo.ManifestPath)" -ForegroundColor Yellow
        Write-Host "  OperationId        : $($manifest.OperationId)" -ForegroundColor DarkGray
        Write-Host "  ArchiveSizeBytes   : $($manifest.ArchiveSizeBytes)" -ForegroundColor DarkGray
        Write-Host "  ArchiveSha256      : $hashPrefix..." -ForegroundColor DarkGray
    }
    else {
        Write-Host "Safety Net manifest  : unavailable ($($manifestInfo.Reason))" -ForegroundColor Yellow
    }

    if ($Global:DryRun) {
        Write-Host "DRY RUN: this would execute wsl --import to re-import the Safety Net tar." -ForegroundColor Yellow
    }
    else {
        Write-Host "This will execute wsl --import to re-import the Safety Net tar." -ForegroundColor Red
    }
    Write-LogEntry "WARN" "Restore-SafetyNet-Rollback" "Safety Net rollback option shown. Distro=$DistroName | InstallPath=$InstallPath | SafetyNet=$SafetyNetPath | Manifest=$($manifestInfo.ManifestPath)" -Distro $DistroName

    $answer = Read-Host "Attempt Safety Net rollback? Type Y to continue"
    if ($answer -cne "Y") {
        Write-Host "Safety Net rollback skipped by user." -ForegroundColor Yellow
        Write-LogEntry "WARN" "Restore-SafetyNet-Rollback" "Safety Net rollback skipped by user" -Distro $DistroName
        return [pscustomobject]@{
            Completed           = $false
            Attempted           = $false
            SkippedBecauseDryRun = $false
            ManualHintNeeded    = $true
        }
    }

    $requiredPhrase = "RESTORE SAFETY NET $DistroName"
    Write-Host "Type the exact phrase below to execute Safety Net rollback:" -ForegroundColor Yellow
    Write-Host "  $requiredPhrase" -ForegroundColor Cyan
    $confirm = Read-Host "Safety Net rollback confirmation"
    if ($confirm -cne $requiredPhrase) {
        Write-Host "Safety Net rollback confirmation phrase did not match. No import was attempted." -ForegroundColor Red
        Write-LogEntry "WARN" "Restore-SafetyNet-Rollback" "Safety Net rollback confirmation phrase mismatch; import not attempted" -Distro $DistroName
        return [pscustomobject]@{
            Completed           = $false
            Attempted           = $false
            SkippedBecauseDryRun = $false
            ManualHintNeeded    = $true
        }
    }

    if ($Global:DryRun) {
        Write-Host "DRY RUN: would import Safety Net tar into $InstallPath for distro $DistroName" -ForegroundColor Yellow
        Write-LogEntry "INFO" "Restore-SafetyNet-Rollback" "DryRun would run Safety Net rollback import. Distro=$DistroName | InstallPath=$InstallPath | SafetyNet=$SafetyNetPath" -Distro $DistroName
        return [pscustomobject]@{
            Completed           = $false
            Attempted           = $false
            SkippedBecauseDryRun = $true
            ManualHintNeeded    = $false
        }
    }

    try {
        Write-LogEntry "WARN" "Restore-SafetyNet-Rollback" "Attempting Safety Net rollback import. Distro=$DistroName | InstallPath=$InstallPath | SafetyNet=$SafetyNetPath" -Distro $DistroName
        $rollbackResult = Invoke-GuardedWSLCommand `
            -Description "Import Safety Net rollback" `
            -Arguments @("--import", $DistroName, $InstallPath, $SafetyNetPath) `
            -Distro $DistroName

        if (-not $rollbackResult.Success) {
            throw "Safety Net rollback import failed with exit code $($rollbackResult.ExitCode). $($rollbackResult.Output)"
        }

        Write-Host "Safety Net rollback completed." -ForegroundColor Green
        Write-LogEntry "INFO" "Restore-SafetyNet-Rollback" "Safety Net rollback completed. Distro=$DistroName | InstallPath=$InstallPath | SafetyNet=$SafetyNetPath" -Distro $DistroName
        return [pscustomobject]@{
            Completed           = $true
            Attempted           = $true
            SkippedBecauseDryRun = $false
            ManualHintNeeded    = $false
        }
    }
    catch {
        Write-Host "[ERROR] Safety Net rollback failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-SafetyNet-Rollback" "Safety Net rollback failed: $($_.Exception.Message)" -Distro $DistroName
        return [pscustomobject]@{
            Completed           = $false
            Attempted           = $true
            SkippedBecauseDryRun = $false
            ManualHintNeeded    = $true
        }
    }
}

function Confirm-OverwriteRestoreDestructiveStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$InstallPath,

        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [string]$RestoreTempRoot = "",

        [string]$SafetyNetPath = "",

        [object]$OverwritePathInfo = $null
    )

    if ($Global:DryRun) {
        Write-Host "[DRY RUN] Overwrite restore destructive phase preview:" -ForegroundColor Cyan
        Write-Host "  DRY RUN: would shutdown WSL before overwrite restore" -ForegroundColor Yellow
        Write-Host "  DRY RUN: would unregister distro $DistroName" -ForegroundColor Yellow
        Write-Host "  DRY RUN: would create/use install path $InstallPath" -ForegroundColor Yellow
        if (-not [string]::IsNullOrWhiteSpace($RestoreTempRoot)) {
            Write-Host "  DRY RUN: would use restore temp root $RestoreTempRoot" -ForegroundColor Yellow
        }
        if (-not [string]::IsNullOrWhiteSpace($SafetyNetPath)) {
            Write-Host "  DRY RUN: Safety Net path would be $SafetyNetPath" -ForegroundColor Yellow
        }
        Write-Host "  DRY RUN: would import archive $BackupFile into $InstallPath" -ForegroundColor Yellow
        Write-Host "DryRun complete; no WSL changes were made." -ForegroundColor Green
        Write-LogEntry "INFO" "Restore-DryRun" "Overwrite restore dry run stopped before WSL changes. Target: $DistroName | InstallPath: $InstallPath | Backup: $BackupFile" -Distro $DistroName
        return $false
    }

    $requiredPhrase = "DELETE $DistroName AND RESTORE"

    Write-OverwriteRestoreDestructiveWarning `
        -DistroName $DistroName `
        -InstallPath $InstallPath `
        -BackupFile $BackupFile `
        -RequiredPhrase $requiredPhrase `
        -RestoreTempRoot $RestoreTempRoot `
        -SafetyNetPath $SafetyNetPath `
        -OverwritePathInfo $OverwritePathInfo

    $confirm = Read-Host "Confirmation"
    if ([string]::IsNullOrWhiteSpace($confirm) -or $confirm -in @("q", "Q", "cancel", "CANCEL")) {
        Write-LogEntry "WARN" "Restore-Confirm" "Overwrite restore cancelled before unregister confirmation" -Distro $DistroName
        return $false
    }

    if ($confirm -cne $requiredPhrase) {
        Write-LogEntry "WARN" "Restore-Confirm" "Overwrite restore confirmation phrase mismatch" -Distro $DistroName
        Write-Host "[ERROR] Confirmation phrase did not match. Restore cancelled before WSL changes." -ForegroundColor Red
        return $false
    }

    Write-LogEntry "WARN" "Restore-Confirm" "Destructive overwrite restore confirmed with exact phrase" -Distro $DistroName
    return $true
}

# =============================================================================
# 7. Backup Operations
# =============================================================================

function New-FullBackupTempPathInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupDir
    )

    $tempDirName = "WSLBM-FullBackup-{0}" -f ([guid]::NewGuid().ToString('N'))
    $tempDir = Join-Path $BackupDir $tempDirName
    $tempTar = Join-Path $tempDir "wsl-export.tar"

    return [pscustomobject]@{
        TempDir = $tempDir
        TempTar = $tempTar
    }
}

function Resolve-FullBackupSpaceCheckPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$Label = "Full backup path",

        [string]$Distro = $Script:CurrentDistro
    )

    try {
        if ([string]::IsNullOrWhiteSpace($Path)) {
            throw "$Label is empty."
        }

        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $candidate = $fullPath

        while (-not [string]::IsNullOrWhiteSpace($candidate)) {
            if (Test-Path -LiteralPath $candidate -PathType Container) {
                return [pscustomobject]@{
                    Success   = $true
                    CheckPath = $candidate
                    FullPath  = $fullPath
                    Reason    = ""
                }
            }

            $parent = Split-Path -Path $candidate -Parent
            if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $candidate) {
                break
            }
            $candidate = $parent
        }

        $root = [System.IO.Path]::GetPathRoot($fullPath)
        if (-not [string]::IsNullOrWhiteSpace($root) -and (Test-Path -LiteralPath $root -PathType Container)) {
            return [pscustomobject]@{
                Success   = $true
                CheckPath = $root
                FullPath  = $fullPath
                Reason    = ""
            }
        }

        throw "Cannot find an existing parent directory or ready root for ${Label}: $Path"
    }
    catch {
        $message = $_.Exception.Message
        Write-Host "[ERROR] Cannot determine full backup space check location for ${Label}: $message" -ForegroundColor Red
        Write-LogEntry "ERROR" "Backup-Full-Space" "Cannot determine space check location for ${Label}: $message" -Distro $Distro
        return [pscustomobject]@{
            Success   = $false
            CheckPath = $null
            FullPath  = $Path
            Reason    = $message
        }
    }
}

function Get-FullBackupFreeSpaceInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$Label = "Full backup path",

        [string]$Distro = $Script:CurrentDistro
    )

    try {
        $resolvedPath = Resolve-FullBackupSpaceCheckPath -Path $Path -Label $Label -Distro $Distro
        if (-not $resolvedPath.Success) {
            return [pscustomobject]@{
                Success        = $false
                TargetPath     = $Path
                CheckPath      = $resolvedPath.CheckPath
                FullPath       = $resolvedPath.FullPath
                AvailableBytes = $null
                SourceKey      = ""
                Reason         = $resolvedPath.Reason
            }
        }

        $space = Get-WSLBMPathFreeSpaceInfo -Path $resolvedPath.CheckPath -Label $Label -LogAction "Backup-Full-Space" -Distro $Distro
        if (-not $space.Success) {
            throw $space.Reason
        }

        return [pscustomobject]@{
            Success        = $true
            TargetPath     = $Path
            CheckPath      = $resolvedPath.CheckPath
            FullPath       = $resolvedPath.FullPath
            AvailableBytes = [long]$space.AvailableBytes
            SourceKey      = "$($space.SourceType):$($space.SourceKey)"
            Reason         = ""
        }
    }
    catch {
        $message = $_.Exception.Message
        Write-Host "[ERROR] Cannot verify full backup free space for ${Label}: $message" -ForegroundColor Red
        Write-LogEntry "ERROR" "Backup-Full-Space" "Cannot verify free space for ${Label}: $message" -Distro $Distro
        return [pscustomobject]@{
            Success        = $false
            TargetPath     = $Path
            CheckPath      = $null
            FullPath       = $Path
            AvailableBytes = $null
            SourceKey      = ""
            Reason         = $message
        }
    }
}

function Test-FullBackupWorkingSpace {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TempPath,

        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [Parameter(Mandatory = $true)]
        [long]$RequiredBytes,

        [string]$Stage = "Full backup space check",

        [long]$TempTarSizeBytes = -1,

        [switch]$CheckTempPath,

        [string]$Distro = $Script:CurrentDistro
    )

    if ($Global:DryRun) {
        Write-Host "DRY RUN: would run FULL backup space check for $Stage" -ForegroundColor Yellow
        Write-Host "  DRY RUN: temp path   : $TempPath" -ForegroundColor Yellow
        Write-Host "  DRY RUN: backup file : $BackupFile" -ForegroundColor Yellow
        return $true
    }

    if ($RequiredBytes -le 0) {
        Write-Host "[ERROR] Full backup required space is invalid: $RequiredBytes bytes." -ForegroundColor Red
        Write-LogEntry "ERROR" "Backup-Full-Space" "Invalid required space for ${Stage}: $RequiredBytes bytes" -Distro $Distro
        return $false
    }

    $backupSpace = Get-FullBackupFreeSpaceInfo -Path $BackupFile -Label "FULL backup archive path" -Distro $Distro
    if (-not $backupSpace.Success) {
        Write-Host "[ERROR] Full backup aborted before compression/export because destination space cannot be verified." -ForegroundColor Red
        Write-Host "  Temp path  : $TempPath" -ForegroundColor Yellow
        Write-Host "  Backup file: $BackupFile" -ForegroundColor Yellow
        return $false
    }

    $spacesToCheck = @($backupSpace)
    if ($CheckTempPath) {
        $tempSpace = Get-FullBackupFreeSpaceInfo -Path $TempPath -Label "FULL backup temp path" -Distro $Distro
        if (-not $tempSpace.Success) {
            Write-Host "[ERROR] Full backup aborted before export because temp space cannot be verified." -ForegroundColor Red
            Write-Host "  Temp path  : $TempPath" -ForegroundColor Yellow
            Write-Host "  Backup file: $BackupFile" -ForegroundColor Yellow
            return $false
        }

        if (-not $tempSpace.SourceKey.Equals($backupSpace.SourceKey, [System.StringComparison]::OrdinalIgnoreCase)) {
            $spacesToCheck += $tempSpace
        }
    }

    Write-Host "  -> Full Backup Space Check: $Stage" -ForegroundColor Cyan
    Write-Host ("     Temp path  : {0}" -f $TempPath) -ForegroundColor DarkGray
    Write-Host ("     Backup file: {0}" -f $BackupFile) -ForegroundColor DarkGray
    if ($TempTarSizeBytes -gt 0) {
        Write-Host ("     Temp tar   : {0}" -f (Format-Bytes $TempTarSizeBytes)) -ForegroundColor DarkGray
    }
    Write-Host ("     Required   : {0}" -f (Format-Bytes $RequiredBytes)) -ForegroundColor DarkGray

    foreach ($space in $spacesToCheck) {
        Write-Host ("     Check path : {0}" -f $space.CheckPath) -ForegroundColor DarkGray
        Write-Host ("     Available  : {0}" -f (Format-Bytes $space.AvailableBytes)) -ForegroundColor DarkGray
        Write-LogEntry "INFO" "Backup-Full-Space" "Stage=$Stage | CheckPath=$($space.CheckPath) | Source=$($space.SourceKey) | Required=$(Format-Bytes $RequiredBytes) | Available=$(Format-Bytes $space.AvailableBytes) | Temp=$TempPath | Backup=$BackupFile" -Distro $Distro

        if ($space.AvailableBytes -lt $RequiredBytes) {
            Write-Host "[ERROR] Not enough free space for FULL backup working files." -ForegroundColor Red
            Write-Host "  Stage      : $Stage" -ForegroundColor Yellow
            Write-Host "  Check path : $($space.CheckPath)" -ForegroundColor Yellow
            Write-Host "  Required   : $(Format-Bytes $RequiredBytes)" -ForegroundColor Yellow
            Write-Host "  Available  : $(Format-Bytes $space.AvailableBytes)" -ForegroundColor Yellow
            Write-Host "  Temp path  : $TempPath" -ForegroundColor Yellow
            Write-Host "  Backup file: $BackupFile" -ForegroundColor Yellow
            Write-LogEntry "ERROR" "Backup-Full-Space" "Insufficient space. Stage=$Stage | CheckPath=$($space.CheckPath) | Required=$(Format-Bytes $RequiredBytes) | Available=$(Format-Bytes $space.AvailableBytes) | Temp=$TempPath | Backup=$BackupFile" -Distro $Distro
            return $false
        }
    }

    Write-Host "  [OK] Full backup space check passed." -ForegroundColor Green
    return $true
}

function Test-FullBackupDirectorySafety {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupDir,

        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [string]$Distro = $Script:CurrentDistro
    )

    # Compatibility parameter retained for backup safety audit context.
    $null = $Distro

    function New-FullBackupDirectorySafetyResult {
        param(
            [bool]$Success,
            [string]$NormalizedBackupDir = "",
            [string]$NormalizedBackupFile = "",
            [string]$Reason = ""
        )

        return [pscustomobject]@{
            Success              = $Success
            NormalizedBackupDir  = $NormalizedBackupDir
            NormalizedBackupFile = $NormalizedBackupFile
            Reason               = $Reason
        }
    }

    $backupDirResolved = Get-NormalizedWindowsPathForComparison -Path $BackupDir -Label "FULL backup directory"
    $backupFileResolved = Get-NormalizedWindowsPathForComparison -Path $BackupFile -Label "FULL backup archive"
    if (-not $backupDirResolved.Success) {
        return New-FullBackupDirectorySafetyResult -Success $false -Reason $backupDirResolved.Reason
    }
    if (-not $backupFileResolved.Success) {
        return New-FullBackupDirectorySafetyResult -Success $false -Reason $backupFileResolved.Reason
    }

    $backupDirFull = $backupDirResolved.NormalizedPath
    $backupFileFull = $backupFileResolved.NormalizedPath
    $comparison = [System.StringComparison]::OrdinalIgnoreCase
    $backupDirName = Split-Path -Path $backupDirFull -Leaf
    if ($backupDirName -notmatch '^\d{4}-\d{2}-\d{2}_\d{4}-FULL$') {
        return New-FullBackupDirectorySafetyResult -Success $false -Reason "FULL backup directory name is not a generated timestamp directory: $backupDirFull"
    }

    $fileParent = Split-Path -Path $backupFileFull -Parent
    $fileName = Split-Path -Path $backupFileFull -Leaf
    if (-not $fileParent.Equals($backupDirFull, $comparison) -or $fileName -ne "wsl-full.7z") {
        return New-FullBackupDirectorySafetyResult -Success $false -Reason "FULL backup archive must be wsl-full.7z directly under the generated backup directory."
    }

    $root = [System.IO.Path]::GetPathRoot($backupDirFull)
    $rootResolved = Get-NormalizedWindowsPathForComparison -Path $root -Label "FULL backup drive root"
    if (-not $rootResolved.Success -or $backupDirFull.Equals($rootResolved.NormalizedPath, $comparison)) {
        return New-FullBackupDirectorySafetyResult -Success $false -Reason "FULL backup directory cannot be a drive root."
    }

    $windowsRootRaw = $env:WINDIR
    if ([string]::IsNullOrWhiteSpace($windowsRootRaw)) { $windowsRootRaw = $env:SystemRoot }
    if (-not [string]::IsNullOrWhiteSpace($windowsRootRaw)) {
        $windowsRootResolved = Get-NormalizedWindowsPathForComparison -Path $windowsRootRaw -Label "Windows system directory"
        if ($windowsRootResolved.Success -and (Test-PathIsSameOrChild -ChildPath $backupDirFull -ParentPath $windowsRootResolved.NormalizedPath)) {
            return New-FullBackupDirectorySafetyResult -Success $false -Reason "FULL backup directory cannot be under the Windows system directory."
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $userProfileResolved = Get-NormalizedWindowsPathForComparison -Path $env:USERPROFILE -Label "USERPROFILE"
        if ($userProfileResolved.Success -and $backupDirFull.Equals($userProfileResolved.NormalizedPath, $comparison)) {
            return New-FullBackupDirectorySafetyResult -Success $false -Reason "FULL backup directory cannot be USERPROFILE itself."
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $scriptRootResolved = Get-NormalizedWindowsPathForComparison -Path $PSScriptRoot -Label "Script directory"
        if ($scriptRootResolved.Success -and $backupDirFull.Equals($scriptRootResolved.NormalizedPath, $comparison)) {
            return New-FullBackupDirectorySafetyResult -Success $false -Reason "FULL backup directory cannot be the script directory itself."
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($Global:Config.InstallRoot)) {
        $installRootResolved = Get-NormalizedWindowsPathForComparison -Path $Global:Config.InstallRoot -Label "Configured install root"
        if ($installRootResolved.Success) {
            if ($backupDirFull.Equals($installRootResolved.NormalizedPath, $comparison)) {
                return New-FullBackupDirectorySafetyResult -Success $false -Reason "FULL backup directory cannot be the configured install root."
            }
            if (Test-PathIsSameOrChild -ChildPath $installRootResolved.NormalizedPath -ParentPath $backupDirFull) {
                return New-FullBackupDirectorySafetyResult -Success $false -Reason "FULL backup directory cannot contain the configured install root."
            }
        }
    }

    return New-FullBackupDirectorySafetyResult -Success $true -NormalizedBackupDir $backupDirFull -NormalizedBackupFile $backupFileFull
}

function Test-FullBackupTempArtifactSafety {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TempDir,

        [Parameter(Mandatory = $true)]
        [string]$TempTar,

        [Parameter(Mandatory = $true)]
        [string]$BackupDir,

        [string]$Distro = $Script:CurrentDistro
    )

    $backupFile = Join-Path $BackupDir "wsl-full.7z"
    $backupSafety = Test-FullBackupDirectorySafety -BackupDir $BackupDir -BackupFile $backupFile -Distro $Distro
    if (-not $backupSafety.Success) {
        return [pscustomobject]@{ Success = $false; TempDir = ""; TempTar = ""; Reason = $backupSafety.Reason }
    }

    $tempDirResolved = Get-NormalizedWindowsPathForComparison -Path $TempDir -Label "FULL backup temp directory"
    $tempTarResolved = Get-NormalizedWindowsPathForComparison -Path $TempTar -Label "FULL backup temp tar"
    if (-not $tempDirResolved.Success) {
        return [pscustomobject]@{ Success = $false; TempDir = ""; TempTar = ""; Reason = $tempDirResolved.Reason }
    }
    if (-not $tempTarResolved.Success) {
        return [pscustomobject]@{ Success = $false; TempDir = ""; TempTar = ""; Reason = $tempTarResolved.Reason }
    }

    $tempDirFull = $tempDirResolved.NormalizedPath
    $tempTarFull = $tempTarResolved.NormalizedPath
    $comparison = [System.StringComparison]::OrdinalIgnoreCase
    $tempDirName = Split-Path -Path $tempDirFull -Leaf
    if ($tempDirName -notmatch '^WSLBM-FullBackup-[0-9a-fA-F]{32}$') {
        return [pscustomobject]@{ Success = $false; TempDir = $tempDirFull; TempTar = $tempTarFull; Reason = "FULL backup temp directory name does not match controlled prefix." }
    }
    if ($tempDirFull.Equals($backupSafety.NormalizedBackupDir, $comparison) -or -not (Test-PathIsSameOrChild -ChildPath $tempDirFull -ParentPath $backupSafety.NormalizedBackupDir)) {
        return [pscustomobject]@{ Success = $false; TempDir = $tempDirFull; TempTar = $tempTarFull; Reason = "FULL backup temp directory must be a child of the generated backup directory." }
    }

    $tarParent = Split-Path -Path $tempTarFull -Parent
    $tarName = Split-Path -Path $tempTarFull -Leaf
    if (-not $tarParent.Equals($tempDirFull, $comparison) -or $tarName -ne "wsl-export.tar") {
        return [pscustomobject]@{ Success = $false; TempDir = $tempDirFull; TempTar = $tempTarFull; Reason = "FULL backup temp tar must be wsl-export.tar directly under the controlled temp directory." }
    }

    return [pscustomobject]@{ Success = $true; TempDir = $tempDirFull; TempTar = $tempTarFull; Reason = "" }
}

function Clear-FullBackupTempArtifacts {
    param(
        [string]$TempDir,
        [string]$TempTar,
        [string]$BackupDir,
        [string]$Distro = $Script:CurrentDistro
    )

    if ($Global:DryRun) {
        return
    }

    function Write-FullBackupCleanupWarning {
        param([string]$Message)

        Write-Host "[WARN] Full backup temp cleanup skipped or incomplete: $Message" -ForegroundColor Yellow
        Write-LogEntry "WARN" "Backup-Full-Cleanup" $Message -Distro $Distro
    }

    if ([string]::IsNullOrWhiteSpace($TempDir) -and [string]::IsNullOrWhiteSpace($TempTar)) {
        return
    }
    if ([string]::IsNullOrWhiteSpace($TempDir) -or [string]::IsNullOrWhiteSpace($TempTar)) {
        Write-FullBackupCleanupWarning "Full backup temp cleanup requires both TempDir and TempTar. TempDir=$TempDir | TempTar=$TempTar"
        return
    }
    if ([string]::IsNullOrWhiteSpace($BackupDir)) {
        Write-FullBackupCleanupWarning "Full backup temp cleanup requires BackupDir for boundary checks. TempDir=$TempDir | TempTar=$TempTar"
        return
    }

    $safety = Test-FullBackupTempArtifactSafety -TempDir $TempDir -TempTar $TempTar -BackupDir $BackupDir -Distro $Distro
    if (-not $safety.Success) {
        Write-FullBackupCleanupWarning "Full backup temp artifact safety check failed: $($safety.Reason) TempDir=$TempDir | TempTar=$TempTar | BackupDir=$BackupDir"
        return
    }

    $tempDirFull = $safety.TempDir
    $tempTarFull = $safety.TempTar

    try {
        if (Test-Path -LiteralPath $tempTarFull -PathType Leaf) {
            Remove-Item -LiteralPath $tempTarFull -Force -ErrorAction Stop
        }
    }
    catch {
        Write-FullBackupCleanupWarning "Failed to remove full backup temp tar $($tempTarFull): $($_.Exception.Message)"
    }

    try {
        if (Test-Path -LiteralPath $tempDirFull -PathType Container) {
            $remainingItem = Get-ChildItem -LiteralPath $tempDirFull -Force -ErrorAction Stop | Select-Object -First 1
            if ($null -eq $remainingItem) {
                Remove-Item -LiteralPath $tempDirFull -Force -ErrorAction Stop
            }
            else {
                Write-FullBackupCleanupWarning "Full backup temp directory is not empty; leaving it for manual review: $tempDirFull"
            }
        }
    }
    catch {
        Write-FullBackupCleanupWarning "Failed to remove empty full backup temp directory $($tempDirFull): $($_.Exception.Message)"
    }
}

function Clear-FullBackupPartialArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupDir,

        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [string]$Distro = $Script:CurrentDistro
    )

    if ($Global:DryRun) { return }

    $safety = Test-FullBackupDirectorySafety -BackupDir $BackupDir -BackupFile $BackupFile -Distro $Distro
    if (-not $safety.Success) {
        Write-Host "[WARN] Full backup partial archive cleanup skipped: $($safety.Reason)" -ForegroundColor Yellow
        Write-LogEntry "WARN" "Backup-Full-Cleanup" "Partial archive cleanup skipped: $($safety.Reason) | BackupFile=$BackupFile" -Distro $Distro
        return
    }

    try {
        if (Test-Path -LiteralPath $safety.NormalizedBackupFile -PathType Leaf) {
            Remove-Item -LiteralPath $safety.NormalizedBackupFile -Force -ErrorAction Stop
        }
    }
    catch {
        Write-Host "[WARN] Failed to remove partial FULL backup archive: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-LogEntry "WARN" "Backup-Full-Cleanup" "Failed to remove partial archive $($safety.NormalizedBackupFile): $($_.Exception.Message)" -Distro $Distro
    }
}

function Clear-FullBackupEmptyDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupDir,

        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [string]$Distro = $Script:CurrentDistro
    )

    if ($Global:DryRun) { return }

    $safety = Test-FullBackupDirectorySafety -BackupDir $BackupDir -BackupFile $BackupFile -Distro $Distro
    if (-not $safety.Success) {
        Write-Host "[WARN] Full backup directory cleanup skipped: $($safety.Reason)" -ForegroundColor Yellow
        Write-LogEntry "WARN" "Backup-Full-Cleanup" "Backup directory cleanup skipped: $($safety.Reason) | BackupDir=$BackupDir" -Distro $Distro
        return
    }

    try {
        if (Test-Path -LiteralPath $safety.NormalizedBackupDir -PathType Container) {
            $remainingItem = Get-ChildItem -LiteralPath $safety.NormalizedBackupDir -Force -ErrorAction Stop | Select-Object -First 1
            if ($null -eq $remainingItem) {
                Remove-Item -LiteralPath $safety.NormalizedBackupDir -Force -ErrorAction Stop
            }
            else {
                Write-Host "[WARN] Full backup directory is not empty; leaving it for manual review: $($safety.NormalizedBackupDir)" -ForegroundColor Yellow
                Write-LogEntry "WARN" "Backup-Full-Cleanup" "Non-empty failed full backup directory left for manual review: $($safety.NormalizedBackupDir)" -Distro $Distro
            }
        }
    }
    catch {
        Write-Host "[WARN] Failed to remove empty FULL backup directory: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-LogEntry "WARN" "Backup-Full-Cleanup" "Failed to remove empty backup directory $($safety.NormalizedBackupDir): $($_.Exception.Message)" -Distro $Distro
    }
}

function Invoke-FullBackupWSLProcessChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [string]$MonitoredFile,

        [switch]$EnableCancelMonitor,

        [string]$Distro = $Script:CurrentDistro
    )

    # Compatibility parameter retained for older FULL backup call sites.
    $null = $MonitoredFile

    $commandPreview = "wsl.exe " + (Format-QuotedArgs $Arguments)
    if ($Global:DryRun) {
        Write-Host "DRY RUN: would run $commandPreview" -ForegroundColor Yellow
        return [pscustomobject]@{
            Success              = $true
            ExitCode             = $null
            SkippedBecauseDryRun = $true
            Description          = $Description
        }
    }

    Write-LogEntry "INFO" "Backup-Full-WSL" "$Description | $commandPreview" -Distro $Distro

    $runnerResult = Invoke-WSLBMNativeProcessChecked `
        -FilePath "wsl.exe" `
        -Arguments $Arguments `
        -OperationName "Backup-Full-WSL" `
        -Description $Description `
        -TimeoutSeconds $Script:DefaultWSLCommandTimeoutSeconds `
        -AllowCancel:([bool]$EnableCancelMonitor) `
        -RegisterActiveProcess `
        -Distro $Distro
    $exitCode = $runnerResult.ExitCode

    if ($runnerResult.TimedOut) {
        throw "$Description failed: wsl.exe timed out after $Script:DefaultWSLCommandTimeoutSeconds seconds."
    }
    if ($runnerResult.Cancelled) {
        throw "$Description failed: cancelled by user."
    }
    if ($null -eq $exitCode) {
        throw "$Description failed: wsl.exe did not report an exit code."
    }
    if ($exitCode -ne 0) {
        throw "$Description failed (wsl.exe exit code $exitCode)."
    }

    return [pscustomobject]@{
        Success              = $true
        ExitCode             = $exitCode
        SkippedBecauseDryRun = $false
        Description          = $Description
    }
}

function Export-FullBackupToTempTar {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Distro,

        [Parameter(Mandatory = $true)]
        [string]$TempTar
    )

    Write-Host "Exporting WSL distro to temporary tar (Press Q to cancel)..." -ForegroundColor Cyan
    # WSL high-risk boundary: FULL export uses the checked FULL-backup wrapper (DryRun, exit-code check, cancel monitor).
    $null = Invoke-FullBackupWSLProcessChecked `
        -Description "Export full backup tar" `
        -Arguments @("--export", $Distro, $TempTar) `
        -MonitoredFile $TempTar `
        -EnableCancelMonitor `
        -Distro $Distro
}

function Test-FullBackupTempTar {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TempTar,

        [long]$MinimumSizeBytes = 1KB
    )

    if (-not (Test-Path -LiteralPath $TempTar -PathType Leaf)) {
        throw "WSL export temp tar was not created: $TempTar"
    }

    $tarSize = (Get-Item -LiteralPath $TempTar).Length
    if ($tarSize -lt $MinimumSizeBytes) {
        throw "WSL export temp tar is too small ($tarSize bytes). Expected at least $MinimumSizeBytes bytes."
    }

    Write-Host ("  [OK] Temp tar check: {0}" -f (Format-Bytes $tarSize)) -ForegroundColor Green
    return [long]$tarSize
}

function Resolve-FullBackup7zPath {
    return Resolve-WSLBMSevenZipPath
}

function Compress-FullBackupTarToArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TempDir,

        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [Parameter(Mandatory = $true)]
        [int]$Threads
    )

    if ($Global:DryRun) {
        Write-Host "DRY RUN: would compress wsl-export.tar into $BackupFile" -ForegroundColor Yellow
        return [pscustomobject]@{
            Success              = $true
            ExitCode             = $null
            SkippedBecauseDryRun = $true
        }
    }

    $sevenZipExe = Resolve-FullBackup7zPath
    $mx = "-mx$($Global:Config.CompressionLevel)"
    $rawArgs = @("a", $BackupFile, "wsl-export.tar", $mx, "-mmt=$Threads", "-bsp1", "-y")

    Write-Host "Compressing temporary tar to wsl-full.7z (Press Q to cancel)..." -ForegroundColor Cyan
    Write-LogEntry "INFO" "Backup-Full-7z" "Compressing wsl-export.tar to $BackupFile"

    $runnerResult = Invoke-WSLBMNativeProcessChecked `
        -FilePath $sevenZipExe `
        -Arguments $rawArgs `
        -OperationName "Backup-Full-7z" `
        -Description "Compress full backup tar" `
        -AllowCancel `
        -RegisterActiveProcess `
        -WorkingDirectory $TempDir `
        -Distro $Script:CurrentDistro
    $exitCode = $runnerResult.ExitCode

    if ($runnerResult.TimedOut) {
        throw "7z compression failed: timed out."
    }
    if ($runnerResult.Cancelled) {
        throw "7z compression failed: cancelled by user."
    }
    if ($null -eq $exitCode) {
        throw "7z compression failed: process did not report an exit code."
    }
    if ($exitCode -ne 0) {
        throw "7z compression failed (exit code $exitCode)."
    }

    return [pscustomobject]@{
        Success              = $true
        ExitCode             = $exitCode
        SkippedBecauseDryRun = $false
    }
}

function Get-UserCustomBackupSourceState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $true)]
        [ValidateSet("USER", "CUSTOM")]
        [string]$BackupType,

        [string]$CustomRelativePath = ""
    )

    $result = [pscustomobject]@{
        Success            = $false
        BackupType         = $BackupType
        SourcePath         = $SourcePath
        CustomRelativePath = $CustomRelativePath
        Exists             = $false
        CanEnumerate       = $false
        IsEmpty            = $null
        Reason             = ""
    }

    if ([string]::IsNullOrWhiteSpace($SourcePath)) {
        $result.Reason = "Source UNC path is empty."
        return $result
    }

    try {
        if (-not (Test-Path -LiteralPath $SourcePath -PathType Container -ErrorAction Stop)) {
            $result.Reason = "Source UNC path does not exist or is not a directory."
            return $result
        }
        $result.Exists = $true
    }
    catch {
        $result.Reason = "Source UNC path is not accessible: $($_.Exception.Message)"
        return $result
    }

    try {
        $firstItem = Get-ChildItem -LiteralPath $SourcePath -Force -ErrorAction Stop | Select-Object -First 1
        $result.CanEnumerate = $true
        $result.IsEmpty = ($null -eq $firstItem)
        $result.Success = $true
        if ($result.IsEmpty) {
            $result.Reason = "Source UNC path is empty."
        }
        else {
            $result.Reason = "Source UNC path exists and can be enumerated."
        }
        return $result
    }
    catch {
        $result.Reason = "Source UNC path exists but cannot be enumerated: $($_.Exception.Message)"
        return $result
    }
}

function Confirm-UserCustomBackupSourceState {
    param(
        [Parameter(Mandatory = $true)]
        $SourceState,

        [Parameter(Mandatory = $true)]
        [string]$ArchivePath
    )

    Write-Host ""
    Write-Host "[USER/CUSTOM Backup Pre-flight]" -ForegroundColor Cyan
    Write-Host "  Backup type : $($SourceState.BackupType)" -ForegroundColor DarkGray
    if ($SourceState.BackupType -eq "CUSTOM") {
        Write-Host "  Custom path : $($SourceState.CustomRelativePath)" -ForegroundColor DarkGray
    }
    Write-Host "  Source UNC  : $($SourceState.SourcePath)" -ForegroundColor DarkGray
    Write-Host "  Archive     : $ArchivePath" -ForegroundColor DarkGray
    Write-Host "  Source check: $($SourceState.Reason)" -ForegroundColor DarkGray

    if (-not $SourceState.Success) {
        Write-Host "[ERROR] Backup aborted before creating backup directory, lock, or running 7z." -ForegroundColor Red
        Write-Host "        Source path is missing, inaccessible, or cannot be enumerated." -ForegroundColor Red
        return $false
    }

    if ($SourceState.IsEmpty) {
        Write-Host "[WARN] Source directory is empty." -ForegroundColor Yellow
        Write-Host "       This may produce an empty or near-empty archive. It will not continue silently." -ForegroundColor Yellow
        $requiredPhrase = "BACKUP EMPTY"
        $confirm = Read-Host "Type '$requiredPhrase' to continue, or press Enter to cancel"
        if ($confirm -cne $requiredPhrase) {
            Write-Host "Backup cancelled before creating backup directory, lock, or running 7z." -ForegroundColor Yellow
            return $false
        }
        Write-Host "Empty source backup explicitly confirmed." -ForegroundColor Yellow
    }

    return $true
}

function Test-UserCustomBackupArchiveCreated {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArchivePath
    )

    if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
        throw "Backup archive was not created: $ArchivePath"
    }

    try {
        $archiveItem = Get-Item -LiteralPath $ArchivePath -ErrorAction Stop
    }
    catch {
        throw "Backup archive cannot be inspected: $ArchivePath ($($_.Exception.Message))"
    }

    if ($archiveItem.Length -le 0) {
        throw "Backup archive is empty (0 bytes): $ArchivePath"
    }

    Write-Host ("  [OK] Archive created: {0}" -f (Format-Bytes $archiveItem.Length)) -ForegroundColor Green
    return [long]$archiveItem.Length
}

function Get-UserCustomBackupWarningSummary {
    return "7z warning exit code 1: some transient cache, symlink, or changing files may be missing; archive passed required keep checks."
}

function Write-UserCustomBackupExitCode1Warning {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("USER", "CUSTOM")]
        [string]$BackupType,

        [Parameter(Mandatory = $true)]
        [string]$ArchivePath
    )

    Write-Host "[WARNING] 7z completed $BackupType backup with warning exit code 1." -ForegroundColor Yellow
    Write-Host "          Archive will be kept only if it exists, is non-empty, and passes integrity verification." -ForegroundColor Yellow
    Write-Host "          Common causes over WSL UNC include .npm/_npx, node_modules/.bin, cache files," -ForegroundColor Yellow
    Write-Host "          broken symlinks, files disappearing during scan, or locked files." -ForegroundColor Yellow
    Write-Host "          Files listed in the 7z warnings may be missing from this archive." -ForegroundColor Yellow
    Write-Host "          USER/CUSTOM is a convenient directory backup, not a full distro backup." -ForegroundColor Yellow
    Write-Host "          Archive path: $ArchivePath" -ForegroundColor Yellow
    Write-Host "          Use FULL backup for full Linux metadata and distro consistency." -ForegroundColor Yellow
}

function Write-UserCustomBackupWarningCompletedSummary {
    Write-Host "COMPLETED WITH WARNINGS. Archive exists, is non-empty, and passed integrity verification." -ForegroundColor Yellow
    Write-Host "Files listed in 7z warnings may be missing from this USER/CUSTOM directory backup." -ForegroundColor Yellow
    Write-Host "Use FULL backup when you need full distro consistency and Linux metadata fidelity." -ForegroundColor Yellow
}

function Show-UserCustomBackupDryRunPreview {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("USER", "CUSTOM")]
        [string]$BackupType,

        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [string]$CustomRelativePath = "",

        [Parameter(Mandatory = $true)]
        [string]$BackupDir,

        [Parameter(Mandatory = $true)]
        [string]$ArchivePath,

        [Parameter(Mandatory = $true)]
        [string[]]$RawArgs,

        [Parameter(Mandatory = $true)]
        [string]$OperationId
    )

    Write-Host "[DRY RUN] $BackupType backup preview:" -ForegroundColor Cyan
    Write-OperationIdBanner -OperationId $OperationId
    Write-UserCustomBackupMetadataWarning
    if ($BackupType -eq "CUSTOM") {
        Write-Host "  Custom path : $CustomRelativePath" -ForegroundColor DarkGray
    }
    Write-Host "  Source UNC  : $SourcePath" -ForegroundColor DarkGray
    Write-Host "  Destination : $BackupDir" -ForegroundColor DarkGray
    Write-Host "  Archive     : $ArchivePath" -ForegroundColor DarkGray
    Write-Host "  7z args     : $(Format-QuotedArgs $RawArgs)" -ForegroundColor DarkGray
    Write-Host "  Risk        : USER/CUSTOM backup over WSL UNC can miss Linux metadata fidelity." -ForegroundColor Yellow
    Write-Host "  Warning     : if real 7z exits with code 1, archive must exist, be non-empty, and pass integrity before it is kept as Warning." -ForegroundColor Yellow
    Write-Host "  DRY RUN: source pre-check skipped because backup DryRun does not call wsl.exe to resolve the WSL user." -ForegroundColor Yellow
    Write-Host "  DRY RUN: would not run WSL, would not run 7z, would not create archive, manifest, lock, note, log, or backup directory." -ForegroundColor Yellow
    Write-Host "DryRun preview completed; no backup changes were made." -ForegroundColor Green
}

function Get-UserCustomBackup7zFailureMessage {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ExitCode
    )

    if ($ExitCode -eq 1) {
        return "7z backup returned warning exit code 1. Archive may be incomplete and must pass existence, size, and integrity checks before it can be kept."
    }

    return "7z backup failed (exit code $ExitCode)."
}

function New-FullBackup {
    if (-not $Script:CurrentDistro) {
        Write-Host "[ERROR] No Distro Selected." -ForegroundColor Red
        return
    }

    if (-not (Test-SafeDistroName -Name $Script:CurrentDistro)) {
        Write-Host "[SECURITY] Cannot backup: Distro name contains unsafe characters." -ForegroundColor Red
        return
    }

    if ($Global:DryRun) {
        $ts = Get-Date -Format "yyyy-MM-dd_HHmm"
        $defaultName = "$ts-FULL"
        $previewBackupDir = Get-BackupDestination -defaultName $defaultName -PreviewOnly
        if (-not $previewBackupDir) { return }
        $previewBackupFile = Join-Path $previewBackupDir "wsl-full.7z"
        $previewTempDir = Join-Path $previewBackupDir "WSLBM-FullBackup-<unique-guid>"
        $previewTempTar = Join-Path $previewTempDir "wsl-export.tar"
        $previewOperationId = New-OperationId
        $previewExportArgs = @("--export", $Script:CurrentDistro, $previewTempTar)
        $preview7zArgs = @("a", $previewBackupFile, "wsl-export.tar", "-mx$($Global:Config.CompressionLevel)", "-mmt=<calculated-safe-threads>", "-bsp1", "-y")

        Write-Host "[DRY RUN] Full backup preview:" -ForegroundColor Cyan
        Write-OperationIdBanner -OperationId $previewOperationId
        Write-Host "  Source distro : $Script:CurrentDistro" -ForegroundColor DarkGray
        Write-Host "  Destination   : $previewBackupDir" -ForegroundColor DarkGray
        Write-Host "  Archive       : $previewBackupFile" -ForegroundColor DarkGray
        Write-Host "  Temp dir      : $previewTempDir" -ForegroundColor DarkGray
        Write-Host "  Temp tar      : $previewTempTar" -ForegroundColor DarkGray
        Write-Host "  WSL export    : wsl.exe $(Format-QuotedArgs $previewExportArgs)" -ForegroundColor DarkGray
        Write-Host "  7z args       : $(Format-QuotedArgs $preview7zArgs)" -ForegroundColor DarkGray
        Write-Host "  DRY RUN: would check FULL backup disk space threshold ($($Global:Config.DiskThresholds.Full) GB)" -ForegroundColor Yellow
        Write-Host "  DRY RUN: would prompt/confirm VS Code safety if needed" -ForegroundColor Yellow
        Write-Host "  DRY RUN: would use current compression level mx$($Global:Config.CompressionLevel) and calculate safe 7z threads" -ForegroundColor Yellow
        Write-Host "  DRY RUN: would create backup directory $previewBackupDir" -ForegroundColor Yellow
        Write-Host "  DRY RUN: would create lock file under $previewBackupDir" -ForegroundColor Yellow
        Write-Host "  DRY RUN: would create controlled temp directory $previewTempDir" -ForegroundColor Yellow
        Write-Host "  DRY RUN: would run fail-closed minimum workspace pre-check for temp tar and final archive locations" -ForegroundColor Yellow
        Write-Host "  DRY RUN: would run wsl.exe --shutdown, then wait 5 seconds" -ForegroundColor Yellow
        Write-Host "  DRY RUN: would export distro '$Script:CurrentDistro' to $previewTempTar" -ForegroundColor Yellow
        Write-Host "  DRY RUN: would validate temp tar exists and is at least 1 KB" -ForegroundColor Yellow
        Write-Host "  DRY RUN: would run second workspace check using actual temp tar size plus max(10%, 1GB) buffer" -ForegroundColor Yellow
        Write-Host "  DRY RUN: would compress wsl-export.tar into $previewBackupFile" -ForegroundColor Yellow
        Write-Host "  DRY RUN: would run final Test-BackupIntegrity on $previewBackupFile" -ForegroundColor Yellow
        Write-Host "  DRY RUN: would clean temp tar and empty controlled temp directory" -ForegroundColor Yellow
        Write-Host "DryRun preview completed; no WSL, 7z, directory, lock, temp tar, backup file, manifest, note, or log writes were performed by New-FullBackup." -ForegroundColor Green
        Read-Host "Press Enter to return..."
        return
    }

    if (-not (Test-DiskSpace $Global:Config.DiskThresholds.Full)) { return }
    if (-not (Close-VSCodeSafely)) { return }

    Select-Compression-Interactive
    $safeThreads = Get-Optimal7zThreads -Level $Global:Config.CompressionLevel

    $ts = Get-Date -Format "yyyy-MM-dd_HHmm"
    $defaultName = "$ts-FULL"
    $backupDir = Get-BackupDestination -defaultName $defaultName
    if (-not $backupDir) { return }

    $backupFile = Join-Path $backupDir "wsl-full.7z"
    $tempInfo = $null
    $tempInfo = New-FullBackupTempPathInfo -BackupDir $backupDir
    $minimumWorkspaceBytes = [long]([double]$Global:Config.DiskThresholds.Full * 1GB)

    Write-Host "[Pre-flight] FULL backup export size cannot be known before wsl --export; checking minimum workspace threshold first." -ForegroundColor Yellow
    if (-not (Test-FullBackupWorkingSpace -TempPath $tempInfo.TempDir -BackupFile $backupFile -RequiredBytes $minimumWorkspaceBytes -Stage "Before WSL export minimum workspace" -CheckTempPath -Distro $Script:CurrentDistro)) {
        Write-Host "[ERROR] Full backup aborted before WSL shutdown/export because workspace pre-flight failed." -ForegroundColor Red
        return
    }

    $backupDirSafety = Test-FullBackupDirectorySafety -BackupDir $backupDir -BackupFile $backupFile -Distro $Script:CurrentDistro
    if (-not $backupDirSafety.Success) {
        Write-Host "[ERROR] Full backup aborted because backup directory safety check failed: $($backupDirSafety.Reason)" -ForegroundColor Red
        Write-LogEntry "ERROR" "Backup-Full-PathSafety" "Backup directory safety check failed: $($backupDirSafety.Reason) | BackupDir=$backupDir | BackupFile=$backupFile" -Distro $Script:CurrentDistro
        return
    }

    if (-not (New-BackupDirectory $backupDir)) { return }

    New-LockFile -OperationType "Full Backup" -TargetDir $backupDir
    $Global:BackupState.IsRunning = $true
    $Global:BackupState.CurrentFile = $backupFile
    $Global:BackupState.CurrentDir = $backupDir

    $Script:CurrentOperationId = New-OperationId
    Write-OperationIdBanner -OperationId $Script:CurrentOperationId
    Write-LogEntry "INFO" "Backup-Full" "Started to $backupFile (threads: $safeThreads) | OpId=$($Script:CurrentOperationId)"

    $msg = ""
    try {
        if (-not (New-BackupDirectory $tempInfo.TempDir)) {
            throw "Failed to create full backup temp directory: $($tempInfo.TempDir)"
        }

        Write-Host "Shutting down WSL (5s cooldown)..." -ForegroundColor Yellow
        # WSL high-risk boundary: FULL backup shutdown uses the checked FULL-backup wrapper after space/path preflight.
        $null = Invoke-FullBackupWSLProcessChecked -Description "Shutdown WSL before full backup" -Arguments @("--shutdown") -Distro $Script:CurrentDistro
        Start-Sleep -Seconds 5

        Export-FullBackupToTempTar -Distro $Script:CurrentDistro -TempTar $tempInfo.TempTar
        $tempTarSizeBytes = Test-FullBackupTempTar -TempTar $tempInfo.TempTar -MinimumSizeBytes 1KB
        $postExportBufferBytes = [long][math]::Max([math]::Ceiling([double]$tempTarSizeBytes * 0.10), [double]1GB)
        $postExportRequiredBytes = [long]($tempTarSizeBytes + $postExportBufferBytes)

        if (-not (Test-FullBackupWorkingSpace -TempPath $tempInfo.TempTar -BackupFile $backupFile -RequiredBytes $postExportRequiredBytes -Stage "After WSL export before 7z compression" -TempTarSizeBytes $tempTarSizeBytes -Distro $Script:CurrentDistro)) {
            throw "Full backup destination space check failed after temp tar export; compression was not started."
        }

        $null = Compress-FullBackupTarToArchive -TempDir $tempInfo.TempDir -BackupFile $backupFile -Threads $safeThreads

        Write-Host "Verifying backup..." -ForegroundColor Cyan
        Test-BackupIntegrity -backupFile $backupFile -backupType "FULL"
        Write-BackupManifestBestEffort -BackupType "FULL" -BackupDir $backupDir -ArchivePath $backupFile -SourceDistro $Script:CurrentDistro

        Remove-LockFile

        Write-Host "SUCCESS! Backup completed." -ForegroundColor Green
        Write-LogEntry "SUCCESS" "Backup-Full" "Completed successfully | OpId=$($Script:CurrentOperationId)"

        Write-Host "Add note (optional, press Enter to skip):"
        $note = Read-Host
        if (-not [string]::IsNullOrWhiteSpace($note)) {
            Write-WSLBMTextFileUtf8NoBom -LiteralPath (Join-Path $backupDir "note.txt") -Content $note
        }

    }
    catch {
        $errMsg = $_.Exception.Message
        if ($errMsg -match "UserCancelled") {
            $msg = "Cancelled by user"
        }
        else {
            $msg = "Failed: $errMsg"
        }
        Write-LogEntry "ERROR" "Backup-Full" "$msg | OpId=$($Script:CurrentOperationId)"
        Write-Host "[ERROR] $msg" -ForegroundColor Red

        Stop-ActiveBackupProcesses

        Clear-FullBackupPartialArchive -BackupDir $backupDir -BackupFile $backupFile -Distro $Script:CurrentDistro
    }
    finally {
        Stop-ActiveBackupProcesses

        if ($null -ne $tempInfo) {
            Clear-FullBackupTempArtifacts -TempDir $tempInfo.TempDir -TempTar $tempInfo.TempTar -BackupDir $backupDir -Distro $Script:CurrentDistro
        }
        Remove-LockFile
        if ($msg -and $msg -ne "") {
            Clear-FullBackupEmptyDirectory -BackupDir $backupDir -BackupFile $backupFile -Distro $Script:CurrentDistro
        }
        $Global:BackupState.IsRunning = $false
        $Global:BackupState.CurrentFile = $null
        $Global:BackupState.CurrentDir = $null
        Clear-BackupCleanupAllowedRoot
        $Script:CurrentOperationId = ""
    }

    Read-Host "Press Enter to return..."
}

function New-UserBackup {
    if (-not $Script:CurrentDistro) {
        Write-Host "[ERROR] No Distro Selected." -ForegroundColor Red
        return
    }

    if ($Global:DryRun) {
        $ts = Get-Date -Format "yyyy-MM-dd_HHmm"
        $backupDir = Get-BackupDestination -defaultName "$ts-USER" -PreviewOnly
        if (-not $backupDir) { return }

        $wslUserPreview = "<wsl-user>"
        $src = "$($Script:WSLPathPrefix)\$Script:CurrentDistro\home\$wslUserPreview"
        $backupFile = Join-Path $backupDir "home.7z"
        $rawArgs = @("a", $backupFile, "$src\*", "-mx$($Global:Config.CompressionLevel)", "-mmt=<calculated-safe-threads>", "-bsp1")
        $previewOperationId = New-OperationId

        Show-UserCustomBackupDryRunPreview `
            -BackupType "USER" `
            -SourcePath $src `
            -BackupDir $backupDir `
            -ArchivePath $backupFile `
            -RawArgs $rawArgs `
            -OperationId $previewOperationId

        Read-Host "Press Enter to return..."
        return
    }

    if (-not (Test-DiskSpace $Global:Config.DiskThresholds.User)) { return }
    if (-not (Close-VSCodeSafely)) { return }

    Select-Compression-Interactive
    $safeThreads = Get-Optimal7zThreads -Level $Global:Config.CompressionLevel

    try {
        $wslUser = Get-WSLUser
    }
    catch {
        Write-Host "[ERROR] USER backup aborted: $($_.Exception.Message)" -ForegroundColor Red
        Write-LogEntry "ERROR" "Backup-User" "Aborted before source path resolution: $($_.Exception.Message)"
        Read-Host "Press Enter to return..."
        return
    }

    $basePath = if ($wslUser -eq "root") { "/root" } else { "/home/$wslUser" }
    $src = "$($Script:WSLPathPrefix)\$Script:CurrentDistro$basePath"

    $ts = Get-Date -Format "yyyy-MM-dd_HHmm"
    $backupDir = Get-BackupDestination -defaultName "$ts-USER"
    if (-not $backupDir) { return }

    $backupFile = Join-Path $backupDir "home.7z"

    $sourceState = Get-UserCustomBackupSourceState -SourcePath $src -BackupType "USER"
    if (-not (Confirm-UserCustomBackupSourceState -SourceState $sourceState -ArchivePath $backupFile)) { return }

    New-BackupDirectory $backupDir | Out-Null

    New-LockFile -OperationType "User Backup" -TargetDir $backupDir
    $Global:BackupState.IsRunning = $true
    $Global:BackupState.CurrentDir = $backupDir
    $Global:BackupState.CurrentFile = $backupFile
    Set-BackupCleanupAllowedRootFromDestination -BackupDir $backupDir

    $Script:CurrentOperationId = New-OperationId
    Write-OperationIdBanner -OperationId $Script:CurrentOperationId
    Write-LogEntry "INFO" "Backup-User" "Started from $src (threads: $safeThreads) | OpId=$($Script:CurrentOperationId)"

    try {
        $mx = "-mx$($Global:Config.CompressionLevel)"
        $rawArgs = @("a", $backupFile, "$src\*", $mx, "-mmt=$safeThreads", "-bsp1")

        $sevenZipExe = Resolve-UserCustomBackup7zPath

        Write-UserCustomBackupMetadataWarning
        Write-Host "  Source UNC  : $src" -ForegroundColor DarkGray
        Write-Host "  Archive     : $backupFile" -ForegroundColor DarkGray
        Write-Host "Executing backup (Press Q to cancel)..." -ForegroundColor Cyan

        $backupProcess = Invoke-WSLBMNativeProcessChecked `
            -FilePath $sevenZipExe `
            -Arguments $rawArgs `
            -OperationName "Backup-User-7z" `
            -Description "Create USER backup archive" `
            -AllowCancel `
            -RegisterActiveProcess `
            -Distro $Script:CurrentDistro

        # Fail closed: timeout, cancel, and null ExitCode are also 7z failures.
        $exitCode = $backupProcess.ExitCode
        if ($backupProcess.TimedOut) {
            throw "7z backup failed: timed out."
        }
        if ($backupProcess.Cancelled) {
            throw "7z backup failed: cancelled by user."
        }
        if ($null -eq $exitCode) {
            throw "7z backup failed: process did not report an exit code."
        }
        $backupStatus = "Success"
        $warningSummary = ""
        if ($exitCode -eq 1) {
            $backupStatus = "Warning"
            $warningSummary = Get-UserCustomBackupWarningSummary
            Write-UserCustomBackupExitCode1Warning -BackupType "USER" -ArchivePath $backupFile
        }
        elseif ($exitCode -ne 0) {
            throw (Get-UserCustomBackup7zFailureMessage -ExitCode $exitCode)
        }

        $null = Test-UserCustomBackupArchiveCreated -ArchivePath $backupFile

        Test-BackupIntegrity -backupFile $backupFile -backupType "USER-FULL"
        if ($backupStatus -eq "Warning") {
            $null = Write-BackupManifest `
                -BackupType "USER" `
                -BackupDir $backupDir `
                -ArchivePath $backupFile `
                -SourceDistro $Script:CurrentDistro `
                -WslUser $wslUser `
                -BackupStatus $backupStatus `
                -SevenZipExitCode $exitCode `
                -WarningSummary $warningSummary
        }
        else {
            Write-BackupManifestBestEffort `
                -BackupType "USER" `
                -BackupDir $backupDir `
                -ArchivePath $backupFile `
                -SourceDistro $Script:CurrentDistro `
                -WslUser $wslUser `
                -BackupStatus $backupStatus `
                -SevenZipExitCode $exitCode `
                -WarningSummary $warningSummary
        }

        Remove-LockFile

        if ($backupStatus -eq "Warning") {
            Write-UserCustomBackupWarningCompletedSummary
            Write-LogEntry "WARN" "Backup-User" "Completed with warnings. 7z exit code $exitCode. $warningSummary | OpId=$($Script:CurrentOperationId)"
        }
        else {
            Write-Host "SUCCESS!" -ForegroundColor Green
            Write-LogEntry "SUCCESS" "Backup-User" "Completed | OpId=$($Script:CurrentOperationId)"
        }

        Write-Host "Add note (optional):"
        $note = Read-Host
        if (-not [string]::IsNullOrWhiteSpace($note)) {
            Write-WSLBMTextFileUtf8NoBom -LiteralPath (Join-Path $backupDir "note.txt") -Content $note
        }

    }
    catch {
        $errMsg = $_.Exception.Message
        $msg = if ($errMsg -match "UserCancelled") { "Cancelled" } else { "Failed: $errMsg" }

        Write-LogEntry "ERROR" "Backup-User" "$msg | OpId=$($Script:CurrentOperationId)"
        Write-Host "[ERROR] $msg" -ForegroundColor Red

        Stop-ActiveBackupProcesses
        Remove-FailedBackupDir
    }
    finally {
        Stop-ActiveBackupProcesses
        Remove-LockFile
        $Global:BackupState.IsRunning = $false
        $Global:BackupState.CurrentFile = $null
        $Global:BackupState.CurrentDir = $null
        Clear-BackupCleanupAllowedRoot
        $Script:CurrentOperationId = ""
    }

    Read-Host "Press Enter to return..."
}

function New-CustomBackup {
    if (-not $Script:CurrentDistro) {
        Write-Host "[ERROR] No Distro Selected." -ForegroundColor Red
        return
    }

    if ($Global:DryRun) {
        Write-Host "Base: /home/<wsl-user>/" -ForegroundColor DarkGray
        $customPathRaw = Read-Host "Enter LINUX relative path (e.g. 'projects/my-code')"

        $customPathValidation = Resolve-SafeUserCustomBackupRelativePath -Path $customPathRaw
        if (-not $customPathValidation.Success) {
            Write-Host "[ERROR] Invalid CUSTOM backup path: $($customPathValidation.Reason)" -ForegroundColor Red
            return
        }

        $cleanPath = $customPathValidation.CleanPath
        $backupName = ($cleanPath -split '/' | Select-Object -Last 1)
        $wslUserPreview = "<wsl-user>"
        $src = "$($Script:WSLPathPrefix)\$Script:CurrentDistro\home\$wslUserPreview\$cleanPath"

        $ts = Get-Date -Format "yyyy-MM-dd_HHmm"
        $backupDir = Get-BackupDestination -defaultName "$ts-CUSTOM" -PreviewOnly
        if (-not $backupDir) { return }

        $backupFile = Join-Path $backupDir "$backupName.7z"
        $rawArgs = @("a", $backupFile, $src, "-mx$($Global:Config.CompressionLevel)", "-mmt=<calculated-safe-threads>", "-bsp1")
        $previewOperationId = New-OperationId

        Show-UserCustomBackupDryRunPreview `
            -BackupType "CUSTOM" `
            -SourcePath $src `
            -CustomRelativePath $cleanPath `
            -BackupDir $backupDir `
            -ArchivePath $backupFile `
            -RawArgs $rawArgs `
            -OperationId $previewOperationId

        Read-Host "Press Enter to return..."
        return
    }

    if (-not (Test-DiskSpace $Global:Config.DiskThresholds.Custom)) { return }
    if (-not (Close-VSCodeSafely)) { return }

    try {
        $wslUser = Get-WSLUser
    }
    catch {
        Write-Host "[ERROR] CUSTOM backup aborted: $($_.Exception.Message)" -ForegroundColor Red
        Write-LogEntry "ERROR" "Backup-Custom" "Aborted before source path resolution: $($_.Exception.Message)"
        Read-Host "Press Enter to return..."
        return
    }

    Write-Host "Base: /home/$wslUser/" -ForegroundColor DarkGray
    $customPathRaw = Read-Host "Enter LINUX relative path (e.g. 'projects/my-code')"

    $customPathValidation = Resolve-SafeUserCustomBackupRelativePath -Path $customPathRaw
    if (-not $customPathValidation.Success) {
        Write-Host "[ERROR] Invalid CUSTOM backup path: $($customPathValidation.Reason)" -ForegroundColor Red
        return
    }

    $cleanPath = $customPathValidation.CleanPath
    $backupName = ($cleanPath -split '/' | Select-Object -Last 1)
    $src = "$($Script:WSLPathPrefix)\$Script:CurrentDistro\home\$wslUser\$cleanPath"

    $ts = Get-Date -Format "yyyy-MM-dd_HHmm"
    $backupDir = Get-BackupDestination -defaultName "$ts-CUSTOM"
    if (-not $backupDir) { return }

    $backupFile = Join-Path $backupDir "$backupName.7z"

    $sourceState = Get-UserCustomBackupSourceState -SourcePath $src -BackupType "CUSTOM" -CustomRelativePath $cleanPath
    if (-not (Confirm-UserCustomBackupSourceState -SourceState $sourceState -ArchivePath $backupFile)) { return }

    Select-Compression-Interactive
    $safeThreads = Get-Optimal7zThreads -Level $Global:Config.CompressionLevel

    New-BackupDirectory $backupDir | Out-Null

    New-LockFile -OperationType "Custom: $cleanPath" -TargetDir $backupDir
    $Global:BackupState.IsRunning = $true
    $Global:BackupState.CurrentFile = $backupFile
    $Global:BackupState.CurrentDir = $backupDir
    Set-BackupCleanupAllowedRootFromDestination -BackupDir $backupDir

    $Script:CurrentOperationId = New-OperationId
    Write-OperationIdBanner -OperationId $Script:CurrentOperationId
    Write-LogEntry "INFO" "Backup-Custom" "Started for $cleanPath | OpId=$($Script:CurrentOperationId)"

    try {
        $mx = "-mx$($Global:Config.CompressionLevel)"
        $rawArgs = @("a", $backupFile, $src, $mx, "-mmt=$safeThreads", "-bsp1")

        $sevenZipExe = Resolve-UserCustomBackup7zPath

        Write-UserCustomBackupMetadataWarning
        Write-Host "  Custom path : $cleanPath" -ForegroundColor DarkGray
        Write-Host "  Source UNC  : $src" -ForegroundColor DarkGray
        Write-Host "  Archive     : $backupFile" -ForegroundColor DarkGray
        Write-Host "Executing backup (Press Q to cancel)..." -ForegroundColor Cyan

        $backupProcess = Invoke-WSLBMNativeProcessChecked `
            -FilePath $sevenZipExe `
            -Arguments $rawArgs `
            -OperationName "Backup-Custom-7z" `
            -Description "Create CUSTOM backup archive" `
            -AllowCancel `
            -RegisterActiveProcess `
            -Distro $Script:CurrentDistro

        # Fail closed: timeout, cancel, and null ExitCode are also 7z failures.
        $exitCode = $backupProcess.ExitCode
        if ($backupProcess.TimedOut) {
            throw "7z backup failed: timed out."
        }
        if ($backupProcess.Cancelled) {
            throw "7z backup failed: cancelled by user."
        }
        if ($null -eq $exitCode) {
            throw "7z backup failed: process did not report an exit code."
        }
        $backupStatus = "Success"
        $warningSummary = ""
        if ($exitCode -eq 1) {
            $backupStatus = "Warning"
            $warningSummary = Get-UserCustomBackupWarningSummary
            Write-UserCustomBackupExitCode1Warning -BackupType "CUSTOM" -ArchivePath $backupFile
        }
        elseif ($exitCode -ne 0) {
            throw (Get-UserCustomBackup7zFailureMessage -ExitCode $exitCode)
        }

        $null = Test-UserCustomBackupArchiveCreated -ArchivePath $backupFile

        Test-BackupIntegrity -backupFile $backupFile -backupType "USER-CUSTOM"
        if ($backupStatus -eq "Warning") {
            $null = Write-BackupManifest `
                -BackupType "CUSTOM" `
                -BackupDir $backupDir `
                -ArchivePath $backupFile `
                -SourceDistro $Script:CurrentDistro `
                -WslUser $wslUser `
                -CustomRelativePath $cleanPath `
                -BackupStatus $backupStatus `
                -SevenZipExitCode $exitCode `
                -WarningSummary $warningSummary
        }
        else {
            Write-BackupManifestBestEffort `
                -BackupType "CUSTOM" `
                -BackupDir $backupDir `
                -ArchivePath $backupFile `
                -SourceDistro $Script:CurrentDistro `
                -WslUser $wslUser `
                -CustomRelativePath $cleanPath `
                -BackupStatus $backupStatus `
                -SevenZipExitCode $exitCode `
                -WarningSummary $warningSummary
        }

        Remove-LockFile

        if ($backupStatus -eq "Warning") {
            Write-UserCustomBackupWarningCompletedSummary
            Write-LogEntry "WARN" "Backup-Custom" "Completed with warnings. 7z exit code $exitCode. $warningSummary | OpId=$($Script:CurrentOperationId)"
        }
        else {
            Write-Host "SUCCESS!" -ForegroundColor Green
            Write-LogEntry "SUCCESS" "Backup-Custom" "Completed | OpId=$($Script:CurrentOperationId)"
        }

        Write-Host "Add note (optional):"
        $note = Read-Host
        if (-not [string]::IsNullOrWhiteSpace($note)) {
            Write-WSLBMTextFileUtf8NoBom -LiteralPath (Join-Path $backupDir "note.txt") -Content $note
        }

    }
    catch {
        $errMsg = $_.Exception.Message
        $msg = if ($errMsg -match "UserCancelled") { "Cancelled" } else { "Failed: $errMsg" }

        Write-LogEntry "ERROR" "Backup-Custom" "$msg | OpId=$($Script:CurrentOperationId)"
        Write-Host "[ERROR] $msg" -ForegroundColor Red

        Stop-ActiveBackupProcesses
        Remove-FailedBackupDir
    }
    finally {
        Stop-ActiveBackupProcesses
        Remove-LockFile
        $Global:BackupState.IsRunning = $false
        $Global:BackupState.CurrentFile = $null
        $Global:BackupState.CurrentDir = $null
        Clear-BackupCleanupAllowedRoot
        $Script:CurrentOperationId = ""
    }

    Read-Host "Press Enter to return..."
}

# =============================================================================
# 8. Restore & Manage Operations
# =============================================================================

function Show-RestoreMenu {
    Clear-Host
    Write-Host "=== RESTORE MENU ===" -ForegroundColor Red

    $scanPath = Get-ValidatedBackupScanPath
    if (-not $scanPath) {
        Read-Host "Press Enter..."
        return
    }

    Write-Host "Scanning: $scanPath" -ForegroundColor DarkGray

    if (-not (Test-Path $scanPath)) {
        Write-Host "Backup path not found." -ForegroundColor Yellow
        Read-Host "Press Enter..."
        return
    }

    $backups = @(Get-ChildItem $scanPath -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)

    if ($backups.Count -eq 0) {
        Write-Host "No backups found."
        Read-Host "Press Enter..."
        return
    }

    $showAllBackups = $false
    $displayedBackupCount = Get-DisplayedBackupCount -Backups $backups
    Show-BackupTable -Backups $backups

    while ($true) {
        $sel = Read-Host "Select backup number (A = show all, 0/q = cancel)"
        if ($sel -eq "0" -or $sel -eq "q" -or $sel -eq "Q") {
            return
        }
        if ($sel -eq "a" -or $sel -eq "A") {
            if ($showAllBackups) {
                Write-Host "All recognized backups are already visible." -ForegroundColor Yellow
            }
            else {
                $showAllBackups = $true
                $displayedBackupCount = $backups.Count
                Show-BackupTable -Backups $backups -ShowAll
            }
            continue
        }

        if ($sel -match '^\d+$') {
            $selNum = [int]$sel
            if ($selNum -gt 0 -and $selNum -le $displayedBackupCount) {
                $target = $backups[$selNum - 1]
                break
            }
            if ($selNum -gt $displayedBackupCount -and $selNum -le $backups.Count) {
                Write-Host "Selection $selNum is not visible. Enter A to show all recognized backups first." -ForegroundColor Red
                continue
            }
        }

        Write-Host "Invalid selection. Enter a visible backup number from 1-$displayedBackupCount, A to show all, or 0/q to cancel." -ForegroundColor Red
    }

    Write-LogEntry "INFO" "Restore-Init" "Selected $($target.Name)"

    if ($target.Name -match "FULL") {
        Write-Host "`nSelected: $($target.Name)" -ForegroundColor Cyan
        Write-Host "[1] Overwrite Current ($Script:CurrentDistro)" -ForegroundColor Red
        Write-Host "[2] Clone to New Instance" -ForegroundColor Green
        Write-Host "[0] Cancel" -ForegroundColor Gray
        while ($true) {
            $subSel = Read-Host "Choose"
            switch ($subSel) {
                "1" { Invoke-RestoreOverwrite -backupDir $target.FullName; return }
                "2" { Invoke-RestoreNewInstance -backupDir $target.FullName; return }
                "0" { Write-Host "Cancelled." -ForegroundColor Yellow; return }
                "q" { Write-Host "Cancelled." -ForegroundColor Yellow; return }
                "Q" { Write-Host "Cancelled." -ForegroundColor Yellow; return }
                default { Write-Host "Invalid choice. Please enter 1, 2, or 0." -ForegroundColor Red }
            }
        }
    }
    else {
        Invoke-RestoreUserData -backupDir $target.FullName
    }
}

function Invoke-RestoreOverwrite {
    param($backupDir)

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "[WARN] Not running as Administrator. Some operations may fail." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "!!! FULL OVERWRITE RESTORE: $Script:CurrentDistro WILL BE REPLACED !!!" -ForegroundColor Red
    Write-Host "This path requires manifest/integrity checks, a verified Safety Net, and exact confirmations." -ForegroundColor Yellow
    Write-Host ""

    Show-ManifestAuditInfo -BackupDirPath $backupDir

    $backupFile = Join-Path $backupDir "wsl-full.7z"
    $overwritePathInfo = Resolve-OverwriteRestoreInstallPath -DistroName $Script:CurrentDistro -BackupFile $backupFile
    if (-not $overwritePathInfo.Success) {
        Write-Host "[ERROR] Overwrite restore cancelled before Safety Net." -ForegroundColor Red
        if (-not [string]::IsNullOrWhiteSpace([string]$overwritePathInfo.Reason)) {
            Write-Host "  Reason: $($overwritePathInfo.Reason)" -ForegroundColor Yellow
        }
        return
    }
    $installPath = $overwritePathInfo.InstallPath

    # Manifest archive consistency pre-check (before any destructive WSL operations).
    $mfCheck = Test-BackupManifestArchiveConsistency -BackupDirPath $backupDir -ArchiveFilePath $backupFile -ExpectedBackupType "FULL"
    if ($mfCheck.IsLegacy) {
        Write-ManifestLegacyCompatibilityWarning
    } elseif (-not $mfCheck.IsConsistent) {
        Write-Host "[ERROR] Manifest archive consistency check failed:" -ForegroundColor Red
        $mfCheck.Errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        Write-LogEntry "ERROR" "Restore-Manifest" "Manifest consistency failed; overwrite restore aborted"
        return
    }

    # Safety Net is a mandatory gate before destructive overwrite restore.
    $safetyFile = $null
    while ($true) {
        $doSafety = Read-Host "Create and verify mandatory Safety Net backup first? [Y/N/Q]"

        if ($doSafety -eq "q" -or $doSafety -eq "Q") {
            Write-LogEntry "WARN" "Restore-SafetyNet" "Cancelled by user before Safety Net"
            Write-Host "Cancelled." -ForegroundColor Yellow
            return
        }

        if ($doSafety -eq "y" -or $doSafety -eq "Y") {
            if (-not (Confirm-RestoreSafetyNetCreation -DistroName $Script:CurrentDistro)) {
                Write-LogEntry "WARN" "Restore-SafetyNet" "Cancelled before Safety Net export confirmation"
                Write-Host "Cancelled before Safety Net creation." -ForegroundColor Yellow
                return
            }

            $safetyFile = New-RestoreSafetyNetBackup -DistroName $Script:CurrentDistro
            if (-not $safetyFile) {
                Write-LogEntry "ERROR" "Restore-SafetyNet" "Safety Net failed; overwrite restore aborted"
                Write-Host "[ERROR] Safety Net creation or validation failed. Overwrite restore cancelled before destructive confirmation." -ForegroundColor Red
                return
            }
            break
        }

        if ($doSafety -eq "n" -or $doSafety -eq "N") {
            Write-LogEntry "WARN" "Restore-SafetyNet" "User refused mandatory Safety Net; overwrite restore aborted"
            Write-Host "[ERROR] Safety Net is required for overwrite restore. Restore cancelled." -ForegroundColor Red
            return
        }

        Write-Host "Please enter Y, N, or Q." -ForegroundColor Red
    }

    $Script:CurrentOperationId = New-OperationId
    Write-OperationIdBanner -OperationId $Script:CurrentOperationId
    Write-LogEntry "INFO" "Restore-Overwrite" "Started overwrite restore for $Script:CurrentDistro | OpId=$($Script:CurrentOperationId)"

    Invoke-RestoreStream -backupFile $backupFile -distroName $Script:CurrentDistro -installPath $installPath -isOverwrite $true -OverwritePathInfo $overwritePathInfo -SafetyNetPath $safetyFile
}

function Invoke-RestoreNewInstance {
    param($backupDir)

    $newName = Read-Host "Enter new instance name (e.g. Ubuntu-Test)"
    if ([string]::IsNullOrWhiteSpace($newName)) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }

    if (-not (Test-SafeDistroName -Name $newName)) {
        Write-Host "[SECURITY] Invalid name. Avoid special characters: & | < > ^ % `" ' ; !" -ForegroundColor Red
        return
    }

    $newPath = Read-Host "Enter install path (press Enter for default)"
    if ([string]::IsNullOrWhiteSpace($newPath)) {
        if (-not (Test-WSLBMInstallRootReady `
                -Path $Global:Config.InstallRoot `
                -Label "Configured Install Root" `
                -InvalidAction "Default clone restore install path is blocked until Settings is corrected.")) {
            return
        }
        $newPath = Join-Path $Global:Config.InstallRoot $newName
    }

    $backupFile = Join-Path $backupDir "wsl-full.7z"
    $installPathSafety = Test-RestoreInstallPathSafety -InstallPath $newPath -BackupFile $backupFile -DistroName $newName -Mode "Clone"
    if (-not $installPathSafety.Success) {
        Write-Host "[ERROR] Clone restore cancelled before restore stream because install path safety check failed." -ForegroundColor Red
        return
    }
    $newPath = $installPathSafety.NormalizedPath

    Write-Host ""
    Write-Host "[FULL Clone Restore Warning]" -ForegroundColor Yellow
    Write-Host "This will import a FULL backup as a new WSL distro: $newName" -ForegroundColor Yellow
    Write-Host "Current distro is not overwritten by the clone path, but the install path receives restored system files." -ForegroundColor Yellow

    Show-ManifestAuditInfo -BackupDirPath $backupDir

    # Manifest archive consistency pre-check (before restore stream).
    $mfCheck = Test-BackupManifestArchiveConsistency -BackupDirPath $backupDir -ArchiveFilePath $backupFile -ExpectedBackupType "FULL"
    if ($mfCheck.IsLegacy) {
        Write-ManifestLegacyCompatibilityWarning
    } elseif (-not $mfCheck.IsConsistent) {
        Write-Host "[ERROR] Manifest archive consistency check failed:" -ForegroundColor Red
        $mfCheck.Errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        Write-LogEntry "ERROR" "Restore-Manifest" "Manifest consistency failed; clone restore aborted"
        return
    }

    $Script:CurrentOperationId = New-OperationId
    Write-OperationIdBanner -OperationId $Script:CurrentOperationId
    Write-LogEntry "INFO" "Restore-Clone" "Started clone restore for $newName | OpId=$($Script:CurrentOperationId)"

    Invoke-RestoreStream -backupFile $backupFile -distroName $newName -installPath $newPath -isOverwrite $false
}

function Invoke-RestoreStream {
    param(
        $backupFile,
        $distroName,
        $installPath,
        $isOverwrite,
        $OverwritePathInfo = $null,
        $SafetyNetPath = ""
    )

    if ($Global:DryRun) {
        $restoreMode = if ($isOverwrite) { "Overwrite" } else { "Clone" }
        try {
            if (-not (Test-Path -LiteralPath $backupFile -PathType Leaf)) {
                throw "Backup file missing: $backupFile"
            }

            Write-Host "[DRY RUN] FULL restore preview starting. No restore actions will be performed." -ForegroundColor Cyan

            $preflight = Test-RestoreImportPreflight -BackupFile $backupFile -InstallPath $installPath -Distro $distroName -Mode $restoreMode
            if (-not $preflight.Success) {
                return
            }
            if ($preflight.InstallPath) {
                $installPath = $preflight.InstallPath
            }

            $restoreTempRoot = ""
            if ($null -ne $preflight.TempPathInfo) {
                $restoreTempRoot = $preflight.TempPathInfo.TempRoot
            }

            if ($isOverwrite) {
                $null = Confirm-OverwriteRestoreDestructiveStep `
                    -DistroName $distroName `
                    -InstallPath $installPath `
                    -BackupFile $backupFile `
                    -RestoreTempRoot $restoreTempRoot `
                    -SafetyNetPath $SafetyNetPath `
                    -OverwritePathInfo $OverwritePathInfo
            }
            else {
                Write-Host "[DRY RUN] Clone restore preview:" -ForegroundColor Cyan
                Write-Host "  DRY RUN: would import archive $backupFile as new distro $distroName" -ForegroundColor Yellow
                Write-Host "  DRY RUN: would use install path $installPath" -ForegroundColor Yellow
                if (-not [string]::IsNullOrWhiteSpace($restoreTempRoot)) {
                    Write-Host "  DRY RUN: would use restore temp root $restoreTempRoot" -ForegroundColor Yellow
                }
                Write-LogEntry "INFO" "Restore-DryRun" "Clone restore dry run stopped before WSL changes. Target: $distroName | InstallPath: $installPath | Backup: $backupFile" -Distro $distroName
            }

            if (-not (Test-Path -LiteralPath $installPath -PathType Container -ErrorAction SilentlyContinue)) {
                Write-Host "DRY RUN: would create install path $installPath" -ForegroundColor Yellow
                Write-LogEntry "INFO" "Restore-DryRun" "Would create install path: $installPath" -Distro $distroName
            }

            Write-Host "DRY RUN: would extract wsl-export.tar from $backupFile to the restore temp path" -ForegroundColor Yellow
            Write-Host "DRY RUN: would import $distroName from the restore temp tar into $installPath" -ForegroundColor Yellow
            Write-Host "[DRY RUN] Restore preview completed. No restore was performed." -ForegroundColor Green
            Write-LogEntry "INFO" "Restore-DryRun" "Preview completed without restore actions. Target=$distroName | Mode=$restoreMode | OpId=$($Script:CurrentOperationId)" -Distro $distroName
        }
        catch {
            $errMsg = $_.Exception.Message
            Write-LogEntry "ERROR" "Restore-DryRun" "Failed: $errMsg | OpId=$($Script:CurrentOperationId)" -Distro $distroName
            Write-Host "[ERROR] RESTORE DRY RUN FAILED: $errMsg" -ForegroundColor Red
        }
        finally {
            $Script:CurrentOperationId = ""
        }

        Read-Host "Press Enter to continue..."
        return
    }

    if (-not (Close-VSCodeSafely)) { return }

    New-LockFile -OperationType "Restore" -TargetDir (Split-Path $backupFile -Parent)
    $Global:BackupState.IsRunning = $true

    Write-LogEntry "INFO" "Restore-Exec" "Target: $distroName | Overwrite: $isOverwrite"

    $restoreTempDir = $null
    $restoreTempTar = $null
    $preflight = $null
    $restoreMode = if ($isOverwrite) { "Overwrite" } else { "Clone" }

    try {
        if (-not (Test-Path $backupFile)) {
            throw "Backup file missing: $backupFile"
        }

        $preflight = Test-RestoreImportPreflight -BackupFile $backupFile -InstallPath $installPath -Distro $distroName -Mode $restoreMode
        if (-not $preflight.Success) {
            return
        }
        if ($preflight.InstallPath) {
            $installPath = $preflight.InstallPath
        }
        $restoreTempRoot = ""
        if ($null -ne $preflight.TempPathInfo) {
            $restoreTempRoot = $preflight.TempPathInfo.TempRoot
        }

        if ($isOverwrite) {
            if (-not (Confirm-OverwriteRestoreDestructiveStep `
                -DistroName $distroName `
                -InstallPath $installPath `
                -BackupFile $backupFile `
                -RestoreTempRoot $restoreTempRoot `
                -SafetyNetPath $SafetyNetPath `
                -OverwritePathInfo $OverwritePathInfo)) {
                Write-Host "[ERROR] Overwrite restore aborted before any destructive WSL changes." -ForegroundColor Red
                return
            }

            Write-Host "Unregistering existing distro..." -ForegroundColor Yellow
            # WSL high-risk boundary: overwrite restore reaches shutdown/unregister only after preflight, Safety Net, and exact confirmation.
            $shutdownResult = Invoke-GuardedWSLCommand -Description "Shutdown WSL before overwrite restore" -Arguments @("--shutdown") -Distro $distroName
            if (-not $shutdownResult.Success) {
                throw "WSL shutdown failed before overwrite restore"
            }
            Start-Sleep -Seconds 1

            # WSL high-risk boundary: unregister remains guarded and follows the shutdown success check.
            $unregisterResult = Invoke-GuardedWSLCommand -Description "Unregister distro before overwrite restore" -Arguments @("--unregister", $distroName) -Distro $distroName
            if (-not $unregisterResult.Success) {
                throw "WSL unregister failed for $distroName"
            }
            Start-Sleep -Seconds 2
        }

        if (-not (Test-Path $installPath)) {
            if ($Global:DryRun) {
                Write-Host "DRY RUN: would create install path $installPath" -ForegroundColor Yellow
                Write-LogEntry "INFO" "Restore-DryRun" "Would create install path: $installPath" -Distro $distroName
            }
            else {
                New-Item -ItemType Directory -Path $installPath -Force | Out-Null
            }
        }

        Write-Host "Restoring (this may take several minutes)..." -ForegroundColor Cyan

        $extractResult = Expand-RestoreArchiveToTempTar -BackupFile $backupFile -Distro $distroName -TarSizeBytes $preflight.TarSizeBytes -TempPathInfo $preflight.TempPathInfo -InstallPath $installPath
        $restoreTempDir = $extractResult.TempDir
        $restoreTempTar = $extractResult.TempTar
        if (-not $extractResult.Success) {
            throw "Restore tar extraction failed"
        }

        $importResult = Invoke-RestoreImportFromTar -DistroName $distroName -InstallPath $installPath -TempTar $restoreTempTar
        if (-not $importResult.Success) {
            throw "WSL import failed for $distroName"
        }

        Remove-LockFile

        Write-Host ""
        Write-Host "SUCCESS! System restored." -ForegroundColor Green
        Write-Host "  Distro: $distroName" -ForegroundColor Cyan
        Write-Host "  Path  : $installPath" -ForegroundColor Cyan
        Write-LogEntry "SUCCESS" "Restore-Exec" "Completed | OpId=$($Script:CurrentOperationId)"

    }
    catch {
        $errMsg = $_.Exception.Message
        Write-LogEntry "ERROR" "Restore-Exec" "Failed: $errMsg | OpId=$($Script:CurrentOperationId)"
        Write-Host "[ERROR] RESTORE FAILED: $errMsg" -ForegroundColor Red

        if ($isOverwrite) {
            $manualRecoveryHintNeeded = $true
            if (-not [string]::IsNullOrWhiteSpace([string]$SafetyNetPath) -and
                (Test-Path -LiteralPath $SafetyNetPath -PathType Leaf)) {
                $rollbackResult = Invoke-RestoreSafetyNetRollbackPrompt `
                    -DistroName $distroName `
                    -InstallPath $installPath `
                    -SafetyNetPath $SafetyNetPath `
                    -OverwritePathInfo $OverwritePathInfo
                $manualRecoveryHintNeeded = [bool]$rollbackResult.ManualHintNeeded
            }
            else {
                Write-LogEntry "WARN" "Restore-SafetyNet-Rollback" "Safety Net rollback unavailable. SafetyNetPath='$SafetyNetPath'" -Distro $distroName
            }

            if ($manualRecoveryHintNeeded) {
                Write-Host ""
                Write-Host "[CRITICAL] Original system was unregistered!" -ForegroundColor Yellow
                Write-Host "If you created a Safety Net, you can restore it with:" -ForegroundColor Yellow
                Write-Host "  wsl --import $distroName <path> <safety-net.tar>" -ForegroundColor Cyan
            }
        }

        Stop-ActiveBackupProcesses

    }
    finally {
        Stop-ActiveBackupProcesses

        Clear-RestoreTempArtifacts -TempDir $restoreTempDir -TempTar $restoreTempTar -Distro $distroName

        Remove-LockFile
        $Global:BackupState.IsRunning = $false
        $Script:CurrentOperationId = ""
    }
    Read-Host "Press Enter to continue..."
}

function Resolve-UserCustomRestore7zPath {
    return Resolve-WSLBMSevenZipPath
}

function Resolve-UserCustomBackup7zPath {
    return Resolve-WSLBMSevenZipPath
}

function Resolve-SafeUserCustomBackupRelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]@{
            Success   = $false
            CleanPath = ""
            Reason    = "Path is empty."
        }
    }

    $cleanPath = $Path.Trim()
    if ($cleanPath -match '^[A-Za-z]:') {
        return [pscustomobject]@{
            Success   = $false
            CleanPath = ""
            Reason    = "Windows drive paths are not allowed. Use a Linux relative path under the current user's home."
        }
    }

    $cleanPath = $cleanPath -replace "^~/", "" -replace "\\", "/"

    if ([string]::IsNullOrWhiteSpace($cleanPath)) {
        return [pscustomobject]@{
            Success   = $false
            CleanPath = ""
            Reason    = "Path is empty after normalization."
        }
    }

    if ($cleanPath.StartsWith("/")) {
        return [pscustomobject]@{
            Success   = $false
            CleanPath = ""
            Reason    = "Absolute paths are not allowed. Enter a path relative to /home/<user>."
        }
    }

    if ($cleanPath -match '[\x00-\x1F\x7F]') {
        return [pscustomobject]@{
            Success   = $false
            CleanPath = ""
            Reason    = "Control characters are not allowed."
        }
    }

    if ($cleanPath.Contains('"')) {
        return [pscustomobject]@{
            Success   = $false
            CleanPath = ""
            Reason    = "Double quotes are not allowed."
        }
    }

    if ($cleanPath -match '[\*\?\[\]]') {
        return [pscustomobject]@{
            Success   = $false
            CleanPath = ""
            Reason    = "Wildcards (* ? [ ]) are not allowed."
        }
    }

    $segments = $cleanPath -split '/'
    foreach ($segment in $segments) {
        if ($segment.Length -eq 0) {
            return [pscustomobject]@{
                Success   = $false
                CleanPath = ""
                Reason    = "Empty path segments are not allowed."
            }
        }

        if ($segment -eq "..") {
            return [pscustomobject]@{
                Success   = $false
                CleanPath = ""
                Reason    = "Path traversal '..' is not allowed."
            }
        }
    }

    return [pscustomobject]@{
        Success   = $true
        CleanPath = $cleanPath
        Reason    = ""
    }
}

function Get-UserCustomRestoreKind {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupDir,

        [Parameter(Mandatory = $true)]
        [string]$BackupFile
    )

    $backupDirName = Split-Path -Path $BackupDir -Leaf
    $backupFileName = Split-Path -Path $BackupFile -Leaf
    if ($backupDirName -match "CUSTOM" -or $backupFileName -ne "home.7z") {
        return "CUSTOM"
    }
    return "USER"
}

function Get-UserCustomRestoreTargetState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    try {
        if (-not (Test-Path -LiteralPath $Destination -PathType Container -ErrorAction Stop)) {
            return [pscustomobject]@{
                CanInspect = $true
                Exists     = $false
                IsNonEmpty = $false
                Reason     = "Target directory does not currently exist."
            }
        }

        $firstChild = Get-ChildItem -LiteralPath $Destination -Force -ErrorAction Stop | Select-Object -First 1
        $reason = if ($null -ne $firstChild) { "Target directory exists and is not empty." } else { "Target directory exists and is empty." }
        return [pscustomobject]@{
            CanInspect = $true
            Exists     = $true
            IsNonEmpty = ($null -ne $firstChild)
            Reason     = $reason
        }
    }
    catch {
        return [pscustomobject]@{
            CanInspect = $false
            Exists     = $true
            IsNonEmpty = $true
            Reason     = "Could not safely inspect target directory: $($_.Exception.Message)"
        }
    }
}

function Write-UserCustomRestoreMetadataWarning {
    Write-UserCustomMetadataWarning -Operation "restore"
}

function Write-UserCustomBackupMetadataWarning {
    Write-UserCustomMetadataWarning -Operation "backup"
}

function Write-UserCustomMetadataWarning {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("backup", "restore")]
        [string]$Operation
    )

    $operationText = if ($Operation -eq "restore") { "restore uses WSL UNC paths plus Windows 7-Zip directory-level extraction" } else { "backup uses WSL UNC paths plus Windows 7-Zip directory-level backup" }

    Write-Host ""
    Write-Host "[LINUX METADATA WARNING]" -ForegroundColor Yellow
    Write-Host "USER/CUSTOM $operationText." -ForegroundColor Yellow
    Write-Host "It does not guarantee full Linux owner/group, permission, symlink, special-file," -ForegroundColor Yellow
    Write-Host "or case-sensitivity fidelity. Use FULL $Operation when Linux metadata fidelity matters." -ForegroundColor Yellow
    Write-Host ""
}

function Confirm-UserCustomRestoreOverwrite {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("USER", "CUSTOM")]
        [string]$RestoreType,

        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [Parameter(Mandatory = $true)]
        [string]$Destination,

        [Parameter(Mandatory = $true)]
        [object]$TargetState,

        [Parameter(Mandatory = $true)]
        [string[]]$RawArgs
    )

    $requiredPhrase = "RESTORE $RestoreType DATA TO $DistroName"
    $targetStateText = if ($TargetState.CanInspect) {
        if (-not $TargetState.Exists) { "Missing" }
        elseif ($TargetState.IsNonEmpty) { "Exists and non-empty" }
        else { "Exists and empty" }
    }
    else {
        "Inspection failed; treated as non-empty/high-risk"
    }

    Write-Host ""
    Write-Host "[USER/CUSTOM Restore Pre-flight]" -ForegroundColor Cyan
    Write-Host "  Restore type : $RestoreType" -ForegroundColor DarkGray
    Write-Host "  Distro       : $DistroName" -ForegroundColor DarkGray
    Write-Host "  Backup file  : $BackupFile" -ForegroundColor DarkGray
    Write-Host "  Destination  : $Destination" -ForegroundColor DarkGray
    Write-Host "  Target state : $targetStateText" -ForegroundColor DarkGray
    Write-Host "  Detail       : $($TargetState.Reason)" -ForegroundColor DarkGray
    Write-Host "  7z args      : $(Format-QuotedArgs $RawArgs)" -ForegroundColor DarkGray
    Write-Host "  Overwrite    : 7z -aoa can overwrite files under the destination after confirmation" -ForegroundColor Yellow

    Write-UserCustomRestoreMetadataWarning

    if ($Global:DryRun) {
        Write-Host "[DRY RUN] USER/CUSTOM restore preview only." -ForegroundColor Cyan
        Write-Host "  DRY RUN: WSL/wsl.exe was not called to resolve the target user" -ForegroundColor Yellow
        Write-Host "  DRY RUN: target UNC path was not probed or enumerated" -ForegroundColor Yellow
        Write-Host "  DRY RUN: 7z extraction intentionally skipped" -ForegroundColor Yellow
        Write-Host "  DRY RUN: no files were written or overwritten under $Destination" -ForegroundColor Yellow
        Write-Host "  DRY RUN: would require confirmation phrase if target is non-empty/high-risk:" -ForegroundColor Yellow
        Write-Host "    $requiredPhrase" -ForegroundColor Cyan
        Write-Host "  DRY RUN: preview completed" -ForegroundColor Green
        return $false
    }

    if ($TargetState.IsNonEmpty -or (-not $TargetState.CanInspect)) {
        Write-Host "[WARNING] USER/CUSTOM restore target appears non-empty or could not be safely inspected." -ForegroundColor Red
        Write-Host "This restore can overwrite existing files under the destination." -ForegroundColor Red
        Write-Host "Type the exact phrase below to allow overwrite extraction, or Q/CANCEL to abort:" -ForegroundColor Yellow
        Write-Host "  $requiredPhrase" -ForegroundColor Cyan

        $confirm = Read-Host "Confirmation"
        if ([string]::IsNullOrWhiteSpace($confirm) -or $confirm -in @("q", "Q", "cancel", "CANCEL")) {
            Write-LogEntry "WARN" "Restore-User-Confirm" "Cancelled before USER/CUSTOM restore overwrite. Type=$RestoreType | Destination=$Destination" -Distro $DistroName
            return $false
        }
        if ($confirm -cne $requiredPhrase) {
            Write-Host "[ERROR] Confirmation phrase did not match. Restore cancelled before 7z extraction." -ForegroundColor Red
            Write-LogEntry "WARN" "Restore-User-Confirm" "Confirmation phrase mismatch. Type=$RestoreType | Destination=$Destination" -Distro $DistroName
            return $false
        }

        Write-LogEntry "WARN" "Restore-User-Confirm" "Confirmed USER/CUSTOM overwrite restore. Type=$RestoreType | Destination=$Destination" -Distro $DistroName
        return $true
    }

    $confirmContinue = Read-Host "Target is empty/missing. Press Enter to continue, or Q/CANCEL to abort"
    if ($confirmContinue -in @("q", "Q", "cancel", "CANCEL")) {
        Write-LogEntry "WARN" "Restore-User-Confirm" "Cancelled before USER/CUSTOM restore. Type=$RestoreType | Destination=$Destination" -Distro $DistroName
        return $false
    }

    Write-LogEntry "INFO" "Restore-User-Confirm" "Confirmed USER/CUSTOM restore to empty/missing target. Type=$RestoreType | Destination=$Destination" -Distro $DistroName
    return $true
}

function Invoke-RestoreUserData {
    param($backupDir)

    $backupFile = Join-Path $backupDir "home.7z"

    if (-not (Test-Path $backupFile)) {
        # Fall back to the first archive in legacy backup folders.
        $found = Get-ChildItem $backupDir -Filter "*.7z" -File | Select-Object -First 1
        if ($found) {
            $backupFile = $found.FullName
        }
        else {
            Write-Host "[ERROR] No .7z file found in backup folder." -ForegroundColor Red
            Read-Host "Press Enter..."
            return
        }
    }

    try {
        $null = Assert-WSLBMSevenZipArchiveInput -ArchivePath $backupFile -Context "USER/CUSTOM restore archive"
    }
    catch {
        Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
        Read-Host "Press Enter..."
        return
    }

    Show-ManifestAuditInfo -BackupDirPath $backupDir

    # Manifest archive consistency pre-check (before overwrite confirmation).
    # Note: ExpectedBackupType="USER" here causes the helper to accept both USER and CUSTOM manifests.
    $mfCheck = Test-BackupManifestArchiveConsistency -BackupDirPath $backupDir -ArchiveFilePath $backupFile -ExpectedBackupType "USER"
    if ($mfCheck.IsLegacy) {
        Write-ManifestLegacyCompatibilityWarning
    } elseif (-not $mfCheck.IsConsistent) {
        Write-Host "[ERROR] Manifest archive consistency check failed:" -ForegroundColor Red
        $mfCheck.Errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        if (-not $Global:DryRun) {
            Write-LogEntry "ERROR" "Restore-Manifest" "Manifest consistency failed; USER/CUSTOM restore aborted"
        }
        Read-Host "Press Enter..."
        return
    }

    $restoreType = Get-UserCustomRestoreKind -BackupDir $backupDir -BackupFile $backupFile
    $manifestInfo = Read-BackupManifest -BackupDirPath $backupDir

    if ($Global:DryRun) {
        $wslUser = ""
        if ($manifestInfo.HasManifest -and $manifestInfo.ManifestStatus -eq "ok" -and -not [string]::IsNullOrWhiteSpace([string]$manifestInfo.WslUser)) {
            $wslUser = ([string]$manifestInfo.WslUser).Trim()
        }
        if ([string]::IsNullOrWhiteSpace($wslUser)) {
            $wslUser = "<wsl-user>"
        }
        $destPath = if ($wslUser -eq "root") { "/root" } else { "/home/$wslUser" }
        $targetState = [pscustomobject]@{
            CanInspect = $false
            Exists     = $true
            IsNonEmpty = $true
            Reason     = "DRY RUN: target UNC was not probed; preview treats the target as high-risk."
        }
    }
    else {
        try {
            $wslUser = Get-WSLUser
        }
        catch {
            Write-Host "[ERROR] USER/CUSTOM restore aborted: $($_.Exception.Message)" -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-User" "Aborted before destination path resolution: $($_.Exception.Message)"
            Read-Host "Press Enter..."
            return
        }

        $destPath = if ($wslUser -eq "root") { "/root" } else { "/home/$wslUser" }
        $targetState = Get-UserCustomRestoreTargetState -Destination "$($Script:WSLPathPrefix)\$Script:CurrentDistro$destPath"
    }

    $dest = "$($Script:WSLPathPrefix)\$Script:CurrentDistro$destPath"

    try {
        $rawArgs = @("x", $backupFile, "-o$dest", "-aoa", "-bsp1")

        if (-not (Confirm-UserCustomRestoreOverwrite `
                    -RestoreType $restoreType `
                    -DistroName $Script:CurrentDistro `
                    -BackupFile $backupFile `
                    -Destination $dest `
                    -TargetState $targetState `
                    -RawArgs $rawArgs)) {
            if ($Global:DryRun) {
                Write-Host "DryRun preview completed. 7z extraction intentionally skipped; no files were written." -ForegroundColor Green
            }
            else {
                Write-Host "Restore cancelled before 7z extraction." -ForegroundColor Yellow
            }
            Read-Host "Press Enter..."
            return
        }

        $Script:CurrentOperationId = New-OperationId
        Write-OperationIdBanner -OperationId $Script:CurrentOperationId
        Write-Host "Restoring to: $dest" -ForegroundColor Cyan
        Write-LogEntry "INFO" "Restore-User" "Type=$restoreType | Target=$dest | Backup=$backupFile | OpId=$($Script:CurrentOperationId)"

        $Global:BackupState.IsActive = $true
        $Global:BackupState.IsRunning = $true
        $Global:BackupState.Operation = "Restore-$restoreType"
        $Global:BackupState.CurrentFile = $backupFile
        $Global:BackupState.CurrentDir = $dest
        $Global:BackupState.ActiveProcess = $null
        $Global:BackupState.StartTime = Get-Date

        $sevenZipExe = Resolve-UserCustomRestore7zPath
        Write-Host "Extracting with 7-Zip (Press Q to cancel)..." -ForegroundColor Cyan
        $restoreProcess = Invoke-WSLBMNativeProcessChecked `
            -FilePath $sevenZipExe `
            -Arguments $rawArgs `
            -OperationName "Restore-User-7z" `
            -Description "Extract USER/CUSTOM restore archive" `
            -AllowCancel `
            -RegisterActiveProcess `
            -Distro $Script:CurrentDistro
        $exitCode = $restoreProcess.ExitCode

        if ($restoreProcess.TimedOut) {
            throw "7z restore failed: timed out."
        }
        if ($restoreProcess.Cancelled) {
            throw "7z restore failed: cancelled by user."
        }
        if ($null -eq $exitCode) {
            throw "7z restore failed: process did not report an exit code."
        }

        if ($exitCode -ne 0) {
            throw "7z restore failed (exit code $exitCode)."
        }

        Write-Host "SUCCESS!" -ForegroundColor Green
        Write-LogEntry "SUCCESS" "Restore-User" "Completed Type=$restoreType | Destination=$dest | OpId=$($Script:CurrentOperationId)"

    }
    catch {
        Write-Host "[ERROR] $_" -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-User" "Failed: $_ | OpId=$($Script:CurrentOperationId)"
        Stop-ActiveBackupProcesses
    }
    finally {
        Stop-ActiveBackupProcesses
        $Global:BackupState.IsActive = $false
        $Global:BackupState.IsRunning = $false
        $Global:BackupState.Operation = $null
        $Global:BackupState.ActiveProcess = $null
        $Global:BackupState.CurrentFile = $null
        $Global:BackupState.CurrentDir = $null
        $Global:BackupState.StartTime = $null
        $Script:CurrentOperationId = ""
    }

    Read-Host "Press Enter..."
}

function Show-DeleteManifestAuditSummary {
    <#
    .SYNOPSIS
        Display compact manifest audit data before delete confirmation.
    .DESCRIPTION
        Missing or damaged manifest data falls back to legacy compatibility.
    .PARAMETER BackupDirPath
        Backup directory path.
    .OUTPUTS
        PSCustomObject manifest summary for logging.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupDirPath
    )

    $mf = Read-BackupManifest -BackupDirPath $BackupDirPath
    $manifestStatus = Get-BackupManifestStatusText -ManifestInfo $mf

    if (-not $mf.HasManifest -or $mf.ManifestStatus -ne "ok") {
        Write-Host "    [Manifest] $($manifestStatus.StatusText) (no trusted manifest data available)" -ForegroundColor $manifestStatus.Color
        return $mf
    }

    # Manifest OK — show compact audit info
    Write-Host "    [Manifest] $($manifestStatus.StatusText)" -ForegroundColor $manifestStatus.Color
    $shownManifestFields = @{}
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "BackupStatus" -Value $mf.BackupStatus -ForegroundColor $manifestStatus.Color -Indent 6 -Width 16
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "SevenZipExitCode" -Value $mf.SevenZipExitCode -Indent 6 -Width 16
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "WarningSummary" -Value $mf.WarningSummary -ForegroundColor Yellow -Indent 6 -Width 16 -Label "Warning"
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "BackupType" -Value $mf.BackupType -Indent 6 -Width 16
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "SourceDistro" -Value $mf.SourceDistro -Indent 6 -Width 16
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "ArchiveName" -Value $mf.ArchiveName -Indent 6 -Width 16
    $archiveSizeText = Format-OptionalByteCount -Value $mf.ArchiveSizeBytes
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "ArchiveSize" -Value $archiveSizeText -Indent 6 -Width 16
    if ($manifestStatus.HashPrefix -ne "-") {
        Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "ArchiveSha256" -Value "$($manifestStatus.HashPrefix)..." -Indent 6 -Width 16
    }
    Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "BackupMode" -Value $mf.BackupMode -Indent 6 -Width 16
    if ($manifestStatus.OpIdPrefix -ne "-") {
        Write-ManifestAuditField -ShownFields $shownManifestFields -FieldName "OperationId" -Value $manifestStatus.OpIdPrefix -Indent 6 -Width 16
    }

    return $mf
}

function Remove-BatchBackups {
    $scanPath = Get-ValidatedBackupScanPath
    if (-not $scanPath) {
        Read-Host "Press Enter..."
        return
    }

    Clear-Host
    Write-Host "=== BATCH DELETE ($scanPath) ===" -ForegroundColor Red

    if (-not (Test-Path $scanPath)) {
        Write-Host "Path not found." -ForegroundColor Yellow
        Read-Host "Press Enter..."
        return
    }

    $backups = @(Get-ChildItem $scanPath -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)

    if ($backups.Count -eq 0) {
        Write-Host "No backups found."
        Read-Host "Press Enter..."
        return
    }

    $showAllBackups = $false
    $displayedBackupCount = Get-DisplayedBackupCount -Backups $backups
    Show-BackupTable -Backups $backups

    $targets = @()
    while ($true) {
        Write-Host ""
        $inputStr = Read-Host "Enter visible numbers to delete (comma separated), A to show all, or 0/q to cancel"

        if ($inputStr -eq "q" -or $inputStr -eq "Q" -or $inputStr -eq "0") {
            return
        }
        if ($inputStr -eq "a" -or $inputStr -eq "A") {
            if ($showAllBackups) {
                Write-Host "All recognized backups are already visible." -ForegroundColor Yellow
            }
            else {
                $showAllBackups = $true
                $displayedBackupCount = $backups.Count
                Show-BackupTable -Backups $backups -ShowAll
            }
            continue
        }

        $tokens = @($inputStr -split "," | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($tokens.Count -eq 0) {
            Write-Host "No selections entered. Use visible numbers 1-$displayedBackupCount, A to show all, or 0/q to cancel." -ForegroundColor Yellow
            continue
        }

        $invalidTokens = @()
        $targets = @()
        foreach ($token in $tokens) {
            if ($token -notmatch '^\d+$') {
                $invalidTokens += "$token (not a number)"
                continue
            }

            $idxNum = [int]$token
            if ($idxNum -le 0 -or $idxNum -gt $displayedBackupCount) {
                $invalidTokens += "$token (not visible/selectable)"
                continue
            }

            $targets += $backups[$idxNum - 1]
        }

        if ($invalidTokens.Count -gt 0) {
            Write-Host "Invalid selection token(s): $($invalidTokens -join ', ')." -ForegroundColor Red
            Write-Host "Only visible backup entries 1-$displayedBackupCount can be deleted from this screen. Enter A to show all recognized backups first." -ForegroundColor Yellow
            continue
        }

        if ($targets.Count -eq 0) {
            Write-Host "No valid selections. Use visible numbers 1-$displayedBackupCount, A to show all, or 0/q to cancel." -ForegroundColor Yellow
            continue
        }

        break
    }

    Write-Host ""
    Write-Host "[BATCH DELETE WARNING] The following backup directories will be permanently deleted:" -ForegroundColor Red
    foreach ($t in $targets) {
        Write-Host "  - $($t.Name)" -ForegroundColor Yellow
        $null = Show-DeleteManifestAuditSummary -BackupDirPath $t.FullName
    }
    Write-Host ""
    Write-Host "  Manifest data is shown for audit only; it is not delete authorization." -ForegroundColor DarkGray
    Write-Host "  The exact DELETE confirmation phrase is still required before deletion starts." -ForegroundColor DarkGray

    $confirm = Read-Host "Type 'DELETE' to confirm (case-sensitive)"
    if ($confirm -cne "DELETE") {
        Write-Host "Cancelled." -ForegroundColor Yellow
        Read-Host "Press Enter..."
        return
    }

    $Script:CurrentOperationId = New-OperationId
    Write-OperationIdBanner -OperationId $Script:CurrentOperationId
    Write-LogEntry "INFO" "Delete-Batch" "Started batch delete of $($targets.Count) backup(s) | OpId=$($Script:CurrentOperationId)"

    foreach ($t in $targets) {
        # Read manifest for audit logging (does not affect delete logic)
        $delMf = Read-BackupManifest -BackupDirPath $t.FullName
        $delManifestStatus = Get-BackupManifestStatusText -ManifestInfo $delMf
        $mfStatus = $delManifestStatus.StatusText
        $mfDistro = $delManifestStatus.SourceDistro
        $mfType   = $delManifestStatus.BackupType
        $mfOpId   = $delManifestStatus.OpIdPrefix
        $mfHash   = $delManifestStatus.HashPrefix

        $deleteResult = Invoke-ProtectedBackupPathDelete `
            -Path $t.FullName `
            -Mode "BatchBackupDelete" `
            -Reason "User confirmed batch backup delete" `
            -AllowedRoot $scanPath `
            -FromRecognizedBackupList

        if ($deleteResult.Success) {
            Write-Host "  Deleted: $($t.Name)" -ForegroundColor Green
            Write-LogEntry "INFO" "Delete-Completed" "Deleted: $($t.Name) | Manifest=$mfStatus | SourceDistro=$mfDistro | BackupType=$mfType | Sha256Prefix=$mfHash | ManifestOpId=$mfOpId | OpId=$($Script:CurrentOperationId)"
        }
        else {
            Write-Host "  Failed to delete: $($t.Name) - $($deleteResult.Reason)" -ForegroundColor Red
            Write-LogEntry "WARN" "Delete-Failed" "Failed: $($t.Name) | Reason=$($deleteResult.Reason) | Manifest=$mfStatus | SourceDistro=$mfDistro | BackupType=$mfType | Sha256Prefix=$mfHash | ManifestOpId=$mfOpId | OpId=$($Script:CurrentOperationId)"
        }
    }

    $Script:CurrentOperationId = ""
    Read-Host "Press Enter..."
}

function Get-BackupList {
    $scanPath = Get-ValidatedBackupScanPath
    if (-not $scanPath) {
        Read-Host "Press Enter..."
        return
    }

    Clear-Host
    Write-Host "=== BACKUP LIST ($scanPath) ===" -ForegroundColor Cyan

    if (-not (Test-Path $scanPath)) {
        Write-Host "Path not found." -ForegroundColor Yellow
        Read-Host "Press Enter..."
        return
    }

    $backups = @(Get-ChildItem $scanPath -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)

    if ($backups.Count -eq 0) {
        Write-Host "No backups found."
        Read-Host "Press Enter..."
        return
    }

    Show-BackupTable -Backups $backups

    Read-Host "Press Enter to return..."
}

# =============================================================================
# 9. Logs & Settings Menus
# =============================================================================

function Show-LogsMenu {
    while ($true) {
        $ym = (Get-Date).ToString('yyyy-MM')
        $opsLog = Join-Path $Global:LogRoot "ops-$ym.log"
        $errLog = Join-Path $Global:LogRoot "error-$ym.log"

        Clear-Host
        Write-Host "=== Log Viewer ===" -ForegroundColor Cyan
        Write-Host "[1] View Operations Log"
        Write-Host "[2] View Error Log"
        Write-Host "[3] Open Log Folder"
        Write-Host "[4] Back"
        $choice = Read-Host "Choose"

        switch ($choice) {
            { $_ -in @("q", "Q", "4") } { return }
            "1" {
                if (Test-Path $opsLog) {
                    Write-Host "--- Last 30 entries ---" -ForegroundColor DarkGray
                    Get-Content $opsLog -Tail 30
                }
                else {
                    Write-Host "No operations log found." -ForegroundColor Yellow
                }
                Read-Host "Press Enter..."
            }
            "2" {
                if (Test-Path $errLog) {
                    Write-Host "--- Error Log ---" -ForegroundColor Red
                    Get-Content $errLog -Tail 20 | ForEach-Object { Write-Host $_ -ForegroundColor Red }
                }
                else {
                    Write-Host "No errors logged. Clean!" -ForegroundColor Green
                }
                Read-Host "Press Enter..."
            }
            "3" {
                if (Test-Path $Global:LogRoot) {
                    Invoke-Item $Global:LogRoot
                }
                else {
                    Write-Host "Log folder not found." -ForegroundColor Yellow
                    Read-Host "Press Enter..."
                }
            }
            "4" { return }
            default { }
        }
    }
}

function Edit-Settings {
    while ($true) {
        Clear-Host
        Write-Host "=== Settings ===" -ForegroundColor Cyan
        Write-Host "[1] Backup Root : $($Global:Config.GlobalBackupRoot)"
        Write-Host "[2] Install Root: $($Global:Config.InstallRoot)"
        Write-Host "[3] 7-Zip Path  : $($Global:Config.SevenZipPath)"
        Write-Host "[4] Compression : mx$($Global:Config.CompressionLevel)"
        Write-Host "[5] Disk Threshold (Full): $($Global:Config.DiskThresholds.Full) GB"
        Write-Host "[6] Manage Instance Paths"
        Write-Host "[7] Back"
        Write-Host "Note: .wslconfig is global WSL2 configuration and is not managed by these settings." -ForegroundColor DarkGray

        $choice = Read-Host "Select"

        switch ($choice) {
            { $_ -in @("q", "Q", "7") } { return }
            "1" {
                $newPath = Read-Host "Enter new Backup Root path"
                if ([string]::IsNullOrWhiteSpace($newPath)) { continue }
                $brValidation = Assert-WSLBMBackupRootPath -Path $newPath -Label "Backup Root"
                Write-WSLBMPathValidationResult -Result $brValidation -Label "Backup Root"
                if (-not $brValidation.IsValid) { continue }
                if (-not (Test-Path $newPath)) {
                    $create = Read-Host "Path doesn't exist. Create? [Y/N/Q]"
                    if ($create -eq "Y" -or $create -eq "y") {
                        New-Item -ItemType Directory -Path $newPath -Force | Out-Null
                    }
                    else { continue }
                }
                if (Test-Path $newPath) {
                    # Check overlap with current install root
                    $overlapCheck = Test-WSLBMRootOverlap -Path1 $newPath -Path2 $Global:Config.InstallRoot -Label1 "Backup Root" -Label2 "Install Root"
                    if (-not $overlapCheck.IsValid) {
                        Write-WSLBMPathValidationResult -Result $overlapCheck -Label "Overlap"
                        continue
                    }
                    $Global:Config.GlobalBackupRoot = $newPath
                    Save-Config
                    Write-Host "Updated." -ForegroundColor Green
                }
            }
            "2" {
                $newPath = Read-Host "Enter new Install Root path"
                if ([string]::IsNullOrWhiteSpace($newPath)) { continue }
                $irValidation = Assert-WSLBMInstallRootPath -Path $newPath -Label "Install Root"
                Write-WSLBMPathValidationResult -Result $irValidation -Label "Install Root"
                if (-not $irValidation.IsValid) { continue }
                if (-not (Test-Path $newPath)) {
                    $create = Read-Host "Path doesn't exist. Create? [Y/N/Q]"
                    if ($create -eq "Y" -or $create -eq "y") {
                        New-Item -ItemType Directory -Path $newPath -Force | Out-Null
                    }
                    else { continue }
                }
                if (Test-Path $newPath) {
                    $Global:Config.InstallRoot = $newPath
                    Save-Config
                    Write-Host "Updated." -ForegroundColor Green
                }
            }
            "3" {
                $newPath = Read-Host "Enter full path to 7z.exe (or press Enter for PATH fallback)"
                if ([string]::IsNullOrWhiteSpace($newPath)) {
                    # Allow clearing to use PATH fallback
                    $Global:Config.SevenZipPath = ""
                    Save-Config
                    Write-Host "Cleared. Will use PATH fallback." -ForegroundColor Green
                    continue
                }
                $szTextCheck = Test-WSLBMPathTextSafety -Path $newPath -Label "7-Zip path"
                if (-not $szTextCheck.IsValid) {
                    Write-WSLBMPathValidationResult -Result $szTextCheck -Label "7-Zip path"
                    continue
                }
                if (Test-Path $newPath -PathType Leaf) {
                    $Global:Config.SevenZipPath = $newPath
                    Save-Config
                    Write-Host "Updated." -ForegroundColor Green
                }
                else {
                    Write-Host "File not found: $newPath" -ForegroundColor Red
                }
            }
            "4" {
                $newLevel = Read-Host "Enter compression level [1-9]"
                if ($newLevel -match '^[1-9]$') {
                    $Global:Config.CompressionLevel = [int]$newLevel
                    Save-Config
                    Write-Host "Updated to mx$newLevel." -ForegroundColor Green
                }
                else {
                    Write-Host "Invalid level." -ForegroundColor Red
                }
            }
            "5" {
                $newThreshold = Read-Host "Enter minimum free space (GB) for Full backup"
                if ($newThreshold -match '^\d+$' -and [int]$newThreshold -gt 0) {
                    $Global:Config.DiskThresholds.Full = [int]$newThreshold
                    Save-Config
                    Write-Host "Updated." -ForegroundColor Green
                }
                else {
                    Write-Host "Invalid value." -ForegroundColor Red
                }
            }
            "6" {
                Write-Host ""
                Write-Host "Instance-specific backup paths:" -ForegroundColor Cyan
                if ($Global:Config.Instances.Count -eq 0) {
                    Write-Host "  (none configured)" -ForegroundColor DarkGray
                }
                else {
                    foreach ($key in $Global:Config.Instances.Keys) {
                        Write-Host "  [$key] -> $($Global:Config.Instances[$key].BackupPath)"
                    }
                }
                Write-Host ""
                $clearName = Read-Host "Enter instance name to clear (or press Enter to skip)"
                if (-not [string]::IsNullOrWhiteSpace($clearName)) {
                    if ($Global:Config.Instances.ContainsKey($clearName)) {
                        $Global:Config.Instances.Remove($clearName)
                        Save-Config
                        Write-Host "Removed path for '$clearName'." -ForegroundColor Green
                    }
                    else {
                        Write-Host "Instance not found." -ForegroundColor Yellow
                    }
                }
                Read-Host "Press Enter..."
            }
            "7" { return }
            default { }
        }
    }
}

function Show-MainMenu {
    Clear-Host

    $instancePath = Get-InstanceBackupPath
    $scanPath = if ($instancePath) { $instancePath } else { $Global:Config.GlobalBackupRoot }

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $adminTag = if ($isAdmin) { " [ADMIN]" } else { "" }

    Write-Host ""
    Write-Host "=== WSL Backup Manager $(Get-WSLBMScriptVersion)$adminTag ===" -ForegroundColor Cyan
    Write-Host "  DISTRO : $Script:CurrentDistro" -ForegroundColor Green
    $modeText = if ($Global:DryRun) { "DRY RUN" } else { "NORMAL" }
    $modeColor = if ($Global:DryRun) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Green }
    Write-Host "  MODE   : " -NoNewline -ForegroundColor DarkGray
    Write-Host $modeText -ForegroundColor $modeColor
    Write-Host "  REPO   : $scanPath" -ForegroundColor DarkGray
    Write-Host "========================================================"
    Write-Host "  [1] New Backup"
    Write-Host "  [2] List Backups"
    Write-Host "  [3] RESTORE / CLONE" -ForegroundColor Yellow
    Write-Host "  [4] BATCH DELETE" -ForegroundColor Red
    Write-Host "  [5] View Logs" -ForegroundColor Cyan
    Write-Host "  [6] Switch Distro"
    Write-Host "  [7] Settings"
    Write-Host "  [8] Diagnostics / Environment Self-Check (read-only)" -ForegroundColor Cyan
    Write-Host "  [9] Exit"
    Write-Host ""

    $choice = Read-Host "Choose"

    switch ($choice) {
        { $_ -in @("q", "Q", "9") } { exit }
        "1" { Show-NewBackupMenu }
        "2" { Get-BackupList }
        "3" { Show-RestoreMenu }
        "4" { Remove-BatchBackups }
        "5" { Show-LogsMenu }
        "6" { Select-WSLDistro -Force }
        "7" { Edit-Settings }
        "8" { Show-WSLBMDiagnostics }
        default { }
    }
}

function Show-NewBackupMenu {
    Clear-Host
    Write-Host "=== New Backup ===" -ForegroundColor Cyan
    $modeText = if ($Global:DryRun) { "DRY RUN" } else { "NORMAL" }
    $modeColor = if ($Global:DryRun) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Green }
    Write-Host "  MODE: " -NoNewline -ForegroundColor DarkGray
    Write-Host $modeText -ForegroundColor $modeColor
    Write-Host "  [1] Full System Backup (wsl --export)"
    Write-Host "  [2] User Home Backup (/home/user)"
    Write-Host "  [3] Custom Path Backup"
    Write-Host "  [0] Cancel"
    Write-Host ""

    $choice = Read-Host "Choose"

    switch ($choice) {
        { $_ -in @("q", "Q", "0") } { return }
        "1" { New-FullBackup }
        "2" { New-UserBackup }
        "3" { New-CustomBackup }
        default { return }
    }
}

# =============================================================================
# 11. Script Entry Point
# =============================================================================

Import-Config
Test-WSLAvailability
Get-WSLPathing

# .wslconfig is a global WSL2 configuration file under %USERPROFILE% and affects all WSL2 distributions.
# This script intentionally provides no automatic .wslconfig writer or menu entry.
# Any future optimization must be designed as an explicit preview/confirm flow with a visible diff.

if (-not (Test-7zInstalled)) {
    Write-Host "[FATAL] 7-Zip is required. Please install it and try again." -ForegroundColor Red
    exit
}

Select-WSLDistro

while ($true) {
    Show-MainMenu
}
