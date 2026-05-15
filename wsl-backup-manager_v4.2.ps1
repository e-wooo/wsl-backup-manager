# WSL Backup Manager v4.2
# Description: Windows PowerShell / WSL2 backup and restore utility.
# Environment: Windows 10/11 (PowerShell 5.1 & Core 7+)
# Collaboration: Claude Opus 4.7 and GPT-5.5.
# Release date: 2026-05-15
# Runtime version is defined by Get-WSLBMScriptVersion.
#
# Current Version Summary:
#   - Moves the UI and restore flow to Backup-WholeDistro / Backup-Path
#     and Restore-WholeDistro / Restore-Path.
#   - Uses folder-name type detection, supported archive selection,
#     and explicit external archive restore type selection.
#   - Splits compression choices into Compression Level and Resource Usage.
#   - Adds paginated Restore and List / Delete backup tables.
#   - Keeps mandatory Safety Net archives under .safety-net with protected
#     delete behavior and shorter list display names.
# Known Limitations:
#   - Legacy USER/CUSTOM backup folders are treated as Path backups by folder name.
#   - Restore-WholeDistro replace is destructive even with Safety Net.
#   - Restore-Path targets must be Linux absolute paths; Windows path targets are not supported.

param(
    [switch]$DryRun
)

# =============================================================================
# Global State & Initialization
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
$Script:WSLBMScriptVersion = "v4.2"
$Script:WSLBMScriptDate = "2026-05-15"
$Script:CurrentDistro = $null
$Script:WSLPathPrefix = "\\wsl.localhost"
$Script:DefaultWSLCommandTimeoutSeconds = 14400
$Script:RestoreExtractTimeoutSeconds = 14400
$Script:ReadOnlyWSLProbeTimeoutSeconds = 30
$Script:SevenZipIntegrityTimeoutSeconds = 14400
$Script:MinimumSafetyNetArchiveBytes = 16MB
$Script:MinimumSafetyNetFreeSpaceBytes = 5GB
$Script:BackupFolderNameRegex = '^\d{4}-\d{2}-\d{2}_\d{4}-(FULL|PATH|CUSTOM|USER)$'

$Global:Config = @{
    GlobalBackupRoot = (Join-Path $PSScriptRoot "Backups")
    InstallRoot      = (Join-Path $PSScriptRoot "Instances")
    SevenZipPath     = ""
    CompressionLevel = "Fast"
    ResourceUsage    = "Low"
    DiskThresholds   = @{ Full = 10; Path = 1 }
    Instances        = @{}
    RecentPaths      = @{}
}

# =============================================================================
# Security Functions
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
# Path Validation Helpers
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
    $dropboxPath = if (Test-Path -LiteralPath "$env:USERPROFILE\Dropbox" -ErrorAction SilentlyContinue) { "$env:USERPROFILE\Dropbox" } else { "" }
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
    $boundaryResult = Test-WSLBMPathClassRule -Path $Path -UsageKey "BackupRoot" -Label $Label
    if (-not $boundaryResult.Success) { $allErrors += $boundaryResult.Errors }
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
# Compression Choices & Resource Scheduler
# =============================================================================

function Convert-WSLBMLegacyCompressionProfile {
    param(
        [AllowNull()]
        [string]$CompressionProfile
    )

    switch ($CompressionProfile) {
        "Safe" {
            return [pscustomobject]@{
                CompressionLevel = "Fast"
                ResourceUsage    = "Low"
            }
        }
        "Balanced" {
            return [pscustomobject]@{
                CompressionLevel = "Balanced"
                ResourceUsage    = "Normal"
            }
        }
        "Max" {
            return [pscustomobject]@{
                CompressionLevel = "Max"
                ResourceUsage    = "High"
            }
        }
        Default { return $null }
    }
}

function Read-WSLBMCompressionLevelForBackup {
    param(
        [string]$DefaultLevel = (Get-WSLBMCompressionLevel)
    )

    if ($DefaultLevel -notin @("Fast", "Balanced", "Max")) {
        $DefaultLevel = "Fast"
    }

    while ($true) {
        Write-WSLBMHostLines -Lines @(
            $null
            @{ Text = "[Compression Level]"; Color = [ConsoleColor]::Cyan }
            "Default: $DefaultLevel"
            $null
            "[1] Fast"
            "    Faster, lower compression ratio."
            "[2] Balanced"
            "    Recommended for daily use."
            "[3] Max"
            "    Higher compression ratio, slower."
            "[Q] Cancel"
            $null
        )

        $choice = Read-Host "Choose compression level (Enter = $DefaultLevel)"
        $selectedLevel = if ([string]::IsNullOrWhiteSpace($choice)) {
            $DefaultLevel
        }
        else {
            switch ($choice) {
                "1" { "Fast" }
                "2" { "Balanced" }
                "3" { "Max" }
                { $_ -in @("q", "Q") } { return $null }
                default { "" }
            }
        }

        if ($selectedLevel -in @("Fast", "Balanced", "Max")) {
            $Global:Config.CompressionLevel = $selectedLevel
            Save-Config
            return $selectedLevel
        }

        Write-Host "Invalid compression level." -ForegroundColor Red
    }
}

function Read-WSLBMResourceUsageForBackup {
    param(
        [string]$DefaultUsage = (Get-WSLBMResourceUsage)
    )

    if ($DefaultUsage -notin @("Low", "Normal", "High")) {
        $DefaultUsage = "Low"
    }

    while ($true) {
        Write-WSLBMHostLines -Lines @(
            $null
            @{ Text = "[Resource Usage]"; Color = [ConsoleColor]::Cyan }
            "Default: $DefaultUsage"
            $null
            "[1] Low"
            "    Fewer threads, lower system impact."
            "[2] Normal"
            "    Balanced resource use."
            "[3] High"
            "    More threads, higher CPU/RAM use."
            "[Q] Cancel"
            $null
        )

        $choice = Read-Host "Choose resource usage (Enter = $DefaultUsage)"
        $selectedUsage = if ([string]::IsNullOrWhiteSpace($choice)) {
            $DefaultUsage
        }
        else {
            switch ($choice) {
                "1" { "Low" }
                "2" { "Normal" }
                "3" { "High" }
                { $_ -in @("q", "Q") } { return $null }
                default { "" }
            }
        }

        if ($selectedUsage -in @("Low", "Normal", "High")) {
            $Global:Config.ResourceUsage = $selectedUsage
            Save-Config
            return $selectedUsage
        }

        Write-Host "Invalid resource usage." -ForegroundColor Red
    }
}

function Read-WSLBMCompressionSettingsForBackup {
    param(
        [string]$DefaultLevel = (Get-WSLBMCompressionLevel),

        [string]$DefaultUsage = (Get-WSLBMResourceUsage)
    )

    $selectedLevel = Read-WSLBMCompressionLevelForBackup -DefaultLevel $DefaultLevel
    if ($null -eq $selectedLevel) {
        return $null
    }

    $selectedUsage = Read-WSLBMResourceUsageForBackup -DefaultUsage $DefaultUsage
    if ($null -eq $selectedUsage) {
        return $null
    }

    return [pscustomobject]@{
        CompressionLevel = $selectedLevel
        ResourceUsage    = $selectedUsage
    }
}

function Read-WSLBMCompressionLevelSetting {
    $selectedLevel = Read-WSLBMCompressionLevelForBackup -DefaultLevel (Get-WSLBMCompressionLevel)
    if ($null -eq $selectedLevel) {
        Write-Host "Compression Level unchanged." -ForegroundColor Yellow
        return $false
    }
    Write-Host "Compression Level updated to $selectedLevel." -ForegroundColor Green
    return $true
}

function Read-WSLBMResourceUsageSetting {
    $selectedUsage = Read-WSLBMResourceUsageForBackup -DefaultUsage (Get-WSLBMResourceUsage)
    if ($null -eq $selectedUsage) {
        Write-Host "Resource Usage unchanged." -ForegroundColor Yellow
        return $false
    }
    Write-Host "Resource Usage updated to $selectedUsage." -ForegroundColor Green
    return $true
}

function Get-WSLBM7zResourceDecision {
    <#
    .SYNOPSIS
        Calculate 7-Zip resource limits for the selected compression choices.
    .DESCRIPTION
        Checks resource pressure and reports risk without changing user choices.
    .PARAMETER Level
        Compression level (1-9).
    .OUTPUTS
        PSCustomObject with selected choices, thread count, and resource warning.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 9)]
        [int]$Level,

        [ValidateSet("Fast", "Balanced", "Max")]
        [string]$CompressionLevel = "Fast",

        [ValidateSet("Low", "Normal", "High")]
        [string]$ResourceUsage = "Low",

        [ValidateSet("WholeDistro", "Path")]
        [string]$WorkloadType = "WholeDistro"
    )

    if ($CompressionLevel -notin @("Fast", "Balanced", "Max")) {
        $CompressionLevel = "Fast"
    }
    if ($ResourceUsage -notin @("Low", "Normal", "High")) {
        $ResourceUsage = "Low"
    }

    $memCostPerThread = switch ($CompressionLevel) {
        "Balanced" { 1200; break }
        "Max" { 1800; break }
        Default { 600 }
    }
    $resourceCapThreads = switch ($ResourceUsage) {
        "Normal" { 12; break }
        "High" { 16; break }
        Default { 4 }
    }

    Write-Host "`n[Pre-flight Resource Check] $(Get-WSLBMScriptVersion)" -ForegroundColor Cyan
    Write-Host "  Compression Level : $CompressionLevel" -ForegroundColor Gray
    Write-Host "  Resource Usage    : $ResourceUsage" -ForegroundColor Gray
    Write-Host "  Workload          : $WorkloadType" -ForegroundColor Gray

    try {
        $os = Get-CimInstance Win32_OperatingSystem | Select-Object -First 1

        $totalRamMB = [math]::Round([double]$os.TotalVisibleMemorySize / 1KB)
        $freeRamMB = [math]::Round([double]$os.FreePhysicalMemory / 1KB)
        $cpuCores = [int]$env:NUMBER_OF_PROCESSORS
        if ($cpuCores -lt 1) { $cpuCores = 1 }

        if ($totalRamMB -le 0 -or $freeRamMB -le 0) {
            throw "Invalid memory values"
        }
    }
    catch {
        Write-Host "[WARN] Could not query system memory. Using CPU and Resource Usage limits only." -ForegroundColor Yellow
        $fallbackCores = [int]$env:NUMBER_OF_PROCESSORS
        if ($fallbackCores -lt 1) { $fallbackCores = 1 }
        $fallbackCpuHeadroom = switch ($ResourceUsage) {
            "Low" { 2; break }
            "Normal" { 1; break }
            Default { 0 }
        }
        $fallbackCpuLimit = $fallbackCores - $fallbackCpuHeadroom
        if ($fallbackCpuLimit -lt 1) { $fallbackCpuLimit = 1 }
        $fallbackThreads = [math]::Min($fallbackCpuLimit, $resourceCapThreads)
        if ($fallbackThreads -lt 1) { $fallbackThreads = 1 }

        Write-Host "  System RAM        : unknown" -ForegroundColor Gray
        Write-Host "  Free RAM          : unknown" -ForegroundColor Gray
        Write-Host "  Base Reserve      : unknown" -ForegroundColor Gray
        Write-Host "  Vmmem Reserve     : unknown" -ForegroundColor Gray
        Write-Host "  Available         : unknown" -ForegroundColor Gray
        Write-Host ("  Thread Cost       : ~{0} MB/thread (mx{1}, includes growth)" -f $memCostPerThread, $Level) -ForegroundColor Gray
        Write-Host ("  Limits            : RAM=unknown | CPU={0} | ResourceCap={1}" -f $fallbackCpuLimit, $resourceCapThreads) -ForegroundColor Gray
        Write-Host ("  Decision          : Using {0} thread(s)." -f $fallbackThreads) -ForegroundColor Yellow
        Write-Host "------------------------------------------------" -ForegroundColor DarkGray

        return [pscustomobject]@{
            CompressionLevel = $CompressionLevel
            ResourceUsage    = $ResourceUsage
            Threads          = [int]$fallbackThreads
            LowResource      = ($fallbackThreads -eq 1)
            Decision         = "MemoryUnknown"
        }
    }

    $baseReserveMB = switch ($ResourceUsage) {
        "Normal" { [math]::Max(($totalRamMB * 0.10), 1536); break }
        "High" { [math]::Max(($totalRamMB * 0.05), 1024); break }
        Default { [math]::Max(($totalRamMB * 0.15), 2560) }
    }

    $vmmemReserveNote = "fixed reserve"
    if ($ResourceUsage -eq "Low") {
        $vmmemReserveMB = 3072
    }
    elseif ($WorkloadType -eq "WholeDistro") {
        $vmmemReserveMB = if ($ResourceUsage -eq "High") { 2048 } else { 3072 }
        $vmmemReserveNote = "whole-distro reserve"
    }
    else {
        $vmmemBufferMB = if ($ResourceUsage -eq "High") { 256 } else { 512 }
        $vmmemMinimumMB = if ($ResourceUsage -eq "High") { 512 } else { 1024 }
        $vmmemFallbackMB = if ($ResourceUsage -eq "High") { 1024 } else { 2048 }
        $vmmemProcess = $null
        try {
            $vmmemProcess = Get-Process -Name "VmmemWSL" -ErrorAction Stop |
                Sort-Object WorkingSet64 -Descending |
                Select-Object -First 1
        }
        catch {
            $vmmemProcess = $null
        }

        if ($null -ne $vmmemProcess -and [long]$vmmemProcess.WorkingSet64 -gt 0) {
            $vmmemWorkingSetMB = [math]::Ceiling([double]$vmmemProcess.WorkingSet64 / 1MB)
            $vmmemReserveMB = [math]::Max(($vmmemWorkingSetMB + $vmmemBufferMB), $vmmemMinimumMB)
            $vmmemReserveNote = "current VmmemWSL + buffer"
        }
        else {
            $vmmemReserveMB = $vmmemFallbackMB
            $vmmemReserveNote = "fallback"
        }
    }

    $totalReserveMB = $baseReserveMB + $vmmemReserveMB
    $availableFor7zMB = $freeRamMB - $totalReserveMB
    $isLowMemory = ($availableFor7zMB -lt $memCostPerThread)

    $ramLimitThreads = [math]::Floor($availableFor7zMB / $memCostPerThread)
    if ($ramLimitThreads -lt 1) { $ramLimitThreads = 1 }

    # Keep CPU headroom for Windows and WSL.
    $cpuHeadroom = switch ($ResourceUsage) {
        "Low" { 2; break }
        "Normal" { 1; break }
        Default { 0 }
    }
    $cpuLimitThreads = $cpuCores - $cpuHeadroom
    if ($cpuLimitThreads -lt 1) { $cpuLimitThreads = 1 }

    $finalThreads = [math]::Min($ramLimitThreads, $cpuLimitThreads)
    $finalThreads = [math]::Min($finalThreads, $resourceCapThreads)
    if ($finalThreads -lt 1) { $finalThreads = 1 }
    $lowResource = ($isLowMemory -or $finalThreads -eq 1)

    Write-Host ("  System RAM        : {0}" -f (Format-Bytes ($totalRamMB * 1MB))) -ForegroundColor Gray
    Write-Host ("  Free RAM          : {0}" -f (Format-Bytes ($freeRamMB * 1MB))) -ForegroundColor Gray
    Write-Host ("  Base Reserve      : {0} (OS/Apps)" -f (Format-Bytes ($baseReserveMB * 1MB))) -ForegroundColor Gray
    Write-Host ("  Vmmem Reserve     : {0} ({1})" -f (Format-Bytes ($vmmemReserveMB * 1MB)), $vmmemReserveNote) -ForegroundColor Gray
    Write-Host ("  Available         : {0} for 7-Zip" -f (Format-Bytes ($availableFor7zMB * 1MB))) -ForegroundColor Gray
    Write-Host ("  Thread Cost       : ~{0} MB/thread (mx{1}, includes growth)" -f $memCostPerThread, $Level) -ForegroundColor Gray
    Write-Host ("  Limits            : RAM={0} | CPU={1} | ResourceCap={2}" -f $ramLimitThreads, $cpuLimitThreads, $resourceCapThreads) -ForegroundColor Gray
    Write-Host ("  Decision          : Using {0} thread(s)." -f $finalThreads) -ForegroundColor Green
    Write-Host "------------------------------------------------" -ForegroundColor DarkGray

    return [pscustomobject]@{
        CompressionLevel = $CompressionLevel
        ResourceUsage    = $ResourceUsage
        Threads          = [int]$finalThreads
        LowResource      = [bool]$lowResource
        Decision         = "UsingThreads"
    }
}

# =============================================================================
# Core Helper Functions
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

function Test-WSLBMCancelInput {
    param([AllowNull()][string]$Value)
    return ([string]::IsNullOrWhiteSpace($Value) -or $Value -in @("q", "Q", "cancel", "CANCEL"))
}

function Read-WSLBMExactConfirmation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RequiredPhrase,
        [string]$Prompt = "Confirmation"
    )
    $confirm = Read-Host $Prompt
    if (Test-WSLBMCancelInput -Value $confirm) { return "Cancelled" }
    if ($confirm -cne $RequiredPhrase) { return "Mismatch" }
    return "Confirmed"
}

function Write-WSLBMRequiredPhrasePrompt {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RequiredPhrase,
        [string]$Message = "Type the exact phrase below to continue, or Q/CANCEL to abort:"
    )
    Write-Host $Message -ForegroundColor Yellow
    Write-Host "  $RequiredPhrase" -ForegroundColor Cyan
}

function Write-WSLBMModeLine {
    param([string]$Label = "  MODE   : ")
    $modeText = if ($Global:DryRun) { "DRY RUN" } else { "NORMAL" }
    $modeColor = if ($Global:DryRun) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Green }
    Write-Host $Label -NoNewline -ForegroundColor DarkGray
    Write-Host $modeText -ForegroundColor $modeColor
}

function Write-WSLBMHostLines {
    param([AllowNull()][object[]]$Lines = @())
    foreach ($line in @($Lines)) {
        if ($null -eq $line) { Write-Host ""; continue }
        if ($line -is [string]) { Write-Host $line; continue }
        if ($null -ne $line.Color) { Write-Host ([string]$line.Text) -ForegroundColor $line.Color }
        else { Write-Host ([string]$line.Text) }
    }
}

function Show-WSLBMMenuHeader {
    param([Parameter(Mandatory = $true)][string]$Title, [ConsoleColor]$Color = [ConsoleColor]::Cyan, [switch]$NoClear)
    if (-not $NoClear) { Clear-Host }
    Write-Host "=== $Title ===" -ForegroundColor $Color
}

function New-BackupArchiveResolveResult {
    param(
        [bool]$Success,
        [bool]$Cancelled = $false,
        [string]$ArchivePath = "",
        [string]$ArchiveFormat = "",
        [string]$Reason = ""
    )
    return [pscustomobject]@{ Success = $Success; Cancelled = $Cancelled; ArchivePath = $ArchivePath; ArchiveFormat = $ArchiveFormat; Reason = $Reason }
}

function New-WSLBMNativeProcessResult {
    param(
        [bool]$Success,
        [AllowNull()]$ExitCode = $null,
        [bool]$TimedOut = $false,
        [bool]$Cancelled = $false,
        [string]$StdOut = "",
        [string]$StdErr = "",
        [string]$Output = "",
        [string]$CombinedOutput = $Output,
        [string]$ErrorMessage = "",
        [AllowNull()]$ProcessId = $null,
        [string]$ArgumentMode = "",
        [bool]$SkippedBecauseDryRun = $false,
        [string]$Description = ""
    )
    return [pscustomobject]@{
        Success              = $Success
        ExitCode             = $ExitCode
        TimedOut             = $TimedOut
        Cancelled            = $Cancelled
        StdOut               = $StdOut
        StdErr               = $StdErr
        Output               = $Output
        CombinedOutput       = $CombinedOutput
        ErrorMessage         = $ErrorMessage
        ProcessId            = $ProcessId
        ArgumentMode         = $ArgumentMode
        SkippedBecauseDryRun = $SkippedBecauseDryRun
        Description          = $Description
    }
}

function New-SafetyNetRollbackResult {
    param(
        [bool]$Completed = $false,
        [bool]$Attempted = $false,
        [bool]$SkippedBecauseDryRun = $false,
        [bool]$ManualHintNeeded = $true
    )
    return [pscustomobject]@{ Completed = $Completed; Attempted = $Attempted; SkippedBecauseDryRun = $SkippedBecauseDryRun; ManualHintNeeded = $ManualHintNeeded }
}

function Get-BackupFolderType {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupDir
    )

    $name = Split-Path -Path $BackupDir -Leaf
    if ($name -notmatch $Script:BackupFolderNameRegex) {
        return "Unknown"
    }

    if ($Matches[1] -eq "FULL") { return "WholeDistro" }
    if ($Matches[1] -in @("PATH", "CUSTOM", "USER")) { return "Path" }
    return "Unknown"
}

function Get-BackupFolderTimeFromName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupDir
    )

    $name = Split-Path -Path $BackupDir -Leaf
    if ($name -notmatch '^(\d{4}-\d{2}-\d{2}_\d{4})-(FULL|PATH|CUSTOM|USER)$') {
        return $null
    }

    try {
        return [datetime]::ParseExact(
            $Matches[1],
            "yyyy-MM-dd_HHmm",
            [Globalization.CultureInfo]::InvariantCulture
        )
    }
    catch {
        return $null
    }
}

function Get-BackupFolderTypeDisplayName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FolderType
    )

    switch ($FolderType) {
        "WholeDistro" { return "WHOLE DISTRO" }
        "Path"        { return "PATH" }
        "SafetyNet"   { return "SAFETY NET" }
        default       { return "UNKNOWN" }
    }
}

function New-RecognizedBackupFolderEntry {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.DirectoryInfo]$Directory
    )

    $folderType = Get-BackupFolderType -BackupDir $Directory.FullName
    if ($folderType -eq "Unknown") {
        return $null
    }

    $backupTime = Get-BackupFolderTimeFromName -BackupDir $Directory.FullName
    if ($null -eq $backupTime) {
        return $null
    }

    return [pscustomobject]@{
        Name            = $Directory.Name
        DisplayName     = $Directory.Name
        FullName        = $Directory.FullName
        BackupDir       = $Directory.FullName
        Type            = $folderType
        RestoreKind     = $folderType
        IsSafetyNet     = $false
        CanDelete       = $true
        LastWriteTime   = $Directory.LastWriteTime
        BackupTime      = $backupTime
        SortTime        = $backupTime
        DisplayModified = $backupTime
        Modified        = $backupTime
    }
}

function Get-SafetyNetArchiveDisplayInfo {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$Archive
    )

    $displayTime = $Archive.LastWriteTime
    $distroLabel = ""

    if ($Archive.Name -match '^SAFETY-NET-(.+)-(\d{8})-(\d{6})\.(7z|tar)$') {
        $distroLabel = $Matches[1]
        try {
            $displayTime = [datetime]::ParseExact(
                "$($Matches[2])-$($Matches[3])",
                "yyyyMMdd-HHmmss",
                [Globalization.CultureInfo]::InvariantCulture
            )
        }
        catch {
            $displayTime = $Archive.LastWriteTime
        }
    }

    $fullDisplayName = if ([string]::IsNullOrWhiteSpace($distroLabel)) {
        "Safety Net - $($displayTime.ToString("yyyy-MM-dd HH:mm"))"
    }
    else {
        "Safety Net - $distroLabel - $($displayTime.ToString("yyyy-MM-dd HH:mm"))"
    }

    $shortTime = $displayTime.ToString("HHmmss")
    $shortDisplayName = if ([string]::IsNullOrWhiteSpace($distroLabel)) {
        "SN_$shortTime"
    }
    else {
        "SN_${distroLabel}_$shortTime"
    }

    return [pscustomobject]@{
        DisplayName     = $shortDisplayName
        FullDisplayName = $fullDisplayName
        DisplayTime     = $displayTime
        DistroLabel     = $distroLabel
    }
}

function Write-SafetyNetBackupEntryDetails {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Entry
    )

    $displayName = if ($null -ne $Entry.PSObject.Properties["DisplayName"]) { [string]$Entry.DisplayName } else { [string]$Entry.Name }
    $archiveName = if ($null -ne $Entry.PSObject.Properties["ArchiveName"]) { [string]$Entry.ArchiveName } else { "" }
    $archivePath = if ($null -ne $Entry.PSObject.Properties["ArchivePath"]) { [string]$Entry.ArchivePath } else { [string]$Entry.FullName }
    $modified = if ($null -ne $Entry.PSObject.Properties["LastWriteTime"]) { [datetime]$Entry.LastWriteTime } else { [datetime]$Entry.DisplayModified }
    $created = $null

    try {
        $archiveItem = Get-Item -LiteralPath $archivePath -ErrorAction Stop
        $modified = $archiveItem.LastWriteTime
        $created = $archiveItem.CreationTime
    }
    catch {
        $created = $null
    }

    $createdText = if ($null -ne $created) { $created.ToString("yyyy-MM-dd HH:mm:ss") } else { "unknown" }
    $sizeBytes = if ($null -ne $Entry.PSObject.Properties["Length"]) { [long]$Entry.Length } else { 0 }

    Write-Host ""
    Write-Host "[Safety Net archive details]" -ForegroundColor Cyan
    Write-Host "  Display name     : $displayName" -ForegroundColor DarkGray
    Write-Host "  Full archive name: $archiveName" -ForegroundColor DarkGray
    Write-Host "  Full archive path: $archivePath" -ForegroundColor DarkGray
    Write-Host "  Modified         : $($modified.ToString("yyyy-MM-dd HH:mm:ss"))" -ForegroundColor DarkGray
    Write-Host "  Created          : $createdText" -ForegroundColor DarkGray
    Write-Host "  Size             : $(Format-Bytes $sizeBytes)" -ForegroundColor DarkGray
    Write-Host "  Type             : SAFETY NET" -ForegroundColor DarkGray
    Write-Host ""
}

function Test-WSLBMBackupEntryIsSafetyNet {
    param(
        [AllowNull()]
        [object]$Entry
    )

    return ($null -ne $Entry -and
        $null -ne $Entry.PSObject.Properties["IsSafetyNet"] -and
        [bool]$Entry.IsSafetyNet)
}

function Get-SupportedBackupArchivesFromFolder {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupDir
    )

    if (-not (Test-Path -LiteralPath $BackupDir -PathType Container)) {
        return @()
    }

    return @(Get-ChildItem -LiteralPath $BackupDir -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name.EndsWith(".7z", [System.StringComparison]::OrdinalIgnoreCase) -or
            $_.Name.EndsWith(".tar", [System.StringComparison]::OrdinalIgnoreCase)
        } |
        Sort-Object Name)
}

function Resolve-BackupArchiveFromFolder {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupDir
    )

    $archives = @(Get-SupportedBackupArchivesFromFolder -BackupDir $BackupDir)
    if ($archives.Count -eq 0) {
        return New-BackupArchiveResolveResult -Success $false -Reason "No supported archive (.7z/.tar) found in backup folder: $BackupDir"
    }

    if ($archives.Count -eq 1) {
        $format = Get-WSLBMArchiveFormatFromPath -ArchivePath $archives[0].FullName
        return New-BackupArchiveResolveResult -Success $true -ArchivePath $archives[0].FullName -ArchiveFormat $format
    }

    Write-Host ""
    Write-Host "[Select backup archive]" -ForegroundColor Cyan
    Write-Host "Backup folder: $BackupDir" -ForegroundColor DarkGray
    for ($i = 0; $i -lt $archives.Count; $i++) {
        $item = $archives[$i]
        Write-Host ("  [{0}] {1} | {2} | {3}" -f ($i + 1), $item.Name, (Format-Bytes $item.Length), $item.LastWriteTime.ToString("yyyy-MM-dd HH:mm")) -ForegroundColor Yellow
    }
    Write-Host "  [Q] Cancel"

    while ($true) {
        $choice = Read-Host "Archive"
        if ($choice -in @("q", "Q", "cancel", "CANCEL")) {
            return New-BackupArchiveResolveResult -Success $false -Cancelled $true -Reason "Cancelled."
        }
        if ($choice -match '^\d+$') {
            $idx = [int]$choice
            if ($idx -ge 1 -and $idx -le $archives.Count) {
                $selected = $archives[$idx - 1]
                $format = Get-WSLBMArchiveFormatFromPath -ArchivePath $selected.FullName
                return New-BackupArchiveResolveResult -Success $true -ArchivePath $selected.FullName -ArchiveFormat $format
            }
        }
        Write-Host "Choose a listed archive number, or Q to cancel." -ForegroundColor Red
    }
}

function Get-RecognizedBackupFolders {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScanPath
    )

    $backupEntries = @(Get-ChildItem -LiteralPath $ScanPath -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { New-RecognizedBackupFolderEntry -Directory $_ } |
        Where-Object { $null -ne $_ } |
        Sort-Object SortTime -Descending)

    $safetyEntries = @(Get-SafetyNetBackupEntries -BackupRoot $ScanPath)

    return @($backupEntries + $safetyEntries |
        Sort-Object SortTime -Descending)
}

function Get-SafetyNetBackupEntries {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupRoot
    )

    $safetyRoot = Join-Path $BackupRoot ".safety-net"
    if (-not (Test-Path -LiteralPath $safetyRoot -PathType Container -ErrorAction SilentlyContinue)) {
        return @()
    }

    $seenDisplayNames = @{}
    return @(Get-ChildItem -LiteralPath $safetyRoot -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name.EndsWith(".7z", [System.StringComparison]::OrdinalIgnoreCase) -or
            $_.Name.EndsWith(".tar", [System.StringComparison]::OrdinalIgnoreCase)
        } |
        Sort-Object LastWriteTime -Descending |
        ForEach-Object {
            $format = Get-WSLBMArchiveFormatFromPath -ArchivePath $_.FullName
            $displayInfo = Get-SafetyNetArchiveDisplayInfo -Archive $_
            $displayName = $displayInfo.DisplayName
            if ($seenDisplayNames.ContainsKey($displayName)) {
                $seenDisplayNames[$displayName]++
                $displayName = "{0}_{1}" -f $displayName, $seenDisplayNames[$displayName]
            }
            else {
                $seenDisplayNames[$displayName] = 1
            }

            [pscustomobject]@{
                Name          = $displayName
                DisplayName   = $displayName
                FullDisplayName = $displayInfo.FullDisplayName
                ArchiveName   = $_.Name
                FullName      = $_.FullName
                BackupDir     = $safetyRoot
                ArchivePath   = $_.FullName
                ArchiveFormat = $format
                Type          = "SafetyNet"
                RestoreKind   = "WholeDistro"
                IsSafetyNet   = $true
                CanDelete     = $false
                LastWriteTime = $_.LastWriteTime
                BackupTime    = $null
                SortTime      = $displayInfo.DisplayTime
                DisplayModified = $displayInfo.DisplayTime
                Modified      = $displayInfo.DisplayTime
                Length        = $_.Length
                Size          = $_.Length
                ArchiveCount  = 1
                Note          = "Safety Net"
                SourceLabel   = "Safety Net archive"
                Success       = $true
                Reason        = ""
                IsExternal    = $false
                LockTargetDir = (Get-RestoreExternalLockRootPath)
            }
        })
}

function Get-BackupPageInfo {
    param(
        [AllowNull()]
        $Backups,

        [int]$Page = 1,

        [int]$PageSize = 20
    )

    $total = if ($null -eq $Backups) { 0 } else { @($Backups).Count }
    if ($PageSize -lt 1) { $PageSize = 20 }
    $pageCount = if ($total -gt 0) { [int][math]::Ceiling($total / [double]$PageSize) } else { 1 }
    if ($Page -lt 1) { $Page = 1 }
    if ($Page -gt $pageCount) { $Page = $pageCount }

    $startIndex = if ($total -gt 0) { ($Page - 1) * $PageSize } else { 0 }
    $count = if ($total -gt 0) { [math]::Min($PageSize, $total - $startIndex) } else { 0 }
    $endIndex = if ($count -gt 0) { $startIndex + $count - 1 } else { -1 }

    return [pscustomobject]@{
        Total      = $total
        Page       = $Page
        PageSize   = $PageSize
        PageCount  = $pageCount
        StartIndex = $startIndex
        EndIndex   = $endIndex
        Count      = $count
    }
}

function Get-WSLBMBackupPagePrompt {
    param(
        [Parameter(Mandatory = $true)]
        [object]$PageInfo,

        [switch]$IncludeExternalArchive
    )

    $parts = @("Select backup number")
    if ($PageInfo.Page -lt $PageInfo.PageCount) { $parts += "[N] Next" }
    if ($PageInfo.Page -gt 1) { $parts += "[P] Previous" }
    if ($IncludeExternalArchive) { $parts += "[E] External archive" }
    $parts += "[0/Q] Cancel"
    return (($parts -join ", ") + ":")
}

function Show-BackupTable {
    param(
        $Backups,

        [int]$Page = 1,

        [int]$PageSize = 20
    )

    $pageInfo = Get-BackupPageInfo -Backups $Backups -Page $Page -PageSize $PageSize

    Write-Host "------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host("{0,-4} {1,-30} {2,-14} {3,-20} {4,-12} {5,-8} {6}" -f "#", "Folder", "Type", "Modified", "Size", "Archives", "Note") -ForegroundColor Gray
    Write-Host "------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGray

    for ($i = 0; $i -lt $pageInfo.Count; $i++) {
        $b = $Backups[$pageInfo.StartIndex + $i]

        $isSafetyNet = Test-WSLBMBackupEntryIsSafetyNet -Entry $b
        $folderType = if ($isSafetyNet) { "SafetyNet" } else { Get-BackupFolderType -BackupDir $b.FullName }
        $type = Get-BackupFolderTypeDisplayName -FolderType $folderType
        $modifiedValue = if ($null -ne $b.PSObject.Properties["DisplayModified"]) { $b.DisplayModified } else { $b.LastWriteTime }
        $date = ([datetime]$modifiedValue).ToString("yyyy-MM-dd HH:mm")

        $note = ""
        if ($isSafetyNet) {
            $note = [string]$b.Note
        }
        else {
            $notePath = Join-Path $b.FullName "note.txt"
            if (Test-Path -LiteralPath $notePath -PathType Leaf) {
                $note = (Get-Content -LiteralPath $notePath -ErrorAction SilentlyContinue | Select-Object -First 1)
            }
        }

        if ($isSafetyNet) {
            $archiveCount = 1
            $sizeStr = Format-Bytes $b.Length
        }
        else {
            $archives = @(Get-SupportedBackupArchivesFromFolder -BackupDir $b.FullName)
            $archiveCount = $archives.Count
            $sizeStr = "0 KB"
            if ($archiveCount -gt 0) {
                $sizeStr = Format-Bytes (($archives | Measure-Object -Property Length -Sum).Sum)
            }
        }

        Write-Host ("[{0,2}] " -f ($i + 1)) -NoNewline -ForegroundColor Cyan
        $displayName = if ($null -ne $b.PSObject.Properties["DisplayName"] -and -not [string]::IsNullOrWhiteSpace([string]$b.DisplayName)) {
            [string]$b.DisplayName
        }
        else {
            [string]$b.Name
        }
        Write-Host ("{0,-30} {1,-14} {2,-20} {3,-12} {4,-8} {5}" -f $displayName, $type, $date, $sizeStr, $archiveCount, $note)
    }
    Write-Host "------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGray
    if ($pageInfo.Total -gt 0) {
        $showStart = $pageInfo.StartIndex + 1
        $showEnd = $pageInfo.EndIndex + 1
        Write-Host ("  Page {0}/{1} | Showing {2}-{3} of {4}. Selection is limited to this visible page." -f $pageInfo.Page, $pageInfo.PageCount, $showStart, $showEnd, $pageInfo.Total) -ForegroundColor Yellow
        if ($pageInfo.PageCount -gt 1) {
            $pageHints = @()
            if ($pageInfo.Page -lt $pageInfo.PageCount) { $pageHints += "N for next" }
            if ($pageInfo.Page -gt 1) { $pageHints += "P for previous" }
            Write-Host ("  Use {0}." -f ($pageHints -join ", ")) -ForegroundColor Yellow
        }
    }
}

# =============================================================================
# OperationId Helpers
#     Short operation IDs used in console banners and audit logs.
# =============================================================================
$Script:CurrentOperationId = ""

function New-OperationId {
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

function Write-ReplaceRestoreDestructiveWarning {
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

        [object]$ReplacePathInfo = $null
    )

    $detectedBasePath = "<unavailable>"
    $configInstallPath = "<unavailable>"
    $manualInstallPath = ""
    $manualPathUsed = $false
    if ($null -ne $ReplacePathInfo) {
        if (-not [string]::IsNullOrWhiteSpace([string]$ReplacePathInfo.DetectedBasePath)) {
            $detectedBasePath = [string]$ReplacePathInfo.DetectedBasePath
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$ReplacePathInfo.ConfigInstallPath)) {
            $configInstallPath = [string]$ReplacePathInfo.ConfigInstallPath
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$ReplacePathInfo.ManualInstallPath)) {
            $manualInstallPath = [string]$ReplacePathInfo.ManualInstallPath
        }
        $manualPathUsed = [bool]$ReplacePathInfo.ManualPathUsed
    }
    $restoreTempRootDisplay = if ([string]::IsNullOrWhiteSpace($RestoreTempRoot)) { "<unavailable>" } else { $RestoreTempRoot }
    $safetyNetPathDisplay = if ([string]::IsNullOrWhiteSpace($SafetyNetPath)) { "<unavailable>" } else { $SafetyNetPath }

    Write-Host ""
    Write-Host "[FINAL WARNING] Restore-WholeDistro replace will unregister the existing WSL distro." -ForegroundColor Red
    Write-Host "Restore mode                             : Replace existing distro" -ForegroundColor Yellow
    Write-Host "Target distro                            : $DistroName" -ForegroundColor Yellow
    Write-Host "Install path                             : $InstallPath" -ForegroundColor Yellow
    Write-Host "Will create Safety Net                   : Yes" -ForegroundColor Yellow
    Write-Host "Required phrase                          : $RequiredPhrase" -ForegroundColor Yellow
    Write-Host "Existing BasePath detected from registry : $detectedBasePath" -ForegroundColor Yellow
    Write-Host "Config/default install path              : $configInstallPath" -ForegroundColor Yellow
    if ($detectedBasePath -ne "<unavailable>" -and
        $configInstallPath -ne "<unavailable>" -and
        -not [string]::Equals($detectedBasePath, $configInstallPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Host "[WARN] Detected existing WSL BasePath differs from configured InstallRoot default; replace restore will use the existing BasePath." -ForegroundColor Yellow
    }
    if ($manualPathUsed) {
        Write-Host "Manual installPath                       : $manualInstallPath" -ForegroundColor Yellow
        Write-Host "Manual path was used because registry BasePath was unavailable." -ForegroundColor Yellow
    }
    Write-Host "Actual installPath to be used after unregister/import: $InstallPath" -ForegroundColor Yellow
    Write-Host "Restore temp root                        : $restoreTempRootDisplay" -ForegroundColor Yellow
    Write-Host "Safety Net path                          : $safetyNetPathDisplay" -ForegroundColor Yellow
    Write-Host "Backup archive                           : $BackupFile" -ForegroundColor Yellow
    Write-Host "This is destructive: unregister happens before import." -ForegroundColor Red
    Write-Host "Safety Net and archive integrity checks must already be complete." -ForegroundColor Red
    Write-WSLBMRequiredPhrasePrompt -RequiredPhrase $RequiredPhrase
}

function Write-LogEntry {
    param(
        [string]$Level,
        [string]$Action,
        [string]$Message,
        [string]$Distro = $Script:CurrentDistro
    )

    if (-not (Test-Path -LiteralPath $Global:LogRoot)) {
        [System.IO.Directory]::CreateDirectory($Global:LogRoot) | Out-Null
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
    try { Add-Content -LiteralPath $opsLog -Value $logLine -Encoding UTF8 } catch {
        # Logging failures are intentionally non-fatal for backup/restore flows.
        $null = $_
    }
    if ($Level -eq "ERROR") {
        try { Add-Content -LiteralPath $errLog -Value $logLine -Encoding UTF8 } catch {
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
    if (-not (Test-Path -LiteralPath $path)) {
        try {
            [System.IO.Directory]::CreateDirectory($path) | Out-Null
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
    $scanPath = $Global:Config.GlobalBackupRoot
    $label = "Configured Backup Root"

    $invalidAction = "Backup list, restore, and delete scanning are blocked. Reconfigure Settings or choose a valid custom backup location."
    if (-not (Test-WSLBMBackupRootReady -Path $scanPath -Label $label -InvalidAction $invalidAction)) {
        return $null
    }

    return $scanPath
}

function Import-Config {
    $shouldSaveConfig = $false
    if (Test-Path -LiteralPath $Global:ConfigPath) {
        try {
            $json = Get-Content -LiteralPath $Global:ConfigPath -Raw | ConvertFrom-Json
            if ($json.GlobalBackupRoot) { $Global:Config.GlobalBackupRoot = $json.GlobalBackupRoot }
            if ($json.InstallRoot) { $Global:Config.InstallRoot = $json.InstallRoot }
            if ($json.SevenZipPath) { $Global:Config.SevenZipPath = $json.SevenZipPath }
            $loadedCompressionLevel = [string]$json.CompressionLevel
            $loadedResourceUsage = [string]$json.ResourceUsage
            if ($loadedCompressionLevel -in @("Fast", "Balanced", "Max")) {
                $Global:Config.CompressionLevel = $loadedCompressionLevel
            }
            if ($loadedResourceUsage -in @("Low", "Normal", "High")) {
                $Global:Config.ResourceUsage = $loadedResourceUsage
            }
            if ($loadedCompressionLevel -notin @("Fast", "Balanced", "Max") -or
                $loadedResourceUsage -notin @("Low", "Normal", "High")) {
                $shouldSaveConfig = $true
                $legacyCompressionProfile = [string]$json.CompressionProfile
                $legacyCompressionSettings = Convert-WSLBMLegacyCompressionProfile `
                    -CompressionProfile $legacyCompressionProfile
                if ($null -ne $legacyCompressionSettings) {
                    if ($loadedCompressionLevel -notin @("Fast", "Balanced", "Max")) {
                        $Global:Config.CompressionLevel = $legacyCompressionSettings.CompressionLevel
                    }
                    if ($loadedResourceUsage -notin @("Low", "Normal", "High")) {
                        $Global:Config.ResourceUsage = $legacyCompressionSettings.ResourceUsage
                    }
                }
            }
            if ($json.DiskThresholds) {
                if ($json.DiskThresholds.Full) { $Global:Config.DiskThresholds.Full = $json.DiskThresholds.Full }
                if ($json.DiskThresholds.Path) { $Global:Config.DiskThresholds.Path = $json.DiskThresholds.Path }
            }
            if ($json.Instances) {
                $Global:Config.Instances = @{}
                $json.Instances.PSObject.Properties | ForEach-Object {
                    $Global:Config.Instances[$_.Name] = @{ BackupPath = $_.Value.BackupPath }
                }
            }
            if ($json.RecentPaths) {
                $Global:Config.RecentPaths = @{}
                $json.RecentPaths.PSObject.Properties | ForEach-Object {
                    $items = @()
                    foreach ($item in @($_.Value)) {
                        if ($null -eq $item) { continue }
                        $pathText = [string]$item.Path
                        $lastUsedText = [string]$item.LastUsed
                        if (-not [string]::IsNullOrWhiteSpace($pathText)) {
                            $items += [pscustomobject]@{ Path = $pathText; LastUsed = $lastUsedText }
                        }
                    }
                    $Global:Config.RecentPaths[$_.Name] = @($items | Select-Object -First 10)
                }
            }
        }
        catch {
            Write-Host "[WARN] Config file malformed. Using defaults." -ForegroundColor Yellow
        }
    }

    $Global:Config.CompressionLevel = Get-WSLBMCompressionLevel
    $Global:Config.ResourceUsage = Get-WSLBMResourceUsage
    if ($shouldSaveConfig) {
        Save-Config
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
        -InvalidAction "It will not be created or used by default install-new restore until Settings is corrected."
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
        $configToSave = [ordered]@{
            GlobalBackupRoot      = $Global:Config.GlobalBackupRoot
            InstallRoot           = $Global:Config.InstallRoot
            SevenZipPath          = $Global:Config.SevenZipPath
            CompressionLevel      = Get-WSLBMCompressionLevel
            ResourceUsage         = Get-WSLBMResourceUsage
            DiskThresholds        = [ordered]@{
                Full = $Global:Config.DiskThresholds.Full
                Path = $Global:Config.DiskThresholds.Path
            }
            RecentPaths           = $Global:Config.RecentPaths
        }

        $configToSave | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Global:ConfigPath -Encoding UTF8
    }
    catch {
        Write-Host "[ERROR] Saving config failed." -ForegroundColor Red
    }
}

# =============================================================================
# 7z Helpers
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
# Native Output Helpers
#     Minimal text decoding for read-only probes and process error summaries.
# =============================================================================

function ConvertTo-WSLBMOutputText {
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

function Get-WSLBMFirstOutputLine {
    param(
        [AllowNull()]
        [object]$Value
    )

    $text = ConvertTo-WSLBMOutputText -Value $Value
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

function ConvertTo-WSLBMCleanOutputText {
    param(
        [AllowNull()]
        [object]$Value
    )

    $text = ConvertTo-WSLBMOutputText -Value $Value
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

function Get-WSLBMRegularOutputEncoding {
    try {
        if ($null -ne [Console]::OutputEncoding) {
            return [Console]::OutputEncoding
        }
    }
    catch {
        $null = $_
    }

    return [System.Text.Encoding]::UTF8
}

function ConvertFrom-WSLBMProbeBytesDirect {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

    $encoding = Get-WSLBMRegularOutputEncoding
    $strictEncoding = $encoding
    try {
        $strictEncoding = [System.Text.Encoding]::GetEncoding(
            $encoding.CodePage,
            [System.Text.EncoderFallback]::ExceptionFallback,
            [System.Text.DecoderFallback]::ExceptionFallback
        )
    }
    catch {
        $strictEncoding = $encoding
    }

    $decoded = $strictEncoding.GetString($Bytes)
    $cleanText = ConvertTo-WSLBMCleanOutputText -Value $decoded
    return [PSCustomObject]@{
        Text         = $cleanText
        EncodingName = $encoding.WebName
    }
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

    $directError = $null
    try {
        $directDecoded = ConvertFrom-WSLBMProbeBytesDirect -Bytes $Bytes
        return [PSCustomObject]@{
            Text          = $directDecoded.Text
            DecodeWarning = $false
            EncodingName  = $directDecoded.EncodingName
        }
    }
    catch {
        $directError = $_.Exception.Message
    }

    Write-Verbose "Output decode failed with console encoding; falling back to UTF-8/default. $directError"
    foreach ($encoding in @([System.Text.Encoding]::UTF8, [System.Text.Encoding]::Default)) {
        try {
            $cleanText = ConvertTo-WSLBMCleanOutputText -Value ($encoding.GetString($Bytes))
            if (-not [string]::IsNullOrWhiteSpace($cleanText)) {
                return [PSCustomObject]@{
                    Text          = $cleanText
                    DecodeWarning = $true
                    EncodingName  = $encoding.WebName
                }
            }
        }
        catch {
            $null = $_
        }
    }

    return [PSCustomObject]@{
        Text          = ""
        DecodeWarning = $true
        EncodingName  = ""
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
        $errorText = ConvertTo-WSLBMOutputText -Value $_.Exception.Message
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
    # Display/fallback helper only. Prefer native process ArgumentList paths
    # for code that can accept arrays.
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
            return New-WSLBMNativeProcessResult `
                -Success $false `
                -ExitCode $exitCode `
                -TimedOut $timedOut `
                -Cancelled $cancelled `
                -StdOut $stdOut `
                -StdErr $stdErr `
                -Output $combined `
                -CombinedOutput $combined `
                -ErrorMessage $errorMessage `
                -ProcessId $processId `
                -ArgumentMode $argumentMode `
                -Description $Description
        }

        if ($null -eq $exitCode) {
            $errorMessage = "Process did not report an exit code."
        }
        elseif ($exitCode -ne 0) {
            $errorMessage = "Process exited with code $exitCode."
        }

        return New-WSLBMNativeProcessResult `
            -Success ($null -ne $exitCode -and $exitCode -eq 0) `
            -ExitCode $exitCode `
            -StdOut $stdOut `
            -StdErr $stdErr `
            -Output $combined `
            -CombinedOutput $combined `
            -ErrorMessage $errorMessage `
            -ProcessId $processId `
            -ArgumentMode $argumentMode `
            -Description $Description
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-LogEntry "ERROR" $OperationName "$Description failed to start or monitor: $errorMessage" -Distro $Distro
        return New-WSLBMNativeProcessResult -Success $false -TimedOut $timedOut -Cancelled $cancelled -ErrorMessage $errorMessage -ProcessId $processId -ArgumentMode $argumentMode -Description $Description
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
    param(
        [Parameter(Mandatory = $true)]
        $gb,

        [string]$Path = ""
    )

    $path = if ([string]::IsNullOrWhiteSpace($Path)) { $Global:Config.GlobalBackupRoot } else { $Path }
    $requiredBytes = [long]([double]$gb * 1GB)
    $space = Get-WSLBMPathFreeSpaceInfo -Path $path -Label "Backup destination" -LogAction "Backup-Space" -Distro $Script:CurrentDistro
    if (-not $space.Success) {
        Write-Host "[ERROR] Cannot verify disk space for backup destination: $($space.Reason)" -ForegroundColor Red
        return $false
    }

    if ($space.AvailableBytes -lt $requiredBytes) {
        Write-Host "Low Disk Space on $($space.SourceKey)! Need $gb GB, only $(Format-Bytes $space.AvailableBytes) free." -ForegroundColor Red
        Write-LogEntry `
            "ERROR" `
            "Backup-Space" `
            "Insufficient space. Required=$(Format-Bytes $requiredBytes) | Available=$(Format-Bytes $space.AvailableBytes) | Path=$path | Source=$($space.SourceType)" `
            -Distro $Script:CurrentDistro
        return $false
    }

    Write-LogEntry `
        "INFO" `
        "Backup-Space" `
        "Disk space check passed. Required=$(Format-Bytes $requiredBytes) | Available=$(Format-Bytes $space.AvailableBytes) | Path=$path | Source=$($space.SourceType)" `
        -Distro $Script:CurrentDistro
    return $true
}

# =============================================================================
# Lock, Monitor & Cleanup
# =============================================================================

function New-LockFile {
    param(
        [string]$OperationType,
        [string]$TargetDir
    )
    $lockPath = Join-Path $TargetDir ".backup-in-progress"
    if (Test-Path -LiteralPath $lockPath) {
        Remove-Item -LiteralPath $lockPath -Force -ErrorAction SilentlyContinue
    }
    $lockContent = @"
Start: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Operation: $OperationType
User: $env:USERNAME
PID: $PID
Distro: $Script:CurrentDistro
"@
    Set-Content -LiteralPath $lockPath -Value $lockContent -Encoding UTF8
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
    if (-not $dir -or -not (Test-Path -LiteralPath $dir)) {
        return
    }

    $lockFile = Join-Path $dir ".backup-in-progress"
    if (-not (Test-Path -LiteralPath $lockFile)) {
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

# =============================================================================
# Path Logic & Selection
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
            $localizedDefaultSuffix = " (" + [char]0x9ED8 + [char]0x8BA4 + ")"
            foreach ($line in $rawList) {
                $clean = $line -replace " \(Default\)", "" -replace ([regex]::Escape($localizedDefaultSuffix)), "" -replace "`0", ""
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

function Get-BackupDestination {
    param(
        [string]$defaultName,
        [switch]$PreviewOnly
    )
    Write-Host ""
    Write-Host "Select Destination:"
    if ($PreviewOnly) {
        Write-Host "  DRY RUN: destination selection will not create directories or save defaults." -ForegroundColor Yellow
    }
    $globalPath = $Global:Config.GlobalBackupRoot
    Write-Host "  [1] Backup Root       ($globalPath)" -ForegroundColor Green
    Write-Host "  [2] Manual Location   (one-time path)" -ForegroundColor Yellow
    $valid = @("1", "2")

    while ($true) {
        $sel = Read-Host "Choose (or Q to cancel)"
        if ($sel -in @("q", "Q")) { return $null }
        if ($sel -in $valid) { break }
        Write-Host "Invalid option." -ForegroundColor Red
    }

    $finalPath = ""
    switch ($sel) {
        "1" { $finalPath = $globalPath }
        "2" { $finalPath = "__MANUAL__" }
    }

    if ($finalPath -eq "__MANUAL__") {
        $finalPath = Read-Host "Enter full path (e.g. D:\Backups\Specific)"
        if ([string]::IsNullOrWhiteSpace($finalPath)) { return $null }
        $manualValidation = Assert-WSLBMBackupRootPath -Path $finalPath -Label "Manual backup path"
        Write-WSLBMPathValidationResult -Result $manualValidation -Label "Manual backup path"
        if (-not $manualValidation.IsValid) { return $null }
        $finalPath = $finalPath.TrimEnd('\')
        if (Test-Path -LiteralPath $finalPath -PathType Leaf) {
            Write-Host "[ERROR] Manual backup path points to a file. Choose a directory." -ForegroundColor Red
            return $null
        }
        if (-not (Test-Path -LiteralPath $finalPath -PathType Container)) {
            if ($PreviewOnly) {
                Write-Host "  DRY RUN: manual destination root does not exist; would create: $finalPath" -ForegroundColor Yellow
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
        Write-Host "  Manual destination is used for this backup only." -ForegroundColor DarkGray
    }
    else {
        $selectedValidation = Assert-WSLBMBackupRootPath -Path $finalPath -Label "Selected backup destination"
        Write-WSLBMPathValidationResult -Result $selectedValidation -Label "Selected backup destination"
        if (-not $selectedValidation.IsValid) {
            Write-Host "[CONFIG ERROR] Selected backup destination is blocked. Reconfigure Settings or choose Manual Location." -ForegroundColor Red
            return $null
        }

        if (Test-Path -LiteralPath $finalPath -PathType Leaf) {
            Write-Host "[CONFIG ERROR] Selected backup destination points to a file. Reconfigure Settings or choose Manual Location." -ForegroundColor Red
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
        [string]$archiveKind,
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
        switch ($archiveKind) {
            "FULL" { 100MB }
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
        $detail = Get-WSLBMFirstOutputLine -Value $checkResult.CombinedOutput
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

function Get-WSLBMCompressionLevel {
    $configuredLevel = [string]$Global:Config.CompressionLevel
    if ($configuredLevel -notin @("Fast", "Balanced", "Max")) {
        return "Fast"
    }
    return $configuredLevel
}

function Get-WSLBMResourceUsage {
    param(
        [string]$DefaultUsage = "Low"
    )

    $configuredUsage = [string]$Global:Config.ResourceUsage
    if ($configuredUsage -notin @("Low", "Normal", "High")) {
        return $DefaultUsage
    }
    return $configuredUsage
}

function Get-WSLBMCompressionMxForLevel {
    param(
        [ValidateSet("Fast", "Balanced", "Max")]
        [string]$CompressionLevel = (Get-WSLBMCompressionLevel)
    )

    switch ($CompressionLevel) {
        "Balanced" { return 7 }
        "Max" { return 9 }
        Default { return 5 }
    }
}

function Get-WSLBM7zCompressionPlan {
    param(
        [ValidateSet("Fast", "Balanced", "Max")]
        [string]$CompressionLevel = (Get-WSLBMCompressionLevel),

        [ValidateSet("Low", "Normal", "High")]
        [string]$ResourceUsage = (Get-WSLBMResourceUsage),

        [ValidateSet("WholeDistro", "Path")]
        [string]$WorkloadType = "WholeDistro",

        [switch]$PromptForProfile
    )

    $requestedLevel = if ($CompressionLevel -in @("Fast", "Balanced", "Max")) {
        $CompressionLevel
    }
    else {
        Get-WSLBMCompressionLevel
    }
    $requestedUsage = if ($ResourceUsage -in @("Low", "Normal", "High")) {
        $ResourceUsage
    }
    else {
        Get-WSLBMResourceUsage
    }

    while ($true) {
        if ($PromptForProfile) {
            $selectedSettings = Read-WSLBMCompressionSettingsForBackup `
                -DefaultLevel (Get-WSLBMCompressionLevel) `
                -DefaultUsage (Get-WSLBMResourceUsage)
            if ($null -eq $selectedSettings) {
                Write-Host "Compression cancelled before 7-Zip started." -ForegroundColor Yellow
                return $null
            }
            $requestedLevel = $selectedSettings.CompressionLevel
            $requestedUsage = $selectedSettings.ResourceUsage
        }

        $levelValue = if ($requestedLevel -in @("Fast", "Balanced", "Max")) { $requestedLevel } else { "Fast" }
        $usageValue = if ($requestedUsage -in @("Low", "Normal", "High")) { $requestedUsage } else { "Low" }
        $mxValue = Get-WSLBMCompressionMxForLevel -CompressionLevel $levelValue
        $decision = Get-WSLBM7zResourceDecision `
            -Level $mxValue `
            -CompressionLevel $levelValue `
            -ResourceUsage $usageValue `
            -WorkloadType $WorkloadType

        if (-not $decision.LowResource) {
            $threads = [int]$decision.Threads
            break
        }

        Write-Host "[WARN] Low available memory for selected settings." -ForegroundColor Yellow
        Write-Host "Compression Level: $levelValue" -ForegroundColor Yellow
        Write-Host "Resource Usage: $usageValue" -ForegroundColor Yellow
        Write-Host "Recommended threads: $($decision.Threads)" -ForegroundColor Yellow
        Write-Host "You can continue, choose different settings, or cancel." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[1] Continue" -ForegroundColor Cyan
        Write-Host "[2] Choose again" -ForegroundColor Cyan
        Write-Host "[Q] Cancel" -ForegroundColor Cyan

        $choice = Read-Host "Choose"
        if ($choice -eq "1") {
            $threads = [int]$decision.Threads
            break
        }
        if ($choice -eq "2") {
            $PromptForProfile = $true
            continue
        }
        if ($choice -in @("q", "Q")) {
            Write-Host "Compression cancelled before 7-Zip started." -ForegroundColor Yellow
            return $null
        }

        Write-Host "Choose 1, 2, or Q." -ForegroundColor Red
    }

    return [pscustomobject]@{
        CompressionLevel = $levelValue
        ResourceUsage    = $usageValue
        Level            = [int]$mxValue
        Threads          = [int]$threads
        MxArg            = "-mx$mxValue"
        MmtArg           = "-mmt=$threads"
    }
}

function Get-WSLBMArchiveFormatFromPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArchivePath
    )

    $leaf = (Split-Path -Path $ArchivePath -Leaf).ToLowerInvariant()
    if ($leaf.EndsWith(".7z")) { return "7z" }
    if ($leaf.EndsWith(".tar")) { return "tar" }
    throw "Unsupported archive format for v4.2: $ArchivePath. Only .7z and .tar are supported."
}

function Test-RestoreArchiveIntegrity {
    param([string]$backupFile)

    Write-Host "  -> Restore Pre-flight: Running full archive integrity check (slower, safer)..." -ForegroundColor Cyan
    try {
        Test-BackupIntegrity -backupFile $backupFile -archiveKind "FULL"
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
            Write-LogEntry `
                "ERROR" `
                "Restore-SafetyNet" `
                "Safety Net archive below minimum threshold. Path=$safetyFile | Actual=$($safetyItem.Length) | Minimum=$Script:MinimumSafetyNetArchiveBytes" `
                -Distro $Script:CurrentDistro
            throw "Safety Net archive is too small. Actual=$(Format-Bytes $safetyItem.Length), minimum=$(Format-Bytes $Script:MinimumSafetyNetArchiveBytes). Path=$safetyFile"
        }

        Test-BackupIntegrity -backupFile $safetyFile -archiveKind "SAFETY-NET" -MinimumSizeBytes $Script:MinimumSafetyNetArchiveBytes
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
    Write-LogEntry `
        "INFO" `
        "Restore-SafetyNet-Space" `
        "Target=$SafetyNetPath | Estimate=$estimatedBytes | Required=$(Format-Bytes $requiredBytes) | Available=$(Format-Bytes $space.AvailableBytes) | Source=$($space.SourceType):$($space.SourceKey)" `
        -Distro $DistroName

    if ($space.AvailableBytes -lt $requiredBytes) {
        Write-Host "[ERROR] Not enough free space for Safety Net export." -ForegroundColor Red
        Write-Host "  Required : $(Format-Bytes $requiredBytes)" -ForegroundColor Yellow
        Write-Host "  Available: $(Format-Bytes $space.AvailableBytes)" -ForegroundColor Yellow
        Write-LogEntry `
            "ERROR" `
            "Restore-SafetyNet-Space" `
            "Insufficient Safety Net export space. Required=$(Format-Bytes $requiredBytes) | Available=$(Format-Bytes $space.AvailableBytes) | Path=$SafetyNetPath" `
            -Distro $DistroName
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

function New-RestoreArchiveTarEntryInfo {
    param(
        [string]$Path,
        [string]$LeafName,
        [long]$SizeBytes = 0
    )

    return [pscustomobject]@{
        Path      = $Path
        LeafName  = $LeafName
        SizeBytes = $SizeBytes
    }
}

function Resolve-RestoreWholeDistroSevenZipTarEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [string]$Distro = $Script:CurrentDistro
    )

    try {
        $null = Assert-WSLBMSevenZipArchiveInput -ArchivePath $BackupFile -Context "Restore-WholeDistro archive"
        $sevenZipExe = Resolve-WSLBMSevenZipPath
        $listResult = Invoke-WSLBMNativeProcessChecked `
            -FilePath $sevenZipExe `
            -Arguments @("l", "-slt", $BackupFile) `
            -OperationName "Restore-WholeDistro-Shape" `
            -Description "List Restore-WholeDistro archive entries" `
            -TimeoutSeconds $Script:RestoreExtractTimeoutSeconds `
            -Distro $Distro

        if ($listResult.TimedOut) {
            return [pscustomobject]@{ Success = $false; Reason = "7z list timed out while detecting WholeDistro tar entry." }
        }
        if ($listResult.Cancelled) {
            return [pscustomobject]@{ Success = $false; Reason = "7z list was cancelled while detecting WholeDistro tar entry." }
        }
        if (-not $listResult.Success) {
            return [pscustomobject]@{ Success = $false; Reason = "7z list failed while detecting WholeDistro tar entry: $($listResult.ErrorMessage)" }
        }

        $outputText = [string]$listResult.StdOut
        if ([string]::IsNullOrWhiteSpace($outputText)) {
            $outputText = [string]$listResult.CombinedOutput
        }

        $entries = @()
        $currentPath = $null
        $currentSize = [long]0
        $currentIsFolder = $false
        $insideEntries = $false
        foreach ($line in @($outputText -split "\r?\n")) {
            $text = [string]$line
            if ($text -match '^-{5,}$') {
                $insideEntries = $true
                $currentPath = $null
                $currentSize = [long]0
                $currentIsFolder = $false
                continue
            }
            if (-not $insideEntries) {
                continue
            }
            if ([string]::IsNullOrWhiteSpace($text)) {
                if (-not [string]::IsNullOrWhiteSpace($currentPath) -and -not $currentIsFolder) {
                    $entries += New-RestorePathArchiveEntryInfo -Path $currentPath -SizeBytes $currentSize -IsFolder $currentIsFolder
                }
                $currentPath = $null
                $currentSize = [long]0
                $currentIsFolder = $false
                continue
            }
            if ($text -match '^Path = (.*)$') {
                if (-not [string]::IsNullOrWhiteSpace($currentPath) -and -not $currentIsFolder) {
                    $entries += New-RestorePathArchiveEntryInfo -Path $currentPath -SizeBytes $currentSize -IsFolder $currentIsFolder
                }
                $currentPath = $Matches[1].Trim()
                $currentSize = [long]0
                $currentIsFolder = $false
                continue
            }
            if ($text -match '^Size = (\d+)$') {
                $currentSize = [long]$Matches[1]
                continue
            }
            if ($text -match '^Folder = \+$') {
                $currentIsFolder = $true
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($currentPath) -and -not $currentIsFolder) {
            $entries += New-RestorePathArchiveEntryInfo -Path $currentPath -SizeBytes $currentSize -IsFolder $currentIsFolder
        }

        $tarEntries = @()
        foreach ($entry in @($entries)) {
            $entryPath = [string]$entry.Path
            $entrySafety = Test-RestorePathArchiveEntrySafety -EntryPath $entryPath
            if (-not $entrySafety.Success) {
                return [pscustomobject]@{ Success = $false; Reason = "WholeDistro .7z tar entry path is unsafe: $($entrySafety.Reason)" }
            }

            if (-not $entryPath.TrimEnd("/", "\").EndsWith(".tar", [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }

            $entryLeaf = Split-Path -Path ($entryPath -replace '/', '\') -Leaf
            $leafSafety = Test-RestorePathArchiveEntrySafety -EntryPath $entryLeaf
            if (-not $leafSafety.Success -or -not $entryLeaf.EndsWith(".tar", [System.StringComparison]::OrdinalIgnoreCase)) {
                return [pscustomobject]@{ Success = $false; Reason = "Detected WholeDistro tar entry name is not safe to extract." }
            }

            $tarEntries += New-RestoreArchiveTarEntryInfo -Path $entryPath -LeafName $entryLeaf -SizeBytes ([long]$entry.SizeBytes)
        }

        if ($tarEntries.Count -eq 0) {
            return [pscustomobject]@{ Success = $false; Reason = "WholeDistro .7z must contain one tar export." }
        }
        if ($tarEntries.Count -eq 1) {
            return [pscustomobject]@{ Success = $true; Entry = $tarEntries[0]; Reason = "" }
        }

        Write-Host ""
        Write-Host "[WholeDistro .7z tar entries]" -ForegroundColor Cyan
        for ($i = 0; $i -lt $tarEntries.Count; $i++) {
            Write-Host ("[{0}] {1} ({2})" -f ($i + 1), $tarEntries[$i].Path, (Format-Bytes ([long]$tarEntries[$i].SizeBytes))) -ForegroundColor Yellow
        }
        Write-Host "[Q] Cancel" -ForegroundColor Yellow

        while ($true) {
            $choice = Read-Host "Select tar export to import"
            if ($choice -in @("q", "Q", "cancel", "CANCEL")) {
                return [pscustomobject]@{ Success = $false; Reason = "WholeDistro .7z contains multiple tar exports; selection was cancelled." }
            }
            if ($choice -match '^\d+$') {
                $index = [int]$choice
                if ($index -ge 1 -and $index -le $tarEntries.Count) {
                    return [pscustomobject]@{ Success = $true; Entry = $tarEntries[$index - 1]; Reason = "" }
                }
            }
            Write-Host "Choose a listed tar entry number, or Q to cancel." -ForegroundColor Red
        }
    }
    catch {
        return [pscustomobject]@{ Success = $false; Reason = $_.Exception.Message }
    }
}

function New-RestorePathArchiveShapeResult {
    param(
        [bool]$Success,
        [string]$Shape = "",
        [string]$TarEntryName = "",
        [string]$TarEntryLeafName = "",
        [long]$TarSizeBytes = -1,
        [long]$TotalSizeBytes = -1,
        [object]$TopLevelInfo = $null,
        [string]$Reason = ""
    )

    return [pscustomobject]@{
        Success          = $Success
        Shape            = $Shape
        TarEntryName     = $TarEntryName
        TarEntryLeafName = $TarEntryLeafName
        TarSizeBytes     = $TarSizeBytes
        TotalSizeBytes   = $TotalSizeBytes
        TopLevelInfo     = $TopLevelInfo
        Reason           = $Reason
    }
}

function New-RestorePathArchiveEntryInfo {
    param(
        [string]$Path,
        [long]$SizeBytes = 0,
        [bool]$IsFolder = $false
    )

    return [pscustomobject]@{
        Path      = $Path
        SizeBytes = $SizeBytes
        IsFolder  = $IsFolder
    }
}

function Test-RestorePathArchiveEntrySafety {
    param(
        [AllowEmptyString()]
        [string]$EntryPath
    )

    if ([string]::IsNullOrWhiteSpace($EntryPath)) {
        return [pscustomobject]@{ Success = $false; NormalizedPath = ""; Reason = "Archive entry path is empty." }
    }

    $normalized = ([string]$EntryPath).Trim() -replace '\\', '/'
    while ($normalized.StartsWith("./", [System.StringComparison]::Ordinal)) {
        $normalized = $normalized.Substring(2)
    }
    $normalized = $normalized.TrimEnd("/")

    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return [pscustomobject]@{ Success = $false; NormalizedPath = ""; Reason = "Archive entry path is empty." }
    }
    if ($normalized -match '[\x00-\x1F\x7F]') {
        return [pscustomobject]@{ Success = $false; NormalizedPath = $normalized; Reason = "Archive entry contains control characters." }
    }
    if ($normalized -match '^[A-Za-z]:') {
        return [pscustomobject]@{ Success = $false; NormalizedPath = $normalized; Reason = "Archive entry must not be drive-rooted." }
    }
    if ($normalized.StartsWith("/", [System.StringComparison]::Ordinal)) {
        return [pscustomobject]@{ Success = $false; NormalizedPath = $normalized; Reason = "Archive entry must not be absolute." }
    }
    if ($normalized.Contains("//")) {
        return [pscustomobject]@{ Success = $false; NormalizedPath = $normalized; Reason = "Archive entry contains an empty path segment." }
    }

    foreach ($segment in @($normalized -split "/")) {
        if ([string]::IsNullOrWhiteSpace($segment) -or $segment -in @(".", "..")) {
            return [pscustomobject]@{ Success = $false; NormalizedPath = $normalized; Reason = "Archive entry contains an unsafe path segment." }
        }
    }

    return [pscustomobject]@{ Success = $true; NormalizedPath = $normalized; Reason = "" }
}

function Get-RestorePathArchiveTopLevelInfoFromEntries {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Entries
    )

    $topLevels = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::Ordinal)
    $hasChildEntries = $false
    $hasDirectoryTopLevelEntry = $false
    $entryCount = 0

    foreach ($entry in @($Entries)) {
        $pathSafety = Test-RestorePathArchiveEntrySafety -EntryPath ([string]$entry.Path)
        if (-not $pathSafety.Success) {
            return New-WSLPathTarTopLevelInfoResult -Success $false -Reason $pathSafety.Reason
        }

        $segments = @(([string]$pathSafety.NormalizedPath) -split "/")
        if ($segments.Count -eq 0) {
            return New-WSLPathTarTopLevelInfoResult -Success $false -Reason "Archive top-level entry is empty."
        }

        $top = [string]$segments[0]
        if ([string]::IsNullOrWhiteSpace($top) -or $top -in @("/", ".", "..")) {
            return New-WSLPathTarTopLevelInfoResult -Success $false -Reason "Archive top-level entry is not safe to use as a Linux path component."
        }
        if ($top.Contains("/") -or $top.Contains("\") -or $top -match '[\x00-\x1F\x7F]') {
            return New-WSLPathTarTopLevelInfoResult -Success $false -Reason "Archive top-level entry is not safe to use as a Linux path component."
        }

        if ($segments.Count -gt 1) {
            $hasChildEntries = $true
        }
        elseif ([bool]$entry.IsFolder) {
            $hasDirectoryTopLevelEntry = $true
        }

        [void]$topLevels.Add($top)
        $entryCount++
    }

    $entries = @($topLevels)
    if ($entries.Count -eq 0 -or $entryCount -eq 0) {
        return New-WSLPathTarTopLevelInfoResult -Success $false -Reason "Archive listing is empty."
    }

    $unique = ($entries.Count -eq 1)
    $topLevelEntry = if ($unique) { [string]$entries[0] } else { "<multiple: $($entries -join ', ')>" }
    return New-WSLPathTarTopLevelInfoResult `
        -Success $true `
        -Unique $unique `
        -TopLevelEntry $topLevelEntry `
        -TopLevelEntries @($entries) `
        -HasChildEntries $hasChildEntries `
        -HasDirectoryTopLevelEntry $hasDirectoryTopLevelEntry
}

function Get-RestorePathArchiveShape {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [Parameter(Mandatory = $true)]
        [ValidateSet("7z", "tar")]
        [string]$ArchiveFormat,

        [string]$Distro = $Script:CurrentDistro
    )

    if ($ArchiveFormat -eq "tar") {
        return New-RestorePathArchiveShapeResult -Success $true -Shape "DirectTar"
    }

    try {
        $null = Assert-WSLBMSevenZipArchiveInput -ArchivePath $BackupFile -Context "Restore-Path archive"
        $sevenZipExe = Resolve-WSLBMSevenZipPath
        $listResult = Invoke-WSLBMNativeProcessChecked `
            -FilePath $sevenZipExe `
            -Arguments @("l", "-slt", $BackupFile) `
            -OperationName "Restore-Path-Shape" `
            -Description "List Restore-Path archive entries" `
            -TimeoutSeconds $Script:RestoreExtractTimeoutSeconds `
            -Distro $Distro

        if ($listResult.TimedOut) {
            return New-RestorePathArchiveShapeResult -Success $false -Reason "7z list timed out while detecting Restore-Path archive shape."
        }
        if ($listResult.Cancelled) {
            return New-RestorePathArchiveShapeResult -Success $false -Reason "7z list was cancelled while detecting Restore-Path archive shape."
        }
        if (-not $listResult.Success) {
            return New-RestorePathArchiveShapeResult -Success $false -Reason "7z list failed while detecting Restore-Path archive shape: $($listResult.ErrorMessage)"
        }

        $outputText = [string]$listResult.StdOut
        if ([string]::IsNullOrWhiteSpace($outputText)) {
            $outputText = [string]$listResult.CombinedOutput
        }

        $entries = @()
        $currentPath = $null
        $currentSize = [long]0
        $currentIsFolder = $false
        $insideEntries = $false
        foreach ($line in @($outputText -split "\r?\n")) {
            $text = [string]$line
            if ($text -match '^-{5,}$') {
                $insideEntries = $true
                $currentPath = $null
                $currentSize = [long]0
                $currentIsFolder = $false
                continue
            }
            if (-not $insideEntries) {
                continue
            }
            if ([string]::IsNullOrWhiteSpace($text)) {
                if (-not [string]::IsNullOrWhiteSpace($currentPath)) {
                    $entries += New-RestorePathArchiveEntryInfo -Path $currentPath -SizeBytes $currentSize -IsFolder $currentIsFolder
                }
                $currentPath = $null
                $currentSize = [long]0
                $currentIsFolder = $false
                continue
            }
            if ($text -match '^Path = (.*)$') {
                if (-not [string]::IsNullOrWhiteSpace($currentPath)) {
                    $entries += New-RestorePathArchiveEntryInfo -Path $currentPath -SizeBytes $currentSize -IsFolder $currentIsFolder
                }
                $currentPath = $Matches[1].Trim()
                $currentSize = [long]0
                $currentIsFolder = $false
                continue
            }
            if ($text -match '^Size = (\d+)$') {
                $currentSize = [long]$Matches[1]
                continue
            }
            if ($text -match '^Folder = \+$') {
                $currentIsFolder = $true
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($currentPath)) {
            $entries += New-RestorePathArchiveEntryInfo -Path $currentPath -SizeBytes $currentSize -IsFolder $currentIsFolder
        }

        if ($entries.Count -eq 0) {
            return New-RestorePathArchiveShapeResult -Success $false -Reason "Restore-Path .7z archive is empty or unreadable."
        }

        $totalSize = [long]0
        foreach ($entry in @($entries)) {
            $pathSafety = Test-RestorePathArchiveEntrySafety -EntryPath ([string]$entry.Path)
            if (-not $pathSafety.Success) {
                return New-RestorePathArchiveShapeResult -Success $false -Reason $pathSafety.Reason
            }
            if (-not [bool]$entry.IsFolder -and [long]$entry.SizeBytes -gt 0) {
                $totalSize += [long]$entry.SizeBytes
            }
        }

        $payloadEntries = @(
            $entries | Where-Object {
                -not [bool]$_.IsFolder
            }
        )
        $tarEntries = @(
            $payloadEntries | Where-Object {
                -not [bool]$_.IsFolder -and
                ([string]$_.Path).TrimEnd("/", "\").EndsWith(".tar", [System.StringComparison]::OrdinalIgnoreCase)
            }
        )
        $otherPayloadEntries = @(
            $payloadEntries | Where-Object {
                -not ([string]$_.Path).TrimEnd("/", "\").EndsWith(".tar", [System.StringComparison]::OrdinalIgnoreCase)
            }
        )

        if ($payloadEntries.Count -eq 1 -and $tarEntries.Count -eq 1) {
            $tarEntry = $tarEntries[0]
            $entryPath = [string]$tarEntry.Path
            $entryLeaf = Split-Path -Path ($entryPath -replace '/', '\') -Leaf
            $leafSafety = Test-RestorePathArchiveEntrySafety -EntryPath $entryLeaf
            if (-not $leafSafety.Success -or -not $entryLeaf.EndsWith(".tar", [System.StringComparison]::OrdinalIgnoreCase)) {
                return New-RestorePathArchiveShapeResult -Success $false -Reason "Detected tar entry name is not safe to extract."
            }
            return New-RestorePathArchiveShapeResult `
                -Success $true `
                -Shape "TarWrapped7z" `
                -TarEntryName $entryPath `
                -TarEntryLeafName $entryLeaf `
                -TarSizeBytes ([long]$tarEntry.SizeBytes) `
                -TotalSizeBytes $totalSize
        }
        if ($tarEntries.Count -gt 1 -and $otherPayloadEntries.Count -eq 0) {
            $tarNames = @($tarEntries | ForEach-Object { [string]$_.Path })
            return New-RestorePathArchiveShapeResult `
                -Success $false `
                -Reason "Restore-Path .7z archive contains multiple .tar entries: $($tarNames -join ', '). Select an archive with exactly one tar entry."
        }

        $topLevelInfo = Get-RestorePathArchiveTopLevelInfoFromEntries -Entries @($entries)
        if (-not $topLevelInfo.Success) {
            return New-RestorePathArchiveShapeResult -Success $false -Reason $topLevelInfo.Reason
        }

        return New-RestorePathArchiveShapeResult `
            -Success $true `
            -Shape "Direct7zTree" `
            -TotalSizeBytes $totalSize `
            -TopLevelInfo $topLevelInfo
    }
    catch {
        return New-RestorePathArchiveShapeResult -Success $false -Reason $_.Exception.Message
    }
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
            if (Test-Path -LiteralPath $candidate -PathType Container) {
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

function New-WSLBMPathRuleResult {
    param(
        [bool]$Success,
        [string]$UsageKey = "",
        [string]$Path = "",
        [string]$NormalizedPath = "",
        [string]$Root = "",
        [string]$Reason = "",
        [string]$FailedRule = "",
        [string[]]$Warnings = @(),
        [object]$RuleSet = $null
    )

    $errors = @()
    if (-not $Success -and -not [string]::IsNullOrWhiteSpace($Reason)) { $errors += $Reason }

    return [pscustomobject]@{
        Success        = $Success
        IsValid        = $Success
        UsageKey       = $UsageKey
        Path           = $Path
        NormalizedPath = $NormalizedPath
        Root           = $Root
        Reason         = $Reason
        FailedRule     = $FailedRule
        Errors         = @($errors)
        Warnings       = @($Warnings)
        RuleSet        = $RuleSet
    }
}

function New-WSLBMPathRelationRule {
    param(
        [string]$Path = "",
        [string]$Label = "Path boundary",
        [string]$Message = "",
        [string]$MissingReason = "",
        [string]$NormalizeFailurePrefix = "",
        [switch]$FailIfMissing
    )

    return [pscustomobject]@{
        Path                   = $Path
        Label                  = $Label
        Message                = $Message
        MissingReason          = $MissingReason
        NormalizeFailurePrefix = $NormalizeFailurePrefix
        FailIfMissing          = [bool]$FailIfMissing
    }
}

function Resolve-WSLBMRuleBoundaryPath {
    param([object]$Rule, [string]$DefaultLabel = "Path boundary")
    if ($null -eq $Rule -or [string]::IsNullOrWhiteSpace([string]$Rule.Path)) {
        $reason = if ($null -ne $Rule -and $Rule.FailIfMissing -and -not [string]::IsNullOrWhiteSpace([string]$Rule.MissingReason)) { [string]$Rule.MissingReason } else { "" }
        return [pscustomobject]@{ Success = $false; Missing = $true; NormalizedPath = ""; Reason = $reason }
    }
    $boundaryLabel = if ([string]::IsNullOrWhiteSpace([string]$Rule.Label)) { $DefaultLabel } else { [string]$Rule.Label }
    $resolved = Get-NormalizedWindowsPathForComparison -Path ([string]$Rule.Path) -Label $boundaryLabel
    if (-not $resolved.Success) {
        $prefix = [string]$Rule.NormalizeFailurePrefix
        $reason = if ([string]::IsNullOrWhiteSpace($prefix)) { $resolved.Reason } else { "$prefix $($resolved.Reason)" }
        return [pscustomobject]@{ Success = $false; Missing = $false; NormalizedPath = ""; Reason = $reason }
    }
    return [pscustomobject]@{ Success = $true; Missing = $false; NormalizedPath = $resolved.NormalizedPath; Reason = "" }
}

function Get-WSLBMPathClassRuleSet {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("BackupRoot", "InstallPath", "TempWorkspace", "DeleteTarget", "SafetyNetRoot", "FullBackupDirectory")]
        [string]$UsageKey,

        [string]$Label = "Path",
        [string[]]$AllowedRoots = @(),
        [string[]]$ForbiddenExactPaths = @(),
        [object[]]$ForbiddenParentRules = @(),
        [object[]]$ForbiddenChildRules = @(),
        [string]$RequiredParentPath = "",
        [string]$RequiredParentReason = "",
        [string]$ShapeRegex = "",
        [string]$ShapeRejectReason = ""
    )

    $ruleSet = [ordered]@{
        UsageKey                                      = $UsageKey
        Label                                         = $Label
        AllowUnc                                      = $false
        UncWarningMessage                             = ""
        RequireLocalDrive                             = $true
        AllowMappedNetworkDrive                       = $false
        MappedNetworkDriveReason                      = "$Label is on a mapped network drive."
        MappedNetworkDriveUnknownReasonPrefix         = "Cannot determine drive safety for ${Label}:"
        AllowDriveRoot                                = $false
        DriveRootReason                               = "$Label cannot be a drive root."
        RequireExistingDirectory                      = $false
        ExistingDirectoryReason                       = "$Label is not an existing directory."
        CheckRootReparsePoint                         = $false
        RootReparsePointReason                        = "$Label is a reparse point, junction, or symlink."
        RequireAllowedRoot                            = $false
        AllowedRoots                                  = @($AllowedRoots)
        BlockAllowedRootExact                         = $true
        AllowedRootExactReasonTemplate                = "Refusing to use a protected root itself: {0}"
        OutsideAllowedRootReason                      = "$Label is outside allowed roots."
        ForbiddenExactPaths                           = @($ForbiddenExactPaths)
        ForbiddenExactReasonTemplate                  = "$Label equals a protected boundary path: {0}"
        BlockWindowsSystemPath                        = $false
        RequireWindowsSystemBoundary                  = $false
        WindowsSystemBoundaryReason                   = "$Label cannot be the Windows system directory or one of its subdirectories."
        WindowsSystemBoundaryMissingReason            = "Cannot determine Windows system directory boundary for $Label."
        WindowsSystemBoundaryNormalizeFailureTemplate = "Cannot normalize Windows system directory boundary: {0}"
        BlockUserProfileExact                         = $false
        RequireUserProfileBoundary                    = $false
        UserProfileExactReason                        = "$Label cannot be USERPROFILE itself."
        UserProfileBoundaryMissingReason              = "Cannot determine USERPROFILE boundary for $Label."
        UserProfileBoundaryNormalizeFailureTemplate   = "Cannot normalize USERPROFILE boundary: {0}"
        WarnUserProfileChild                          = $false
        UserProfileChildWarning                       = "$Label is under USERPROFILE; ensure it is not synced, redirected, or used for personal files."
        BlockUserCommonDirectoryChild                 = $false
        UserCommonDirectoryReasonTemplate             = "$Label cannot be under USERPROFILE\{0}."
        BlockSyncFolderSegment                        = $false
        SyncFolderSegmentReasonTemplate               = "$Label appears to be under a sync folder segment: {0}"
        WarnConfiguredSyncFolder                      = $false
        ConfiguredSyncFolderWarningTemplate           = "$Label is inside a {0} folder ({1}). Sync folders may cause backup corruption."
        RequirePSScriptRootBoundary                   = $false
        BlockPSScriptRootExact                        = $false
        BlockPSScriptRootChild                        = $false
        BlockPSScriptRootParent                       = $false
        AllowPSScriptRootChildWhenUnderInstallRoot    = $false
        PSScriptRootMissingReason                     = "Cannot determine script directory boundary for $Label."
        PSScriptRootNormalizeFailureTemplate          = "Cannot normalize script directory boundary: {0}"
        PSScriptRootExactReason                       = "$Label cannot be the script directory itself."
        PSScriptRootChildReason                       = "$Label cannot be under the script directory."
        PSScriptRootParentReason                      = "$Label cannot contain the script directory."
        RequireBackupRootBoundary                     = $false
        BlockBackupRootExact                          = $false
        BlockBackupRootChild                          = $false
        BlockBackupRootParent                         = $false
        BackupRootMissingReason                       = "Cannot determine configured backup root boundary for $Label."
        BackupRootNormalizeFailureTemplate            = "Cannot normalize configured backup root: {0}"
        BackupRootExactReason                         = "$Label cannot be the configured backup root."
        BackupRootChildReason                         = "$Label cannot be under the configured backup root."
        BackupRootParentReason                        = "$Label cannot contain the configured backup root."
        RequireInstallRootBoundary                    = $false
        ValidateInstallRootIfPresent                  = $false
        BlockInstallRootExact                         = $false
        BlockInstallRootChild                         = $false
        BlockInstallRootParent                        = $false
        InstallRootMissingReason                      = "Cannot determine configured install root boundary for $Label."
        InstallRootNormalizeFailureTemplate           = "Cannot normalize configured install root boundary: {0}"
        InstallRootExactReason                        = "$Label cannot be the configured install root."
        InstallRootChildReason                        = "$Label cannot be under the configured install root."
        InstallRootParentReason                       = "$Label cannot contain the configured install root."
        RequireTempBoundary                           = $false
        BlockTempChild                                = $false
        TempBoundaryMissingReason                     = "Cannot determine TEMP boundary for $Label."
        TempBoundaryNormalizeFailureTemplate          = "Cannot normalize TEMP boundary: {0}"
        TempChildReason                               = "$Label cannot be the TEMP directory or one of its subdirectories."
        RequiredParentPath                            = $RequiredParentPath
        RequiredParentReason                          = $RequiredParentReason
        ForbiddenParentRules                          = @($ForbiddenParentRules)
        ForbiddenChildRules                           = @($ForbiddenChildRules)
        ShapeRegex                                    = $ShapeRegex
        ShapeRejectReason                             = $ShapeRejectReason
    }

    function Set-WSLBMRuleValues {
        param(
            [hashtable]$Values
        )

        foreach ($key in $Values.Keys) {
            $ruleSet[$key] = $Values[$key]
        }
    }

    switch ($UsageKey) {
        "BackupRoot" {
            Set-WSLBMRuleValues @{
                AllowUnc                   = $true
                UncWarningMessage          = "$Label is a UNC/network path. Performance and reliability may be affected."
                RequireLocalDrive          = $false
                AllowMappedNetworkDrive    = $true
                DriveRootReason            = "$Label points to a drive root ({0}). This is not allowed."
                BlockUserProfileExact      = $true
                UserProfileExactReason     = "$Label points to the user profile root ($env:USERPROFILE). This is not allowed."
                WarnConfiguredSyncFolder   = $true
            }
            foreach ($sysDir in @($env:SystemRoot, "$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", "$env:ProgramFiles", "${env:ProgramFiles(x86)}", "$env:ProgramData")) {
                if ([string]::IsNullOrWhiteSpace($sysDir)) { continue }
                $ruleSet.ForbiddenParentRules += New-WSLBMPathRelationRule -Path $sysDir -Label "System directory" -Message "$Label is inside a system directory ($sysDir). This is not allowed."
            }
        }
        "InstallPath" {
            Set-WSLBMRuleValues @{
                MappedNetworkDriveReason              = "Mapped network drives are not allowed for restore install paths."
                MappedNetworkDriveUnknownReasonPrefix = "Cannot determine drive safety for install path root '{0}':"
                DriveRootReason                       = "Drive root restore targets are not allowed."
                BlockWindowsSystemPath                = $true
                RequireWindowsSystemBoundary          = $true
                WindowsSystemBoundaryReason           = "Restore install path cannot be the Windows system directory or one of its subdirectories."
                WindowsSystemBoundaryMissingReason    = "Cannot determine Windows system directory boundary for restore install path."
                RequireTempBoundary                   = $true
                BlockTempChild                        = $true
                TempBoundaryMissingReason             = "Cannot determine TEMP boundary for restore install path."
                TempChildReason                       = "Restore install path cannot be the TEMP directory or one of its subdirectories."
                RequireUserProfileBoundary            = $true
                BlockUserProfileExact                 = $true
                UserProfileBoundaryMissingReason      = "Cannot determine USERPROFILE boundary for restore install path."
                UserProfileExactReason                = "USERPROFILE and the .wslconfig directory are not allowed as restore install targets."
                BlockUserCommonDirectoryChild         = $true
                UserCommonDirectoryReasonTemplate     = "Restore install path cannot be under USERPROFILE\{0}."
                WarnUserProfileChild                  = $true
                UserProfileChildWarning               = "Restore install path is under USERPROFILE; ensure it is not synced, redirected, or used for personal files."
                RequirePSScriptRootBoundary           = $true
                BlockPSScriptRootExact                = $true
                BlockPSScriptRootChild                = $true
                BlockPSScriptRootParent               = $true
                AllowPSScriptRootChildWhenUnderInstallRoot = $true
                PSScriptRootMissingReason             = "Cannot determine script directory boundary for restore install path."
                PSScriptRootExactReason               = "Restore install path cannot be the script directory itself."
                PSScriptRootChildReason               = "Restore install path cannot be under the script directory unless it is under the configured install root."
                PSScriptRootParentReason              = "Restore install path cannot contain the script directory."
                RequireBackupRootBoundary             = $true
                BlockBackupRootChild                  = $true
                BlockBackupRootParent                 = $true
                BackupRootMissingReason               = "Cannot determine configured backup root boundary for restore install path."
                BackupRootChildReason                 = "Restore install path cannot be under the configured backup root."
                BackupRootParentReason                = "Restore install path cannot contain the configured backup root."
                ValidateInstallRootIfPresent          = $true
                BlockSyncFolderSegment                = $true
                SyncFolderSegmentReasonTemplate       = "Restore install path appears to be under a sync folder segment: {0}."
            }
        }
        "TempWorkspace" {
            Set-WSLBMRuleValues @{
                AllowUnc                = $true
                RequireLocalDrive       = $false
                AllowMappedNetworkDrive = $true
                DriveRootReason         = "$Label cannot be a drive root."
            }
        }
        "DeleteTarget" {
            Set-WSLBMRuleValues @{
                RequireExistingDirectory              = $true
                ExistingDirectoryReason               = "Target is not an existing directory."
                MappedNetworkDriveReason              = "Mapped network drives are not allowed for backup deletion."
                MappedNetworkDriveUnknownReasonPrefix = "Cannot determine drive safety for backup delete target:"
                DriveRootReason                       = "Drive root deletion is not allowed."
                CheckRootReparsePoint                 = $true
                RootReparsePointReason                = "Backup delete target is a reparse point, junction, or symlink."
                RequireAllowedRoot                    = $true
                AllowedRootExactReasonTemplate        = "Refusing to delete a backup root itself: {0}"
                OutsideAllowedRootReason              = "Target is outside allowed backup deletion roots."
                ForbiddenExactReasonTemplate          = "Target equals a protected boundary path: {0}"
                BlockWindowsSystemPath                = $true
                WindowsSystemBoundaryReason           = "Target is under the Windows system directory."
                BlockUserProfileExact                 = $true
                UserProfileExactReason                = "Target equals a protected boundary path: {0}"
                BlockUserCommonDirectoryChild         = $true
                UserCommonDirectoryReasonTemplate     = "Target is under USERPROFILE\{0}."
                RequireInstallRootBoundary            = $false
                BlockInstallRootChild                 = $true
                InstallRootChildReason                = "Target is under the configured install root."
                BlockTempChild                        = $true
                TempChildReason                       = "Target is under the TEMP root."
                BlockSyncFolderSegment                = $true
                SyncFolderSegmentReasonTemplate       = "Target appears to be under a sync folder segment: {0}"
            }
            if ([string]::IsNullOrWhiteSpace($ruleSet.ShapeRegex)) {
                $ruleSet.ShapeRegex = $Script:BackupFolderNameRegex
                $ruleSet.ShapeRejectReason = "Directory name does not match a WSLBM generated backup name."
            }
            $forbiddenRestoreDeleteBoundaries = @(
                $env:USERPROFILE,
                $PSScriptRoot,
                $Global:Config.InstallRoot,
                $Global:Config.GlobalBackupRoot,
                (Get-RestoreSafetyNetRootPath),
                (Get-InstanceBackupPath),
                [System.IO.Path]::GetTempPath()
            )
            foreach ($forbiddenRaw in $forbiddenRestoreDeleteBoundaries) {
                if (-not [string]::IsNullOrWhiteSpace($forbiddenRaw)) { $ruleSet.ForbiddenExactPaths += $forbiddenRaw }
            }
        }
        "SafetyNetRoot" {
            Set-WSLBMRuleValues @{
                AllowUnc                   = $true
                RequireLocalDrive          = $false
                AllowMappedNetworkDrive    = $true
                RequireBackupRootBoundary  = $true
                BlockBackupRootExact       = $true
                BackupRootExactReason      = "Safety Net root cannot be the configured backup root itself."
            }
            if ([string]::IsNullOrWhiteSpace($ruleSet.RequiredParentPath)) {
                $ruleSet.RequiredParentPath = $Global:Config.GlobalBackupRoot; $ruleSet.RequiredParentReason = "Safety Net root must stay under the configured backup root."
            }
            if ([string]::IsNullOrWhiteSpace($ruleSet.ShapeRegex)) {
                $ruleSet.ShapeRegex = '^\.safety-net$'; $ruleSet.ShapeRejectReason = "Safety Net root must be the .safety-net directory."
            }
        }
        "FullBackupDirectory" {
            Set-WSLBMRuleValues @{
                AllowUnc                    = $true
                RequireLocalDrive           = $false
                AllowMappedNetworkDrive     = $true
                DriveRootReason             = "FULL backup directory cannot be a drive root."
                BlockWindowsSystemPath      = $true
                WindowsSystemBoundaryReason = "FULL backup directory cannot be under the Windows system directory."
                BlockUserProfileExact       = $true
                UserProfileExactReason      = "FULL backup directory cannot be USERPROFILE itself."
                BlockPSScriptRootExact      = $true
                PSScriptRootExactReason     = "FULL backup directory cannot be the script directory itself."
                BlockInstallRootExact       = $true
                BlockInstallRootParent      = $true
                InstallRootExactReason      = "FULL backup directory cannot be the configured install root."
                InstallRootParentReason     = "FULL backup directory cannot contain the configured install root."
            }
        }
    }

    return [pscustomobject]$ruleSet
}

function Test-WSLBMPathClassRule {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet("BackupRoot", "InstallPath", "TempWorkspace", "DeleteTarget", "SafetyNetRoot", "FullBackupDirectory")]
        [string]$UsageKey,

        [string]$Label = "Path",
        [string[]]$AllowedRoots = @(),
        [string[]]$ForbiddenExactPaths = @(),
        [object[]]$ForbiddenParentRules = @(),
        [object[]]$ForbiddenChildRules = @(),
        [string]$RequiredParentPath = "",
        [string]$RequiredParentReason = "",
        [string]$ShapeRegex = "",
        [string]$ShapeRejectReason = ""
    )

    $ruleSet = Get-WSLBMPathClassRuleSet `
        -UsageKey $UsageKey `
        -Label $Label `
        -AllowedRoots $AllowedRoots `
        -ForbiddenExactPaths $ForbiddenExactPaths `
        -ForbiddenParentRules $ForbiddenParentRules `
        -ForbiddenChildRules $ForbiddenChildRules `
        -RequiredParentPath $RequiredParentPath `
        -RequiredParentReason $RequiredParentReason `
        -ShapeRegex $ShapeRegex `
        -ShapeRejectReason $ShapeRejectReason

    function Deny-WSLBMPathClassRule {
        param(
            [string]$Reason,
            [string]$FailedRule,
            [string]$NormalizedPath = "",
            [string]$Root = ""
        )

        New-WSLBMPathRuleResult `
            -Success $false `
            -UsageKey $UsageKey `
            -Path $Path `
            -NormalizedPath $NormalizedPath `
            -Root $Root `
            -Reason $Reason `
            -FailedRule $FailedRule `
            -RuleSet $ruleSet
    }
    function Format-WSLBMRuleReason { param([string]$Template, [string]$Value) if ($Template -like '*{0}*') { return $Template -f $Value }; return $Template }
    function Resolve-WSLBMNamedBoundary {
        param(
            [string]$RawPath,
            [string]$BoundaryLabel,
            [bool]$Require,
            [string]$MissingReason,
            [string]$NormalizeFailureTemplate,
            [string]$FailedRule,
            [bool]$FailOnNormalize
        )
        if ([string]::IsNullOrWhiteSpace($RawPath)) {
            if ($Require) { return [pscustomobject]@{ Success = $false; Path = ""; Failure = (Deny-WSLBMPathClassRule -Reason $MissingReason -FailedRule $FailedRule -NormalizedPath $normalizedPath -Root $root) } }
            return [pscustomobject]@{ Success = $true; Path = ""; Failure = $null }
        }
        $resolved = Get-NormalizedWindowsPathForComparison -Path $RawPath -Label $BoundaryLabel
        if (-not $resolved.Success) {
            if ($FailOnNormalize) {
                return [pscustomobject]@{
                    Success = $false
                    Path    = ""
                    Failure = (Deny-WSLBMPathClassRule `
                            -Reason (Format-WSLBMRuleReason $NormalizeFailureTemplate $resolved.Reason) `
                            -FailedRule $FailedRule `
                            -NormalizedPath $normalizedPath `
                            -Root $root)
                }
            }
            return [pscustomobject]@{ Success = $true; Path = ""; Failure = $null }
        }
        return [pscustomobject]@{ Success = $true; Path = $resolved.NormalizedPath; Failure = $null }
    }
    function Test-WSLBMBoundaryRelation {
        param(
            [string]$BoundaryPath,
            [string]$FailedRule,
            [bool]$Exact,
            [string]$ExactReason,
            [bool]$Child,
            [string]$ChildReason,
            [bool]$Parent,
            [string]$ParentReason
        )
        if ([string]::IsNullOrWhiteSpace($BoundaryPath)) { return $null }
        if ($Exact -and $normalizedPath.Equals($BoundaryPath, $comparison)) { return Deny-WSLBMPathClassRule -Reason $ExactReason -FailedRule $FailedRule -NormalizedPath $normalizedPath -Root $root }
        if ($Child -and (Test-PathIsSameOrChild -ChildPath $normalizedPath -ParentPath $BoundaryPath)) {
            return Deny-WSLBMPathClassRule `
                -Reason $ChildReason `
                -FailedRule $FailedRule `
                -NormalizedPath $normalizedPath `
                -Root $root
        }
        if ($Parent -and (Test-PathIsSameOrChild -ChildPath $BoundaryPath -ParentPath $normalizedPath)) {
            return Deny-WSLBMPathClassRule `
                -Reason $ParentReason `
                -FailedRule $FailedRule `
                -NormalizedPath $normalizedPath `
                -Root $root
        }
        return $null
    }

    $pathResolved = Get-NormalizedWindowsPathForComparison -Path $Path -Label $Label
    if (-not $pathResolved.Success) { return Deny-WSLBMPathClassRule -Reason $pathResolved.Reason -FailedRule "Normalize" }

    $normalizedPath = $pathResolved.NormalizedPath
    $comparison = [System.StringComparison]::OrdinalIgnoreCase
    $warnings = @()
    $root = [System.IO.Path]::GetPathRoot($normalizedPath)

    if ($normalizedPath.StartsWith('\\', $comparison)) {
        if (-not $ruleSet.AllowUnc) {
            $uncReason = switch ($UsageKey) {
                "InstallPath" { "UNC or network restore targets are not allowed." }
                "DeleteTarget" { "UNC or network backup deletion targets are not allowed." }
                default { "$Label cannot be a UNC/network path." }
            }
            return Deny-WSLBMPathClassRule -Reason $uncReason -FailedRule "UNC" -NormalizedPath $normalizedPath -Root $root
        }
        if (-not [string]::IsNullOrWhiteSpace($ruleSet.UncWarningMessage)) {
            $warnings += $ruleSet.UncWarningMessage
        }
    }

    if ($ruleSet.RequireLocalDrive -and ([string]::IsNullOrWhiteSpace($root) -or $root -notmatch '^[A-Za-z]:\\')) {
        $localDriveReason = switch ($UsageKey) {
            "InstallPath" { "Install path must be on a local drive path such as D:\WSL\Instance." }
            "DeleteTarget" { "Target must be on a local drive path." }
            default { "$Label must be on a local drive path." }
        }
        return Deny-WSLBMPathClassRule -Reason $localDriveReason -FailedRule "LocalDrive" -NormalizedPath $normalizedPath -Root $root
    }

    if (-not [string]::IsNullOrWhiteSpace($root)) {
        $rootResolved = Get-NormalizedWindowsPathForComparison -Path $root -Label "$Label root"
        if (-not $rootResolved.Success) {
            return Deny-WSLBMPathClassRule -Reason $rootResolved.Reason -FailedRule "RootNormalize" -NormalizedPath $normalizedPath -Root $root
        }
        if (-not $ruleSet.AllowDriveRoot -and $normalizedPath.Equals($rootResolved.NormalizedPath, $comparison)) {
            $rootText = $rootResolved.NormalizedPath.TrimEnd([char[]]@('\', '/'))
            $driveRootReason = Format-WSLBMRuleReason $ruleSet.DriveRootReason $rootText
            return Deny-WSLBMPathClassRule -Reason $driveRootReason -FailedRule "DriveRoot" -NormalizedPath $normalizedPath -Root $rootResolved.NormalizedPath
        }
    }

    if ($ruleSet.RequireLocalDrive -and -not $ruleSet.AllowMappedNetworkDrive) {
        try {
            $driveInfo = New-Object -TypeName System.IO.DriveInfo -ArgumentList $root
            if ($driveInfo.DriveType -eq [System.IO.DriveType]::Network) {
                return Deny-WSLBMPathClassRule -Reason $ruleSet.MappedNetworkDriveReason -FailedRule "MappedNetworkDrive" -NormalizedPath $normalizedPath -Root $root
            }
        }
        catch {
            $prefix = [string]$ruleSet.MappedNetworkDriveUnknownReasonPrefix
            if ($prefix -like '*{0}*') {
                $prefix = $prefix -f $root
            }
            return Deny-WSLBMPathClassRule -Reason "$prefix $($_.Exception.Message)" -FailedRule "MappedNetworkDrive" -NormalizedPath $normalizedPath -Root $root
        }
    }

    if ($ruleSet.RequireExistingDirectory -and -not (Test-Path -LiteralPath $normalizedPath -PathType Container)) {
        return Deny-WSLBMPathClassRule -Reason $ruleSet.ExistingDirectoryReason -FailedRule "ExistingDirectory" -NormalizedPath $normalizedPath -Root $root
    }

    if ($ruleSet.CheckRootReparsePoint) {
        try {
            $targetItem = Get-Item -LiteralPath $normalizedPath -Force -ErrorAction Stop
            if (($targetItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                return Deny-WSLBMPathClassRule -Reason $ruleSet.RootReparsePointReason -FailedRule "RootReparsePoint" -NormalizedPath $normalizedPath -Root $root
            }
        }
        catch {
            $message = if ($UsageKey -eq "DeleteTarget") {
                "Cannot inspect backup delete target attributes: $($_.Exception.Message)"
            }
            else {
                "Cannot inspect ${Label} attributes: $($_.Exception.Message)"
            }
            return Deny-WSLBMPathClassRule -Reason $message -FailedRule "RootReparsePoint" -NormalizedPath $normalizedPath -Root $root
        }
    }

    $normalizedAllowedRoots = @()
    foreach ($candidateRoot in @($ruleSet.AllowedRoots)) {
        if ([string]::IsNullOrWhiteSpace($candidateRoot)) { continue }
        $rootCandidateResolved = Get-NormalizedWindowsPathForComparison -Path $candidateRoot -Label "Allowed $Label root"
        if ($rootCandidateResolved.Success) {
            $normalizedAllowedRoots += $rootCandidateResolved.NormalizedPath
        }
    }
    $normalizedAllowedRoots = @($normalizedAllowedRoots | Select-Object -Unique)
    if ($ruleSet.RequireAllowedRoot) {
        if ($normalizedAllowedRoots.Count -eq 0) {
            $reason = if ($UsageKey -eq "DeleteTarget") { "No safe backup deletion root could be determined." } else { "No safe allowed root could be determined for $Label." }
            return Deny-WSLBMPathClassRule -Reason $reason -FailedRule "AllowedRoot" -NormalizedPath $normalizedPath -Root $root
        }

        $underAllowedRoot = $false
        foreach ($allowed in $normalizedAllowedRoots) {
            if ($normalizedPath.Equals($allowed, $comparison)) {
                if ($ruleSet.BlockAllowedRootExact) {
                    return Deny-WSLBMPathClassRule -Reason ($ruleSet.AllowedRootExactReasonTemplate -f $allowed) -FailedRule "AllowedRootExact" -NormalizedPath $normalizedPath -Root $root
                }
                $underAllowedRoot = $true
                break
            }
            if (Test-PathIsSameOrChild -ChildPath $normalizedPath -ParentPath $allowed) {
                $underAllowedRoot = $true
                break
            }
        }

        if (-not $underAllowedRoot) {
            return Deny-WSLBMPathClassRule -Reason $ruleSet.OutsideAllowedRootReason -FailedRule "AllowedRoot" -NormalizedPath $normalizedPath -Root $root
        }
    }

    $windowsRootRaw = if ([string]::IsNullOrWhiteSpace($env:WINDIR)) { $env:SystemRoot } else { $env:WINDIR }
    $windowsBoundary = Resolve-WSLBMNamedBoundary `
        $windowsRootRaw `
        "Windows system directory" `
        ([bool]$ruleSet.RequireWindowsSystemBoundary) `
        $ruleSet.WindowsSystemBoundaryMissingReason `
        $ruleSet.WindowsSystemBoundaryNormalizeFailureTemplate `
        "WindowsSystemBoundary" `
        ([bool]$ruleSet.RequireWindowsSystemBoundary)
    if (-not $windowsBoundary.Success) { return $windowsBoundary.Failure }
    if ($ruleSet.BlockWindowsSystemPath -and
        -not [string]::IsNullOrWhiteSpace($windowsBoundary.Path) -and
        (Test-PathIsSameOrChild -ChildPath $normalizedPath -ParentPath $windowsBoundary.Path)) {
        return Deny-WSLBMPathClassRule `
            -Reason $ruleSet.WindowsSystemBoundaryReason `
            -FailedRule "WindowsSystemBoundary" `
            -NormalizedPath $normalizedPath `
            -Root $root
    }

    $tempBoundary = Resolve-WSLBMNamedBoundary `
        ([System.IO.Path]::GetTempPath()) `
        "TEMP root" `
        ([bool]$ruleSet.RequireTempBoundary) `
        $ruleSet.TempBoundaryMissingReason `
        $ruleSet.TempBoundaryNormalizeFailureTemplate `
        "TempBoundary" `
        ([bool]$ruleSet.RequireTempBoundary)
    if (-not $tempBoundary.Success) { return $tempBoundary.Failure }
    if ($ruleSet.BlockTempChild -and
        -not [string]::IsNullOrWhiteSpace($tempBoundary.Path) -and
        (Test-PathIsSameOrChild -ChildPath $normalizedPath -ParentPath $tempBoundary.Path)) {
        return Deny-WSLBMPathClassRule `
            -Reason $ruleSet.TempChildReason `
            -FailedRule "TempBoundary" `
            -NormalizedPath $normalizedPath `
            -Root $root
    }

    $userBoundary = Resolve-WSLBMNamedBoundary `
        $env:USERPROFILE `
        "USERPROFILE" `
        ([bool]$ruleSet.RequireUserProfileBoundary) `
        $ruleSet.UserProfileBoundaryMissingReason `
        $ruleSet.UserProfileBoundaryNormalizeFailureTemplate `
        "UserProfileBoundary" `
        ([bool]$ruleSet.RequireUserProfileBoundary)
    if (-not $userBoundary.Success) { return $userBoundary.Failure }
    if (-not [string]::IsNullOrWhiteSpace($userBoundary.Path)) {
        if ($ruleSet.BlockUserProfileExact -and $normalizedPath.Equals($userBoundary.Path, $comparison)) {
            return Deny-WSLBMPathClassRule `
                -Reason (Format-WSLBMRuleReason $ruleSet.UserProfileExactReason $userBoundary.Path) `
                -FailedRule "UserProfileBoundary" `
                -NormalizedPath $normalizedPath `
                -Root $root
        }
        if ($ruleSet.BlockUserCommonDirectoryChild) {
            foreach ($highRiskUserDir in @("Desktop", "Documents", "Downloads")) {
                $userCommonDirectory = Join-Path $userBoundary.Path $highRiskUserDir
                if (Test-PathIsSameOrChild -ChildPath $normalizedPath -ParentPath $userCommonDirectory) {
                    return Deny-WSLBMPathClassRule `
                        -Reason ($ruleSet.UserCommonDirectoryReasonTemplate -f $highRiskUserDir) `
                        -FailedRule "UserCommonDirectory" `
                        -NormalizedPath $normalizedPath `
                        -Root $root
                }
            }
        }
        if ($ruleSet.WarnUserProfileChild -and (Test-PathIsSameOrChild -ChildPath $normalizedPath -ParentPath $userBoundary.Path)) { $warnings += $ruleSet.UserProfileChildWarning }
    }

    $scriptBoundaryRequired = $ruleSet.RequirePSScriptRootBoundary -or $ruleSet.BlockPSScriptRootExact -or $ruleSet.BlockPSScriptRootChild -or $ruleSet.BlockPSScriptRootParent
    if ($scriptBoundaryRequired) {
        $scriptBoundary = Resolve-WSLBMNamedBoundary `
            $PSScriptRoot `
            "Script directory" `
            ([bool]$ruleSet.RequirePSScriptRootBoundary) `
            $ruleSet.PSScriptRootMissingReason `
            $ruleSet.PSScriptRootNormalizeFailureTemplate `
            "PSScriptRootBoundary" `
            ([bool]$ruleSet.RequirePSScriptRootBoundary)
        if (-not $scriptBoundary.Success) { return $scriptBoundary.Failure }
        $failure = Test-WSLBMBoundaryRelation `
            $scriptBoundary.Path `
            "PSScriptRootBoundary" `
            ([bool]$ruleSet.BlockPSScriptRootExact) `
            $ruleSet.PSScriptRootExactReason `
            $false `
            "" `
            ([bool]$ruleSet.BlockPSScriptRootParent) `
            $ruleSet.PSScriptRootParentReason
        if ($null -ne $failure) { return $failure }
        if ($ruleSet.BlockPSScriptRootChild -and -not [string]::IsNullOrWhiteSpace($scriptBoundary.Path) -and (Test-PathIsSameOrChild -ChildPath $normalizedPath -ParentPath $scriptBoundary.Path)) {
            $allowScriptChild = $false
            if ($ruleSet.AllowPSScriptRootChildWhenUnderInstallRoot -and -not [string]::IsNullOrWhiteSpace($Global:Config.InstallRoot)) {
                $installRootForScriptRule = Get-NormalizedWindowsPathForComparison -Path $Global:Config.InstallRoot -Label "Configured install root"
                if ($installRootForScriptRule.Success) { $allowScriptChild = Test-PathIsSameOrChild -ChildPath $normalizedPath -ParentPath $installRootForScriptRule.NormalizedPath }
                else {
                    return Deny-WSLBMPathClassRule `
                        -Reason ($ruleSet.InstallRootNormalizeFailureTemplate -f $installRootForScriptRule.Reason) `
                        -FailedRule "InstallRootBoundary" `
                        -NormalizedPath $normalizedPath `
                        -Root $root
                }
            }
            if (-not $allowScriptChild) { return Deny-WSLBMPathClassRule -Reason $ruleSet.PSScriptRootChildReason -FailedRule "PSScriptRootBoundary" -NormalizedPath $normalizedPath -Root $root }
        }
    }

    $backupBoundaryRequired = $ruleSet.RequireBackupRootBoundary -or $ruleSet.BlockBackupRootExact -or $ruleSet.BlockBackupRootChild -or $ruleSet.BlockBackupRootParent
    if ($backupBoundaryRequired) {
        $backupBoundary = Resolve-WSLBMNamedBoundary `
            $Global:Config.GlobalBackupRoot `
            "Global backup root" `
            ([bool]$ruleSet.RequireBackupRootBoundary) `
            $ruleSet.BackupRootMissingReason `
            $ruleSet.BackupRootNormalizeFailureTemplate `
            "BackupRootBoundary" `
            ([bool]$ruleSet.RequireBackupRootBoundary)
        if (-not $backupBoundary.Success) { return $backupBoundary.Failure }
        $failure = Test-WSLBMBoundaryRelation `
            $backupBoundary.Path `
            "BackupRootBoundary" `
            ([bool]$ruleSet.BlockBackupRootExact) `
            $ruleSet.BackupRootExactReason `
            ([bool]$ruleSet.BlockBackupRootChild) `
            $ruleSet.BackupRootChildReason `
            ([bool]$ruleSet.BlockBackupRootParent) `
            $ruleSet.BackupRootParentReason
        if ($null -ne $failure) { return $failure }
    }

    $installBoundaryRequired = $ruleSet.RequireInstallRootBoundary -or $ruleSet.ValidateInstallRootIfPresent -or $ruleSet.BlockInstallRootExact -or $ruleSet.BlockInstallRootChild -or $ruleSet.BlockInstallRootParent
    if ($installBoundaryRequired) {
        $installBoundary = Resolve-WSLBMNamedBoundary `
            $Global:Config.InstallRoot `
            "Configured install root" `
            ([bool]$ruleSet.RequireInstallRootBoundary) `
            $ruleSet.InstallRootMissingReason `
            $ruleSet.InstallRootNormalizeFailureTemplate `
            "InstallRootBoundary" `
            ([bool]($ruleSet.RequireInstallRootBoundary -or $ruleSet.ValidateInstallRootIfPresent))
        if (-not $installBoundary.Success) { return $installBoundary.Failure }
        $failure = Test-WSLBMBoundaryRelation `
            $installBoundary.Path `
            "InstallRootBoundary" `
            ([bool]$ruleSet.BlockInstallRootExact) `
            $ruleSet.InstallRootExactReason `
            ([bool]$ruleSet.BlockInstallRootChild) `
            $ruleSet.InstallRootChildReason `
            ([bool]$ruleSet.BlockInstallRootParent) `
            $ruleSet.InstallRootParentReason
        if ($null -ne $failure) { return $failure }
    }

    foreach ($forbiddenRaw in @($ruleSet.ForbiddenExactPaths)) {
        if ([string]::IsNullOrWhiteSpace($forbiddenRaw)) { continue }
        $forbiddenResolved = Get-NormalizedWindowsPathForComparison -Path $forbiddenRaw -Label "Forbidden $Label boundary"
        if ($forbiddenResolved.Success -and $normalizedPath.Equals($forbiddenResolved.NormalizedPath, $comparison)) {
            return Deny-WSLBMPathClassRule -Reason ($ruleSet.ForbiddenExactReasonTemplate -f $forbiddenResolved.NormalizedPath) -FailedRule "ForbiddenExact" -NormalizedPath $normalizedPath -Root $root
        }
    }

    foreach ($parentRule in @($ruleSet.ForbiddenParentRules)) {
        $parentResolved = Resolve-WSLBMRuleBoundaryPath -Rule $parentRule -DefaultLabel "Forbidden $Label parent"
        if (-not $parentResolved.Success) {
            if (-not [string]::IsNullOrWhiteSpace($parentResolved.Reason)) {
                return Deny-WSLBMPathClassRule -Reason $parentResolved.Reason -FailedRule "ForbiddenParent" -NormalizedPath $normalizedPath -Root $root
            }
            continue
        }

        if (Test-PathIsSameOrChild -ChildPath $normalizedPath -ParentPath $parentResolved.NormalizedPath) {
            return Deny-WSLBMPathClassRule -Reason ([string]$parentRule.Message) -FailedRule "ForbiddenParent" -NormalizedPath $normalizedPath -Root $root
        }
    }

    foreach ($childRule in @($ruleSet.ForbiddenChildRules)) {
        $childResolved = Resolve-WSLBMRuleBoundaryPath -Rule $childRule -DefaultLabel "Forbidden $Label child"
        if (-not $childResolved.Success) {
            if (-not [string]::IsNullOrWhiteSpace($childResolved.Reason)) {
                return Deny-WSLBMPathClassRule -Reason $childResolved.Reason -FailedRule "ForbiddenChild" -NormalizedPath $normalizedPath -Root $root
            }
            continue
        }

        if (Test-PathIsSameOrChild -ChildPath $childResolved.NormalizedPath -ParentPath $normalizedPath) {
            return Deny-WSLBMPathClassRule -Reason ([string]$childRule.Message) -FailedRule "ForbiddenChild" -NormalizedPath $normalizedPath -Root $root
        }
    }

    if ($ruleSet.WarnConfiguredSyncFolder) {
        $dropboxPath = if (Test-Path -LiteralPath "$env:USERPROFILE\Dropbox" -ErrorAction SilentlyContinue) { "$env:USERPROFILE\Dropbox" } else { "" }
        foreach ($sync in @(
                @{ Name = "OneDrive"; Path = $env:OneDrive },
                @{ Name = "OneDrive Commercial"; Path = $env:OneDriveCommercial },
                @{ Name = "Dropbox"; Path = $dropboxPath }
            )) {
            if ([string]::IsNullOrWhiteSpace([string]$sync.Path)) { continue }
            if (Test-PathIsSameOrChild -ChildPath $normalizedPath -ParentPath ([string]$sync.Path)) {
                $warnings += ($ruleSet.ConfiguredSyncFolderWarningTemplate -f $sync.Name, $sync.Path)
                break
            }
        }
    }

    if ($ruleSet.BlockSyncFolderSegment) {
        $pathSegments = $normalizedPath -split '[\\/]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        foreach ($segment in $pathSegments) {
            if ($segment -match '^(OneDrive( - .+)?|Dropbox|Google Drive|GoogleDrive|iCloudDrive|Box)$') {
                return Deny-WSLBMPathClassRule -Reason ($ruleSet.SyncFolderSegmentReasonTemplate -f $segment) -FailedRule "SyncFolderSegment" -NormalizedPath $normalizedPath -Root $root
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ruleSet.ShapeRegex)) {
        $leafName = Split-Path -Path $normalizedPath -Leaf
        if ($leafName -notmatch $ruleSet.ShapeRegex) {
            return Deny-WSLBMPathClassRule -Reason $ruleSet.ShapeRejectReason -FailedRule "ShapeRegex" -NormalizedPath $normalizedPath -Root $root
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ruleSet.RequiredParentPath)) {
        $requiredParentResolved = Get-NormalizedWindowsPathForComparison -Path $ruleSet.RequiredParentPath -Label "Required $Label parent"
        if (-not $requiredParentResolved.Success) {
            return Deny-WSLBMPathClassRule -Reason $requiredParentResolved.Reason -FailedRule "RequiredParent" -NormalizedPath $normalizedPath -Root $root
        }
        if ($normalizedPath.Equals($requiredParentResolved.NormalizedPath, $comparison) -or -not (Test-PathIsSameOrChild -ChildPath $normalizedPath -ParentPath $requiredParentResolved.NormalizedPath)) {
            $requiredParentReason = if ([string]::IsNullOrWhiteSpace($ruleSet.RequiredParentReason)) {
                "$Label must be a child of the required parent path."
            }
            else {
                $ruleSet.RequiredParentReason
            }
            return Deny-WSLBMPathClassRule -Reason $requiredParentReason -FailedRule "RequiredParent" -NormalizedPath $normalizedPath -Root $root
        }
    }

    return New-WSLBMPathRuleResult `
        -Success $true `
        -UsageKey $UsageKey `
        -Path $Path `
        -NormalizedPath $normalizedPath `
        -Root $root `
        -Warnings $warnings `
        -RuleSet $ruleSet
}

function Get-WSLDistroRegistryInfo {
    param([Parameter(Mandatory = $true)][string]$DistroName)

    $lxssRoot = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss"
    function New-WSLDistroRegistryInfoResult {
        param(
            [bool]$Success,
            [string]$RegistryKey = "",
            [string]$DistributionName = "",
            [string]$BasePathRaw = "",
            [string]$BasePath = "",
            [string]$Reason = ""
        )

        [pscustomobject]@{
            Success          = $Success
            DistroName       = $DistroName
            RegistryKey      = $RegistryKey
            DistributionName = $DistributionName
            BasePathRaw      = $BasePathRaw
            BasePath         = $BasePath
            Reason           = $Reason
        }
    }
    if ([string]::IsNullOrWhiteSpace($DistroName)) {
        return New-WSLDistroRegistryInfoResult -Success $false -Reason "Distro name is empty."
    }

    try {
        if (-not (Test-Path -LiteralPath $lxssRoot -PathType Container)) {
            return New-WSLDistroRegistryInfoResult -Success $false -Reason "WSL Lxss registry root was not found."
        }

        foreach ($key in (Get-ChildItem -LiteralPath $lxssRoot -ErrorAction Stop)) {
            $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
            $name = [string]$props.DistributionName
            if (-not [string]::Equals($name, $DistroName, [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }

            $basePathRaw = [string]$props.BasePath
            if ([string]::IsNullOrWhiteSpace($basePathRaw)) {
                return New-WSLDistroRegistryInfoResult -Success $false -RegistryKey $key.Name -DistributionName $name -Reason "Registry entry was found, but BasePath is empty."
            }

            $expandedBasePath = [Environment]::ExpandEnvironmentVariables($basePathRaw)
            $basePathResolved = Get-NormalizedWindowsPathForComparison -Path $expandedBasePath -Label "WSL registry BasePath"
            if (-not $basePathResolved.Success) {
                return New-WSLDistroRegistryInfoResult -Success $false -RegistryKey $key.Name -DistributionName $name -BasePathRaw $basePathRaw -Reason $basePathResolved.Reason
            }

            return New-WSLDistroRegistryInfoResult -Success $true -RegistryKey $key.Name -DistributionName $name -BasePathRaw $basePathRaw -BasePath $basePathResolved.NormalizedPath
        }

        return New-WSLDistroRegistryInfoResult -Success $false -Reason "No WSL registry entry matched distro '$DistroName'."
    }
    catch {
        return New-WSLDistroRegistryInfoResult -Success $false -Reason $_.Exception.Message
    }
}

function Resolve-ReplaceRestoreInstallPath {
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
        Write-Host "[Restore-WholeDistro Replace Install Path]" -ForegroundColor Cyan
        Write-Host "  Current distro name       : $DistroName" -ForegroundColor Yellow
        Write-Host "  Detected current BasePath : $($registryInfo.BasePath)" -ForegroundColor Yellow
        Write-Host "  Config/default install path: $configInstallPath" -ForegroundColor Yellow
        Write-Host "  Actual installPath to use : $selectedPath" -ForegroundColor Yellow

        if (-not [string]::IsNullOrWhiteSpace($configInstallPath) -and
            -not [string]::Equals($registryInfo.BasePath, $configInstallPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            $warning = "Detected existing WSL BasePath differs from configured InstallRoot default; replace restore will use the existing BasePath."
            Write-Host "[WARN] $warning" -ForegroundColor Yellow
            Write-LogEntry "WARN" "Restore-InstallPath" $warning -Distro $DistroName
        }

        $installPathSafety = Test-RestoreInstallPathSafety -InstallPath $selectedPath -BackupFile $BackupFile -DistroName $DistroName -Mode "Replace"
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
    Write-Host "[WARN] Replace restore will not silently use the configured/default InstallRoot path." -ForegroundColor Yellow
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
                Reason                    = "User cancelled manual replace restore install path entry."
            }
        }

        $installPathSafety = Test-RestoreInstallPathSafety -InstallPath $manualPath -BackupFile $BackupFile -DistroName $DistroName -Mode "Replace"
        if ($installPathSafety.Success) {
            Write-Host "Manual installPath accepted because registry BasePath was unavailable." -ForegroundColor Yellow
            Write-LogEntry "WARN" "Restore-InstallPath" "Manual replace restore install path accepted because registry BasePath was unavailable: $($installPathSafety.NormalizedPath)" -Distro $DistroName
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
# Delete Safety Helpers
#     Guard backup directory deletion with boundary, shape, and reparse checks.
# =============================================================================

function New-ProtectedBackupPathDeleteResult {
    param(
        [bool]$Success,
        [bool]$SkippedBecauseDryRun = $false,
        [string]$DeletedPath = "",
        [string]$Reason = "",
        [string]$FolderType = "Unknown",
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
        FolderType               = $FolderType
        HasInProgressLock        = $HasInProgressLock
        RequireInProgressLock    = $RequireInProgressLock
        FromRecognizedBackupList = $FromRecognizedBackupList
        ReparsePointScan         = $ReparsePointScan
    }
}

function Test-WSLBMBackupDirectoryShape {
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$RequireInProgressLock, [switch]$FromRecognizedBackupList)

    function New-BackupDirectoryShapeResult {
        param([bool]$Success, [string]$Reason = "", [string]$FolderType = "Unknown", [bool]$HasInProgressLock = $false)
        return New-ProtectedBackupPathDeleteResult `
            -Success $Success `
            -DeletedPath $Path `
            -Reason $Reason `
            -FolderType $FolderType `
            -HasInProgressLock $HasInProgressLock `
            -RequireInProgressLock ([bool]$RequireInProgressLock) `
            -FromRecognizedBackupList ([bool]$FromRecognizedBackupList)
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return New-BackupDirectoryShapeResult -Success $false -Reason "Target is not an existing directory."
    }

    $name = Split-Path -Path $Path -Leaf
    if ($name -notmatch $Script:BackupFolderNameRegex) {
        return New-BackupDirectoryShapeResult -Success $false -Reason "Directory name does not match a WSLBM generated backup name."
    }

    $folderType = $Matches[1]
    $lockPath = Join-Path $Path ".backup-in-progress"
    $hasLock = Test-Path -LiteralPath $lockPath -PathType Leaf

    if ($RequireInProgressLock -and (-not $hasLock)) {
        return New-BackupDirectoryShapeResult -Success $false -Reason "Failed backup cleanup requires .backup-in-progress." -FolderType $folderType -HasInProgressLock $hasLock
    }

    if ($hasLock) {
        return New-BackupDirectoryShapeResult -Success $true -FolderType $folderType -HasInProgressLock $hasLock
    }

    if (-not $FromRecognizedBackupList) {
        return New-BackupDirectoryShapeResult -Success $false -Reason "Directory was not marked as coming from the recognized backup list." -FolderType $folderType -HasInProgressLock $hasLock
    }

    $archives = @(Get-SupportedBackupArchivesFromFolder -BackupDir $Path)
    if ($archives.Count -gt 0) {
        return New-BackupDirectoryShapeResult -Success $true -FolderType $folderType -HasInProgressLock $hasLock
    }

    return New-BackupDirectoryShapeResult -Success $false -Reason "Backup directory does not contain a supported archive (.7z/.tar)." -FolderType $folderType -HasInProgressLock $hasLock
}

function Test-BackupDirectoryReparsePointSafety {
    # This scan targets ReparsePoint entries such as junctions, directory symlinks, and mount points.
    # It does not expand ordinary hard link files and is only a backup-delete boundary check,
    # not a general proof that arbitrary directory deletion is safe.
    param([Parameter(Mandatory = $true)][string]$Path, [int]$MaxReportedPaths = 10)

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
            [string]$FolderType = "Unknown",
            [bool]$HasInProgressLock = $false,
            [object]$ReparsePointScan = $null
        )

        Write-Host "[WARN] Backup directory delete blocked: $Message" -ForegroundColor Yellow
        Write-LogEntry "WARN" "Delete-Blocked" "Mode=$Mode | $Message | Path=$NormalizedPath | Reason=$Reason" -Distro $Distro
        return New-ProtectedBackupPathDeleteResult `
            -Success $false `
            -DeletedPath $NormalizedPath `
            -Reason $Message `
            -FolderType $FolderType `
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
        Write-Host ("     Folder type              : {0}" -f $Shape.FolderType) -ForegroundColor DarkGray
        Write-Host ("     Has .backup-in-progress  : {0}" -f $Shape.HasInProgressLock) -ForegroundColor DarkGray
        Write-Host ("     Directory shape          : Passed" ) -ForegroundColor DarkGray
        Write-Host ("     Reparse scan             : {0}" -f $scanStatus) -ForegroundColor DarkGray
        Write-Host "     Reparse scan scope       : ReparsePoint-only; hard link files are not expanded." -ForegroundColor DarkGray
        Write-Host ("     Reparse point found      : {0}" -f $ReparsePointScan.HasReparsePoint) -ForegroundColor DarkGray
        Write-Host ("     Scanned directories      : {0}" -f $ReparsePointScan.ScannedDirectories) -ForegroundColor DarkGray
        Write-Host ("     Scanned items            : {0}" -f $ReparsePointScan.ScannedItems) -ForegroundColor DarkGray
        Write-Host ("     First reparse path       : {0}" -f $firstReparsePath) -ForegroundColor DarkGray
        Write-Host ("     Scan reason              : {0}" -f $scanReason) -ForegroundColor DarkGray

        $deleteAuditMessage = @(
            "Mode=$Mode"
            "Target=$TargetPath"
            "DryRun=$([bool]$Global:DryRun)"
            "FromRecognizedBackupList=$([bool]$FromRecognizedBackupList)"
            "RequireInProgressLock=$([bool]$RequireInProgressLock)"
            "FolderType=$($Shape.FolderType)"
            "HasInProgressLock=$($Shape.HasInProgressLock)"
            "ReparseScan=$scanStatus"
            "ReparseScanScope=ReparsePoint-only; hard link files are not expanded."
            "HasReparsePoint=$($ReparsePointScan.HasReparsePoint)"
            "ScannedDirectories=$($ReparsePointScan.ScannedDirectories)"
            "ScannedItems=$($ReparsePointScan.ScannedItems)"
            "FirstReparsePath=$firstReparsePath"
            "ScanReason=$scanReason"
            "Reason=$Reason"
        ) -join " | "

        Write-LogEntry "INFO" "Delete-Audit" $deleteAuditMessage -Distro $Distro
    }

    $candidateAllowedRoots = if ($Mode -eq "FailedBackupCleanup") {
        @($AllowedRoot)
    }
    else {
        @($Global:Config.GlobalBackupRoot, $AllowedRoot)
    }

    $deleteForbiddenExactPaths = @($AllowedRoot)
    $deleteRule = Test-WSLBMPathClassRule `
        -Path $Path `
        -UsageKey "DeleteTarget" `
        -Label "Backup delete target" `
        -AllowedRoots $candidateAllowedRoots `
        -ForbiddenExactPaths $deleteForbiddenExactPaths
    $targetForDeny = if ([string]::IsNullOrWhiteSpace($deleteRule.NormalizedPath)) { $Path } else { $deleteRule.NormalizedPath }
    if (-not $deleteRule.Success) {
        return Deny-ProtectedBackupPathDelete -Message $deleteRule.Reason -NormalizedPath $targetForDeny
    }

    $target = $deleteRule.NormalizedPath

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
            -FolderType $shape.FolderType `
            -HasInProgressLock $shape.HasInProgressLock `
            -ReparsePointScan $reparsePointScan
    }

    if ($Global:DryRun) {
        Write-Host "DRY RUN: would delete backup directory: $target" -ForegroundColor Yellow
        Write-LogEntry `
            "INFO" `
            "Delete-DryRun" `
            "Mode=$Mode | Would delete backup directory: $target | FolderType=$($shape.FolderType) | HasInProgressLock=$($shape.HasInProgressLock) | ReparseScan=Passed | Reason=$Reason" `
            -Distro $Distro
        return New-ProtectedBackupPathDeleteResult `
            -Success $true `
            -SkippedBecauseDryRun $true `
            -DeletedPath $target `
            -FolderType $shape.FolderType `
            -HasInProgressLock $shape.HasInProgressLock `
            -RequireInProgressLock ([bool]$RequireInProgressLock) `
            -FromRecognizedBackupList ([bool]$FromRecognizedBackupList) `
            -ReparsePointScan $reparsePointScan
    }

    Write-Host "  Deleting backup directory: $target" -ForegroundColor DarkGray
    Write-LogEntry "WARN" "Delete" "Mode=$Mode | Deleting backup directory: $target | FolderType=$($shape.FolderType) | HasInProgressLock=$($shape.HasInProgressLock) | ReparseScan=Passed | Reason=$Reason" -Distro $Distro

    try {
        Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop
        Write-LogEntry "INFO" "Delete" "Mode=$Mode | Removed backup directory: $target" -Distro $Distro
        return New-ProtectedBackupPathDeleteResult `
            -Success $true `
            -DeletedPath $target `
            -FolderType $shape.FolderType `
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
            -FolderType $shape.FolderType `
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

    $backupDir = Split-Path -Path $BackupFile -Parent
    $backupDirParentRule = New-WSLBMPathRelationRule `
        -Path $backupDir `
        -Label "Backup file directory" `
        -Message "Restore install path cannot be the backup file directory or one of its subdirectories." `
        -MissingReason "Cannot determine backup file directory for restore path safety check." `
        -NormalizeFailurePrefix "Cannot normalize backup file directory:" `
        -FailIfMissing
    $backupDirChildRule = New-WSLBMPathRelationRule `
        -Path $backupDir `
        -Label "Backup file directory" `
        -Message "Restore install path cannot contain the backup file directory." `
        -MissingReason "Cannot determine backup file directory for restore path safety check." `
        -NormalizeFailurePrefix "Cannot normalize backup file directory:" `
        -FailIfMissing

    $installRule = Test-WSLBMPathClassRule `
        -Path $InstallPath `
        -UsageKey "InstallPath" `
        -Label "Install path" `
        -ForbiddenParentRules @($backupDirParentRule) `
        -ForbiddenChildRules @($backupDirChildRule)
    if (-not $installRule.Success) {
        return New-InstallPathFailure -Reason $installRule.Reason
    }

    $install = $installRule.NormalizedPath
    foreach ($warning in @($installRule.Warnings)) {
        Write-Host "[WARN] $warning" -ForegroundColor Yellow
        if ($warning -like "Restore install path is under USERPROFILE*") {
            Write-LogEntry "WARN" "Restore-PathSafety" "Mode=$Mode | InstallPath under USERPROFILE allowed with warning: $install" -Distro $DistroName
        }
        else {
            Write-LogEntry "WARN" "Restore-PathSafety" "Mode=$Mode | $warning | InstallPath=$install" -Distro $DistroName
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

        [string]$Distro = $Script:CurrentDistro,

        [switch]$SkipBackupDirCandidate
    )

    $null = $SkipBackupDirCandidate

    $installResolved = Get-NormalizedWindowsPathForComparison -Path $InstallPath -Label "Restore install path"
    if (-not $installResolved.Success) {
        throw "Cannot determine restore temp root because install path is unsafe: $($installResolved.Reason)"
    }

    $operationId = Get-RestoreTempOperationId
    $candidates = New-RestoreTempCandidateParents -OperationId $operationId -Distro $Distro
    foreach ($candidate in $candidates) {
        $candidate | Add-Member -NotePropertyName InstallPath -NotePropertyValue $installResolved.NormalizedPath -Force
    }

    return @($candidates)
}

function Get-RestoreTempOperationId {
    if ([string]::IsNullOrWhiteSpace($Script:CurrentOperationId)) {
        $Script:CurrentOperationId = New-OperationId
    }
    return $Script:CurrentOperationId
}

function New-RestoreTempCandidateParents {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OperationId,

        [string]$Distro = $Script:CurrentDistro
    )

    $candidates = @()

    $backupRootReady = Assert-WSLBMBackupRootPath -Path $Global:Config.GlobalBackupRoot -Label "Restore temp Backup Root"
    if ($backupRootReady.IsValid) {
        $backupRootResolved = Get-NormalizedWindowsPathForComparison -Path $Global:Config.GlobalBackupRoot -Label "Restore temp Backup Root"
        if ($backupRootResolved.Success) {
            $candidates += [pscustomobject]@{
                ParentRoot     = $backupRootResolved.NormalizedPath
                TempDirPrefix  = ".tmp\restore-$OperationId"
                Source         = "BackupRootTmp"
                Warning        = ""
                UsedSystemTemp = $false
            }
        }
    }
    else {
        Write-LogEntry "WARN" "Restore-TempRoot" "Configured Backup Root is not usable as restore temp parent: $($backupRootReady.Errors -join ' ')" -Distro $Distro
    }

    $userTempRaw = [System.IO.Path]::GetTempPath()
    if (-not [string]::IsNullOrWhiteSpace($userTempRaw)) {
        $userTempResolved = Get-NormalizedWindowsPathForComparison -Path $userTempRaw -Label "User TEMP root"
        if ($userTempResolved.Success) {
            $userProfileResolved = Get-NormalizedWindowsPathForComparison -Path $env:USERPROFILE -Label "USERPROFILE"
            if ($userProfileResolved.Success -and $userTempResolved.NormalizedPath.Equals($userProfileResolved.NormalizedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
                Write-LogEntry "WARN" "Restore-TempRoot" "Skipping user TEMP fallback because it resolves to USERPROFILE root: $($userTempResolved.NormalizedPath)" -Distro $Distro
            }
            else {
                $candidates += [pscustomobject]@{
                    ParentRoot     = $userTempResolved.NormalizedPath
                    TempDirPrefix  = "wsl-backup-manager\restore-$OperationId"
                    Source         = "UserTempToolRoot"
                    Warning        = "Restore temp fallback: user TEMP tool directory selected because Backup Root .tmp is not safe for this archive."
                    UsedSystemTemp = $true
                }
            }
        }
    }

    return @($candidates)
}

function New-RestoreTempForbiddenParentRules {
    param(
        [string]$BackupFile = "",
        [string]$InstallPath = ""
    )

    $rules = @()

    if (-not [string]::IsNullOrWhiteSpace($BackupFile)) {
        $backupDirRaw = Split-Path -Path $BackupFile -Parent
        if (-not [string]::IsNullOrWhiteSpace($backupDirRaw)) {
            $rules += New-WSLBMPathRelationRule `
                -Path $backupDirRaw `
                -Label "Restore archive directory" `
                -Message "Restore temp workspace cannot be under the selected archive directory."
        }
    }

    $safetyRoot = Get-RestoreSafetyNetRootPath
    if (-not [string]::IsNullOrWhiteSpace($safetyRoot)) {
        $rules += New-WSLBMPathRelationRule `
            -Path $safetyRoot `
            -Label "Safety Net root" `
            -Message "Restore temp workspace cannot be under .safety-net."
    }

    if (-not [string]::IsNullOrWhiteSpace($InstallPath)) {
        $rules += New-WSLBMPathRelationRule `
            -Path $InstallPath `
            -Label "Restore install path" `
            -Message "Restore temp workspace cannot be under the target install path."
    }

    if (-not [string]::IsNullOrWhiteSpace($Global:Config.InstallRoot)) {
        $rules += New-WSLBMPathRelationRule `
            -Path $Global:Config.InstallRoot `
            -Label "Configured install root" `
            -Message "Restore temp workspace cannot be under the configured install root."
    }

    foreach ($sysDir in @($env:SystemRoot, "$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", "$env:ProgramFiles", "${env:ProgramFiles(x86)}", "$env:ProgramData")) {
        if ([string]::IsNullOrWhiteSpace($sysDir)) { continue }
        $rules += New-WSLBMPathRelationRule `
            -Path $sysDir `
            -Label "Protected restore temp boundary" `
            -Message "Restore temp workspace cannot be under a system directory."
    }

    return @($rules)
}

function New-ControlledRestoreTempPathInfo {
    param(
        [Parameter(Mandatory = $true)][object[]]$CandidateParents,
        [Parameter(Mandatory = $true)][string]$TempDirPrefix,
        [Parameter(Mandatory = $true)][string]$TarName,
        [Parameter(Mandatory = $true)][string]$PathLabel,
        [Parameter(Mandatory = $true)][string]$DisplayLabel,
        [Parameter(Mandatory = $true)][string]$LogAction,
        [Parameter(Mandatory = $true)][string]$RequiredParentReason,
        [object[]]$ForbiddenParentRules = @(),
        [Parameter(Mandatory = $true)][string]$ShapeRegex,
        [Parameter(Mandatory = $true)][string]$ShapeRejectReason,
        [Parameter(Mandatory = $true)][string]$FailureMessage,
        [string]$Distro = $Script:CurrentDistro
    )

    foreach ($candidate in @($CandidateParents)) {
        if (-not (Test-RestoreTempRootWritable -Path $candidate.ParentRoot)) {
            Write-LogEntry "WARN" $LogAction "Skipping $DisplayLabel parent because it is not writable: $($candidate.ParentRoot)" -Distro $Distro
            continue
        }

        $candidateRootItem = Get-Item -LiteralPath $candidate.ParentRoot -Force -ErrorAction Stop
        if (($candidateRootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Write-LogEntry "WARN" $LogAction "Skipping $DisplayLabel parent because it is a reparse point: $($candidate.ParentRoot)" -Distro $Distro
            continue
        }

        for ($attempt = 1; $attempt -le 3; $attempt++) {
            $candidatePrefix = if (
                $null -ne $candidate.PSObject.Properties["TempDirPrefix"] -and
                -not [string]::IsNullOrWhiteSpace([string]$candidate.TempDirPrefix)
            ) {
                [string]$candidate.TempDirPrefix
            }
            else {
                $TempDirPrefix
            }
            $tempDirName = "{0}-{1}" -f $candidatePrefix, ([guid]::NewGuid().ToString('N'))
            $tempDir = Join-Path $candidate.ParentRoot $tempDirName
            $tempDirResolved = Get-NormalizedWindowsPathForComparison -Path $tempDir -Label $PathLabel
            if (-not $tempDirResolved.Success) { continue }
            $tempDirImmediateParent = [System.IO.Path]::GetDirectoryName($tempDirResolved.NormalizedPath)
            if (Test-Path -LiteralPath $tempDirImmediateParent -PathType Container -ErrorAction SilentlyContinue) {
                $tempDirParentItem = Get-Item -LiteralPath $tempDirImmediateParent -Force -ErrorAction Stop
                if (($tempDirParentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    Write-LogEntry "WARN" $LogAction "Skipping $DisplayLabel parent because immediate temp parent is a reparse point: $tempDirImmediateParent" -Distro $Distro
                    continue
                }
            }

            $tempDirRule = Test-WSLBMPathClassRule `
                -Path $tempDirResolved.NormalizedPath `
                -UsageKey "TempWorkspace" `
                -Label $PathLabel `
                -RequiredParentPath $candidate.ParentRoot `
                -RequiredParentReason $RequiredParentReason `
                -ForbiddenParentRules @($ForbiddenParentRules) `
                -ShapeRegex $ShapeRegex `
                -ShapeRejectReason $ShapeRejectReason
            if (-not $tempDirRule.Success) { continue }
            if (Test-Path -LiteralPath $tempDirResolved.NormalizedPath -ErrorAction SilentlyContinue) { continue }

            if (-not [string]::IsNullOrWhiteSpace($candidate.Warning)) {
                Write-Host "[WARN] $($candidate.Warning)" -ForegroundColor Yellow
                Write-LogEntry "WARN" $LogAction $candidate.Warning -Distro $Distro
            }

            $tempTar = Join-Path $tempDirResolved.NormalizedPath $TarName
            Write-Host "  ${DisplayLabel}: $($tempDirResolved.NormalizedPath)" -ForegroundColor DarkGray
            Write-LogEntry "INFO" $LogAction "Source=$($candidate.Source) | TempRoot=$($tempDirResolved.NormalizedPath) | Parent=$($candidate.ParentRoot)" -Distro $Distro
            return [pscustomobject]@{
                TempRoot       = $tempDirResolved.NormalizedPath
                TempDir        = $tempDirResolved.NormalizedPath
                TempTar        = $tempTar
                ParentRoot     = $candidate.ParentRoot
                Source         = $candidate.Source
                UsedSystemTemp = ([bool]$candidate.UsedSystemTemp)
            }
        }
    }

    throw "No safe restore temp workspace is available. $FailureMessage"
}

function New-RestoreTempPathInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [Parameter(Mandatory = $true)]
        [string]$InstallPath,

        [string]$Distro = $Script:CurrentDistro,

        [string]$TarName = "wsl-export.tar",

        [switch]$SkipBackupDirCandidate
    )

    if ([string]::IsNullOrWhiteSpace($TarName) -or
        $TarName.Contains("\") -or
        $TarName.Contains("/") -or
        -not $TarName.EndsWith(".tar", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Restore temp tar name must be a safe tar file leaf name."
    }

    $operationId = Get-RestoreTempOperationId
    $tempRootCandidates = @(Resolve-RestoreTempRoot `
        -BackupFile $BackupFile `
        -InstallPath $InstallPath `
        -Distro $Distro `
        -SkipBackupDirCandidate:$SkipBackupDirCandidate)
    $tempDirPrefix = ".tmp\restore-$operationId"
    $normalizedInstallPath = if ($tempRootCandidates.Count -gt 0) { [string]$tempRootCandidates[0].InstallPath } else { $InstallPath }
    $forbiddenParentRules = New-RestoreTempForbiddenParentRules -BackupFile $BackupFile -InstallPath $normalizedInstallPath

    return New-ControlledRestoreTempPathInfo `
        -CandidateParents @($tempRootCandidates) `
        -TempDirPrefix $tempDirPrefix `
        -TarName $TarName `
        -PathLabel "Restore temp directory" `
        -DisplayLabel "Restore temp root" `
        -LogAction "Restore-TempRoot" `
        -RequiredParentReason "Restore temp directory must be under the selected temp parent root." `
        -ForbiddenParentRules @($forbiddenParentRules) `
        -ShapeRegex '^restore-\d{8}-\d{6}-[0-9a-f]{4}-[0-9a-fA-F]{32}$' `
        -ShapeRejectReason "Restore temp directory name does not match controlled prefix." `
        -FailureMessage "Cannot allocate a unique restore temp directory from configured candidates." `
        -Distro $Distro
}

function Clear-RestoreTempArtifacts {
    param(
        [string]$TempDir,
        [string]$TempTar,
        [string]$Distro = $Script:CurrentDistro,
        [string]$ExpectedTarName = "wsl-export.tar",
        [string]$ExpectedTempDirRegex = '^restore-\d{8}-\d{6}-[0-9a-f]{4}-[0-9a-fA-F]{32}$',
        [string]$TempDirShapeRejectReason = "Restore temp directory name does not match controlled prefix"
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

    $tempDirParent = Split-Path -Path $tempDirResolved.NormalizedPath -Parent
    if ([string]::IsNullOrWhiteSpace($tempDirParent) -or $tempDirParent -eq $tempDirResolved.NormalizedPath) {
        Write-RestoreCleanupWarning "Restore temp directory has no safe parent boundary: $($tempDirResolved.NormalizedPath)"
        return
    }

    $tempDirRule = Test-WSLBMPathClassRule `
        -Path $tempDirResolved.NormalizedPath `
        -UsageKey "TempWorkspace" `
        -Label "Restore temp directory" `
        -RequiredParentPath $tempDirParent `
        -RequiredParentReason "Restore temp directory has no safe parent boundary: $($tempDirResolved.NormalizedPath)" `
        -ShapeRegex $ExpectedTempDirRegex `
        -ShapeRejectReason "${TempDirShapeRejectReason}: $($tempDirResolved.NormalizedPath)"
    if (-not $tempDirRule.Success) {
        Write-RestoreCleanupWarning $tempDirRule.Reason
        return
    }

    $tarParent = Split-Path -Path $tempTarResolved.NormalizedPath -Parent
    $tarName = Split-Path -Path $tempTarResolved.NormalizedPath -Leaf
    if (-not $tarParent.Equals($tempDirResolved.NormalizedPath, [System.StringComparison]::OrdinalIgnoreCase) -or $tarName -ne $ExpectedTarName) {
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
        $restoreSpaceMessage = @(
            "Label=$Label"
            "Target=$Path"
            "CheckPath=$($resolvedPath.CheckPath)"
            "Source=$spaceSource"
            "Tar=$(Format-Bytes $TarSizeBytes)"
            "Required=$(Format-Bytes $requiredBytes)"
            "Available=$(Format-Bytes $availableBytes)"
        ) -join " | "
        Write-LogEntry `
            "INFO" `
            "Restore-Space" `
            $restoreSpaceMessage `
            -Distro $Distro

        if ($availableBytes -lt $requiredBytes) {
            Write-Host "[ERROR] Not enough free space for restore payload." -ForegroundColor Red
            Write-Host "  Target    : $Path" -ForegroundColor Yellow
            Write-Host "  Check path: $($resolvedPath.CheckPath)" -ForegroundColor Yellow
            Write-Host "  Required  : $(Format-Bytes $requiredBytes)" -ForegroundColor Yellow
            Write-Host "  Available : $(Format-Bytes $availableBytes)" -ForegroundColor Yellow
            Write-LogEntry `
                "ERROR" `
                "Restore-Space" `
                "Insufficient space. Label=$Label | Target=$Path | CheckPath=$($resolvedPath.CheckPath) | Required=$(Format-Bytes $requiredBytes) | Available=$(Format-Bytes $availableBytes)" `
                -Distro $Distro
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

function Resolve-WSLLinuxRestoreSpaceCheckPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LinuxPath,

        [Parameter(Mandatory = $true)]
        [string]$DistroName
    )

    $validation = Test-LinuxAbsolutePathLiteral -Path $LinuxPath
    if (-not $validation.Success) {
        return [pscustomobject]@{ Success = $false; CheckPath = ""; Reason = $validation.Reason }
    }

    if ($Global:DryRun) {
        return [pscustomobject]@{ Success = $true; CheckPath = $validation.Path; Reason = "" }
    }

    $candidate = $validation.Path
    while (-not [string]::IsNullOrWhiteSpace($candidate)) {
        $probe = Invoke-WSLPathProbe `
            -DistroName $DistroName `
            -ProbeArguments @("test", "-d", $candidate) `
            -Description "Find Restore-Path space check directory"

        if ($probe.ExitCode -eq 0) {
            return [pscustomobject]@{ Success = $true; CheckPath = $candidate; Reason = "" }
        }
        if ($probe.ExitCode -ne 1) {
            return [pscustomobject]@{
                Success   = $false
                CheckPath = ""
                Reason    = "Cannot inspect Linux path '$candidate': $($probe.CombinedOutput)"
            }
        }

        $candidate = Get-LinuxPathParentLiteral -Path $candidate
    }

    return [pscustomobject]@{
        Success   = $false
        CheckPath = ""
        Reason    = "Cannot find an existing Linux directory for Restore-Path space check: $LinuxPath"
    }
}

function Test-WSLLinuxPathFreeSpaceForRestorePayload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LinuxPath,

        [Parameter(Mandatory = $true)]
        [long]$TarSizeBytes,

        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [string]$Label = "Restore-Path target"
    )

    if ($TarSizeBytes -le 0) {
        Write-Host "[ERROR] Restore-Path tar size is invalid: $TarSizeBytes bytes." -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-Path-Space" "Invalid Restore-Path tar size: $TarSizeBytes bytes" -Distro $DistroName
        return $false
    }

    $bufferBytes = [long][math]::Max([math]::Ceiling([double]$TarSizeBytes * 0.10), [double]1GB)
    $requiredBytes = [long]($TarSizeBytes + $bufferBytes)
    $resolved = Resolve-WSLLinuxRestoreSpaceCheckPath -LinuxPath $LinuxPath -DistroName $DistroName
    if (-not $resolved.Success) {
        Write-Host "[ERROR] Restore-Path target space check failed closed: $($resolved.Reason)" -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-Path-Space" "Cannot resolve target filesystem. Target=$LinuxPath | Reason=$($resolved.Reason)" -Distro $DistroName
        return $false
    }

    if ($Global:DryRun) {
        Write-Host "DRY RUN: would check WSL target filesystem free space at $($resolved.CheckPath)" -ForegroundColor Yellow
        Write-LogEntry "INFO" "Restore-Path-Space" "DryRun would check target filesystem. Target=$LinuxPath | CheckPath=$($resolved.CheckPath) | Required=$(Format-Bytes $requiredBytes)" -Distro $DistroName
        return $true
    }

    $dfResult = Invoke-WSLPathProbe `
        -DistroName $DistroName `
        -ProbeArguments @("df", "-P", "-B1", "--", $resolved.CheckPath) `
        -Description "Check Restore-Path target filesystem free space"
    if (-not $dfResult.Success) {
        Write-Host "[ERROR] Cannot verify Restore-Path target filesystem free space." -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-Path-Space" "df failed. Target=$LinuxPath | CheckPath=$($resolved.CheckPath) | Output=$($dfResult.CombinedOutput)" -Distro $DistroName
        return $false
    }

    $dfOutput = [string]$dfResult.StdOut
    if ([string]::IsNullOrWhiteSpace($dfOutput)) {
        $dfOutput = [string]$dfResult.CombinedOutput
    }
    $dfLines = @($dfOutput -split "\r?\n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($dfLines.Count -lt 2) {
        Write-Host "[ERROR] Cannot parse Restore-Path target filesystem free space output." -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-Path-Space" "Unexpected df output. Target=$LinuxPath | CheckPath=$($resolved.CheckPath) | Output=$dfOutput" -Distro $DistroName
        return $false
    }

    $dfParts = @(([string]$dfLines[-1]).Trim() -split "\s+")
    $availableBytes = [long]0
    if ($dfParts.Count -lt 4 -or -not [long]::TryParse([string]$dfParts[3], [ref]$availableBytes)) {
        Write-Host "[ERROR] Cannot parse available bytes from Restore-Path target filesystem free space output." -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-Path-Space" "Cannot parse available bytes. Target=$LinuxPath | CheckPath=$($resolved.CheckPath) | Output=$dfOutput" -Distro $DistroName
        return $false
    }

    Write-Host "  -> Restore-Path Target Space Check: $Label" -ForegroundColor Cyan
    Write-Host "     Target    : ${DistroName}:$LinuxPath" -ForegroundColor DarkGray
    Write-Host "     Check path: $($resolved.CheckPath)" -ForegroundColor DarkGray
    Write-Host "     Tar size  : $(Format-Bytes $TarSizeBytes)" -ForegroundColor DarkGray
    Write-Host "     Buffer    : $(Format-Bytes $bufferBytes)" -ForegroundColor DarkGray
    Write-Host "     Required  : $(Format-Bytes $requiredBytes)" -ForegroundColor DarkGray
    Write-Host "     Available : $(Format-Bytes $availableBytes)" -ForegroundColor DarkGray
    Write-LogEntry `
        "INFO" `
        "Restore-Path-Space" `
        "Target=$LinuxPath | CheckPath=$($resolved.CheckPath) | Tar=$(Format-Bytes $TarSizeBytes) | Required=$(Format-Bytes $requiredBytes) | Available=$(Format-Bytes $availableBytes)" `
        -Distro $DistroName

    if ($availableBytes -lt $requiredBytes) {
        Write-Host "[ERROR] Not enough free space on the WSL target filesystem for Restore-Path." -ForegroundColor Red
        Write-Host "  Target    : ${DistroName}:$LinuxPath" -ForegroundColor Yellow
        Write-Host "  Check path: $($resolved.CheckPath)" -ForegroundColor Yellow
        Write-Host "  Required  : $(Format-Bytes $requiredBytes)" -ForegroundColor Yellow
        Write-Host "  Available : $(Format-Bytes $availableBytes)" -ForegroundColor Yellow
        Write-LogEntry `
            "ERROR" `
            "Restore-Path-Space" `
            "Insufficient target filesystem space. Target=$LinuxPath | CheckPath=$($resolved.CheckPath) | Required=$(Format-Bytes $requiredBytes) | Available=$(Format-Bytes $availableBytes)" `
            -Distro $DistroName
        return $false
    }

    Write-Host "  [OK] Restore-Path target filesystem space check passed." -ForegroundColor Green
    return $true
}

function New-RestoreImportPreflightResult {
    param(
        [bool]$Success,
        [long]$TarSizeBytes = -1,
        [long]$RequiredBytes = 0,
        [long]$BufferBytes = 0,
        [bool]$SkippedBecauseDryRun = $Global:DryRun,
        [string]$InstallPath = "",
        [object]$InstallPathSafety = $null,
        [object]$TempPathInfo = $null,
        [string]$TarEntryName = "",
        [string]$TarEntryLeafName = ""
    )

    return [pscustomobject]@{
        Success              = $Success
        TarSizeBytes         = $TarSizeBytes
        RequiredBytes        = $RequiredBytes
        BufferBytes          = $BufferBytes
        SkippedBecauseDryRun = $SkippedBecauseDryRun
        InstallPath          = $InstallPath
        InstallPathSafety    = $InstallPathSafety
        TempPathInfo         = $TempPathInfo
        TarEntryName         = $TarEntryName
        TarEntryLeafName     = $TarEntryLeafName
    }
}

function Test-RestoreImportPreflight {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [Parameter(Mandatory = $true)]
        [string]$InstallPath,

        [string]$Distro = $Script:CurrentDistro,

        [string]$Mode = "Restore",

        [ValidateSet("7z", "tar")]
        [string]$ArchiveFormat = "7z",

        [switch]$ArchiveIsExternal
    )

    $minimumTarSizeBytes = 1KB
    $tarEntryName = ""
    $tarEntryLeafName = ""
    $tempPathInfo = $null

    $installPathSafety = Test-RestoreInstallPathSafety -InstallPath $InstallPath -BackupFile $BackupFile -DistroName $Distro -Mode $Mode
    if (-not $installPathSafety.Success) {
        Write-Host "[ERROR] Restore aborted before any WSL changes because install path safety pre-flight failed." -ForegroundColor Red
        return New-RestoreImportPreflightResult -Success $false -InstallPath $InstallPath -InstallPathSafety $installPathSafety
    }

    if ($Global:DryRun) {
        Write-Host "DRY RUN: restore install path safety check passed for $($installPathSafety.NormalizedPath)" -ForegroundColor Yellow
        Write-Host "DRY RUN: would run full restore archive integrity check for $BackupFile" -ForegroundColor Yellow
        if ($ArchiveFormat -eq "tar") {
            Write-Host "DRY RUN: would use the external/raw tar archive size directly; no archive extraction is needed before import." -ForegroundColor Yellow
        }
        else {
            Write-Host "DRY RUN: would detect the WholeDistro tar export entry by listing $BackupFile" -ForegroundColor Yellow
            Write-Host "DRY RUN: would allocate a restore temp root for the selected tar export." -ForegroundColor Yellow
            Write-Host "DRY RUN: would check restore temp root free space for the selected tar export." -ForegroundColor Yellow
        }
        Write-Host "DRY RUN: would check install path free space for restore payload at $InstallPath" -ForegroundColor Yellow
        $dryRunTempRoot = if ($ArchiveFormat -eq "7z") { "<selected after tar entry detection>" } else { "<not used for raw tar>" }
        $dryRunPreflightMessage = @(
            "Mode=$Mode"
            "ArchiveFormat=$ArchiveFormat"
            "External=$([bool]$ArchiveIsExternal)"
            "Would validate install path safety, archive, payload size, and required target space."
            "Backup=$BackupFile"
            "InstallPath=$InstallPath"
            "TempRoot=$dryRunTempRoot"
        ) -join " | "
        Write-LogEntry `
            "INFO" `
            "Restore-Preflight-DryRun" `
            $dryRunPreflightMessage `
            -Distro $Distro
        return New-RestoreImportPreflightResult -Success $true -SkippedBecauseDryRun $true -InstallPath $installPathSafety.NormalizedPath -InstallPathSafety $installPathSafety -TempPathInfo $tempPathInfo
    }

    if (-not (Test-RestoreArchiveIntegrity -backupFile $BackupFile)) {
        Write-LogEntry "ERROR" "Restore-Preflight" "Archive integrity check failed: $BackupFile" -Distro $Distro
        Write-Host "[ERROR] Restore aborted before any WSL changes." -ForegroundColor Red
        return New-RestoreImportPreflightResult -Success $false -SkippedBecauseDryRun $false -InstallPath $installPathSafety.NormalizedPath -InstallPathSafety $installPathSafety -TempPathInfo $tempPathInfo
    }

    if ($ArchiveFormat -eq "tar") {
        try {
            $archiveItem = Get-Item -LiteralPath $BackupFile -ErrorAction Stop
            $tarSizeBytes = [long]$archiveItem.Length
            Write-Host "  -> Restore Pre-flight: Using raw tar archive size: $(Format-Bytes $tarSizeBytes)" -ForegroundColor Cyan
            Write-LogEntry "INFO" "Restore-Preflight" "Raw tar restore payload size=$(Format-Bytes $tarSizeBytes) | Archive=$BackupFile" -Distro $Distro
        }
        catch {
            Write-Host "[ERROR] Restore pre-flight failed: cannot read raw tar archive size: $($_.Exception.Message)" -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-Preflight" "Cannot read raw tar archive size: $($_.Exception.Message)" -Distro $Distro
            return New-RestoreImportPreflightResult `
                -Success $false `
                -SkippedBecauseDryRun $false `
                -InstallPath $installPathSafety.NormalizedPath `
                -InstallPathSafety $installPathSafety `
                -TempPathInfo $tempPathInfo
        }
    }
    else {
        $entryResult = Resolve-RestoreWholeDistroSevenZipTarEntry -BackupFile $BackupFile -Distro $Distro
        if (-not $entryResult.Success) {
            Write-Host "[ERROR] Restore pre-flight failed: $($entryResult.Reason)" -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-Preflight" "WholeDistro .7z tar entry detection failed: $($entryResult.Reason)" -Distro $Distro
            return New-RestoreImportPreflightResult -Success $false -SkippedBecauseDryRun $false -InstallPath $installPathSafety.NormalizedPath -InstallPathSafety $installPathSafety
        }

        $tarEntryName = [string]$entryResult.Entry.Path
        $tarEntryLeafName = [string]$entryResult.Entry.LeafName
        $tarSizeBytes = [long]$entryResult.Entry.SizeBytes
        Write-Host "  -> Restore Pre-flight: Using tar export entry: $tarEntryName" -ForegroundColor Cyan
        Write-LogEntry "INFO" "Restore-Preflight" "WholeDistro .7z tar export entry=$tarEntryName | Size=$(Format-Bytes $tarSizeBytes)" -Distro $Distro

        try {
            $tempPathInfo = New-RestoreTempPathInfo `
                -BackupFile $BackupFile `
                -InstallPath $installPathSafety.NormalizedPath `
                -Distro $Distro `
                -TarName $tarEntryLeafName `
                -SkipBackupDirCandidate:$ArchiveIsExternal
        }
        catch {
            Write-Host "[ERROR] Restore aborted before any WSL changes because restore temp root could not be selected: $($_.Exception.Message)" -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-Preflight" "Cannot select restore temp root: $($_.Exception.Message)" -Distro $Distro
            return New-RestoreImportPreflightResult -Success $false -SkippedBecauseDryRun $false -InstallPath $installPathSafety.NormalizedPath -InstallPathSafety $installPathSafety -TempPathInfo $tempPathInfo
        }
    }

    if ($tarSizeBytes -lt $minimumTarSizeBytes) {
        Write-Host "[ERROR] Restore tar entry is too small ($(Format-Bytes $tarSizeBytes))." -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-Preflight" "Archive tar entry too small: $tarSizeBytes bytes" -Distro $Distro
        return New-RestoreImportPreflightResult `
            -Success $false `
            -TarSizeBytes $tarSizeBytes `
            -SkippedBecauseDryRun $false `
            -InstallPath $installPathSafety.NormalizedPath `
            -InstallPathSafety $installPathSafety `
            -TempPathInfo $tempPathInfo `
            -TarEntryName $tarEntryName `
            -TarEntryLeafName $tarEntryLeafName
    }

    $bufferBytes = [long][math]::Max([math]::Ceiling([double]$tarSizeBytes * 0.10), [double]1GB)
    $requiredBytes = [long]($tarSizeBytes + $bufferBytes)
    Write-LogEntry "INFO" "Restore-Preflight" "Restore payload size=$(Format-Bytes $tarSizeBytes) | Required per target=$(Format-Bytes $requiredBytes)" -Distro $Distro

    if ($ArchiveFormat -eq "7z") {
        if (-not (Test-PathFreeSpaceForRestorePayload -Path $tempPathInfo.TempRoot -TarSizeBytes $tarSizeBytes -Label "Restore temp root" -Distro $Distro)) {
            Write-Host "[ERROR] Restore aborted before any WSL changes because restore temp root space pre-flight failed." -ForegroundColor Red
            return New-RestoreImportPreflightResult `
                -Success $false `
                -TarSizeBytes $tarSizeBytes `
                -SkippedBecauseDryRun $false `
                -InstallPath $installPathSafety.NormalizedPath `
                -InstallPathSafety $installPathSafety `
                -TempPathInfo $tempPathInfo `
                -TarEntryName $tarEntryName `
                -TarEntryLeafName $tarEntryLeafName
        }
    }

    if (-not (Test-PathFreeSpaceForRestorePayload -Path $installPathSafety.NormalizedPath -TarSizeBytes $tarSizeBytes -Label "Install path" -Distro $Distro)) {
        Write-Host "[ERROR] Restore aborted before any WSL changes because install path space pre-flight failed." -ForegroundColor Red
        return New-RestoreImportPreflightResult `
            -Success $false `
            -TarSizeBytes $tarSizeBytes `
            -SkippedBecauseDryRun $false `
            -InstallPath $installPathSafety.NormalizedPath `
            -InstallPathSafety $installPathSafety `
            -TempPathInfo $tempPathInfo `
            -TarEntryName $tarEntryName `
            -TarEntryLeafName $tarEntryLeafName
    }

    return New-RestoreImportPreflightResult `
        -Success $true `
        -TarSizeBytes $tarSizeBytes `
        -RequiredBytes $requiredBytes `
        -BufferBytes $bufferBytes `
        -SkippedBecauseDryRun $false `
        -InstallPath $installPathSafety.NormalizedPath `
        -InstallPathSafety $installPathSafety `
        -TempPathInfo $tempPathInfo `
        -TarEntryName $tarEntryName `
        -TarEntryLeafName $tarEntryLeafName
}

function New-RestoreArchiveExtractResult {
    param(
        [bool]$Success,
        [object]$ExitCode = $null,
        [bool]$SkippedBecauseDryRun = $false,
        [bool]$TimedOut = $false,
        [bool]$Cancelled = $false,
        [string]$TempDir = $null,
        [string]$TempTar = $null,
        [object]$TempPathInfo = $null
    )
    if ($null -ne $TempPathInfo) {
        $TempDir = $TempPathInfo.TempDir
        $TempTar = $TempPathInfo.TempTar
    }
    return [pscustomobject]@{ Success = $Success; ExitCode = $ExitCode; SkippedBecauseDryRun = $SkippedBecauseDryRun; TimedOut = $TimedOut; Cancelled = $Cancelled; TempDir = $TempDir; TempTar = $TempTar }
}

function Expand-RestoreArchiveToTempTar {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [string]$Distro = $Script:CurrentDistro,

        [long]$TarSizeBytes = -1,

        [object]$TempPathInfo = $null,

        [string]$InstallPath = "",

        [string]$TarEntryName = "",

        [long]$MinimumTarSizeBytes = 1KB
    )

    if ([string]::IsNullOrWhiteSpace($TarEntryName)) {
        throw "Restore archive tar entry name was not resolved."
    }
    $tarEntryName = $TarEntryName
    $tarEntryLeafName = Split-Path -Path ($tarEntryName -replace '/', '\') -Leaf
    $minimumTarSizeBytes = if ($MinimumTarSizeBytes -gt 0) { $MinimumTarSizeBytes } else { 1KB }
    try {
        $tempPathInfo = $TempPathInfo
        if ($null -eq $tempPathInfo) {
            if ([string]::IsNullOrWhiteSpace($InstallPath)) {
                throw "Restore temp path requires the target install path."
            }
            $tempPathInfo = New-RestoreTempPathInfo `
                -BackupFile $BackupFile `
                -InstallPath $InstallPath `
                -Distro $Distro `
                -TarName $tarEntryLeafName
        }
        $tempDir = $tempPathInfo.TempDir
        $tempTar = $tempPathInfo.TempTar
    }
    catch {
        Write-Host "[ERROR] Restore tar extraction failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-Extract" "Cannot allocate controlled temp path: $($_.Exception.Message)" -Distro $Distro
        return New-RestoreArchiveExtractResult -Success $false -SkippedBecauseDryRun $Global:DryRun
    }

    if ($Global:DryRun) {
        Write-Host "DRY RUN: would read uncompressed size of $tarEntryName from $BackupFile" -ForegroundColor Yellow
        Write-Host "DRY RUN: would check restore temp root free space for restore tar plus safety buffer at $tempDir" -ForegroundColor Yellow
        Write-Host "DRY RUN: would extract $tarEntryName from $BackupFile to $tempTar" -ForegroundColor Yellow
        Write-Host "DRY RUN: would validate extracted tar exists and is at least $(Format-Bytes $minimumTarSizeBytes)" -ForegroundColor Yellow
        Write-LogEntry "INFO" "Restore-Extract-DryRun" "Would read $tarEntryName size, check restore temp root space, and extract to $tempTar" -Distro $Distro
        return New-RestoreArchiveExtractResult -Success $true -SkippedBecauseDryRun $true -TempPathInfo $tempPathInfo
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
            return New-RestoreArchiveExtractResult -Success $false -TempPathInfo $tempPathInfo
        }

        if (-not (Test-PathFreeSpaceForRestorePayload -Path $tempDir -TarSizeBytes $tarSizeBytes -Label "Restore temp root" -Distro $Distro)) {
            return New-RestoreArchiveExtractResult -Success $false -TempPathInfo $tempPathInfo
        }

        if (Test-Path -LiteralPath $tempDir -ErrorAction SilentlyContinue) {
            throw "Controlled restore TEMP directory already exists: $tempDir"
        }
        [System.IO.Directory]::CreateDirectory($tempDir) | Out-Null

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
            return New-RestoreArchiveExtractResult -Success $false -ExitCode $exitCode -TimedOut $true -TempPathInfo $tempPathInfo
        }
        if ($extractProcess.Cancelled) {
            Write-Host "[WARN] Restore tar extraction cancelled by user." -ForegroundColor Yellow
            Write-LogEntry "WARN" "Restore-Extract" "7z extraction cancelled by user" -Distro $Distro
            return New-RestoreArchiveExtractResult -Success $false -ExitCode $exitCode -Cancelled $true -TempPathInfo $tempPathInfo
        }
        if ($null -eq $exitCode) {
            Write-Host "[ERROR] Failed to extract restore tar: 7z did not report an exit code." -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-Extract" "7z failed without reporting an exit code" -Distro $Distro
            return New-RestoreArchiveExtractResult -Success $false -TempPathInfo $tempPathInfo
        }
        if ($exitCode -ne 0) {
            Write-Host "[ERROR] Failed to extract restore tar (7z exit code $exitCode)." -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-Extract" "7z failed with exit code $exitCode" -Distro $Distro
            return New-RestoreArchiveExtractResult -Success $false -ExitCode $exitCode -TempPathInfo $tempPathInfo
        }

        if (-not (Test-Path -LiteralPath $tempTar -PathType Leaf)) {
            Write-Host "[ERROR] Restore tar extraction failed: $tempTar was not created." -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-Extract" "Extracted tar missing: $tempTar" -Distro $Distro
            return New-RestoreArchiveExtractResult -Success $false -ExitCode $exitCode -TempPathInfo $tempPathInfo
        }

        $tarItem = Get-Item -LiteralPath $tempTar
        if ($tarItem.Length -lt $minimumTarSizeBytes) {
            Write-Host "[ERROR] Restore tar extraction failed: file is too small ($(Format-Bytes $tarItem.Length))." -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-Extract" "Extracted tar too small: $($tarItem.Length) bytes" -Distro $Distro
            return New-RestoreArchiveExtractResult -Success $false -ExitCode $exitCode -TempPathInfo $tempPathInfo
        }

        Write-Host "  [OK] Restore tar extracted: $(Format-Bytes $tarItem.Length)" -ForegroundColor Green
        Write-LogEntry "INFO" "Restore-Extract" "Extracted $tarEntryName ($(Format-Bytes $tarItem.Length))" -Distro $Distro
        return New-RestoreArchiveExtractResult -Success $true -ExitCode $exitCode -TempPathInfo $tempPathInfo
    }
    catch {
        Write-Host "[ERROR] Restore tar extraction failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-Extract" "Exception: $($_.Exception.Message)" -Distro $Distro
        return New-RestoreArchiveExtractResult -Success $false -TempPathInfo $tempPathInfo
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

function Test-WSLBMDistroRegistryRecordPresent {
    param(
        [AllowNull()]
        [object]$RegistryInfo
    )

    if ($null -eq $RegistryInfo) {
        return $false
    }

    return ([bool]$RegistryInfo.Success -or
        -not [string]::IsNullOrWhiteSpace([string]$RegistryInfo.RegistryKey) -or
        -not [string]::IsNullOrWhiteSpace([string]$RegistryInfo.DistributionName))
}

function Test-WSLBMRestoreCleanupProtectedBoundary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    foreach ($boundaryRaw in @(
            $env:USERPROFILE,
            $PSScriptRoot,
            $Global:Config.InstallRoot,
            $Global:Config.GlobalBackupRoot,
            (Get-RestoreSafetyNetRootPath),
            (Get-InstanceBackupPath),
            [System.IO.Path]::GetTempPath())) {
        if ([string]::IsNullOrWhiteSpace($boundaryRaw)) {
            continue
        }

        $boundary = Get-NormalizedWindowsPathForComparison -Path $boundaryRaw -Label "Restore cleanup protected boundary"
        if ($boundary.Success -and $Path.Equals($boundary.NormalizedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Invoke-ProtectedRestoreInstallPathCleanup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstallPath,

        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [bool]$InstallPathCreatedByRestore,

        [string]$Reason = "Restore import failure cleanup"
    )

    if (-not $InstallPathCreatedByRestore) {
        Write-Host "[WARN] Install path existed before this restore; automatic install path cleanup was skipped." -ForegroundColor Yellow
        Write-Host "       Review manually: $InstallPath" -ForegroundColor Yellow
        Write-LogEntry "WARN" "Restore-Import-Cleanup" "Install path cleanup skipped because path was not created by this restore. Path=$InstallPath | Reason=$Reason" -Distro $DistroName
        return $false
    }

    $safety = Test-RestoreInstallPathSafety `
        -InstallPath $InstallPath `
        -BackupFile $BackupFile `
        -DistroName $DistroName `
        -Mode "ImportFailureCleanup"
    if (-not $safety.Success) {
        Write-Host "[WARN] Install path cleanup blocked by safety check. Manual cleanup may be required." -ForegroundColor Yellow
        Write-LogEntry "WARN" "Restore-Import-Cleanup" "Install path cleanup blocked by safety check. Path=$InstallPath | Reason=$($safety.Reason)" -Distro $DistroName
        return $false
    }

    $target = $safety.NormalizedPath
    if (Test-WSLBMRestoreCleanupProtectedBoundary -Path $target) {
        Write-Host "[WARN] Install path cleanup blocked because the target is a protected boundary path." -ForegroundColor Yellow
        Write-LogEntry "WARN" "Restore-Import-Cleanup" "Install path cleanup blocked by protected boundary. Path=$target" -Distro $DistroName
        return $false
    }
    if (-not (Test-Path -LiteralPath $target -PathType Container)) {
        Write-LogEntry "INFO" "Restore-Import-Cleanup" "Install path cleanup not needed; path does not exist. Path=$target" -Distro $DistroName
        return $true
    }

    $reparsePointScan = Test-BackupDirectoryReparsePointSafety -Path $target
    if (-not $reparsePointScan.Success) {
        Write-Host "[WARN] Install path cleanup blocked by reparse point safety scan." -ForegroundColor Yellow
        Write-LogEntry "WARN" "Restore-Import-Cleanup" "Install path cleanup blocked by reparse scan. Path=$target | Reason=$($reparsePointScan.Reason)" -Distro $DistroName
        return $false
    }

    if ($Global:DryRun) {
        Write-Host "DRY RUN: would remove partial restore install path $target" -ForegroundColor Yellow
        Write-LogEntry "INFO" "Restore-Import-Cleanup" "DryRun would remove install path. Path=$target | Reason=$Reason" -Distro $DistroName
        return $true
    }

    try {
        Write-Host "Cleaning partial restore install path..." -ForegroundColor Yellow
        Write-Host "  Path: $target" -ForegroundColor DarkGray
        Write-LogEntry "WARN" "Restore-Import-Cleanup" "Removing partial restore install path. Path=$target | Reason=$Reason" -Distro $DistroName
        Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop
        Write-LogEntry "INFO" "Restore-Import-Cleanup" "Removed partial restore install path. Path=$target" -Distro $DistroName
        return $true
    }
    catch {
        Write-Host "[WARN] Failed to clean partial restore install path: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "       Manual cleanup may be required: $target" -ForegroundColor Yellow
        Write-LogEntry "ERROR" "Restore-Import-Cleanup" "Failed to remove install path. Path=$target | Error=$($_.Exception.Message)" -Distro $DistroName
        return $false
    }
}

function Invoke-RestorePartialDistroCleanup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$InstallPath,

        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [Parameter(Mandatory = $true)]
        [ValidateSet("InstallNew", "Replace")]
        [string]$Branch,

        [bool]$InstallPathCreatedByRestore = $false
    )

    Write-Host "[Restore import failure cleanup]" -ForegroundColor Yellow
    Write-LogEntry "WARN" "Restore-Import-Cleanup" "Starting partial import cleanup. Branch=$Branch | Distro=$DistroName | InstallPath=$InstallPath" -Distro $DistroName

    $distroCleanupOk = $true
    $registryInfo = Get-WSLDistroRegistryInfo -DistroName $DistroName
    if (Test-WSLBMDistroRegistryRecordPresent -RegistryInfo $registryInfo) {
        Write-Host "Partial target distro appears registered; unregistering before continuing cleanup." -ForegroundColor Yellow
        $unregisterResult = Invoke-GuardedWSLCommand `
            -Description "Cleanup partial restore distro after import failure" `
            -Arguments @("--unregister", $DistroName) `
            -Distro $DistroName
        $distroCleanupOk = [bool]$unregisterResult.Success
        if (-not $distroCleanupOk) {
            Write-Host "[WARN] Failed to unregister partial target distro. Manual cleanup is required: $DistroName" -ForegroundColor Yellow
            Write-LogEntry "ERROR" "Restore-Import-Cleanup" "Failed to unregister partial target distro. Branch=$Branch" -Distro $DistroName
        }
    }
    elseif (Test-WSLBMRegistryInfoIsExplicitMissing -RegistryInfo $registryInfo) {
        Write-Host "No registered partial target distro was found." -ForegroundColor DarkGray
        Write-LogEntry "INFO" "Restore-Import-Cleanup" "No registered partial target distro found. Branch=$Branch" -Distro $DistroName
    }
    else {
        $distroCleanupOk = $false
        Write-Host "[WARN] Cannot determine whether a partial target distro was registered." -ForegroundColor Yellow
        Write-Host "       Manual check may be required for distro: $DistroName" -ForegroundColor Yellow
        Write-LogEntry "WARN" "Restore-Import-Cleanup" "Registry state uncertain during cleanup. Branch=$Branch | Reason=$($registryInfo.Reason)" -Distro $DistroName
    }

    $installPathCleanupOk = $true
    if ($Branch -eq "InstallNew") {
        $installPathCleanupOk = Invoke-ProtectedRestoreInstallPathCleanup `
            -InstallPath $InstallPath `
            -BackupFile $BackupFile `
            -DistroName $DistroName `
            -InstallPathCreatedByRestore ([bool]$InstallPathCreatedByRestore) `
            -Reason "Install-new import failed"
    }

    if (-not $distroCleanupOk -or -not $installPathCleanupOk) {
        Write-Host "[WARN] Import failure cleanup was incomplete." -ForegroundColor Yellow
        Write-Host "       Manually review target distro '$DistroName' and install path '$InstallPath'." -ForegroundColor Yellow
        Write-LogEntry "WARN" "Restore-Import-Cleanup" "Cleanup incomplete. Branch=$Branch | DistroCleanup=$distroCleanupOk | InstallPathCleanup=$installPathCleanupOk | InstallPath=$InstallPath" -Distro $DistroName
        return $false
    }

    Write-LogEntry "INFO" "Restore-Import-Cleanup" "Partial import cleanup completed. Branch=$Branch | InstallPath=$InstallPath" -Distro $DistroName
    return $true
}

function Get-RestoreSafetyNetRootPath {
    if ([string]::IsNullOrWhiteSpace($Global:Config.GlobalBackupRoot)) {
        return ""
    }

    return (Join-Path $Global:Config.GlobalBackupRoot ".safety-net")
}

function Get-RestoreSafetyNetSafeDistroFileName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName
    )

    return ($DistroName -replace '[\\/:*?"<>|]', '_')
}

function Show-RestoreSafetyNetEntriesForDistro {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName
    )

    $safetyRoot = Get-RestoreSafetyNetRootPath
    Write-Host ""
    Write-Host "[Existing Safety Net Entries]" -ForegroundColor Cyan
    Write-Host "  Distro          : $DistroName" -ForegroundColor DarkGray
    Write-Host "  Safety Net root : $safetyRoot" -ForegroundColor DarkGray

    if ([string]::IsNullOrWhiteSpace($safetyRoot)) {
        Write-Host "  No entries shown: configured Backup Root is empty." -ForegroundColor Yellow
        return
    }

    if (-not (Test-Path -LiteralPath $safetyRoot -PathType Container -ErrorAction SilentlyContinue)) {
        Write-Host "  No existing Safety Net entries found." -ForegroundColor DarkGray
        return
    }

    $safeFileNameDistro = Get-RestoreSafetyNetSafeDistroFileName -DistroName $DistroName
    $entries = @(Get-ChildItem -LiteralPath $safetyRoot -Filter "SAFETY-NET-$safeFileNameDistro-*.tar" -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)

    if ($entries.Count -eq 0) {
        Write-Host "  No existing Safety Net entries found." -ForegroundColor DarkGray
        return
    }

    foreach ($entry in $entries) {
        Write-Host ("  - {0}" -f $entry.Name) -ForegroundColor Yellow
        Write-Host ("      LastWriteTime: {0}" -f $entry.LastWriteTime) -ForegroundColor DarkGray
        Write-Host ("      Size         : {0}" -f (Format-Bytes $entry.Length)) -ForegroundColor DarkGray
    }
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

    $safetyRoot = Get-RestoreSafetyNetRootPath
    if ([string]::IsNullOrWhiteSpace($safetyRoot)) {
        Write-Host "[ERROR] Safety Net failed: Safety Net root cannot be resolved." -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-SafetyNet" "Safety Net root cannot be resolved" -Distro $DistroName
        return $null
    }

    $safeFileNameDistro = Get-RestoreSafetyNetSafeDistroFileName -DistroName $DistroName
    $safetyFile = Join-Path $safetyRoot "SAFETY-NET-$safeFileNameDistro-$(Get-Date -Format 'yyyyMMdd-HHmmss').tar"

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

        if (-not (New-BackupDirectory $safetyRoot)) {
            Write-Host "[ERROR] Safety Net failed: cannot access Safety Net root." -ForegroundColor Red
            Write-LogEntry "ERROR" "Restore-SafetyNet" "Cannot access Safety Net root: $safetyRoot" -Distro $DistroName
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
    Write-Host "Create and verify a Safety Net tar for '$DistroName'." -ForegroundColor Yellow
    Write-Host "This does not unregister or import a distro." -ForegroundColor Yellow
    Write-WSLBMRequiredPhrasePrompt -RequiredPhrase $requiredPhrase -Message "Type the exact phrase below to create the Safety Net, or Q/CANCEL to abort:"

    $confirmationResult = Read-WSLBMExactConfirmation -RequiredPhrase $requiredPhrase -Prompt "Safety Net confirmation"
    if ($confirmationResult -eq "Cancelled") {
        Write-LogEntry "WARN" "Restore-SafetyNet-Confirm" "Safety Net creation cancelled before export confirmation" -Distro $DistroName
        return $false
    }

    if ($confirmationResult -eq "Mismatch") {
        Write-LogEntry "WARN" "Restore-SafetyNet-Confirm" "Safety Net creation confirmation phrase mismatch" -Distro $DistroName
        Write-Host "[ERROR] Safety Net confirmation phrase did not match. Safety Net creation cancelled before export." -ForegroundColor Red
        return $false
    }

    Write-LogEntry "WARN" "Restore-SafetyNet-Confirm" "Safety Net creation confirmed with exact phrase" -Distro $DistroName
    return $true
}

function Invoke-RestoreSafetyNetRollbackPrompt {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$InstallPath,

        [Parameter(Mandatory = $true)]
        [string]$SafetyNetPath,

        [object]$ReplacePathInfo = $null
    )

    $detectedBasePath = "<unavailable>"
    if ($null -ne $ReplacePathInfo -and
        -not [string]::IsNullOrWhiteSpace([string]$ReplacePathInfo.DetectedBasePath)) {
        $detectedBasePath = [string]$ReplacePathInfo.DetectedBasePath
    }

    Write-Host ""
    Write-Host "[Safety Net Rollback Available]" -ForegroundColor Yellow
    Write-Host "Target distro        : $DistroName" -ForegroundColor Yellow
    Write-Host "Original install path: $detectedBasePath" -ForegroundColor Yellow
    Write-Host "Rollback import path : $InstallPath" -ForegroundColor Yellow
    Write-Host "Safety Net tar       : $SafetyNetPath" -ForegroundColor Yellow

    if ($Global:DryRun) {
        Write-Host "DRY RUN: this would execute wsl --import to re-import the Safety Net tar." -ForegroundColor Yellow
    }
    else {
        Write-Host "This will execute wsl --import to re-import the Safety Net tar." -ForegroundColor Red
    }
    Write-LogEntry "WARN" "Restore-SafetyNet-Rollback" "Safety Net rollback option shown. Distro=$DistroName | InstallPath=$InstallPath | SafetyNet=$SafetyNetPath" -Distro $DistroName

    $answer = Read-Host "Attempt Safety Net rollback? Type Y to continue"
    if ($answer -cne "Y") {
        Write-Host "Safety Net rollback skipped by user." -ForegroundColor Yellow
        Write-LogEntry "WARN" "Restore-SafetyNet-Rollback" "Safety Net rollback skipped by user" -Distro $DistroName
        return New-SafetyNetRollbackResult
    }

    $requiredPhrase = "RESTORE SAFETY NET $DistroName"
    Write-WSLBMRequiredPhrasePrompt -RequiredPhrase $requiredPhrase -Message "Type the exact phrase below to execute Safety Net rollback:"
    $confirm = Read-Host "Safety Net rollback confirmation"
    if ($confirm -cne $requiredPhrase) {
        Write-Host "Safety Net rollback confirmation phrase did not match. No import was attempted." -ForegroundColor Red
        Write-LogEntry "WARN" "Restore-SafetyNet-Rollback" "Safety Net rollback confirmation phrase mismatch; import not attempted" -Distro $DistroName
        return New-SafetyNetRollbackResult
    }

    if ($Global:DryRun) {
        Write-Host "DRY RUN: would validate Safety Net archive integrity before rollback import." -ForegroundColor Yellow
        Write-Host "DRY RUN: would import Safety Net tar into $InstallPath for distro $DistroName" -ForegroundColor Yellow
        Write-LogEntry "INFO" "Restore-SafetyNet-Rollback" "DryRun would run Safety Net rollback import. Distro=$DistroName | InstallPath=$InstallPath | SafetyNet=$SafetyNetPath" -Distro $DistroName
        return New-SafetyNetRollbackResult -SkippedBecauseDryRun $true -ManualHintNeeded $false
    }

    if (-not (Test-SafetyNetArchive -safetyFile $SafetyNetPath)) {
        Write-Host "[ERROR] Safety Net rollback cancelled before import because archive integrity validation failed." -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-SafetyNet-Rollback" "Safety Net integrity validation failed before rollback import. SafetyNet=$SafetyNetPath" -Distro $DistroName
        return New-SafetyNetRollbackResult
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
        return New-SafetyNetRollbackResult -Completed $true -Attempted $true -ManualHintNeeded $false
    }
    catch {
        Write-Host "[ERROR] Safety Net rollback failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-SafetyNet-Rollback" "Safety Net rollback failed: $($_.Exception.Message)" -Distro $DistroName
        return New-SafetyNetRollbackResult -Attempted $true
    }
}

function Confirm-ReplaceRestoreDestructiveStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$InstallPath,

        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [string]$RestoreTempRoot = "",

        [string]$SafetyNetPath = "",

        [object]$ReplacePathInfo = $null
    )

    if ($Global:DryRun) {
        Write-Host "[DRY RUN] Restore-WholeDistro replace destructive phase preview:" -ForegroundColor Cyan
        Write-Host "  DRY RUN: would require exact phrase REPLACE $DistroName before destructive WSL changes" -ForegroundColor Yellow
        Write-Host "  DRY RUN: would shutdown WSL before replace restore" -ForegroundColor Yellow
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
        Write-LogEntry "INFO" "Restore-DryRun" "Replace restore dry run stopped before WSL changes. Target: $DistroName | InstallPath: $InstallPath | Backup: $BackupFile" -Distro $DistroName
        return $false
    }

    $requiredPhrase = "REPLACE $DistroName"

    Write-ReplaceRestoreDestructiveWarning `
        -DistroName $DistroName `
        -InstallPath $InstallPath `
        -BackupFile $BackupFile `
        -RequiredPhrase $requiredPhrase `
        -RestoreTempRoot $RestoreTempRoot `
        -SafetyNetPath $SafetyNetPath `
        -ReplacePathInfo $ReplacePathInfo

    $confirmationResult = Read-WSLBMExactConfirmation -RequiredPhrase $requiredPhrase
    if ($confirmationResult -eq "Cancelled") {
        Write-LogEntry "WARN" "Restore-Confirm" "Replace restore cancelled before unregister confirmation" -Distro $DistroName
        return $false
    }

    if ($confirmationResult -eq "Mismatch") {
        Write-LogEntry "WARN" "Restore-Confirm" "Replace restore confirmation phrase mismatch" -Distro $DistroName
        Write-Host "[ERROR] Confirmation phrase did not match. Restore cancelled before WSL changes." -ForegroundColor Red
        return $false
    }

    Write-LogEntry "WARN" "Restore-Confirm" "Destructive replace restore confirmed with exact phrase" -Distro $DistroName
    return $true
}

# =============================================================================
# Backup Operations
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
        Write-LogEntry `
            "INFO" `
            "Backup-Full-Space" `
            "Stage=$Stage | CheckPath=$($space.CheckPath) | Source=$($space.SourceKey) | Required=$(Format-Bytes $RequiredBytes) | Available=$(Format-Bytes $space.AvailableBytes) | Temp=$TempPath | Backup=$BackupFile" `
            -Distro $Distro

        if ($space.AvailableBytes -lt $RequiredBytes) {
            Write-Host "[ERROR] Not enough free space for FULL backup working files." -ForegroundColor Red
            Write-Host "  Stage      : $Stage" -ForegroundColor Yellow
            Write-Host "  Check path : $($space.CheckPath)" -ForegroundColor Yellow
            Write-Host "  Required   : $(Format-Bytes $RequiredBytes)" -ForegroundColor Yellow
            Write-Host "  Available  : $(Format-Bytes $space.AvailableBytes)" -ForegroundColor Yellow
            Write-Host "  Temp path  : $TempPath" -ForegroundColor Yellow
            Write-Host "  Backup file: $BackupFile" -ForegroundColor Yellow
            Write-LogEntry `
                "ERROR" `
                "Backup-Full-Space" `
                "Insufficient space. Stage=$Stage | CheckPath=$($space.CheckPath) | Required=$(Format-Bytes $RequiredBytes) | Available=$(Format-Bytes $space.AvailableBytes) | Temp=$TempPath | Backup=$BackupFile" `
                -Distro $Distro
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

    $backupDirRule = Test-WSLBMPathClassRule `
        -Path $BackupDir `
        -UsageKey "FullBackupDirectory" `
        -Label "FULL backup directory" `
        -ShapeRegex '^\d{4}-\d{2}-\d{2}_\d{4}-FULL$' `
        -ShapeRejectReason "FULL backup directory name is not a generated timestamp directory."
    $backupFileResolved = Get-NormalizedWindowsPathForComparison -Path $BackupFile -Label "FULL backup archive"
    if (-not $backupDirRule.Success) {
        return New-FullBackupDirectorySafetyResult -Success $false -Reason $backupDirRule.Reason
    }
    if (-not $backupFileResolved.Success) {
        return New-FullBackupDirectorySafetyResult -Success $false -Reason $backupFileResolved.Reason
    }

    $backupDirFull = $backupDirRule.NormalizedPath
    $backupFileFull = $backupFileResolved.NormalizedPath
    $comparison = [System.StringComparison]::OrdinalIgnoreCase

    $fileParent = Split-Path -Path $backupFileFull -Parent
    if (-not $fileParent.Equals($backupDirFull, $comparison)) {
        return New-FullBackupDirectorySafetyResult -Success $false -Reason "FULL backup archive must be directly under the generated backup directory."
    }
    try {
        $null = Get-WSLBMArchiveFormatFromPath -ArchivePath $backupFileFull
    }
    catch {
        return New-FullBackupDirectorySafetyResult -Success $false -Reason "FULL backup archive must use a supported extension (.7z/.tar)."
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

        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [string]$Distro = $Script:CurrentDistro
    )

    $backupSafety = Test-FullBackupDirectorySafety -BackupDir $BackupDir -BackupFile $BackupFile -Distro $Distro
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

    $tempDirRule = Test-WSLBMPathClassRule `
        -Path $tempDirFull `
        -UsageKey "TempWorkspace" `
        -Label "FULL backup temp directory" `
        -RequiredParentPath $backupSafety.NormalizedBackupDir `
        -RequiredParentReason "FULL backup temp directory must be a child of the generated backup directory." `
        -ShapeRegex '^WSLBM-FullBackup-[0-9a-fA-F]{32}$' `
        -ShapeRejectReason "FULL backup temp directory name does not match controlled prefix."
    if (-not $tempDirRule.Success) {
        return [pscustomobject]@{ Success = $false; TempDir = $tempDirFull; TempTar = $tempTarFull; Reason = $tempDirRule.Reason }
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
        [string]$BackupFile,
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
    if ([string]::IsNullOrWhiteSpace($BackupDir) -or [string]::IsNullOrWhiteSpace($BackupFile)) {
        Write-FullBackupCleanupWarning "Full backup temp cleanup requires BackupDir and BackupFile for boundary checks. TempDir=$TempDir | TempTar=$TempTar"
        return
    }

    $safety = Test-FullBackupTempArtifactSafety -TempDir $TempDir -TempTar $TempTar -BackupDir $BackupDir -BackupFile $BackupFile -Distro $Distro
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
        [object]$CompressionPlan,

        [string]$TarEntryName = "wsl-export.tar",

        [string]$ArchiveDisplayName = "wsl-full.7z",

        [string]$OperationName = "Backup-Full-7z",

        [string]$Description = "Compress full backup tar",

        [string]$Distro = $Script:CurrentDistro
    )

    if ([string]::IsNullOrWhiteSpace($TarEntryName) -or $TarEntryName -match '[\\/]') {
        throw "Compression tar entry name must be a single file name."
    }

    if ($Global:DryRun) {
        Write-Host "DRY RUN: would compress $TarEntryName into $BackupFile" -ForegroundColor Yellow
        Write-Host "DRY RUN: CompressionLevel=$($CompressionPlan.CompressionLevel), ResourceUsage=$($CompressionPlan.ResourceUsage)" -ForegroundColor Yellow
        Write-Host "DRY RUN: mx$($CompressionPlan.Level), threads=$($CompressionPlan.Threads)" -ForegroundColor Yellow
        return [pscustomobject]@{
            Success              = $true
            ExitCode             = $null
            SkippedBecauseDryRun = $true
        }
    }

    $sevenZipExe = Resolve-FullBackup7zPath
    $rawArgs = @("a", $BackupFile, $TarEntryName, $CompressionPlan.MxArg, $CompressionPlan.MmtArg, "-bsp1", "-y")

    Write-Host "Compressing temporary tar to $ArchiveDisplayName (Press Q to cancel)..." -ForegroundColor Cyan
    Write-Host "  Compression Level: $($CompressionPlan.CompressionLevel) (mx$($CompressionPlan.Level))" -ForegroundColor DarkGray
    Write-Host "  Resource Usage   : $($CompressionPlan.ResourceUsage), threads=$($CompressionPlan.Threads)" -ForegroundColor DarkGray
    $compressionLog = @(
        "Compressing $TarEntryName to $BackupFile"
        "CompressionLevel=$($CompressionPlan.CompressionLevel)"
        "ResourceUsage=$($CompressionPlan.ResourceUsage)"
        "mx$($CompressionPlan.Level)"
        "Threads=$($CompressionPlan.Threads)"
    ) -join " | "
    Write-LogEntry "INFO" $OperationName $compressionLog -Distro $Distro

    $runnerResult = Invoke-WSLBMNativeProcessChecked `
        -FilePath $sevenZipExe `
        -Arguments $rawArgs `
        -OperationName $OperationName `
        -Description $Description `
        -AllowCancel `
        -RegisterActiveProcess `
        -WorkingDirectory $TempDir `
        -Distro $Distro
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

function New-ArchiveStrategy {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("7z", "tar")]
        [string]$ArchiveFormat,

        [ValidateSet("WholeDistro", "Path")]
        [string]$WorkloadType = "Path",

        [AllowNull()]
        [object]$CompressionTool = $null,

        [AllowNull()]
        [object]$TarTool = $null,

        [switch]$PromptForProfile
    )

    $compressionPlan = if ($ArchiveFormat -eq "7z") {
        Get-WSLBM7zCompressionPlan -WorkloadType $WorkloadType -PromptForProfile:$PromptForProfile
    }
    else {
        $null
    }
    if ($ArchiveFormat -eq "7z" -and $null -eq $compressionPlan) {
        return $null
    }

    return [pscustomobject]@{
        ArchiveFormat      = $ArchiveFormat
        CompressionLevel   = if ($null -ne $compressionPlan) { $compressionPlan.CompressionLevel } else { $null }
        ResourceUsage      = if ($null -ne $compressionPlan) { $compressionPlan.ResourceUsage } else { $null }
        CompressionMx      = if ($null -ne $compressionPlan) { $compressionPlan.Level } else { $null }
        CompressionThreads = if ($null -ne $compressionPlan) { $compressionPlan.Threads } else { $null }
        CompressionTool    = $CompressionTool
        TarTool            = $TarTool
        IntegrityCheck     = if ($ArchiveFormat -eq "7z") { "7z t" } else { "7z t tar archive" }
        DryRunPreview      = if ($WorkloadType -eq "Path") {
            if ($ArchiveFormat -eq "7z") { "WSL tar stdout -> path.tar -> 7z archive" } else { "WSL tar stdout -> tar archive" }
        } else {
            "wsl --export tar -> 7z archive"
        }
    }
}

function New-BackupPlan {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("WholeDistro", "Path")]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [string]$SourceDistro,

        [AllowNull()]
        [string]$SourceLinuxPath = $null,

        [Parameter(Mandatory = $true)]
        [string]$DestinationDir,

        [Parameter(Mandatory = $true)]
        [string]$ArchivePath,

        [Parameter(Mandatory = $true)]
        [object]$ArchiveStrategy,

        [string]$TempDir = "", [string]$TempTar = "", [string[]]$WslPreviewArgs = @(), [string[]]$CompressionPreviewArgs = @()
    )

    return [pscustomobject]@{
        Type                   = $Type
        SourceDistro           = $SourceDistro
        SourceLinuxPath        = $SourceLinuxPath
        DestinationDir         = $DestinationDir
        ArchivePath            = $ArchivePath
        ArchiveStrategy        = $ArchiveStrategy
        TempDir                = $TempDir
        TempTar                = $TempTar
        WslPreviewArgs         = @($WslPreviewArgs)
        CompressionPreviewArgs = @($CompressionPreviewArgs)
    }
}

function New-RestorePlan {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("WholeDistro", "Path")]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [string]$TargetDistro,

        [AllowNull()]
        [string]$TargetLinuxPath = $null,

        [Parameter(Mandatory = $true)]
        [string]$ArchivePath,

        [Parameter(Mandatory = $true)]
        [object]$ArchiveStrategy,

        [string]$RestoreMode = "",

        [string]$ArchiveTopLevelEntry = "",

        [string]$UserInputPath = "",

        [string]$ExpectedFinalPath = "",

        [bool]$StripTopLevelEntry = $false
    )

    return [pscustomobject]@{
        Type                 = $Type
        TargetDistro         = $TargetDistro
        TargetLinuxPath      = $TargetLinuxPath
        ArchivePath          = $ArchivePath
        ArchiveStrategy      = $ArchiveStrategy
        RestoreMode          = $RestoreMode
        ArchiveTopLevelEntry = $ArchiveTopLevelEntry
        UserInputPath        = $UserInputPath
        ExpectedFinalPath    = $ExpectedFinalPath
        StripTopLevelEntry   = $StripTopLevelEntry
    }
}

function Test-LinuxAbsolutePathLiteral {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [string]$Path
    )

    $expansionMessage = "Path expansion is intentionally disabled. Enter a full Linux absolute path starting with /."
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]@{ Success = $false; Path = ""; Reason = "Path is empty. $expansionMessage" }
    }

    $candidate = $Path.Trim()
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        return [pscustomobject]@{ Success = $false; Path = ""; Reason = "Path is empty. $expansionMessage" }
    }
    if ($candidate -match "[\x00-\x1F\x7F]" -or $candidate -match "\r|\n") {
        return [pscustomobject]@{ Success = $false; Path = ""; Reason = "Control characters and newlines are not allowed. $expansionMessage" }
    }
    if (-not $candidate.StartsWith("/", [System.StringComparison]::Ordinal)) {
        return [pscustomobject]@{ Success = $false; Path = ""; Reason = $expansionMessage }
    }
    if ($candidate.Contains("~") -or $candidate.Contains('$')) {
        return [pscustomobject]@{ Success = $false; Path = ""; Reason = $expansionMessage }
    }
    if ($candidate.Contains("..")) {
        return [pscustomobject]@{ Success = $false; Path = ""; Reason = "Path traversal '..' is not allowed. $expansionMessage" }
    }

    if ($candidate -ne "/") {
        $candidate = $candidate.TrimEnd("/")
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            $candidate = "/"
        }
    }

    if ($candidate -ne "/" -and $candidate.Contains("//")) {
        return [pscustomobject]@{ Success = $false; Path = ""; Reason = "Empty path segments are not allowed. $expansionMessage" }
    }

    return [pscustomobject]@{ Success = $true; Path = $candidate; Reason = "" }
}

function Join-LinuxPathLiteral {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Parent,

        [Parameter(Mandatory = $true)]
        [string]$Child
    )

    if ($Child -eq ".") { return $Parent }
    if ($Parent -eq "/") { return "/$Child" }
    return "$Parent/$Child"
}

function Get-LinuxPathParentLiteral {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($Path -eq "/") {
        return ""
    }

    $lastSlash = $Path.LastIndexOf("/")
    if ($lastSlash -le 0) {
        return "/"
    }

    return $Path.Substring(0, $lastSlash)
}

function Get-DefaultPathBackupArchiveBaseName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceLinuxPath
    )

    if ($SourceLinuxPath -eq "/") {
        return "root"
    }

    $leaf = ($SourceLinuxPath.TrimEnd("/") -split "/")[-1]
    if ([string]::IsNullOrWhiteSpace($leaf)) {
        return "path"
    }
    return $leaf
}

function Resolve-BackupArchiveBaseName {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$BaseName
    )

    $candidate = $BaseName.Trim()
    if ($candidate.EndsWith(".7z", [System.StringComparison]::OrdinalIgnoreCase)) {
        $candidate = $candidate.Substring(0, $candidate.Length - 3)
    }

    if ([string]::IsNullOrWhiteSpace($candidate)) {
        return [pscustomobject]@{ Success = $false; BaseName = ""; ArchiveName = ""; Reason = "Archive basename cannot be empty." }
    }
    if ($candidate.Length -gt 120) {
        return [pscustomobject]@{ Success = $false; BaseName = ""; ArchiveName = ""; Reason = "Archive basename is too long; use 120 characters or fewer." }
    }
    if ($candidate -match '[\\/:*?"<>|]') {
        return [pscustomobject]@{ Success = $false; BaseName = ""; ArchiveName = ""; Reason = 'Archive basename cannot contain \ / : * ? " < > |.' }
    }
    if ($candidate -match '[\x00-\x1F\x7F]') {
        return [pscustomobject]@{ Success = $false; BaseName = ""; ArchiveName = ""; Reason = "Archive basename cannot contain control characters." }
    }
    if ($candidate.EndsWith(".", [System.StringComparison]::Ordinal) -or
        $candidate.EndsWith(" ", [System.StringComparison]::Ordinal)) {
        return [pscustomobject]@{ Success = $false; BaseName = ""; ArchiveName = ""; Reason = "Archive basename cannot end with a dot or space." }
    }

    $reservedStem = [System.IO.Path]::GetFileNameWithoutExtension($candidate)
    if ([string]::IsNullOrWhiteSpace($reservedStem)) { $reservedStem = $candidate }
    if ($reservedStem -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
        return [pscustomobject]@{ Success = $false; BaseName = ""; ArchiveName = ""; Reason = "Archive basename uses a reserved Windows device name." }
    }

    return [pscustomobject]@{ Success = $true; BaseName = $candidate; ArchiveName = "$candidate.7z"; Reason = "" }
}

function Read-BackupArchiveBaseName {
    param([Parameter(Mandatory = $true)][string]$Title, [Parameter(Mandatory = $true)][string]$DefaultBaseName)

    while ($true) {
        Write-Host ""
        Write-Host "[$Title]" -ForegroundColor Cyan
        Write-Host "Default archive basename: $DefaultBaseName" -ForegroundColor DarkGray
        Write-Host "Press Enter to use the default, or type a custom basename. You may include or omit the .7z suffix." -ForegroundColor DarkGray
        $inputName = Read-Host "Archive basename"
        if ($inputName -in @("q", "Q", "cancel", "CANCEL")) {
            return [pscustomobject]@{ Success = $false; BaseName = ""; ArchiveName = ""; Cancelled = $true; Reason = "Cancelled." }
        }

        $candidate = if ([string]::IsNullOrWhiteSpace($inputName)) { $DefaultBaseName } else { $inputName }
        $resolved = Resolve-BackupArchiveBaseName -BaseName $candidate
        if ($resolved.Success) {
            Write-Host "Archive file will be: $($resolved.ArchiveName)" -ForegroundColor Green
            return [pscustomobject]@{ Success = $true; BaseName = $resolved.BaseName; ArchiveName = $resolved.ArchiveName; Cancelled = $false; Reason = "" }
        }

        Write-Host "[ERROR] $($resolved.Reason)" -ForegroundColor Red
    }
}

function Read-PathBackupArchiveBaseName {
    param([Parameter(Mandatory = $true)][string]$SourceLinuxPath)

    return Read-BackupArchiveBaseName `
        -Title "Path backup archive name" `
        -DefaultBaseName (Get-DefaultPathBackupArchiveBaseName -SourceLinuxPath $SourceLinuxPath)
}

function Get-LinuxRecentPathsForDistro {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName
    )

    if ($null -eq $Global:Config.RecentPaths) {
        $Global:Config.RecentPaths = @{}
    }
    if (-not $Global:Config.RecentPaths.ContainsKey($DistroName)) {
        return @()
    }
    return @($Global:Config.RecentPaths[$DistroName] | Select-Object -First 10)
}

function Add-LinuxRecentPathForDistro {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$LinuxPath
    )

    $validation = Test-LinuxAbsolutePathLiteral -Path $LinuxPath
    if (-not $validation.Success) { return }

    if ($null -eq $Global:Config.RecentPaths) {
        $Global:Config.RecentPaths = @{}
    }

    $now = (Get-Date).ToUniversalTime().ToString("o")
    $existing = @(Get-LinuxRecentPathsForDistro -DistroName $DistroName | Where-Object {
        -not [string]::Equals([string]$_.Path, $validation.Path, [System.StringComparison]::Ordinal)
    })
    $updated = @([pscustomobject]@{ Path = $validation.Path; LastUsed = $now }) + $existing
    $Global:Config.RecentPaths[$DistroName] = @($updated | Select-Object -First 10)
    Save-Config
}

function Clear-LinuxRecentPaths {
    $Global:Config.RecentPaths = @{}
    Save-Config
    Write-Host "Recent Linux paths cleared." -ForegroundColor Green
    Write-LogEntry "INFO" "Config" "Cleared recent Linux paths."
}

function Test-WSLBMWindowsPathLike {
    param(
        [AllowNull()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $text = $Path.Trim()
    return ($text -match '^[A-Za-z]:' -or
        $text.StartsWith("\\", [System.StringComparison]::Ordinal) -or
        $text.StartsWith("//", [System.StringComparison]::Ordinal))
}

function Read-LinuxPathFromSelectionMenu {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Backup-Path", "Restore-Path")]
        [string]$Purpose
    )

    while ($true) {
        Write-Host ""
        Write-Host "Enter Linux absolute path. Options:" -ForegroundColor Cyan
        Write-Host "  [1] /home/<current-wsl-user>"
        Write-Host "  [2] /root"
        Write-Host "  [3] Recent paths"
        $recent = @(Get-LinuxRecentPathsForDistro -DistroName $DistroName)
        $recentLetters = @{}
        for ($i = 0; $i -lt $recent.Count; $i++) {
            $letter = [char]([int][char]'a' + $i)
            $key = "3$letter"
            $recentLetters[$key] = [string]$recent[$i].Path
            $lastUsed = [string]$recent[$i].LastUsed
            if ([string]::IsNullOrWhiteSpace($lastUsed)) { $lastUsed = "unknown" }
            Write-Host ("      [{0}] {1}     (last used {2})" -f $key, $recent[$i].Path, $lastUsed) -ForegroundColor DarkGray
        }
        if ($recent.Count -eq 0) {
            Write-Host "      (none)" -ForegroundColor DarkGray
        }
        Write-Host "  [4] Type a path manually"
        Write-Host "  [Q] Cancel"

        $choice = Read-Host "$Purpose path"
        if ($choice -in @("q", "Q", "cancel", "CANCEL")) {
            return [pscustomobject]@{ Success = $false; LinuxPath = ""; UserInputPath = ""; Cancelled = $true }
        }

        $candidate = $null
        if ($choice -eq "1") {
            try {
                $wslUser = Get-WSLUser
                $candidate = "/home/$wslUser"
            }
            catch {
                Write-Host "[ERROR] Cannot resolve current WSL user: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "Choose another option or try again." -ForegroundColor Yellow
                continue
            }
        }
        elseif ($choice -eq "2") {
            $candidate = "/root"
        }
        elseif ($recentLetters.ContainsKey($choice)) {
            $candidate = $recentLetters[$choice]
            Write-Host "Selected recent path: $candidate" -ForegroundColor DarkGray
            $replacement = Read-Host "Press Enter to use it, or type a replacement full Linux absolute path"
            if (-not [string]::IsNullOrWhiteSpace($replacement)) {
                $candidate = $replacement
            }
        }
        elseif ($choice -eq "3") {
            if ($recent.Count -eq 0) {
                Write-Host "No recent paths for this distro." -ForegroundColor Yellow
            }
            else {
                Write-Host "Enter one of the recent path keys, for example 3a." -ForegroundColor Yellow
            }
            continue
        }
        elseif ($choice -eq "4") {
            $candidate = Read-Host "Type a full Linux absolute path"
        }
        else {
            Write-Host "Invalid option." -ForegroundColor Red
            continue
        }

        if (Test-WSLBMWindowsPathLike -Path $candidate) {
            Write-Host "[ERROR] Windows paths are not supported for $Purpose. Enter a WSL Linux absolute path starting with /, or Q to cancel." -ForegroundColor Red
            continue
        }

        $validation = Test-LinuxAbsolutePathLiteral -Path $candidate
        if (-not $validation.Success) {
            Write-Host "[ERROR] $($validation.Reason)" -ForegroundColor Red
            continue
        }

        return [pscustomobject]@{ Success = $true; LinuxPath = $validation.Path; UserInputPath = $candidate; Cancelled = $false }
    }
}

function Get-LinuxTarSourceSpec {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceLinuxPath
    )

    if ($SourceLinuxPath -eq "/") {
        return [pscustomobject]@{ Parent = "/"; Entry = "." }
    }

    $lastSlash = $SourceLinuxPath.LastIndexOf("/")
    $parent = if ($lastSlash -le 0) { "/" } else { $SourceLinuxPath.Substring(0, $lastSlash) }
    $entry = $SourceLinuxPath.Substring($lastSlash + 1)
    return [pscustomobject]@{ Parent = $parent; Entry = $entry }
}

function Get-WSLPathTarToolInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName
    )

    if ($Global:DryRun) {
        return [pscustomobject]@{ Name = "tar"; Version = "unknown" }
    }

    try {
        $result = Invoke-WSLBMNativeProcessChecked `
            -FilePath "wsl.exe" `
            -Arguments @("-d", $DistroName, "--", "tar", "--version") `
            -OperationName "Tar-Version" `
            -Description "Read WSL tar version" `
            -TimeoutSeconds 30 `
            -Distro $DistroName

        if ($result.Success) {
            $firstLine = @((([string]$result.CombinedOutput) -split "\r?\n") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
            if ($firstLine.Count -gt 0) {
                return [pscustomobject]@{ Name = "tar"; Version = [string]$firstLine[0] }
            }
        }
    }
    catch {
        $null = $_
    }

    return [pscustomobject]@{ Name = "tar"; Version = "unknown" }
}

function Invoke-WSLBMNativeStdoutToFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [string]$OperationName = "NativeStdoutToFile",

        [string]$Description = "",

        [int]$TimeoutSeconds = $Script:DefaultWSLCommandTimeoutSeconds,

        [string]$Distro = $Script:CurrentDistro
    )

    $argumentString = ConvertTo-WSLBMNativeArgumentString -Arguments $Arguments
    $commandPreview = if ([string]::IsNullOrWhiteSpace($argumentString)) { $FilePath } else { "$FilePath $argumentString" }
    if ($Global:DryRun) {
        Write-Host "DRY RUN: would stream stdout from $commandPreview to $OutputPath" -ForegroundColor Yellow
        return [pscustomobject]@{ Success = $true; ExitCode = $null; SkippedBecauseDryRun = $true; TimedOut = $false; Cancelled = $false; StdErr = ""; CombinedOutput = "" }
    }

    $process = $null
    $fileStream = $null
    $stdoutTask = $null
    $stderrTask = $null
    $timedOut = $false
    $cancelled = $false
    $startedAt = Get-Date
    $previousActiveProcess = $Global:BackupState.ActiveProcess
    $argumentMode = "Unknown"

    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $FilePath
        $argumentMode = Set-WSLBMProcessStartInfoArguments -StartInfo $startInfo -Arguments $Arguments
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.CreateNoWindow = $true

        $fileStream = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        Write-LogEntry "INFO" $OperationName "$Description | ArgumentMode=$argumentMode | $commandPreview" -Distro $Distro
        if (-not $process.Start()) {
            throw "Process did not start."
        }
        $Global:BackupState.ActiveProcess = $process
        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($fileStream)
        $stderrTask = $process.StandardError.ReadToEndAsync()

        while (-not $process.HasExited) {
            if ($TimeoutSeconds -gt 0 -and ((Get-Date) - $startedAt).TotalSeconds -ge $TimeoutSeconds) {
                $timedOut = $true
                Stop-WSLBMProcessTree -Process $process -OperationName $OperationName
                break
            }
            if (Test-WSLBMUserCancelRequested) {
                $cancelled = $true
                Write-Host "`n[Abort] User requested cancel..." -ForegroundColor Yellow
                Stop-WSLBMProcessTree -Process $process -OperationName $OperationName
                break
            }
            Start-Sleep -Milliseconds 200
        }

        $null = $process.WaitForExit(5000)
        if ($null -ne $stdoutTask) { $null = $stdoutTask.Wait(5000) }
        if ($null -ne $fileStream) { $fileStream.Flush() }
        if ($null -ne $stderrTask) { $null = $stderrTask.Wait(5000) }
        $stdoutCompleted = ($null -ne $stdoutTask -and $stdoutTask.IsCompleted)
        $stdErr = if ($null -ne $stderrTask -and $stderrTask.IsCompleted) { [string]$stderrTask.Result } else { "" }
        $exitCode = if ($process.HasExited) { $process.ExitCode } else { $null }
        return [pscustomobject]@{
            Success              = (-not $timedOut -and -not $cancelled -and $stdoutCompleted -and $null -ne $exitCode -and $exitCode -eq 0)
            ExitCode             = $exitCode
            SkippedBecauseDryRun = $false
            TimedOut             = $timedOut
            Cancelled            = $cancelled
            StdErr               = $stdErr
            CombinedOutput       = if ($stdoutCompleted) { $stdErr } else { "stdout stream did not complete." }
        }
    }
    catch {
        Write-LogEntry "ERROR" $OperationName "$Description failed: $($_.Exception.Message)" -Distro $Distro
        return [pscustomobject]@{ Success = $false; ExitCode = $null; SkippedBecauseDryRun = $false; TimedOut = $timedOut; Cancelled = $cancelled; StdErr = $_.Exception.Message; CombinedOutput = $_.Exception.Message }
    }
    finally {
        if ($null -ne $fileStream) { $fileStream.Dispose() }
        if ($null -ne $process) { $process.Dispose() }
        $Global:BackupState.ActiveProcess = $previousActiveProcess
    }
}

function Invoke-WSLBMFileToNativeStdin {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$InputPath,

        [string]$OperationName = "NativeFileToStdin",

        [string]$Description = "",

        [int]$TimeoutSeconds = $Script:DefaultWSLCommandTimeoutSeconds,

        [string]$Distro = $Script:CurrentDistro
    )

    $argumentString = ConvertTo-WSLBMNativeArgumentString -Arguments $Arguments
    $commandPreview = if ([string]::IsNullOrWhiteSpace($argumentString)) { $FilePath } else { "$FilePath $argumentString" }
    if ($Global:DryRun) {
        Write-Host "DRY RUN: would stream $InputPath into stdin of $commandPreview" -ForegroundColor Yellow
        return [pscustomobject]@{ Success = $true; ExitCode = $null; SkippedBecauseDryRun = $true; TimedOut = $false; Cancelled = $false; CombinedOutput = "" }
    }

    $process = $null
    $inputStream = $null
    $stdinTask = $null
    $stdoutTask = $null
    $stderrTask = $null
    $timedOut = $false
    $cancelled = $false
    $startedAt = Get-Date
    $previousActiveProcess = $Global:BackupState.ActiveProcess
    $argumentMode = "Unknown"

    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $FilePath
        $argumentMode = Set-WSLBMProcessStartInfoArguments -StartInfo $startInfo -Arguments $Arguments
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardInput = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.CreateNoWindow = $true

        $inputStream = [System.IO.File]::OpenRead($InputPath)
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        Write-LogEntry "INFO" $OperationName "$Description | ArgumentMode=$argumentMode | $commandPreview" -Distro $Distro
        if (-not $process.Start()) {
            throw "Process did not start."
        }
        $Global:BackupState.ActiveProcess = $process
        $stdinTask = $inputStream.CopyToAsync($process.StandardInput.BaseStream)
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()

        while (-not $process.HasExited) {
            if ($null -ne $stdinTask -and $stdinTask.IsCompleted) {
                try { $process.StandardInput.Close() } catch { $null = $_ }
            }
            if ($TimeoutSeconds -gt 0 -and ((Get-Date) - $startedAt).TotalSeconds -ge $TimeoutSeconds) {
                $timedOut = $true
                Stop-WSLBMProcessTree -Process $process -OperationName $OperationName
                break
            }
            if (Test-WSLBMUserCancelRequested) {
                $cancelled = $true
                Write-Host "`n[Abort] User requested cancel..." -ForegroundColor Yellow
                Stop-WSLBMProcessTree -Process $process -OperationName $OperationName
                break
            }
            Start-Sleep -Milliseconds 200
        }

        $null = $process.WaitForExit(5000)
        if ($null -ne $stdinTask) { $null = $stdinTask.Wait(5000) }
        try { $process.StandardInput.Close() } catch { $null = $_ }
        if ($null -ne $stdoutTask) { $null = $stdoutTask.Wait(5000) }
        if ($null -ne $stderrTask) { $null = $stderrTask.Wait(5000) }
        $stdinCompleted = ($null -ne $stdinTask -and $stdinTask.IsCompleted)
        $stdOut = if ($null -ne $stdoutTask -and $stdoutTask.IsCompleted) { [string]$stdoutTask.Result } else { "" }
        $stdErr = if ($null -ne $stderrTask -and $stderrTask.IsCompleted) { [string]$stderrTask.Result } else { "" }
        $combined = (($stdOut, $stdErr) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join [Environment]::NewLine
        if (-not $stdinCompleted) {
            $combined = (($combined, "stdin stream did not complete.") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join [Environment]::NewLine
        }
        $exitCode = if ($process.HasExited) { $process.ExitCode } else { $null }
        return [pscustomobject]@{
            Success              = (-not $timedOut -and -not $cancelled -and $stdinCompleted -and $null -ne $exitCode -and $exitCode -eq 0)
            ExitCode             = $exitCode
            SkippedBecauseDryRun = $false
            TimedOut             = $timedOut
            Cancelled            = $cancelled
            CombinedOutput       = $combined
        }
    }
    catch {
        Write-LogEntry "ERROR" $OperationName "$Description failed: $($_.Exception.Message)" -Distro $Distro
        return [pscustomobject]@{ Success = $false; ExitCode = $null; SkippedBecauseDryRun = $false; TimedOut = $timedOut; Cancelled = $cancelled; CombinedOutput = $_.Exception.Message }
    }
    finally {
        if ($null -ne $inputStream) { $inputStream.Dispose() }
        if ($null -ne $process) { $process.Dispose() }
        $Global:BackupState.ActiveProcess = $previousActiveProcess
    }
}

function Read-FullBackupArchiveBaseName {
    return Read-BackupArchiveBaseName -Title "WholeDistro backup archive name" -DefaultBaseName "wsl-full"
}

function Invoke-WSLPathTarCreateArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$SourceLinuxPath,

        [Parameter(Mandatory = $true)]
        [string]$ArchivePath
    )

    $spec = Get-LinuxTarSourceSpec -SourceLinuxPath $SourceLinuxPath
    $tarArgs = @("-d", $DistroName, "--", "tar", "-cpf", "-", "-C", $spec.Parent, "--", $spec.Entry)
    Write-Host "Creating Path backup with WSL tar (Press Q to cancel)..." -ForegroundColor Cyan
    Write-Host "  Source : ${DistroName}:$SourceLinuxPath" -ForegroundColor DarkGray
    Write-Host "  Archive: $ArchivePath" -ForegroundColor DarkGray
    return Invoke-WSLBMNativeStdoutToFile `
        -FilePath "wsl.exe" `
        -Arguments $tarArgs `
        -OutputPath $ArchivePath `
        -OperationName "Backup-Path-Tar" `
        -Description "Create Path backup archive with WSL tar" `
        -TimeoutSeconds $Script:DefaultWSLCommandTimeoutSeconds `
        -Distro $DistroName
}

function Invoke-WSLPathTarExtractArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$ArchivePath,

        [Parameter(Mandatory = $true)]
        [string]$TargetLinuxPath,

        [switch]$StripTopLevelEntry
    )

    $mkdirResult = Invoke-GuardedWSLCommand `
        -Description "Create Restore-Path target directory" `
        -Arguments @("-d", $DistroName, "--", "mkdir", "-p", "--", $TargetLinuxPath) `
        -Distro $DistroName
    if (-not $mkdirResult.Success) {
        return $mkdirResult
    }

    $tarArgs = @("-d", $DistroName, "--", "tar", "-xpf", "-", "-C", $TargetLinuxPath)
    if ($StripTopLevelEntry) {
        $tarArgs += "--strip-components=1"
    }
    Write-Host "Extracting Path backup with WSL tar (Press Q to cancel)..." -ForegroundColor Cyan
    Write-Host "  Target : ${DistroName}:$TargetLinuxPath" -ForegroundColor DarkGray
    Write-Host "  Strip top-level entry: $(if ($StripTopLevelEntry) { 'Yes' } else { 'No' })" -ForegroundColor DarkGray
    return Invoke-WSLBMFileToNativeStdin `
        -FilePath "wsl.exe" `
        -Arguments $tarArgs `
        -InputPath $ArchivePath `
        -OperationName "Restore-Path-Tar" `
        -Description "Extract Path backup archive with WSL tar" `
        -TimeoutSeconds $Script:DefaultWSLCommandTimeoutSeconds `
        -Distro $DistroName
}

function Resolve-WSLBMWindowsTarPath {
    $tarCommand = Get-Command "tar.exe" -ErrorAction SilentlyContinue
    if ($tarCommand -and -not [string]::IsNullOrWhiteSpace([string]$tarCommand.Source)) {
        return [string]$tarCommand.Source
    }

    $tarCommand = Get-Command "tar" -ErrorAction SilentlyContinue
    if ($tarCommand -and -not [string]::IsNullOrWhiteSpace([string]$tarCommand.Source)) {
        return [string]$tarCommand.Source
    }

    throw "Direct .7z tree restore requires Windows tar.exe to stream the extracted temp tree into WSL tar."
}

function New-RestorePathDirectTreeExtractResult {
    param(
        [bool]$Success,
        [object]$ExitCode = $null,
        [bool]$TimedOut = $false,
        [bool]$Cancelled = $false,
        [string]$ExtractRoot = "",
        [object]$TempPathInfo = $null,
        [string]$Reason = ""
    )

    return [pscustomobject]@{
        Success      = $Success
        ExitCode     = $ExitCode
        TimedOut     = $TimedOut
        Cancelled    = $Cancelled
        ExtractRoot  = $ExtractRoot
        TempPathInfo = $TempPathInfo
        Reason       = $Reason
    }
}

function Invoke-RestorePathDirect7zTreeExtract {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [Parameter(Mandatory = $true)]
        [object]$TempPathInfo,

        [long]$EstimatedSizeBytes = -1,

        [string]$Distro = $Script:CurrentDistro
    )

    try {
        $tempDir = [string]$TempPathInfo.TempDir
        $extractRoot = Join-Path $tempDir "direct-tree"
        $tempDirResolved = Get-NormalizedWindowsPathForComparison -Path $tempDir -Label "Restore-Path temp directory"
        $extractRootResolved = Get-NormalizedWindowsPathForComparison -Path $extractRoot -Label "Restore-Path direct tree extract root"
        if (-not $tempDirResolved.Success -or -not $extractRootResolved.Success) {
            throw "Cannot normalize Restore-Path direct tree temp paths."
        }
        if (-not (Test-PathIsSameOrChild -ChildPath $extractRootResolved.NormalizedPath -ParentPath $tempDirResolved.NormalizedPath)) {
            throw "Direct .7z extract root is not inside the controlled Restore-Path temp workspace."
        }

        $archiveItem = Get-Item -LiteralPath $BackupFile -ErrorAction Stop
        $spaceEstimate = if ($EstimatedSizeBytes -gt 0) { [long]$EstimatedSizeBytes } else { [long]$archiveItem.Length }
        if ($spaceEstimate -gt 0 -and $spaceEstimate -lt ([long]::MaxValue / 2)) {
            $spaceEstimate = [long]($spaceEstimate * 2)
        }
        if (-not (Test-PathFreeSpaceForRestorePayload -Path $tempDir -TarSizeBytes $spaceEstimate -Label "Restore-Path direct tree temp root" -Distro $Distro)) {
            return New-RestorePathDirectTreeExtractResult -Success $false -ExtractRoot $extractRoot -TempPathInfo $TempPathInfo -Reason "Insufficient temp workspace space."
        }

        if (Test-Path -LiteralPath $tempDir -ErrorAction SilentlyContinue) {
            throw "Controlled Restore-Path TEMP directory already exists: $tempDir"
        }
        [System.IO.Directory]::CreateDirectory($extractRoot) | Out-Null

        $sevenZipExe = Resolve-WSLBMSevenZipPath
        Write-Host "Extracting direct .7z file tree to temporary workspace..." -ForegroundColor Cyan
        Write-Host "  Temp: $extractRoot" -ForegroundColor DarkGray
        $extractResult = Invoke-WSLBMNativeProcessChecked `
            -FilePath $sevenZipExe `
            -Arguments @("x", $BackupFile, "-o$extractRoot", "-y", "-bd") `
            -OperationName "Restore-Path-Direct7z-Extract" `
            -Description "Extract direct .7z tree to Restore-Path temp workspace" `
            -TimeoutSeconds $Script:RestoreExtractTimeoutSeconds `
            -AllowCancel `
            -RegisterActiveProcess `
            -Distro $Distro

        if ($extractResult.TimedOut) {
            return New-RestorePathDirectTreeExtractResult `
                -Success $false `
                -ExitCode $extractResult.ExitCode `
                -TimedOut $true `
                -ExtractRoot $extractRoot `
                -TempPathInfo $TempPathInfo `
                -Reason "7z direct tree extraction timed out."
        }
        if ($extractResult.Cancelled) {
            return New-RestorePathDirectTreeExtractResult `
                -Success $false `
                -ExitCode $extractResult.ExitCode `
                -Cancelled $true `
                -ExtractRoot $extractRoot `
                -TempPathInfo $TempPathInfo `
                -Reason "7z direct tree extraction was cancelled."
        }
        if (-not $extractResult.Success) {
            return New-RestorePathDirectTreeExtractResult -Success $false -ExitCode $extractResult.ExitCode -ExtractRoot $extractRoot -TempPathInfo $TempPathInfo -Reason $extractResult.ErrorMessage
        }
        if (-not (Test-Path -LiteralPath $extractRoot -PathType Container)) {
            return New-RestorePathDirectTreeExtractResult -Success $false -ExitCode $extractResult.ExitCode -ExtractRoot $extractRoot -TempPathInfo $TempPathInfo -Reason "Direct .7z extract root was not created."
        }

        $firstChild = Get-ChildItem -LiteralPath $extractRoot -Force -ErrorAction Stop | Select-Object -First 1
        if ($null -eq $firstChild) {
            return New-RestorePathDirectTreeExtractResult -Success $false -ExitCode $extractResult.ExitCode -ExtractRoot $extractRoot -TempPathInfo $TempPathInfo -Reason "Direct .7z archive extracted no files."
        }

        return New-RestorePathDirectTreeExtractResult -Success $true -ExitCode $extractResult.ExitCode -ExtractRoot $extractRoot -TempPathInfo $TempPathInfo
    }
    catch {
        return New-RestorePathDirectTreeExtractResult -Success $false -ExtractRoot $extractRoot -TempPathInfo $TempPathInfo -Reason $_.Exception.Message
    }
}

function Convert-RestorePathDirectTreeToTempTar {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExtractRoot,

        [Parameter(Mandatory = $true)]
        [string]$TempTar,

        [Parameter(Mandatory = $true)]
        [object]$TopLevelInfo,

        [switch]$StripTopLevelEntry,

        [string]$Distro = $Script:CurrentDistro
    )

    try {
        $sourceRoot = $ExtractRoot
        if ($StripTopLevelEntry) {
            if (-not $TopLevelInfo.Unique) {
                throw "Direct .7z overwrite restore requires one safe top-level folder."
            }
            $sourceRoot = Join-Path $ExtractRoot ([string]$TopLevelInfo.TopLevelEntry)
        }

        $extractRootResolved = Get-NormalizedWindowsPathForComparison -Path $ExtractRoot -Label "Restore-Path direct tree extract root"
        $sourceRootResolved = Get-NormalizedWindowsPathForComparison -Path $sourceRoot -Label "Restore-Path direct tree tar source"
        if (-not $extractRootResolved.Success -or -not $sourceRootResolved.Success) {
            throw "Cannot normalize direct .7z tree source path."
        }
        if (-not (Test-PathIsSameOrChild -ChildPath $sourceRootResolved.NormalizedPath -ParentPath $extractRootResolved.NormalizedPath)) {
            throw "Direct .7z tar source is not inside the controlled extract root."
        }
        if (-not (Test-Path -LiteralPath $sourceRootResolved.NormalizedPath -PathType Container)) {
            throw "Direct .7z tar source is not a directory: $($sourceRootResolved.NormalizedPath)"
        }
        if (Test-Path -LiteralPath $TempTar -ErrorAction SilentlyContinue) {
            throw "Restore-Path direct tree temp tar already exists: $TempTar"
        }

        $tarExe = Resolve-WSLBMWindowsTarPath
        Write-Host "Preparing direct .7z file tree for WSL restore..." -ForegroundColor Cyan
        Write-Host "  Source: $($sourceRootResolved.NormalizedPath)" -ForegroundColor DarkGray
        $tarResult = Invoke-WSLBMNativeStdoutToFile `
            -FilePath $tarExe `
            -Arguments @("-cpf", "-", "-C", $sourceRootResolved.NormalizedPath, ".") `
            -OutputPath $TempTar `
            -OperationName "Restore-Path-Direct7z-Tar" `
            -Description "Create temp tar from direct .7z tree" `
            -TimeoutSeconds $Script:DefaultWSLCommandTimeoutSeconds `
            -Distro $Distro

        if (-not $tarResult.Success) {
            return New-RestoreArchiveExtractResult -Success $false -ExitCode $tarResult.ExitCode -TimedOut $tarResult.TimedOut -Cancelled $tarResult.Cancelled -TempTar $TempTar
        }

        $tarItem = Get-Item -LiteralPath $TempTar -ErrorAction Stop
        if ($tarItem.Length -lt 100) {
            Write-Host "[ERROR] Direct .7z temp tar is too small ($(Format-Bytes $tarItem.Length))." -ForegroundColor Red
            return New-RestoreArchiveExtractResult -Success $false -ExitCode $tarResult.ExitCode -TempTar $TempTar
        }

        return New-RestoreArchiveExtractResult -Success $true -ExitCode $tarResult.ExitCode -TempTar $TempTar
    }
    catch {
        Write-Host "[ERROR] Direct .7z tree staging failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-Path-Direct7z-Tar" "Failed: $($_.Exception.Message)" -Distro $Distro
        return New-RestoreArchiveExtractResult -Success $false -TempTar $TempTar
    }
}

function Clear-RestorePathDirectTreeExtractedFiles {
    param(
        [string]$TempDir,
        [string]$ExtractRoot,
        [string]$Distro = $Script:CurrentDistro
    )

    $null = $Distro
    if ($Global:DryRun -or [string]::IsNullOrWhiteSpace($TempDir) -or [string]::IsNullOrWhiteSpace($ExtractRoot)) {
        return
    }

    try {
        $tempDirResolved = Get-NormalizedWindowsPathForComparison -Path $TempDir -Label "Restore-Path temp directory"
        $extractRootResolved = Get-NormalizedWindowsPathForComparison -Path $ExtractRoot -Label "Restore-Path direct tree extract root"
        if (-not $tempDirResolved.Success -or -not $extractRootResolved.Success) {
            throw "Cannot normalize direct tree cleanup paths."
        }

        $tempDirParent = Split-Path -Path $tempDirResolved.NormalizedPath -Parent
        $tempDirRule = Test-WSLBMPathClassRule `
            -Path $tempDirResolved.NormalizedPath `
            -UsageKey "TempWorkspace" `
            -Label "Restore-Path temp directory" `
            -RequiredParentPath $tempDirParent `
            -RequiredParentReason "Restore-Path temp directory must have a safe parent boundary." `
            -ShapeRegex '^restore-\d{8}-\d{6}-[0-9a-f]{4}-[0-9a-fA-F]{32}$' `
            -ShapeRejectReason "Restore-Path temp directory name does not match controlled prefix"
        if (-not $tempDirRule.Success) {
            throw $tempDirRule.Reason
        }

        $extractParent = Split-Path -Path $extractRootResolved.NormalizedPath -Parent
        $extractLeaf = Split-Path -Path $extractRootResolved.NormalizedPath -Leaf
        if (-not $extractParent.Equals($tempDirResolved.NormalizedPath, [System.StringComparison]::OrdinalIgnoreCase) -or $extractLeaf -ne "direct-tree") {
            throw "Direct tree extract root is not the expected child of the controlled temp directory."
        }

        if (Test-Path -LiteralPath $extractRootResolved.NormalizedPath -PathType Container) {
            Remove-Item -LiteralPath $extractRootResolved.NormalizedPath -Recurse -Force -ErrorAction Stop
        }
    }
    catch {
        Write-Host "[WARN] Direct .7z temp tree cleanup skipped or incomplete: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-LogEntry "WARN" "Restore-Cleanup" "Direct .7z temp tree cleanup skipped or incomplete: $($_.Exception.Message)" -Distro $Distro
    }
}

function Read-RestorePathMode {
    while ($true) {
        Write-Host ""
        Write-Host "[Restore-Path mode]" -ForegroundColor Cyan
        Write-Host "[1] Overwrite existing path" -ForegroundColor Yellow
        Write-Host "    Restore into the target path. Top-level archive folder is stripped."
        Write-Host "[2] Extract under target directory" -ForegroundColor Yellow
        Write-Host "    Extract inside the target directory. Top-level archive folder is preserved."
        Write-Host "[Q] Cancel"

        $choice = Read-Host "Select Restore-Path mode"
        switch ($choice) {
            "1" { return [pscustomobject]@{ Success = $true; Mode = "Overwrite"; Label = "Overwrite existing path"; StripTopLevelEntry = $true } }
            "2" { return [pscustomobject]@{ Success = $true; Mode = "ExtractUnder"; Label = "Extract under target directory"; StripTopLevelEntry = $false } }
            { $_ -in @("q", "Q", "cancel", "CANCEL") } { return [pscustomobject]@{ Success = $false; Mode = ""; Label = ""; StripTopLevelEntry = $false } }
            default { Write-Host "Invalid option." -ForegroundColor Red }
        }
    }
}

function ConvertFrom-WSLBMTarHeaderString {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [int]$Offset,

        [Parameter(Mandatory = $true)]
        [int]$Count
    )

    $end = $Offset
    $limit = $Offset + $Count
    while ($end -lt $limit -and $Bytes[$end] -ne 0) {
        $end++
    }
    if ($end -le $Offset) { return "" }
    return ([System.Text.Encoding]::UTF8.GetString($Bytes, $Offset, ($end - $Offset))).Trim()
}

function ConvertFrom-WSLBMTarOctalSize {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

    $text = (ConvertFrom-WSLBMTarHeaderString -Bytes $Bytes -Offset 124 -Count 12).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return [long]0 }
    $text = $text.Trim([char]0, " ")
    if ($text -notmatch '^[0-7]+$') {
        throw "Tar header contains a non-octal size field."
    }
    return [Convert]::ToInt64($text, 8)
}

function New-WSLPathTarTopLevelInfoResult {
    param(
        [bool]$Success,
        [bool]$Unique = $false,
        [string]$TopLevelEntry = "",
        [object[]]$TopLevelEntries = @(),
        [bool]$HasChildEntries = $false,
        [bool]$HasDirectoryTopLevelEntry = $false,
        [string]$Reason = ""
    )

    return [pscustomobject]@{
        Success                    = $Success
        Unique                     = $Unique
        TopLevelEntry              = $TopLevelEntry
        TopLevelEntries            = @($TopLevelEntries)
        HasChildEntries            = $HasChildEntries
        HasDirectoryTopLevelEntry  = $HasDirectoryTopLevelEntry
        Reason                     = $Reason
    }
}

function Get-WSLPathTarTopLevelInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$ArchivePath
    )

    $null = $DistroName

    $topLevels = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::Ordinal)
    $hasChildEntries = $false
    $hasDirectoryTopLevelEntry = $false
    $entryCount = 0
    $stream = $null
    try {
        if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
            throw "Tar archive not found: $ArchivePath"
        }

        $stream = [System.IO.File]::Open($ArchivePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $header = New-Object byte[] 512
        while ($true) {
            $read = $stream.Read($header, 0, 512)
            if ($read -eq 0) { break }
            if ($read -ne 512) {
                throw "Tar archive ended in a partial header."
            }

            $isZeroBlock = $true
            for ($i = 0; $i -lt 512; $i++) {
                if ($header[$i] -ne 0) {
                    $isZeroBlock = $false
                    break
                }
            }
            if ($isZeroBlock) { break }

            $entrySize = ConvertFrom-WSLBMTarOctalSize -Bytes $header
            $typeFlag = [char]$header[156]
            $name = ConvertFrom-WSLBMTarHeaderString -Bytes $header -Offset 0 -Count 100
            $prefix = ConvertFrom-WSLBMTarHeaderString -Bytes $header -Offset 345 -Count 155
            $entry = if ([string]::IsNullOrWhiteSpace($prefix)) { $name } else { "$prefix/$name" }

            if ([string]::IsNullOrWhiteSpace($entry)) {
                return New-WSLPathTarTopLevelInfoResult `
                    -Success $false `
                    -TopLevelEntries @($topLevels) `
                    -HasChildEntries $hasChildEntries `
                    -HasDirectoryTopLevelEntry $hasDirectoryTopLevelEntry `
                    -Reason "Archive top-level entry is empty."
            }
            if ($typeFlag -in @([char]'x', [char]'g', [char]'L', [char]'K')) {
                $blocksToSkipOnly = [long][Math]::Ceiling($entrySize / 512.0)
                if ($blocksToSkipOnly -gt 0) {
                    $null = $stream.Seek(($blocksToSkipOnly * 512), [System.IO.SeekOrigin]::Current)
                }
                continue
            }
            if ($entry.StartsWith("/", [System.StringComparison]::Ordinal) -or $entry.StartsWith("\", [System.StringComparison]::Ordinal)) {
                return New-WSLPathTarTopLevelInfoResult `
                    -Success $false `
                    -TopLevelEntries @($topLevels) `
                    -HasChildEntries $hasChildEntries `
                    -HasDirectoryTopLevelEntry $hasDirectoryTopLevelEntry `
                    -Reason "Archive top-level entry must not be absolute."
            }

            while ($entry.StartsWith("./", [System.StringComparison]::Ordinal)) {
                if ($entry.Length -eq 2) {
                    $entry = "."
                    break
                }
                $entry = $entry.Substring(2)
            }

            $entryForSegments = $entry.TrimEnd("/")
            if ([string]::IsNullOrWhiteSpace($entryForSegments)) {
                return New-WSLPathTarTopLevelInfoResult `
                    -Success $false `
                    -TopLevelEntries @($topLevels) `
                    -HasChildEntries $hasChildEntries `
                    -HasDirectoryTopLevelEntry $hasDirectoryTopLevelEntry `
                    -Reason "Archive top-level entry is empty."
            }

            $segments = @($entryForSegments -split "/")
            foreach ($segment in $segments) {
                if ([string]::IsNullOrWhiteSpace($segment) -or $segment -in @(".", "..") -or $segment -match '[\x00-\x1F\x7F]' -or $segment.Contains("\")) {
                    return New-WSLPathTarTopLevelInfoResult `
                        -Success $false `
                        -TopLevelEntries @($topLevels) `
                        -HasChildEntries $hasChildEntries `
                        -HasDirectoryTopLevelEntry $hasDirectoryTopLevelEntry `
                        -Reason "Archive entry contains an unsafe path segment."
                }
            }

            $top = [string]$segments[0]
            if ([string]::IsNullOrWhiteSpace($top) -or $top -in @("/", ".", "..")) {
                return New-WSLPathTarTopLevelInfoResult `
                    -Success $false `
                    -TopLevelEntries @($topLevels) `
                    -HasChildEntries $hasChildEntries `
                    -HasDirectoryTopLevelEntry $hasDirectoryTopLevelEntry `
                    -Reason "Archive top-level entry is not safe to use as a Linux path component."
            }
            if ($segments.Count -gt 1) {
                $hasChildEntries = $true
            }
            elseif ($typeFlag -eq [char]'5' -or $entry.EndsWith("/", [System.StringComparison]::Ordinal)) {
                $hasDirectoryTopLevelEntry = $true
            }
            [void]$topLevels.Add($top)
            $entryCount++

            $blocksToSkip = [long][Math]::Ceiling($entrySize / 512.0)
            if ($blocksToSkip -gt 0) {
                $null = $stream.Seek(($blocksToSkip * 512), [System.IO.SeekOrigin]::Current)
            }
        }
    }
    catch {
        return New-WSLPathTarTopLevelInfoResult -Success $false -Reason $_.Exception.Message
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }

    $entries = @($topLevels)
    if ($entries.Count -eq 0 -or $entryCount -eq 0) {
        return New-WSLPathTarTopLevelInfoResult -Success $false -Reason "Archive tar listing is empty."
    }

    foreach ($entry in $entries) {
        if ([string]::IsNullOrWhiteSpace($entry) -or $entry -in @("/", ".", "..") -or $entry -match '[\x00-\x1F\x7F]' -or $entry.Contains("/") -or $entry.Contains("\")) {
            return New-WSLPathTarTopLevelInfoResult `
                -Success $false `
                -TopLevelEntries @($entries) `
                -HasChildEntries $hasChildEntries `
                -HasDirectoryTopLevelEntry $hasDirectoryTopLevelEntry `
                -Reason "Archive top-level entry is not safe to use as a Linux path component."
        }
    }

    $unique = ($entries.Count -eq 1)
    $topLevelEntry = if ($unique) { [string]$entries[0] } else { "<multiple: $($entries -join ', ')>" }
    return New-WSLPathTarTopLevelInfoResult `
        -Success $true `
        -Unique $unique `
        -TopLevelEntry $topLevelEntry `
        -TopLevelEntries @($entries) `
        -HasChildEntries $hasChildEntries `
        -HasDirectoryTopLevelEntry $hasDirectoryTopLevelEntry
}

function Invoke-WSLPathProbe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string[]]$ProbeArguments,

        [string]$Description = "WSL path probe"
    )

    if ($Global:DryRun) {
        return [pscustomobject]@{ Success = $true; ExitCode = 0; SkippedBecauseDryRun = $true; CombinedOutput = "" }
    }

    return Invoke-WSLBMNativeProcessChecked `
        -FilePath "wsl.exe" `
        -Arguments (@("-d", $DistroName, "--") + $ProbeArguments) `
        -OperationName "WSL-Path-Probe" `
        -Description $Description `
        -TimeoutSeconds 30 `
        -Distro $DistroName
}

function Test-WSLLinuxPathExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$LinuxPath
    )

    $result = Invoke-WSLPathProbe -DistroName $DistroName -ProbeArguments @("test", "-e", $LinuxPath) -Description "Test Linux path exists"
    if ($result.SkippedBecauseDryRun) { return $true }
    if ($result.ExitCode -eq 0) { return $true }
    if ($result.ExitCode -eq 1) { return $false }
    throw "Cannot inspect Linux path '$LinuxPath': $($result.CombinedOutput)"
}

function New-RestorePathTargetState {
    param(
        [bool]$CanInspect,
        [bool]$Exists = $true,
        [bool]$IsDirectory = $true,
        [bool]$IsNonEmpty = $true,
        [bool]$IsSymlink = $false,
        [string]$Reason = ""
    )

    return [pscustomobject]@{
        CanInspect  = $CanInspect
        Exists      = $Exists
        IsDirectory = $IsDirectory
        IsNonEmpty  = $IsNonEmpty
        IsSymlink   = $IsSymlink
        Reason      = $Reason
    }
}

function Get-RestorePathTargetState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$TargetLinuxPath
    )

    if ($Global:DryRun) {
        return New-RestorePathTargetState -CanInspect $false -Reason "DRY RUN: target path was not probed; preview treats the target as high-risk."
    }

    $isSymlink = Invoke-WSLPathProbe -DistroName $DistroName -ProbeArguments @("test", "-L", $TargetLinuxPath) -Description "Test Restore-Path target symlink"
    if ($isSymlink.ExitCode -eq 0) {
        return New-RestorePathTargetState -CanInspect $true -IsDirectory $false -IsSymlink $true -Reason "Target path is a symbolic link. Restore-Path refuses to follow it."
    }
    if ($isSymlink.ExitCode -ne 1) {
        return New-RestorePathTargetState -CanInspect $false -IsDirectory $false -Reason "Could not inspect target symlink state: $($isSymlink.CombinedOutput)"
    }

    $exists = Invoke-WSLPathProbe -DistroName $DistroName -ProbeArguments @("test", "-e", $TargetLinuxPath) -Description "Test Restore-Path target exists"
    if ($exists.ExitCode -eq 1) {
        return New-RestorePathTargetState -CanInspect $true -Exists $false -IsNonEmpty $false -Reason "Target path does not exist and will be created as a directory."
    }
    if ($exists.ExitCode -ne 0) {
        return New-RestorePathTargetState -CanInspect $false -IsDirectory $false -Reason "Could not inspect target existence: $($exists.CombinedOutput)"
    }

    $isDirectory = Invoke-WSLPathProbe -DistroName $DistroName -ProbeArguments @("test", "-d", $TargetLinuxPath) -Description "Test Restore-Path target is directory"
    if ($isDirectory.ExitCode -ne 0) {
        return New-RestorePathTargetState -CanInspect $true -IsDirectory $false -Reason "Target exists but is not a directory."
    }

    $findResult = Invoke-WSLPathProbe -DistroName $DistroName -ProbeArguments @("find", $TargetLinuxPath, "-mindepth", "1", "-maxdepth", "1", "-print", "-quit") -Description "Inspect Restore-Path target contents"
    if ($findResult.ExitCode -ne 0) {
        return New-RestorePathTargetState -CanInspect $false -Reason "Could not safely inspect target contents: $($findResult.CombinedOutput)"
    }

    $isNonEmpty = -not [string]::IsNullOrWhiteSpace([string]$findResult.StdOut)
    $reason = if ($isNonEmpty) { "Target directory exists and is not empty." } else { "Target directory exists and is empty." }
    return New-RestorePathTargetState -CanInspect $true -IsNonEmpty $isNonEmpty -Reason $reason
}

function Invoke-RestorePathExactReplacePrepare {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$TargetLinuxPath
    )

    if ($TargetLinuxPath -eq "/") {
        throw "Overwrite existing path refuses to clear the Linux root directory."
    }

    $state = Get-RestorePathTargetState -DistroName $DistroName -TargetLinuxPath $TargetLinuxPath
    if (-not $state.CanInspect) {
        throw "Cannot safely inspect target before exact replace: $($state.Reason)"
    }
    if ($state.IsSymlink) {
        throw "Target path is a symbolic link. Restore-Path refuses to follow it."
    }
    if ($state.Exists -and -not $state.IsDirectory) {
        throw "Overwrite existing path currently supports directory-style Path restore only; target exists but is not a directory."
    }

    if (-not $state.Exists) {
        $mkdirResult = Invoke-GuardedWSLCommand `
            -Description "Create Restore-Path exact replace target directory" `
            -Arguments @("-d", $DistroName, "--", "mkdir", "-p", "--", $TargetLinuxPath) `
            -Distro $DistroName
        if (-not $mkdirResult.Success) {
            throw "Failed to create target directory before exact replace."
        }
        return
    }

    Write-Host "Deleting existing target contents before exact Restore-Path..." -ForegroundColor Yellow
    Write-Host "  Target: ${DistroName}:$TargetLinuxPath" -ForegroundColor DarkGray
    $deleteResult = Invoke-GuardedWSLCommand `
        -Description "Clear Restore-Path exact replace target contents" `
        -Arguments @("-d", $DistroName, "--", "find", $TargetLinuxPath, "-mindepth", "1", "-maxdepth", "1", "-exec", "rm", "-rf", "--one-file-system", "--", "{}", "+") `
        -Distro $DistroName
    if (-not $deleteResult.Success) {
        throw "Failed to delete existing target contents before exact replace. Restore aborted before extraction."
    }
}

function New-RestorePathTargetContextResult {
    param([bool]$Success, [string]$ExpectedFinalPath = "", [object]$TargetState = $null, [string]$Reason = "")
    return [pscustomobject]@{ Success = $Success; ExpectedFinalPath = $ExpectedFinalPath; TargetState = $TargetState; Reason = $Reason }
}

function Get-RestorePathTargetContext {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [object]$RestoreMode,

        [Parameter(Mandatory = $true)]
        [object]$TargetSelection,

        [Parameter(Mandatory = $true)]
        [object]$TopLevelInfo
    )

    $expectedFinalPath = if ($RestoreMode.Mode -eq "Overwrite") {
        $TargetSelection.LinuxPath
    }
    elseif ($TopLevelInfo.Unique) {
        Join-LinuxPathLiteral -Parent $TargetSelection.LinuxPath -Child $TopLevelInfo.TopLevelEntry
    }
    else {
        "unknown"
    }

    if ($RestoreMode.Mode -eq "ExtractUnder") {
        $targetContainerState = Get-RestorePathTargetState -DistroName $DistroName -TargetLinuxPath $TargetSelection.LinuxPath
        if ($targetContainerState.Exists -and -not $targetContainerState.IsDirectory) {
            Write-Host "[ERROR] Extract-under target exists but is not a directory. Restore cancelled before extraction." -ForegroundColor Red
            return New-RestorePathTargetContextResult -Success $false -ExpectedFinalPath $expectedFinalPath -Reason "Extract-under target exists but is not a directory."
        }
    }

    $targetState = if ($expectedFinalPath -eq "unknown") {
        New-RestorePathTargetState -CanInspect $false -Reason "Archive top-level entry is unknown; final path cannot be inspected before extraction."
    }
    else {
        Get-RestorePathTargetState -DistroName $DistroName -TargetLinuxPath $expectedFinalPath
    }

    return New-RestorePathTargetContextResult -Success $true -ExpectedFinalPath $expectedFinalPath -TargetState $targetState
}

function Show-BackupPlanDryRun {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Plan,

        [Parameter(Mandatory = $true)]
        [string]$OperationId
    )

    if ($Plan.Type -eq "WholeDistro") {
        Write-Host "[DRY RUN] Full backup preview:" -ForegroundColor Cyan
        Write-OperationIdBanner -OperationId $OperationId

        $compressionSummary = @(
            "$($Plan.ArchiveStrategy.CompressionLevel), $($Plan.ArchiveStrategy.ResourceUsage)"
            "mx$($Plan.ArchiveStrategy.CompressionMx)"
            "threads=$($Plan.ArchiveStrategy.CompressionThreads)"
        ) -join ", "
        $summaryLines = @(
            "  Source distro : $($Plan.SourceDistro)"
            "  Destination   : $($Plan.DestinationDir)"
            "  Archive       : $($Plan.ArchivePath)"
            "  Temp dir      : $($Plan.TempDir)"
            "  Temp tar      : $($Plan.TempTar)"
            "  Compression   : $compressionSummary"
            "  WSL export    : wsl.exe $(Format-QuotedArgs $Plan.WslPreviewArgs)"
            "  7z args       : $(Format-QuotedArgs $Plan.CompressionPreviewArgs)"
        )
        $summaryLines | ForEach-Object { Write-Host $_ -ForegroundColor DarkGray }

        $fullBackupDryRunLines = @(
            "  DRY RUN: would check FULL backup disk space threshold ($($Global:Config.DiskThresholds.Full) GB)"
            "  DRY RUN: would prompt/confirm VS Code safety if needed"
            "  DRY RUN: would use CompressionLevel=$($Plan.ArchiveStrategy.CompressionLevel)."
            "  DRY RUN: would use ResourceUsage=$($Plan.ArchiveStrategy.ResourceUsage), mx$($Plan.ArchiveStrategy.CompressionMx), threads=$($Plan.ArchiveStrategy.CompressionThreads)."
            "  DRY RUN: would create backup directory $($Plan.DestinationDir)"
            "  DRY RUN: would create lock file under $($Plan.DestinationDir)"
            "  DRY RUN: would create controlled temp directory $($Plan.TempDir)"
            "  DRY RUN: would run fail-closed minimum workspace pre-check for temp tar and final archive locations"
            "  DRY RUN: would run wsl.exe --shutdown, then wait 5 seconds"
            "  DRY RUN: would export distro '$($Plan.SourceDistro)' to $($Plan.TempTar)"
            "  DRY RUN: would validate temp tar exists and is at least 1 KB"
            "  DRY RUN: would run second workspace check using actual temp tar size plus max(10%, 1GB) buffer"
            "  DRY RUN: would compress wsl-export.tar into $($Plan.ArchivePath)"
            "  DRY RUN: would run final Test-BackupIntegrity on $($Plan.ArchivePath)"
            "  DRY RUN: backup output remains the archive plus optional note.txt"
            "  DRY RUN: would clean temp tar and empty controlled temp directory"
        )
        $fullBackupDryRunLines | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }

        Write-Host "DryRun preview completed; no WSL, 7z, directory, lock, temp tar, backup file, note, or log writes were performed by New-FullBackup." -ForegroundColor Green
        return
    }

    Write-Host "[DRY RUN] Backup plan preview:" -ForegroundColor Cyan
    Write-OperationIdBanner -OperationId $OperationId
    $pathSummaryLines = @(
        "  Type        : $($Plan.Type)"
        "  Source      : $($Plan.SourceDistro):$($Plan.SourceLinuxPath)"
        "  Destination : $($Plan.DestinationDir)"
        "  Archive     : $($Plan.ArchivePath)"
        "  Format      : $($Plan.ArchiveStrategy.ArchiveFormat)"
        "  Level       : $($Plan.ArchiveStrategy.CompressionLevel)"
        "  Resources   : $($Plan.ArchiveStrategy.ResourceUsage)"
    )
    $pathSummaryLines | ForEach-Object { Write-Host $_ -ForegroundColor DarkGray }
    if ($null -ne $Plan.ArchiveStrategy.CompressionMx -and $null -ne $Plan.ArchiveStrategy.CompressionThreads) {
        Write-Host "  Compression : mx$($Plan.ArchiveStrategy.CompressionMx), threads=$($Plan.ArchiveStrategy.CompressionThreads)" -ForegroundColor DarkGray
    }
    else {
        Write-Host "  Compression : n/a for tar archive format" -ForegroundColor DarkGray
    }
    Write-Host "  Strategy    : $($Plan.ArchiveStrategy.DryRunPreview)" -ForegroundColor DarkGray
    $pathDryRunLines = @("  DRY RUN: would validate Linux path literally with no shell expansion.")
    if ($Plan.ArchiveStrategy.ArchiveFormat -eq "7z") {
        $archiveLeaf = Split-Path -Path $Plan.ArchivePath -Leaf
        $pathDryRunLines += @(
            "  DRY RUN: would create controlled temp directory $($Plan.TempDir)."
            "  DRY RUN: would run WSL tar inside distro and stream tar stdout to $($Plan.TempTar)."
            "  DRY RUN: would compress path.tar into $archiveLeaf with the selected compression settings."
            "  DRY RUN: would remove temporary path.tar and empty controlled temp directory after $archiveLeaf is verified."
        )
    }
    else {
        $pathDryRunLines += "  DRY RUN: would run WSL tar inside distro and stream tar stdout to the archive."
    }
    $pathDryRunLines += @(
        "  DRY RUN: would not use WSL UNC paths and would not run host 7-Zip to read Linux files."
        "  DRY RUN: backup output remains the archive plus optional note.txt."
    )
    $pathDryRunLines | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
    Write-Host "DryRun preview completed; no backup changes were made." -ForegroundColor Green
}

function Show-RestorePlanDryRun {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Plan
    )

    Write-Host "[DRY RUN] Restore plan preview:" -ForegroundColor Cyan
    Write-Host "  Type        : $($Plan.Type)" -ForegroundColor DarkGray
    Write-Host "  Distro      : $($Plan.TargetDistro)" -ForegroundColor DarkGray
    if (-not [string]::IsNullOrWhiteSpace([string]$Plan.RestoreMode)) {
        Write-Host "  Restore mode: $($Plan.RestoreMode)" -ForegroundColor DarkGray
    }
    Write-Host "  Target      : $($Plan.TargetLinuxPath)" -ForegroundColor DarkGray
    if (-not [string]::IsNullOrWhiteSpace([string]$Plan.ExpectedFinalPath)) {
        Write-Host "  Final path  : $($Plan.ExpectedFinalPath)" -ForegroundColor DarkGray
    }
    Write-Host "  Strip top   : $(if ($Plan.StripTopLevelEntry) { 'Yes' } else { 'No' })" -ForegroundColor DarkGray
    Write-Host "  Archive     : $($Plan.ArchivePath)" -ForegroundColor DarkGray
    Write-Host "  Format      : $($Plan.ArchiveStrategy.ArchiveFormat)" -ForegroundColor DarkGray
    Write-Host "  DRY RUN: would inspect the archive tar top-level entry before confirmation." -ForegroundColor Yellow
    Write-Host "  DRY RUN: would run archive integrity checks before extraction in a real run." -ForegroundColor Yellow
    Write-Host "  DRY RUN: would inspect the actual final path; if non-empty, exact phrase would be required:" -ForegroundColor Yellow
    Write-Host "    RESTORE PATH TO $($Plan.TargetDistro):$($Plan.TargetLinuxPath)" -ForegroundColor Cyan
    if ($Plan.ArchiveStrategy.ArchiveFormat -eq "7z") {
        $archiveLeaf = Split-Path -Path $Plan.ArchivePath -Leaf
        Write-Host "  DRY RUN: would detect $archiveLeaf shape before restore; tar-wrapped and direct-tree .7z archives use a controlled temp directory." -ForegroundColor Yellow
    }
    else {
        Write-Host "  DRY RUN: would extract the tar archive using WSL tar inside the target distro." -ForegroundColor Yellow
    }
    Write-Host "DryRun preview completed; no restore changes were made." -ForegroundColor Green
}

function Test-PathBackupArchiveCreated {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArchivePath
    )

    if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
        throw "Path backup archive was not created: $ArchivePath"
    }

    $archiveItem = Get-Item -LiteralPath $ArchivePath -ErrorAction Stop
    if ($archiveItem.Length -le 0) {
        throw "Path backup archive is empty (0 bytes): $ArchivePath"
    }

    Write-Host ("  [OK] Archive created: {0}" -f (Format-Bytes $archiveItem.Length)) -ForegroundColor Green
    return [long]$archiveItem.Length
}

function Invoke-BackupArchiveIntegrityCheck {
    param([Parameter(Mandatory = $true)][string]$ArchivePath, [Parameter(Mandatory = $true)][string]$ArchiveKind, [switch]$CheckCreated, [switch]$ShowVerifyingMessage)

    if ($ShowVerifyingMessage) {
        Write-Host "Verifying backup..." -ForegroundColor Cyan
    }
    if ($CheckCreated) {
        $null = Test-PathBackupArchiveCreated -ArchivePath $ArchivePath
    }
    Test-BackupIntegrity -backupFile $ArchivePath -archiveKind $ArchiveKind
}

function Start-BackupRuntimeState {
    param([Parameter(Mandatory = $true)][string]$OperationType, [Parameter(Mandatory = $true)][string]$BackupDir, [Parameter(Mandatory = $true)][string]$BackupFile, [switch]$RecordCleanupAllowedRoot)

    New-LockFile -OperationType $OperationType -TargetDir $BackupDir
    $Global:BackupState.IsRunning = $true
    $Global:BackupState.CurrentFile = $BackupFile
    $Global:BackupState.CurrentDir = $BackupDir
    if ($RecordCleanupAllowedRoot) {
        Set-BackupCleanupAllowedRootFromDestination -BackupDir $BackupDir
    }
}

function Clear-BackupRuntimeState {
    Stop-ActiveBackupProcesses
    Remove-LockFile
    $Global:BackupState.IsRunning = $false; $Global:BackupState.CurrentFile = $null; $Global:BackupState.CurrentDir = $null
    Clear-BackupCleanupAllowedRoot
    $Script:CurrentOperationId = ""
}

function Write-BackupNoteIfProvided {
    param([Parameter(Mandatory = $true)][string]$BackupDir)

    Write-Host "Add note (optional, press Enter to skip):"
    $note = Read-Host
    if (-not [string]::IsNullOrWhiteSpace($note)) {
        Write-WSLBMTextFileUtf8NoBom -LiteralPath (Join-Path $BackupDir "note.txt") -Content $note
    }
}

function New-PathBackupTempPathInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupDir
    )

    $tempDirName = "WSLBM-PathBackup-{0}" -f ([guid]::NewGuid().ToString('N'))
    $tempDir = Join-Path $BackupDir $tempDirName
    $tempTar = Join-Path $tempDir "path.tar"

    return [pscustomobject]@{
        TempDir = $tempDir
        TempTar = $tempTar
    }
}

function Clear-PathBackupTempArtifacts {
    param(
        [string]$TempDir,
        [string]$TempTar,
        [string]$BackupDir,
        [string]$Distro = $Script:CurrentDistro
    )

    if ($Global:DryRun) { return }
    $cleanupDistro = $Distro

    function Write-PathBackupCleanupWarning {
        param([string]$Message)

        Write-Host "[WARN] Path backup temp cleanup skipped or incomplete: $Message" -ForegroundColor Yellow
        Write-LogEntry "WARN" "Backup-Path-Cleanup" $Message -Distro $cleanupDistro
    }

    if ([string]::IsNullOrWhiteSpace($TempDir) -and [string]::IsNullOrWhiteSpace($TempTar)) {
        return
    }
    if ([string]::IsNullOrWhiteSpace($TempDir) -or [string]::IsNullOrWhiteSpace($TempTar)) {
        Write-PathBackupCleanupWarning "Path backup temp cleanup requires both TempDir and TempTar. TempDir=$TempDir | TempTar=$TempTar"
        return
    }
    if ([string]::IsNullOrWhiteSpace($BackupDir)) {
        Write-PathBackupCleanupWarning "Path backup temp cleanup requires BackupDir for boundary checks. TempDir=$TempDir | TempTar=$TempTar"
        return
    }

    $backupDirResolved = Get-NormalizedWindowsPathForComparison -Path $BackupDir -Label "Path backup directory"
    $tempDirResolved = Get-NormalizedWindowsPathForComparison -Path $TempDir -Label "Path backup temp directory"
    $tempTarResolved = Get-NormalizedWindowsPathForComparison -Path $TempTar -Label "Path backup temp tar"
    if (-not $backupDirResolved.Success -or -not $tempDirResolved.Success -or -not $tempTarResolved.Success) {
        Write-PathBackupCleanupWarning "Cannot normalize path backup temp paths safely. BackupDir=$BackupDir | TempDir=$TempDir | TempTar=$TempTar"
        return
    }

    $tempDirFull = $tempDirResolved.NormalizedPath
    $tempTarFull = $tempTarResolved.NormalizedPath
    $comparison = [System.StringComparison]::OrdinalIgnoreCase

    $tempDirRule = Test-WSLBMPathClassRule `
        -Path $tempDirFull `
        -UsageKey "TempWorkspace" `
        -Label "Path backup temp directory" `
        -RequiredParentPath $backupDirResolved.NormalizedPath `
        -RequiredParentReason "Path backup temp directory must be a child of the generated backup directory." `
        -ShapeRegex '^WSLBM-PathBackup-[0-9a-fA-F]{32}$' `
        -ShapeRejectReason "Path backup temp directory name does not match controlled prefix."
    if (-not $tempDirRule.Success) {
        Write-PathBackupCleanupWarning $tempDirRule.Reason
        return
    }

    $tarParent = Split-Path -Path $tempTarFull -Parent
    $tarName = Split-Path -Path $tempTarFull -Leaf
    if (-not $tarParent.Equals($tempDirFull, $comparison) -or $tarName -ne "path.tar") {
        Write-PathBackupCleanupWarning "Path backup temp tar must be path.tar directly under the controlled temp directory."
        return
    }

    try {
        if (Test-Path -LiteralPath $tempTarFull -PathType Leaf) {
            Remove-Item -LiteralPath $tempTarFull -Force -ErrorAction Stop
        }
    }
    catch {
        Write-PathBackupCleanupWarning "Failed to remove path backup temp tar $($tempTarFull): $($_.Exception.Message)"
    }

    try {
        if (Test-Path -LiteralPath $tempDirFull -PathType Container) {
            $remainingItem = Get-ChildItem -LiteralPath $tempDirFull -Force -ErrorAction Stop | Select-Object -First 1
            if ($null -eq $remainingItem) {
                Remove-Item -LiteralPath $tempDirFull -Force -ErrorAction Stop
            }
            else {
                Write-PathBackupCleanupWarning "Path backup temp directory is not empty; leaving it for manual review: $tempDirFull"
            }
        }
    }
    catch {
        Write-PathBackupCleanupWarning "Failed to remove empty path backup temp directory $($tempDirFull): $($_.Exception.Message)"
    }
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
        $previewArchiveName = Read-FullBackupArchiveBaseName
        if (-not $previewArchiveName.Success) { return }
        $previewBackupFile = Join-Path $previewBackupDir $previewArchiveName.ArchiveName
        $previewTempDir = Join-Path $previewBackupDir "WSLBM-FullBackup-<unique-guid>"
        $previewTempTar = Join-Path $previewTempDir "wsl-export.tar"
        $previewStrategy = New-ArchiveStrategy `
            -ArchiveFormat "7z" `
            -WorkloadType "WholeDistro" `
            -CompressionTool ([pscustomobject]@{ Name = "7z"; Version = $null }) `
            -PromptForProfile
        if ($null -eq $previewStrategy) { return }
        $previewExportArgs = @("--export", $Script:CurrentDistro, $previewTempTar)
        $preview7zArgs = @(
            "a",
            $previewBackupFile,
            "wsl-export.tar",
            "-mx$($previewStrategy.CompressionMx)",
            "-mmt=$($previewStrategy.CompressionThreads)",
            "-bsp1",
            "-y"
        )
        $previewPlan = New-BackupPlan `
            -Type "WholeDistro" `
            -SourceDistro $Script:CurrentDistro `
            -DestinationDir $previewBackupDir `
            -ArchivePath $previewBackupFile `
            -ArchiveStrategy $previewStrategy `
            -TempDir $previewTempDir `
            -TempTar $previewTempTar `
            -WslPreviewArgs $previewExportArgs `
            -CompressionPreviewArgs $preview7zArgs
        Show-BackupPlanDryRun -Plan $previewPlan -OperationId (New-OperationId)
        Read-Host "Press Enter to return..."
        return
    }

    if (-not (Test-DiskSpace $Global:Config.DiskThresholds.Full)) { return }
    if (-not (Close-VSCodeSafely)) { return }

    $compressionPlan = Get-WSLBM7zCompressionPlan -WorkloadType "WholeDistro" -PromptForProfile
    if ($null -eq $compressionPlan) { return }

    $ts = Get-Date -Format "yyyy-MM-dd_HHmm"
    $defaultName = "$ts-FULL"
    $backupDir = Get-BackupDestination -defaultName $defaultName
    if (-not $backupDir) { return }

    $archiveNameSelection = Read-FullBackupArchiveBaseName
    if (-not $archiveNameSelection.Success) { return }
    $backupFile = Join-Path $backupDir $archiveNameSelection.ArchiveName
    $tempInfo = $null
    $tempInfo = New-FullBackupTempPathInfo -BackupDir $backupDir
    $minimumWorkspaceBytes = [long]([double]$Global:Config.DiskThresholds.Full * 1GB)

    Write-Host "[Pre-flight] FULL backup export size cannot be known before wsl --export; checking minimum workspace threshold first." -ForegroundColor Yellow
    if (-not (Test-FullBackupWorkingSpace `
                -TempPath $tempInfo.TempDir `
                -BackupFile $backupFile `
                -RequiredBytes $minimumWorkspaceBytes `
                -Stage "Before WSL export minimum workspace" `
                -CheckTempPath `
                -Distro $Script:CurrentDistro)) {
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

    Start-BackupRuntimeState -OperationType "Full Backup" -BackupDir $backupDir -BackupFile $backupFile

    $Script:CurrentOperationId = New-OperationId
    Write-OperationIdBanner -OperationId $Script:CurrentOperationId
    $fullBackupStartMessage = @(
        "Started to $backupFile"
        "CompressionLevel=$($compressionPlan.CompressionLevel)"
        "ResourceUsage=$($compressionPlan.ResourceUsage)"
        "mx$($compressionPlan.Level)"
        "Threads=$($compressionPlan.Threads)"
        "OpId=$($Script:CurrentOperationId)"
    ) -join " | "
    Write-LogEntry "INFO" "Backup-Full" $fullBackupStartMessage

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

        if (-not (Test-FullBackupWorkingSpace `
                    -TempPath $tempInfo.TempTar `
                    -BackupFile $backupFile `
                    -RequiredBytes $postExportRequiredBytes `
                    -Stage "After WSL export before 7z compression" `
                    -TempTarSizeBytes $tempTarSizeBytes `
                    -Distro $Script:CurrentDistro)) {
            throw "Full backup destination space check failed after temp tar export; compression was not started."
        }

        $null = Compress-FullBackupTarToArchive -TempDir $tempInfo.TempDir -BackupFile $backupFile -CompressionPlan $compressionPlan

        Invoke-BackupArchiveIntegrityCheck -ArchivePath $backupFile -ArchiveKind "FULL" -ShowVerifyingMessage

        Remove-LockFile

        Write-Host "SUCCESS: WholeDistro backup completed." -ForegroundColor Green
        Write-Host "  Archive: $backupFile" -ForegroundColor Cyan
        Write-LogEntry "SUCCESS" "Backup-Full" "Completed successfully | OpId=$($Script:CurrentOperationId)"

        Write-BackupNoteIfProvided -BackupDir $backupDir

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
        if ($null -ne $tempInfo) {
            Clear-FullBackupTempArtifacts -TempDir $tempInfo.TempDir -TempTar $tempInfo.TempTar -BackupDir $backupDir -BackupFile $backupFile -Distro $Script:CurrentDistro
        }
        if ($msg -and $msg -ne "") {
            Clear-FullBackupEmptyDirectory -BackupDir $backupDir -BackupFile $backupFile -Distro $Script:CurrentDistro
        }
        Clear-BackupRuntimeState
    }

    Read-Host "Press Enter to return..."
}

function New-PathBackup {
    if (-not $Script:CurrentDistro) {
        Write-Host "[ERROR] No Distro Selected." -ForegroundColor Red
        return
    }

    if (-not (Test-SafeDistroName -Name $Script:CurrentDistro)) {
        Write-Host "[SECURITY] Cannot backup: Distro name contains unsafe characters." -ForegroundColor Red
        return
    }

    $pathSelection = Read-LinuxPathFromSelectionMenu -DistroName $Script:CurrentDistro -Purpose "Backup-Path"
    if (-not $pathSelection.Success) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }
    $sourceLinuxPath = $pathSelection.LinuxPath

    $archiveNameSelection = Read-PathBackupArchiveBaseName -SourceLinuxPath $sourceLinuxPath
    if (-not $archiveNameSelection.Success) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }

    $ts = Get-Date -Format "yyyy-MM-dd_HHmm"
    $defaultName = "$ts-PATH"
    $backupDir = Get-BackupDestination -defaultName $defaultName -PreviewOnly:$Global:DryRun
    if (-not $backupDir) { return }

    $backupFile = Join-Path $backupDir $archiveNameSelection.ArchiveName
    $tempInfo = New-PathBackupTempPathInfo -BackupDir $backupDir

    if ($Global:DryRun) {
        $tarTool = Get-WSLPathTarToolInfo -DistroName $Script:CurrentDistro
        $strategy = New-ArchiveStrategy `
            -ArchiveFormat "7z" `
            -WorkloadType "Path" `
            -CompressionTool ([pscustomobject]@{ Name = "7z"; Version = $null }) `
            -TarTool $tarTool `
            -PromptForProfile
        if ($null -eq $strategy) { return }
        $plan = New-BackupPlan `
            -Type "Path" `
            -SourceDistro $Script:CurrentDistro `
            -SourceLinuxPath $sourceLinuxPath `
            -DestinationDir $backupDir `
            -ArchivePath $backupFile `
            -ArchiveStrategy $strategy `
            -TempDir $tempInfo.TempDir `
            -TempTar $tempInfo.TempTar

        Show-BackupPlanDryRun -Plan $plan -OperationId (New-OperationId)
        Read-Host "Press Enter to return..."
        return
    }

    if (-not (Test-DiskSpace $Global:Config.DiskThresholds.Path -Path $backupDir)) { return }
    if (-not (Close-VSCodeSafely)) { return }

    try {
        if (-not (Test-WSLLinuxPathExists -DistroName $Script:CurrentDistro -LinuxPath $sourceLinuxPath)) {
            Write-Host "[ERROR] Backup-Path source does not exist: $sourceLinuxPath" -ForegroundColor Red
            Read-Host "Press Enter to return..."
            return
        }
    }
    catch {
        Write-Host "[ERROR] Backup-Path source check failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-LogEntry "ERROR" "Backup-Path" "Source check failed: $($_.Exception.Message)" -Distro $Script:CurrentDistro
        Read-Host "Press Enter to return..."
        return
    }

    $compressionPlan = Get-WSLBM7zCompressionPlan -WorkloadType "Path" -PromptForProfile
    if ($null -eq $compressionPlan) { return }
    if (-not (New-BackupDirectory $backupDir)) { return }

    Start-BackupRuntimeState -OperationType "Path Backup" -BackupDir $backupDir -BackupFile $backupFile -RecordCleanupAllowedRoot

    $Script:CurrentOperationId = New-OperationId
    Write-OperationIdBanner -OperationId $Script:CurrentOperationId
    $pathBackupStartMessage = @(
        "Started from $sourceLinuxPath to $backupFile"
        "CompressionLevel=$($compressionPlan.CompressionLevel)"
        "ResourceUsage=$($compressionPlan.ResourceUsage)"
        "mx$($compressionPlan.Level)"
        "Threads=$($compressionPlan.Threads)"
        "OpId=$($Script:CurrentOperationId)"
    ) -join " | "
    Write-LogEntry "INFO" "Backup-Path" $pathBackupStartMessage -Distro $Script:CurrentDistro

    try {
        if (-not (New-BackupDirectory $tempInfo.TempDir)) {
            throw "Failed to create path backup temp directory: $($tempInfo.TempDir)"
        }

        $tarResult = Invoke-WSLPathTarCreateArchive `
            -DistroName $Script:CurrentDistro `
            -SourceLinuxPath $sourceLinuxPath `
            -ArchivePath $tempInfo.TempTar

        if ($tarResult.TimedOut) {
            throw "WSL tar backup timed out."
        }
        if ($tarResult.Cancelled) {
            throw "WSL tar backup cancelled by user."
        }
        if ($null -eq $tarResult.ExitCode) {
            throw "WSL tar backup did not report an exit code."
        }
        if (-not $tarResult.Success) {
            $detail = Get-WSLBMFirstOutputLine -Value $tarResult.CombinedOutput
            if ([string]::IsNullOrWhiteSpace($detail)) {
                throw "WSL tar backup failed (exit code $($tarResult.ExitCode))."
            }
            throw "WSL tar backup failed (exit code $($tarResult.ExitCode)): $detail"
        }

        $null = Test-PathBackupArchiveCreated -ArchivePath $tempInfo.TempTar
        $null = Compress-FullBackupTarToArchive `
            -TempDir $tempInfo.TempDir `
            -BackupFile $backupFile `
            -CompressionPlan $compressionPlan `
            -TarEntryName "path.tar" `
            -ArchiveDisplayName $archiveNameSelection.ArchiveName `
            -OperationName "Backup-Path-7z" `
            -Description "Compress Path backup tar" `
            -Distro $Script:CurrentDistro
        Invoke-BackupArchiveIntegrityCheck -ArchivePath $backupFile -ArchiveKind "PATH" -CheckCreated

        Add-LinuxRecentPathForDistro -DistroName $Script:CurrentDistro -LinuxPath $sourceLinuxPath
        Remove-LockFile

        Write-Host "SUCCESS: Path backup completed." -ForegroundColor Green
        Write-Host "  Archive: $backupFile" -ForegroundColor Cyan
        Write-LogEntry "SUCCESS" "Backup-Path" "Completed from $sourceLinuxPath | OpId=$($Script:CurrentOperationId)" -Distro $Script:CurrentDistro

        Write-BackupNoteIfProvided -BackupDir $backupDir
    }
    catch {
        $errMsg = $_.Exception.Message
        $msg = if ($errMsg -match "UserCancelled") { "Cancelled" } else { "Failed: $errMsg" }
        Write-LogEntry "ERROR" "Backup-Path" "$msg | OpId=$($Script:CurrentOperationId)" -Distro $Script:CurrentDistro
        Write-Host "[ERROR] $msg" -ForegroundColor Red
        Stop-ActiveBackupProcesses
        Remove-FailedBackupDir
    }
    finally {
        Clear-PathBackupTempArtifacts `
            -TempDir $tempInfo.TempDir `
            -TempTar $tempInfo.TempTar `
            -BackupDir $backupDir `
            -Distro $Script:CurrentDistro
        Clear-BackupRuntimeState
    }

    Read-Host "Press Enter to return..."
}

# =============================================================================
# Restore & Manage Operations
# =============================================================================

function Get-BackupEntryRestoreKind {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupDir
    )

    return (Get-BackupFolderType -BackupDir $BackupDir)
}

function Resolve-ExternalArchivePathLiteral {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ArchivePath
    )

    $textCheck = Test-WSLBMPathTextSafety -Path $ArchivePath -Label "External archive path"
    if (-not $textCheck.IsValid) {
        return [pscustomobject]@{ Success = $false; FullName = ""; Directory = ""; ArchiveFormat = ""; Reason = ($textCheck.Errors -join " ") }
    }

    $candidate = $ArchivePath.Trim()
    if (-not ($candidate -match '^[A-Za-z]:[\\/]' -or $candidate.StartsWith("\\", [System.StringComparison]::Ordinal))) {
        return [pscustomobject]@{
            Success       = $false
            FullName      = ""
            Directory     = ""
            ArchiveFormat = ""
            Reason        = "External archive path must be a full literal Windows path, for example D:\Backups\backup.7z or \\server\share\backup.tar."
        }
    }

    try {
        $format = Get-WSLBMArchiveFormatFromPath -ArchivePath $candidate
    }
    catch {
        return [pscustomobject]@{ Success = $false; FullName = ""; Directory = ""; ArchiveFormat = ""; Reason = $_.Exception.Message }
    }

    try {
        $item = Assert-WSLBMSevenZipArchiveInput -ArchivePath $candidate -Context "External archive"
        $fullName = [System.IO.Path]::GetFullPath($item.FullName)
        $directory = [System.IO.Path]::GetDirectoryName($fullName)
        if ([string]::IsNullOrWhiteSpace($directory)) {
            return [pscustomobject]@{ Success = $false; FullName = ""; Directory = ""; ArchiveFormat = ""; Reason = "Cannot determine external archive directory." }
        }

        return [pscustomobject]@{
            Success       = $true
            FullName      = $fullName
            Directory     = $directory
            ArchiveFormat = $format
            Reason        = ""
        }
    }
    catch {
        return [pscustomobject]@{ Success = $false; FullName = ""; Directory = ""; ArchiveFormat = ""; Reason = $_.Exception.Message }
    }
}

function Get-RestoreExternalLockRootPath {
    return (Join-Path $Global:LogRoot "restore-locks")
}

function Initialize-RestoreLockTargetDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LockTargetDir
    )

    if ([string]::IsNullOrWhiteSpace($LockTargetDir)) {
        throw "Restore lock target directory is empty."
    }

    if (-not (Test-Path -LiteralPath $LockTargetDir -PathType Container -ErrorAction SilentlyContinue)) {
        [System.IO.Directory]::CreateDirectory($LockTargetDir) | Out-Null
    }
}

function New-RestoreBackupView {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$BackupInput,

        [ValidateSet("", "WholeDistro", "Path")]
        [string]$ExpectedRestoreType = "",

        [switch]$IsExternal
    )

    if ($null -ne $BackupInput -and
        $null -ne $BackupInput.PSObject.Properties["ArchivePath"] -and
        $null -ne $BackupInput.PSObject.Properties["BackupDir"]) {
        if (-not [string]::IsNullOrWhiteSpace($ExpectedRestoreType) -and
            $BackupInput.RestoreKind -ne $ExpectedRestoreType) {
            return [pscustomobject]@{ Success = $false; Reason = "Selected entry type is $($BackupInput.RestoreKind), not $ExpectedRestoreType." }
        }
        return $BackupInput
    }

    $backupDir = ""
    $archivePath = ""
    $archiveFormat = ""
    $sourceLabel = if ($IsExternal) { "external archive" } else { "scanned backup" }
    $lockTargetDir = ""

    if ($IsExternal) {
        $resolvedExternal = Resolve-ExternalArchivePathLiteral -ArchivePath ([string]$BackupInput)
        if (-not $resolvedExternal.Success) {
            return [pscustomobject]@{ Success = $false; Reason = $resolvedExternal.Reason }
        }

        $archivePath = $resolvedExternal.FullName
        $backupDir = $resolvedExternal.Directory
        $archiveFormat = $resolvedExternal.ArchiveFormat
        $lockTargetDir = Get-RestoreExternalLockRootPath
    }
    else {
        if ([string]::IsNullOrWhiteSpace([string]$BackupInput)) {
            return [pscustomobject]@{ Success = $false; Reason = "Backup directory is empty." }
        }

        $backupDir = [string]$BackupInput
        if (-not (Test-Path -LiteralPath $backupDir -PathType Container)) {
            return [pscustomobject]@{ Success = $false; Reason = "Scanned backup directory not found: $backupDir" }
        }
        $lockTargetDir = Get-RestoreExternalLockRootPath
    }

    if (-not $IsExternal) {
        $folderKind = Get-BackupEntryRestoreKind -BackupDir $backupDir
        if ($folderKind -eq "Unknown") {
            return [pscustomobject]@{ Success = $false; Reason = "Selected folder is not a recognized backup folder: $backupDir" }
        }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedRestoreType) -and $folderKind -ne $ExpectedRestoreType) {
            return [pscustomobject]@{ Success = $false; Reason = "Selected folder type is $folderKind, not $ExpectedRestoreType." }
        }

        $resolvedArchive = Resolve-BackupArchiveFromFolder -BackupDir $backupDir
        if (-not $resolvedArchive.Success) {
            return [pscustomobject]@{ Success = $false; Reason = $resolvedArchive.Reason }
        }
        $archivePath = $resolvedArchive.ArchivePath
        $archiveFormat = $resolvedArchive.ArchiveFormat
    }

    $restoreKindValue = if (-not [string]::IsNullOrWhiteSpace($ExpectedRestoreType)) {
        $ExpectedRestoreType
    } elseif (-not $IsExternal) {
        Get-BackupEntryRestoreKind -BackupDir $backupDir
    } else {
        "Unknown"
    }

    return [pscustomobject]@{
        Success         = $true
        Reason          = ""
        SourceLabel     = $sourceLabel
        IsExternal      = [bool]$IsExternal
        BackupDir       = $backupDir
        ArchivePath     = $archivePath
        ArchiveFormat   = $archiveFormat
        RestoreKind     = $restoreKindValue
        LockTargetDir   = $lockTargetDir
    }
}

function Write-RestoreBackupViewSummary {
    param(
        [Parameter(Mandatory = $true)]
        [object]$View
    )

    $flow = if ($View.RestoreKind -in @("WholeDistro", "Path")) { "Restore-$($View.RestoreKind)" } else { "not selected" }
    Write-Host ""
    Write-Host "[Restore Source]" -ForegroundColor Cyan
    Write-Host "  Source       : $($View.SourceLabel)" -ForegroundColor DarkGray
    if (Test-WSLBMBackupEntryIsSafetyNet -Entry $View) {
        Write-SafetyNetBackupEntryDetails -Entry $View
        Write-Host "  This is a WholeDistro export created before replace." -ForegroundColor Yellow
    }
    elseif ($View.IsExternal) {
        Write-Host "  External archive: $($View.ArchivePath)" -ForegroundColor Yellow
    }
    else {
        Write-Host "  Scanned backup : $($View.BackupDir)" -ForegroundColor DarkGray
        Write-Host "  Archive        : $($View.ArchivePath)" -ForegroundColor DarkGray
    }
    Write-Host "  Archive format: $($View.ArchiveFormat)" -ForegroundColor DarkGray
    Write-Host "  Restore type : $($View.RestoreKind)" -ForegroundColor DarkGray
    Write-Host "  Flow         : $flow" -ForegroundColor DarkGray
    if ($View.IsExternal) {
        Write-Host "  External archive will remain in place; it is not copied into Backup Root." -ForegroundColor Yellow
    }
    if (Test-WSLBMBackupEntryIsSafetyNet -Entry $View) {
        Write-Host "  Choose Replace existing distro to roll back, or Install as new distro to inspect separately." -ForegroundColor Yellow
    }
    Write-Host ""
}

function Read-ExternalArchiveRestoreKind {
    while ($true) {
        Write-Host ""
        Write-Host "Select restore type for external archive:" -ForegroundColor Cyan
        Write-Host "  [1] WholeDistro backup - restore or clone a WSL distro"
        Write-Host "  [2] Path backup        - restore files into a Linux path"
        Write-Host "  [Q] Cancel"
        $choice = Read-Host "Restore type"
        switch ($choice) {
            "1" { return "WholeDistro" }
            "2" { return "Path" }
            { $_ -in @("q", "Q", "cancel", "CANCEL") } { return "" }
            default { Write-Host "Choose 1, 2, or Q." -ForegroundColor Red }
        }
    }
}

function Invoke-RestoreExternalArchive {
    Write-Host ""
    Write-Host "[Load External Archive]" -ForegroundColor Cyan
    Write-Host "Accepted archive formats: .7z and .tar only." -ForegroundColor DarkGray
    Write-Host "This entry is independent of scanned backup root results." -ForegroundColor DarkGray

    $archiveInput = Read-Host "Enter external archive path (Q/CANCEL to abort)"
    if ([string]::IsNullOrWhiteSpace($archiveInput) -or $archiveInput -in @("q", "Q", "cancel", "CANCEL")) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }

    $selectedKind = Read-ExternalArchiveRestoreKind
    if ([string]::IsNullOrWhiteSpace($selectedKind)) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }

    $view = New-RestoreBackupView -BackupInput $archiveInput -ExpectedRestoreType $selectedKind -IsExternal
    if (-not $view.Success) {
        Write-Host "[ERROR] External archive rejected: $($view.Reason)" -ForegroundColor Red
        Read-Host "Press Enter..."
        return
    }

    Write-RestoreBackupViewSummary -View $view

    Write-LogEntry "INFO" "Restore-External" "Selected external archive. Type=$($view.RestoreKind) | Archive=$($view.ArchivePath)" -Distro $Script:CurrentDistro

    if ($view.RestoreKind -eq "WholeDistro") {
        Invoke-RestoreWholeDistro -backupDir $view
    }
    elseif ($view.RestoreKind -eq "Path") {
        Invoke-RestorePath -backupDir $view
    }
    else {
        Write-Host "[ERROR] Cannot determine restore type for external archive." -ForegroundColor Red
        Read-Host "Press Enter..."
    }
}

function Show-RestoreMenu {
    Clear-Host
    Write-Host "=== RESTORE MENU ===" -ForegroundColor Red

    $scanPath = Get-ValidatedBackupScanPath
    $backups = @()

    if ($scanPath) {
        Write-Host "Scanning scanned backup root: $scanPath" -ForegroundColor DarkGray
        if (Test-Path -LiteralPath $scanPath -PathType Container) {
            $backups = @(Get-RecognizedBackupFolders -ScanPath $scanPath)
        }
        else {
            Write-Host "Scanned backup root not found; external archive loading is still available." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "Scanned backup root is not available; external archive loading is still available." -ForegroundColor Yellow
    }

    $currentPage = 1
    $pageSize = 20
    $pageInfo = Get-BackupPageInfo -Backups $backups -Page $currentPage -PageSize $pageSize
    if ($backups.Count -gt 0) {
        Show-BackupTable -Backups $backups -Page $pageInfo.Page -PageSize $pageSize
    }
    else {
        Write-Host "No scanned backups found." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Restore flows: WholeDistro / Path / External archive" -ForegroundColor DarkGray

    while ($true) {
        $sel = Read-Host (Get-WSLBMBackupPagePrompt -PageInfo $pageInfo -IncludeExternalArchive)
        if ($sel -eq "0" -or $sel -eq "q" -or $sel -eq "Q") {
            return
        }
        if ($sel -eq "e" -or $sel -eq "E") {
            Invoke-RestoreExternalArchive
            return
        }
        if ($sel -eq "n" -or $sel -eq "N") {
            if ($backups.Count -eq 0) {
                Write-Host "No scanned backups are available. Use E to load an external archive." -ForegroundColor Yellow
                continue
            }
            if ($pageInfo.Page -ge $pageInfo.PageCount) {
                Write-Host "No next page." -ForegroundColor Yellow
                continue
            }
            $currentPage++
            $pageInfo = Get-BackupPageInfo -Backups $backups -Page $currentPage -PageSize $pageSize
            Show-BackupTable -Backups $backups -Page $pageInfo.Page -PageSize $pageSize
            continue
        }
        if ($sel -eq "p" -or $sel -eq "P") {
            if ($backups.Count -eq 0) {
                Write-Host "No scanned backups are available. Use E to load an external archive." -ForegroundColor Yellow
                continue
            }
            if ($pageInfo.Page -le 1) {
                Write-Host "No previous page." -ForegroundColor Yellow
                continue
            }
            $currentPage--
            $pageInfo = Get-BackupPageInfo -Backups $backups -Page $currentPage -PageSize $pageSize
            Show-BackupTable -Backups $backups -Page $pageInfo.Page -PageSize $pageSize
            continue
        }

        if ($sel -match '^\d+$') {
            $selNum = [int]$sel
            if ($selNum -gt 0 -and $selNum -le $pageInfo.Count) {
                $target = $backups[$pageInfo.StartIndex + $selNum - 1]
                break
            }
            if ($backups.Count -gt $pageInfo.Count) {
                Write-Host "Number is not on this page." -ForegroundColor Red
                continue
            }
        }

        if ($backups.Count -eq 0) {
            Write-Host "Invalid selection. Enter E to load an external archive, or 0/q to cancel." -ForegroundColor Red
        }
        else {
            Write-Host "Invalid selection. Use a visible number, E, or 0/Q." -ForegroundColor Red
        }
    }

    Write-LogEntry "INFO" "Restore-Init" "Selected $($target.Name)"

    $isSafetyNet = Test-WSLBMBackupEntryIsSafetyNet -Entry $target
    $restoreKind = if ($isSafetyNet) {
        "WholeDistro"
    }
    else {
        Get-BackupEntryRestoreKind -BackupDir $target.FullName
    }
    if ($restoreKind -eq "WholeDistro") {
        Write-Host "`nSelected: $($target.Name)" -ForegroundColor Cyan
        if ($isSafetyNet) {
            Write-Host "Selected Safety Net archive." -ForegroundColor Yellow
            Write-Host "This restores a WholeDistro export created before replace." -ForegroundColor Yellow
            Write-Host "Choose Replace existing distro to roll back, or Install as new distro to inspect it separately." -ForegroundColor Yellow
            Invoke-RestoreWholeDistro -backupDir $target
        }
        else {
            Invoke-RestoreWholeDistro -backupDir $target.FullName
        }
    }
    elseif ($restoreKind -eq "Path") {
        Invoke-RestorePath -backupDir $target.FullName
    }
    else {
        Write-Host "[ERROR] Cannot determine restore type for selected backup." -ForegroundColor Red
        Read-Host "Press Enter..."
    }
}

function Test-WSLBMRegistryInfoIsExplicitMissing {
    param(
        [Parameter(Mandatory = $true)]
        [object]$RegistryInfo
    )

    if ($null -eq $RegistryInfo) {
        return $false
    }

    return ((-not [bool]$RegistryInfo.Success) -and
        [string]::IsNullOrWhiteSpace([string]$RegistryInfo.RegistryKey) -and
        [string]::IsNullOrWhiteSpace([string]$RegistryInfo.DistributionName) -and
        [string]::IsNullOrWhiteSpace([string]$RegistryInfo.BasePathRaw) -and
        [string]::IsNullOrWhiteSpace([string]$RegistryInfo.BasePath) -and
        ([string]$RegistryInfo.Reason).StartsWith("No WSL registry entry matched distro", [System.StringComparison]::Ordinal))
}

function Confirm-RestoreWholeDistroInstallNew {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$InstallPath,

        [Parameter(Mandatory = $true)]
        [string]$BackupFile
    )

    $requiredPhrase = "INSTALL NEW $DistroName"

    Write-Host ""
    Write-Host "[Restore-WholeDistro INSTALL NEW Confirmation]" -ForegroundColor Yellow
    Write-Host "Import this archive as a new WSL distro. No existing distro will be overwritten." -ForegroundColor Yellow
    Write-Host "Restore mode   : Install new distro" -ForegroundColor Yellow
    Write-Host "Target distro  : $DistroName" -ForegroundColor Yellow
    Write-Host "Install path   : $InstallPath" -ForegroundColor Yellow
    Write-Host "Backup archive : $BackupFile" -ForegroundColor Yellow
    Write-Host "Required phrase: $requiredPhrase" -ForegroundColor Yellow
    Write-WSLBMRequiredPhrasePrompt -RequiredPhrase $requiredPhrase

    $confirmationResult = Read-WSLBMExactConfirmation -RequiredPhrase $requiredPhrase
    if ($confirmationResult -eq "Cancelled") {
        Write-LogEntry "WARN" "Restore-WholeDistro-Confirm" "Install-new restore cancelled before import confirmation" -Distro $DistroName
        return $false
    }

    if ($confirmationResult -eq "Mismatch") {
        Write-LogEntry "WARN" "Restore-WholeDistro-Confirm" "Install-new restore confirmation phrase mismatch" -Distro $DistroName
        Write-Host "[ERROR] Confirmation phrase did not match. Restore cancelled before WSL changes." -ForegroundColor Red
        return $false
    }

    Write-LogEntry "WARN" "Restore-WholeDistro-Confirm" "Install-new restore confirmed with exact phrase" -Distro $DistroName
    return $true
}

function Write-RestoreWholeDistroModeSummary {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Replace existing distro", "Install new distro")]
        [string]$RestoreMode,

        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$InstallPath,

        [bool]$WillCreateSafetyNet,

        [Parameter(Mandatory = $true)]
        [string]$RequiredPhrase
    )

    Write-Host ""
    Write-Host "[Restore-WholeDistro target semantics]" -ForegroundColor Cyan
    Write-Host "  Restore mode          : $RestoreMode" -ForegroundColor Yellow
    Write-Host "  Target distro         : $DistroName" -ForegroundColor Yellow
    Write-Host "  Install path          : $InstallPath" -ForegroundColor Yellow
    if ($WillCreateSafetyNet) {
        Write-Host "  Will create Safety Net: Yes" -ForegroundColor Yellow
        Write-Host "  Replacement behavior   : existing distro is unregistered after Safety Net, then imported from archive" -ForegroundColor Yellow
    }
    else {
        Write-Host "  Replacement behavior   : install-new creates a separate distro; no existing distro is merged or replaced" -ForegroundColor Yellow
    }
    Write-Host "  Required phrase       : $RequiredPhrase" -ForegroundColor Yellow
}

function Read-RestoreWholeDistroMode {
    while ($true) {
        Write-Host ""
        Write-Host "[Restore-WholeDistro mode]" -ForegroundColor Cyan
        Write-Host "[1] Replace existing distro" -ForegroundColor Yellow
        Write-Host "    Restore into an existing distro name. Requires Safety Net and REPLACE <distro>."
        Write-Host "[2] Install as new distro" -ForegroundColor Yellow
        Write-Host "    Import as a new distro name and install path. Requires INSTALL NEW <distro>."
        Write-Host "[Q] Cancel"

        $choice = Read-Host "Select Restore-WholeDistro mode"
        switch ($choice) {
            "1" { return [pscustomobject]@{ Success = $true; Mode = "Replace"; Label = "Replace existing distro" } }
            "2" { return [pscustomobject]@{ Success = $true; Mode = "InstallNew"; Label = "Install as new distro" } }
            { $_ -in @("q", "Q", "cancel", "CANCEL") } { return [pscustomobject]@{ Success = $false; Mode = ""; Label = "" } }
            default { Write-Host "Choose 1, 2, or Q." -ForegroundColor Red }
        }
    }
}

function Invoke-RestoreWholeDistro {
    param($backupDir)

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "[WARN] Not running as Administrator. Some operations may fail." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "[Restore-WholeDistro]" -ForegroundColor Cyan
    Write-Host "Restore a WholeDistro archive. Choose replace or install-new before entering the target name." -ForegroundColor Yellow
    Write-Host ""

    $view = New-RestoreBackupView -BackupInput $backupDir -ExpectedRestoreType "WholeDistro"
    if (-not $view.Success) {
        Write-Host "[ERROR] Restore-WholeDistro source rejected: $($view.Reason)" -ForegroundColor Red
        return
    }

    $backupDir = $view.BackupDir
    $backupFile = $view.ArchivePath
    $archiveFormat = $view.ArchiveFormat
    if ($view.RestoreKind -ne "WholeDistro") {
        Write-Host "[ERROR] Restore-WholeDistro only handles WholeDistro restore sources." -ForegroundColor Red
        return
    }
    if ($view.IsExternal -or (Test-WSLBMBackupEntryIsSafetyNet -Entry $view)) {
        Write-RestoreBackupViewSummary -View $view
    }

    $restoreMode = Read-RestoreWholeDistroMode
    if (-not $restoreMode.Success) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        Write-LogEntry "WARN" "Restore-WholeDistro" "Cancelled before restore mode selection"
        return
    }

    $targetNameInput = Read-Host "Enter target distro name (press Enter for current: $Script:CurrentDistro; Q/CANCEL to abort)"
    $targetNameInputText = if ($null -eq $targetNameInput) { "" } else { $targetNameInput.Trim() }
    if ($targetNameInputText -in @("q", "Q", "cancel", "CANCEL")) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        Write-LogEntry "WARN" "Restore-WholeDistro" "Cancelled before target distro selection"
        return
    }

    $targetName = $targetNameInputText
    if ([string]::IsNullOrWhiteSpace($targetName)) {
        $targetName = $Script:CurrentDistro
    }

    if (-not (Test-SafeDistroName -Name $targetName)) {
        Write-Host "[SECURITY] Invalid name. Avoid special characters: & | < > ^ % `" ' ; !" -ForegroundColor Red
        return
    }

    $registryInfo = Get-WSLDistroRegistryInfo -DistroName $targetName
    if ($restoreMode.Mode -eq "Replace" -and -not $registryInfo.Success) {
        if (Test-WSLBMRegistryInfoIsExplicitMissing -RegistryInfo $registryInfo) {
            Write-Host "[ERROR] Target distro does not exist. Choose Install as new distro or enter an existing distro." -ForegroundColor Red
        }
        else {
            Write-Host "[ERROR] Restore-WholeDistro cannot determine whether target distro exists. Failing closed." -ForegroundColor Red
            if ($null -ne $registryInfo -and -not [string]::IsNullOrWhiteSpace([string]$registryInfo.Reason)) {
                Write-Host "  Reason: $($registryInfo.Reason)" -ForegroundColor Yellow
            }
        }
        Write-LogEntry "ERROR" "Restore-WholeDistro" "Replace mode target validation failed. Target=$targetName | Reason=$($registryInfo.Reason)" -Distro $targetName
        return
    }

    if ($restoreMode.Mode -eq "InstallNew" -and $registryInfo.Success) {
        Write-Host "[ERROR] Target distro already exists. Choose Replace existing distro or enter a new distro name." -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-WholeDistro" "Install-new mode rejected existing target. Target=$targetName" -Distro $targetName
        return
    }

    if ($restoreMode.Mode -eq "InstallNew" -and -not (Test-WSLBMRegistryInfoIsExplicitMissing -RegistryInfo $registryInfo)) {
        Write-Host "[ERROR] Restore-WholeDistro cannot determine whether target distro exists. Failing closed." -ForegroundColor Red
        if ($null -ne $registryInfo -and -not [string]::IsNullOrWhiteSpace([string]$registryInfo.Reason)) {
            Write-Host "  Reason: $($registryInfo.Reason)" -ForegroundColor Yellow
        }
        Write-LogEntry "ERROR" "Restore-WholeDistro" "Registry state uncertain; restore aborted. Target=$targetName | Reason=$($registryInfo.Reason)" -Distro $targetName
        return
    }

    if ($registryInfo.Success) {
        Write-Host ""
        Write-Host "[Restore-WholeDistro] Replace existing distro." -ForegroundColor Yellow
        if ($Global:DryRun) {
            Write-Host "[DRY RUN] Mode: Replace existing distro." -ForegroundColor Cyan
            Write-Host "[DRY RUN] Would use Safety Net + REPLACE $targetName + shutdown + unregister + import." -ForegroundColor Cyan
        }

        $replacePathInfo = Resolve-ReplaceRestoreInstallPath -DistroName $targetName -BackupFile $backupFile
        if ((-not $replacePathInfo.Success) -or
            (-not [bool]$replacePathInfo.RegistryBasePathAvailable) -or
            [bool]$replacePathInfo.ManualPathUsed) {
            Write-Host "[ERROR] Replace restore cancelled before Safety Net." -ForegroundColor Red
            if ($null -ne $replacePathInfo -and -not [string]::IsNullOrWhiteSpace([string]$replacePathInfo.Reason)) {
                Write-Host "  Reason: $($replacePathInfo.Reason)" -ForegroundColor Yellow
            }
            if ($null -ne $replacePathInfo -and [bool]$replacePathInfo.ManualPathUsed) {
                Write-Host "  Reason: registry BasePath became unavailable; manual path fallback is not allowed for Restore-WholeDistro replace routing." -ForegroundColor Yellow
            }
            Write-LogEntry "ERROR" "Restore-WholeDistro" "Replace branch failed closed before Safety Net. Target=$targetName" -Distro $targetName
            return
        }
        $installPath = $replacePathInfo.InstallPath
        Write-RestoreWholeDistroModeSummary `
            -RestoreMode "Replace existing distro" `
            -DistroName $targetName `
            -InstallPath $installPath `
            -WillCreateSafetyNet $true `
            -RequiredPhrase "REPLACE $targetName"

        # Safety Net is a mandatory gate before destructive replace restore.
        Show-RestoreSafetyNetEntriesForDistro -DistroName $targetName
        $safetyFile = $null
        if ($Global:DryRun) {
            $safetyRoot = Get-RestoreSafetyNetRootPath
            $safeFileNameDistro = Get-RestoreSafetyNetSafeDistroFileName -DistroName $targetName
            if ([string]::IsNullOrWhiteSpace($safetyRoot)) {
                $safetyFile = "SAFETY-NET-$safeFileNameDistro-DRYRUN.tar"
            }
            else {
                $safetyFile = Join-Path $safetyRoot "SAFETY-NET-$safeFileNameDistro-DRYRUN.tar"
            }
            Write-Host "[DRY RUN] Would require Safety Net creation and verification before REPLACE $targetName." -ForegroundColor Cyan
        }
        else {
            while ($true) {
                $doSafety = Read-Host "Create and verify mandatory Safety Net backup first? [Y/N/Q]"

                if ($doSafety -eq "q" -or $doSafety -eq "Q") {
                    Write-LogEntry "WARN" "Restore-SafetyNet" "Cancelled by user before Safety Net" -Distro $targetName
                    Write-Host "Cancelled." -ForegroundColor Yellow
                    return
                }

                if ($doSafety -eq "y" -or $doSafety -eq "Y") {
                    if (-not (Confirm-RestoreSafetyNetCreation -DistroName $targetName)) {
                        Write-LogEntry "WARN" "Restore-SafetyNet" "Cancelled before Safety Net export confirmation" -Distro $targetName
                        Write-Host "Cancelled before Safety Net creation." -ForegroundColor Yellow
                        return
                    }

                    $safetyFile = New-RestoreSafetyNetBackup -DistroName $targetName
                    if (-not $safetyFile) {
                        Write-LogEntry "ERROR" "Restore-SafetyNet" "Safety Net failed; replace restore aborted" -Distro $targetName
                        Write-Host "[ERROR] Safety Net creation or validation failed. Replace restore cancelled before destructive confirmation." -ForegroundColor Red
                        return
                    }
                    break
                }

                if ($doSafety -eq "n" -or $doSafety -eq "N") {
                    Write-LogEntry "WARN" "Restore-SafetyNet" "User refused mandatory Safety Net; replace restore aborted" -Distro $targetName
                    Write-Host "[ERROR] Safety Net is required for replace restore. Restore cancelled." -ForegroundColor Red
                    return
                }

                Write-Host "Please enter Y, N, or Q." -ForegroundColor Red
            }
        }

        $Script:CurrentOperationId = New-OperationId
        Write-OperationIdBanner -OperationId $Script:CurrentOperationId
        Write-LogEntry "INFO" "Restore-WholeDistro" "Started replace restore for $targetName | OpId=$($Script:CurrentOperationId)" -Distro $targetName

        Invoke-RestoreStream `
            -backupFile $backupFile `
            -distroName $targetName `
            -installPath $installPath `
            -IsReplace $true `
            -ReplacePathInfo $replacePathInfo `
            -SafetyNetPath $safetyFile `
            -ArchiveFormat $archiveFormat `
            -ArchiveIsExternal:([bool]$view.IsExternal) `
            -LockTargetDir $view.LockTargetDir
        return
    }

    Write-Host ""
    Write-Host "[Restore-WholeDistro] Install as new distro." -ForegroundColor Green
    if ($Global:DryRun) {
        Write-Host "[DRY RUN] Mode: Install as new distro." -ForegroundColor Cyan
        Write-Host "[DRY RUN] Target distro '$targetName' does not exist. No existing distro will be overwritten." -ForegroundColor Cyan
        Write-Host "[DRY RUN] Would require INSTALL NEW $targetName + import." -ForegroundColor Cyan
    }

    $newPath = Read-Host "Enter install path (press Enter for default; Q/CANCEL to abort)"
    $newPathCommand = if ($null -eq $newPath) { "" } else { $newPath.Trim() }
    if ($newPathCommand -in @("q", "Q", "cancel", "CANCEL")) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        Write-LogEntry "WARN" "Restore-WholeDistro" "Cancelled before install-new path selection" -Distro $targetName
        return
    }
    if ([string]::IsNullOrWhiteSpace($newPath)) {
        if (-not (Test-WSLBMInstallRootReady `
                -Path $Global:Config.InstallRoot `
                -Label "Configured Install Root" `
                -InvalidAction "Default install-new restore path is blocked until Settings is corrected.")) {
            return
        }
        $newPath = Join-Path $Global:Config.InstallRoot $targetName
    }

    $installPathSafety = Test-RestoreInstallPathSafety -InstallPath $newPath -BackupFile $backupFile -DistroName $targetName -Mode "InstallNew"
    if (-not $installPathSafety.Success) {
        Write-Host "[ERROR] Install-new restore cancelled before restore stream because install path safety check failed." -ForegroundColor Red
        return
    }
    $newPath = $installPathSafety.NormalizedPath
    Write-RestoreWholeDistroModeSummary `
        -RestoreMode "Install new distro" `
        -DistroName $targetName `
        -InstallPath $newPath `
        -WillCreateSafetyNet $false `
        -RequiredPhrase "INSTALL NEW $targetName"

    Write-Host ""
    Write-Host "[Restore-WholeDistro INSTALL NEW Warning]" -ForegroundColor Yellow
    Write-Host "Import archive as new distro '$targetName'." -ForegroundColor Yellow
    Write-Host "No existing distro will be overwritten." -ForegroundColor Yellow

    if ($Global:DryRun) {
        Write-Host "[DRY RUN] Would require exact phrase: INSTALL NEW $targetName" -ForegroundColor Cyan
    }
    elseif (-not (Confirm-RestoreWholeDistroInstallNew -DistroName $targetName -InstallPath $newPath -BackupFile $backupFile)) {
        return
    }

    $Script:CurrentOperationId = New-OperationId
    Write-OperationIdBanner -OperationId $Script:CurrentOperationId
    Write-LogEntry "INFO" "Restore-WholeDistro" "Started install-new restore for $targetName | OpId=$($Script:CurrentOperationId)" -Distro $targetName

    Invoke-RestoreStream `
        -backupFile $backupFile `
        -distroName $targetName `
        -installPath $newPath `
        -IsReplace $false `
        -ArchiveFormat $archiveFormat `
        -ArchiveIsExternal:([bool]$view.IsExternal) `
        -LockTargetDir $view.LockTargetDir
}

function Invoke-RestoreStream {
    param(
        $backupFile,
        $distroName,
        $installPath,
        $IsReplace,
        $ReplacePathInfo = $null,
        $SafetyNetPath = "",
        [ValidateSet("7z", "tar")]
        [string]$ArchiveFormat = "7z",
        [bool]$ArchiveIsExternal = $false,
        [string]$LockTargetDir = ""
    )

    if ($Global:DryRun) {
        $restoreMode = if ($IsReplace) { "Replace" } else { "InstallNew" }
        try {
            if (-not (Test-Path -LiteralPath $backupFile -PathType Leaf)) {
                throw "Backup file missing: $backupFile"
            }

            Write-Host "[DRY RUN] Restore-WholeDistro preview starting. No restore actions will be performed." -ForegroundColor Cyan

            if ($ArchiveIsExternal) {
                Write-Host "  DRY RUN: external archive path is $backupFile" -ForegroundColor Yellow
                Write-Host "  DRY RUN: archive is not copied into Backup Root and is not rewritten." -ForegroundColor Yellow
            }

            $preflight = Test-RestoreImportPreflight `
                -BackupFile $backupFile `
                -InstallPath $installPath `
                -Distro $distroName `
                -Mode $restoreMode `
                -ArchiveFormat $ArchiveFormat `
                -ArchiveIsExternal:([bool]$ArchiveIsExternal)
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

            if ($IsReplace) {
                $null = Confirm-ReplaceRestoreDestructiveStep `
                    -DistroName $distroName `
                    -InstallPath $installPath `
                    -BackupFile $backupFile `
                    -RestoreTempRoot $restoreTempRoot `
                    -SafetyNetPath $SafetyNetPath `
                    -ReplacePathInfo $ReplacePathInfo
            }
            else {
                Write-Host "[DRY RUN] Restore-WholeDistro install-new preview:" -ForegroundColor Cyan
                Write-Host "  DRY RUN: would import archive $backupFile as new distro $distroName" -ForegroundColor Yellow
                Write-Host "  DRY RUN: would use install path $installPath" -ForegroundColor Yellow
                if (-not [string]::IsNullOrWhiteSpace($restoreTempRoot)) {
                    Write-Host "  DRY RUN: would use restore temp root $restoreTempRoot" -ForegroundColor Yellow
                }
                Write-LogEntry "INFO" "Restore-DryRun" "Install-new restore dry run stopped before WSL changes. Target: $distroName | InstallPath: $installPath | Backup: $backupFile" -Distro $distroName
            }

            if (-not (Test-Path -LiteralPath $installPath -PathType Container -ErrorAction SilentlyContinue)) {
                Write-Host "DRY RUN: would create install path $installPath" -ForegroundColor Yellow
                Write-LogEntry "INFO" "Restore-DryRun" "Would create install path: $installPath" -Distro $distroName
            }

            if ($ArchiveFormat -eq "tar") {
                Write-Host "DRY RUN: would import the raw tar archive directly from $backupFile" -ForegroundColor Yellow
                Write-Host "DRY RUN: would import $distroName from the raw tar archive into $installPath" -ForegroundColor Yellow
            }
            else {
                Write-Host "DRY RUN: would extract the selected tar export from $backupFile to the restore temp path" -ForegroundColor Yellow
                Write-Host "DRY RUN: would import $distroName from the restore temp tar into $installPath" -ForegroundColor Yellow
            }
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

    $effectiveLockTargetDir = $LockTargetDir
    if ([string]::IsNullOrWhiteSpace($effectiveLockTargetDir)) {
        $effectiveLockTargetDir = Get-RestoreExternalLockRootPath
    }
    Initialize-RestoreLockTargetDirectory -LockTargetDir $effectiveLockTargetDir
    New-LockFile -OperationType "Restore" -TargetDir $effectiveLockTargetDir
    $Global:BackupState.IsRunning = $true

    $restoreBranch = if ($IsReplace) { "Replace" } else { "InstallNew" }
    Write-LogEntry "INFO" "Restore-Exec" "Target: $distroName | Branch: $restoreBranch | ArchiveFormat=$ArchiveFormat | External=$ArchiveIsExternal"

    $restoreTempDir = $null
    $restoreTempTar = $null
    $restoreTempExpectedTarName = $null
    $preflight = $null
    $restoreMode = if ($IsReplace) { "Replace" } else { "InstallNew" }
    $installPathCreatedByRestore = $false
    $importAttempted = $false
    $importSucceeded = $false

    try {
        if (-not (Test-Path -LiteralPath $backupFile)) {
            throw "Backup file missing: $backupFile"
        }

        $preflight = Test-RestoreImportPreflight `
            -BackupFile $backupFile `
            -InstallPath $installPath `
            -Distro $distroName `
            -Mode $restoreMode `
            -ArchiveFormat $ArchiveFormat `
            -ArchiveIsExternal:([bool]$ArchiveIsExternal)
        if (-not $preflight.Success) {
            return
        }
        if ($preflight.InstallPath) {
            $installPath = $preflight.InstallPath
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$preflight.TarEntryLeafName)) {
            $restoreTempExpectedTarName = [string]$preflight.TarEntryLeafName
        }
        $restoreTempRoot = ""
        if ($null -ne $preflight.TempPathInfo) {
            $restoreTempRoot = $preflight.TempPathInfo.TempRoot
        }

        if ($IsReplace) {
            if (-not (Confirm-ReplaceRestoreDestructiveStep `
                -DistroName $distroName `
                -InstallPath $installPath `
                -BackupFile $backupFile `
                -RestoreTempRoot $restoreTempRoot `
                -SafetyNetPath $SafetyNetPath `
                -ReplacePathInfo $ReplacePathInfo)) {
                Write-Host "[ERROR] Replace restore aborted before any destructive WSL changes." -ForegroundColor Red
                return
            }

            Write-Host "Unregistering existing distro..." -ForegroundColor Yellow
            # WSL high-risk boundary: replace restore reaches shutdown/unregister only after preflight, Safety Net, and exact confirmation.
            $shutdownResult = Invoke-GuardedWSLCommand -Description "Shutdown WSL before replace restore" -Arguments @("--shutdown") -Distro $distroName
            if (-not $shutdownResult.Success) {
                throw "WSL shutdown failed before replace restore"
            }
            Start-Sleep -Seconds 1

            # WSL high-risk boundary: unregister remains guarded and follows the shutdown success check.
            $unregisterResult = Invoke-GuardedWSLCommand -Description "Unregister distro before replace restore" -Arguments @("--unregister", $distroName) -Distro $distroName
            if (-not $unregisterResult.Success) {
                throw "WSL unregister failed for $distroName"
            }
            Start-Sleep -Seconds 2
        }

        if (-not (Test-Path -LiteralPath $installPath)) {
            $installPathCreatedByRestore = $true
            if ($Global:DryRun) {
                Write-Host "DRY RUN: would create install path $installPath" -ForegroundColor Yellow
                Write-LogEntry "INFO" "Restore-DryRun" "Would create install path: $installPath" -Distro $distroName
            }
            else {
                [System.IO.Directory]::CreateDirectory($installPath) | Out-Null
            }
        }

        Write-Host "Restoring (this may take several minutes)..." -ForegroundColor Cyan

        $importTar = $null
        if ($ArchiveFormat -eq "tar") {
            $importTar = $backupFile
            Write-Host "Using raw tar archive directly for WSL import." -ForegroundColor Cyan
            Write-LogEntry "INFO" "Restore-Extract" "Raw tar archive used directly; no temp extraction. Archive=$backupFile" -Distro $distroName
        }
        else {
            if ([string]::IsNullOrWhiteSpace([string]$preflight.TarEntryName) -or
                [string]::IsNullOrWhiteSpace([string]$restoreTempExpectedTarName)) {
                throw "Restore .7z archive tar entry was not resolved."
            }
            $extractResult = Expand-RestoreArchiveToTempTar `
                -BackupFile $backupFile `
                -Distro $distroName `
                -TarSizeBytes $preflight.TarSizeBytes `
                -TempPathInfo $preflight.TempPathInfo `
                -InstallPath $installPath `
                -TarEntryName ([string]$preflight.TarEntryName)
            $restoreTempDir = $extractResult.TempDir
            $restoreTempTar = $extractResult.TempTar
            if (-not $extractResult.Success) {
                throw "Restore tar extraction failed"
            }
            $importTar = $restoreTempTar
        }

        $importAttempted = $true
        $importResult = Invoke-RestoreImportFromTar -DistroName $distroName -InstallPath $installPath -TempTar $importTar
        if (-not $importResult.Success) {
            throw "WSL import failed for $distroName"
        }
        $importSucceeded = $true

        Remove-LockFile

        Write-Host ""
        Write-Host "SUCCESS: WholeDistro restore completed." -ForegroundColor Green
        Write-Host "  Distro: $distroName" -ForegroundColor Cyan
        Write-Host "  Path  : $installPath" -ForegroundColor Cyan
        Write-LogEntry "SUCCESS" "Restore-Exec" "Completed | OpId=$($Script:CurrentOperationId)"

    }
    catch {
        $errMsg = $_.Exception.Message
        Write-LogEntry "ERROR" "Restore-Exec" "Failed: $errMsg | OpId=$($Script:CurrentOperationId)"
        Write-Host "[ERROR] RESTORE FAILED: $errMsg" -ForegroundColor Red

        if ($IsReplace) {
            $manualRecoveryHintNeeded = $true
            if ($importAttempted -and -not $importSucceeded) {
                Write-Host "[WARN] Import failed after unregister; checking for partial target distro before Safety Net rollback." -ForegroundColor Yellow
                $null = Invoke-RestorePartialDistroCleanup `
                    -DistroName $distroName `
                    -InstallPath $installPath `
                    -BackupFile $backupFile `
                    -Branch "Replace" `
                    -InstallPathCreatedByRestore ([bool]$installPathCreatedByRestore)
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$SafetyNetPath) -and
                (Test-Path -LiteralPath $SafetyNetPath -PathType Leaf)) {
                $rollbackResult = Invoke-RestoreSafetyNetRollbackPrompt `
                    -DistroName $distroName `
                    -InstallPath $installPath `
                    -SafetyNetPath $SafetyNetPath `
                    -ReplacePathInfo $ReplacePathInfo
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
        elseif ($importAttempted -and -not $importSucceeded) {
            $null = Invoke-RestorePartialDistroCleanup `
                -DistroName $distroName `
                -InstallPath $installPath `
                -BackupFile $backupFile `
                -Branch "InstallNew" `
                -InstallPathCreatedByRestore ([bool]$installPathCreatedByRestore)
        }

        Stop-ActiveBackupProcesses

    }
    finally {
        Stop-ActiveBackupProcesses

        Clear-RestoreTempArtifacts `
            -TempDir $restoreTempDir `
            -TempTar $restoreTempTar `
            -Distro $distroName `
            -ExpectedTarName $restoreTempExpectedTarName

        Remove-LockFile
        $Global:BackupState.IsRunning = $false
        $Script:CurrentOperationId = ""
    }
    Read-Host "Press Enter to continue..."
}

function Confirm-RestorePathTarget {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistroName,

        [Parameter(Mandatory = $true)]
        [string]$RestoreModeLabel,

        [Parameter(Mandatory = $true)]
        [string]$ArchiveTopLevelEntry,

        [Parameter(Mandatory = $true)]
        [string]$UserInputPath,

        [Parameter(Mandatory = $true)]
        [string]$NormalizedTargetPath,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedFinalPath,

        [Parameter(Mandatory = $true)]
        [object]$TargetState
    )

    $isOverwriteExactReplace = ($RestoreModeLabel -eq "Overwrite existing path")
    $requiredPhrase = "RESTORE PATH TO ${DistroName}:$NormalizedTargetPath"
    $targetStateText = if ($TargetState.CanInspect) {
        if ($TargetState.IsSymlink) { "Exists but is a symbolic link" }
        elseif (-not $TargetState.Exists) { "Missing" }
        elseif (-not $TargetState.IsDirectory) { "Exists but is not a directory" }
        elseif ($TargetState.IsNonEmpty) { "Exists and non-empty" }
        else { "Exists and empty" }
    }
    else {
        "Inspection failed; treated as non-empty/high-risk"
    }
    $willOverwrite = ($isOverwriteExactReplace -or $TargetState.IsNonEmpty -or (-not $TargetState.CanInspect))

    Write-Host ""
    Write-Host "[Restore-Path Pre-flight]" -ForegroundColor Cyan
    Write-Host "  Distro                   : $DistroName" -ForegroundColor DarkGray
    if ($isOverwriteExactReplace) {
        Write-Host "  Restore mode             : Overwrite existing path" -ForegroundColor DarkGray
        Write-Host "  Archive top-level entry  : $ArchiveTopLevelEntry" -ForegroundColor DarkGray
        Write-Host "  Target path              : $NormalizedTargetPath" -ForegroundColor DarkGray
        Write-Host "  Existing target contents : will be deleted before restore" -ForegroundColor Yellow
        Write-Host "  Expected final path      : $ExpectedFinalPath" -ForegroundColor DarkGray
        Write-Host "  Strip top-level entry    : Yes" -ForegroundColor DarkGray
    }
    else {
        Write-Host "  Restore mode            : Extract under target directory" -ForegroundColor DarkGray
        Write-Host "  Archive top-level entry : $ArchiveTopLevelEntry" -ForegroundColor DarkGray
        Write-Host "  Target directory        : $NormalizedTargetPath" -ForegroundColor DarkGray
        Write-Host "  Expected final path     : $ExpectedFinalPath" -ForegroundColor DarkGray
        Write-Host "  Strip top-level entry   : No" -ForegroundColor DarkGray
    }
    Write-Host "  User input path          : $UserInputPath" -ForegroundColor DarkGray
    Write-Host "  Will overwrite existing files: $(if ($willOverwrite) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($willOverwrite) { [ConsoleColor]::Yellow } else { [ConsoleColor]::DarkGray })
    Write-Host "  Required phrase          : $requiredPhrase" -ForegroundColor DarkGray
    Write-Host "  Final path state         : $targetStateText" -ForegroundColor DarkGray
    Write-Host "  Detail                   : $($TargetState.Reason)" -ForegroundColor DarkGray

    if ($Global:DryRun) {
        Write-Host "[DRY RUN] Restore-Path confirmation preview only." -ForegroundColor Cyan
        Write-Host "  DRY RUN: would require the exact phrase below before any delete or tar extraction:" -ForegroundColor Yellow
        Write-Host "    $requiredPhrase" -ForegroundColor Cyan
        return $false
    }

    if ($TargetState.IsSymlink) {
        Write-Host "[ERROR] Restore-Path target is a symbolic link. Restore cancelled before delete/extraction." -ForegroundColor Red
        return $false
    }

    if ($TargetState.Exists -and -not $TargetState.IsDirectory) {
        if ($isOverwriteExactReplace) {
            Write-Host "[ERROR] Overwrite existing path currently supports directory-style Path restore only. Target exists but is not a directory." -ForegroundColor Red
        }
        else {
            Write-Host "[ERROR] Restore-Path final path exists but is not a directory. Restore cancelled before extraction." -ForegroundColor Red
        }
        return $false
    }

    if ($willOverwrite) {
        if ($isOverwriteExactReplace) {
            Write-Host "[WARNING] Overwrite existing path is destructive exact replace." -ForegroundColor Red
            Write-Host "Existing target contents will be deleted before tar extraction." -ForegroundColor Red
        }
        else {
            Write-Host "[WARNING] Restore-Path final path appears non-empty or could not be safely inspected." -ForegroundColor Red
            Write-Host "This restore can overwrite files under the expected final path." -ForegroundColor Red
        }
        Write-WSLBMRequiredPhrasePrompt -RequiredPhrase $requiredPhrase

        $confirmationResult = Read-WSLBMExactConfirmation -RequiredPhrase $requiredPhrase
        if ($confirmationResult -eq "Cancelled") {
            Write-LogEntry "WARN" "Restore-Path-Confirm" "Cancelled before Restore-Path overwrite. Target=$NormalizedTargetPath | Final=$ExpectedFinalPath" -Distro $DistroName
            return $false
        }
        if ($confirmationResult -eq "Mismatch") {
            Write-Host "[ERROR] Confirmation phrase did not match. Restore cancelled before WSL tar extraction." -ForegroundColor Red
            Write-LogEntry "WARN" "Restore-Path-Confirm" "Confirmation phrase mismatch. Target=$NormalizedTargetPath | Final=$ExpectedFinalPath" -Distro $DistroName
            return $false
        }

        Write-LogEntry "WARN" "Restore-Path-Confirm" "Confirmed Restore-Path overwrite. Target=$NormalizedTargetPath | Final=$ExpectedFinalPath" -Distro $DistroName
        return $true
    }

    $confirmContinue = Read-Host "Expected final path is empty/missing. Press Enter to continue, or Q/CANCEL to abort"
    if ($confirmContinue -in @("q", "Q", "cancel", "CANCEL")) {
        Write-LogEntry "WARN" "Restore-Path-Confirm" "Cancelled before Restore-Path to empty/missing final path. Target=$NormalizedTargetPath | Final=$ExpectedFinalPath" -Distro $DistroName
        return $false
    }

    Write-LogEntry "INFO" "Restore-Path-Confirm" "Confirmed Restore-Path to empty/missing final path. Target=$NormalizedTargetPath | Final=$ExpectedFinalPath" -Distro $DistroName
    return $true
}

function New-PathRestoreTempPathInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFile,

        [string]$TarName = "restore-path.tar",

        [string]$Distro = $Script:CurrentDistro
    )

    $operationId = Get-RestoreTempOperationId
    $candidateParents = New-RestoreTempCandidateParents -OperationId $operationId -Distro $Distro
    $forbiddenParentRules = New-RestoreTempForbiddenParentRules -BackupFile $BackupFile

    return New-ControlledRestoreTempPathInfo `
        -CandidateParents $candidateParents `
        -TempDirPrefix ".tmp\restore-$operationId" `
        -TarName $TarName `
        -PathLabel "Path restore temp directory" `
        -DisplayLabel "Restore-Path temp root" `
        -LogAction "Restore-Path-TempRoot" `
        -RequiredParentReason "Path restore temp directory must be under the selected temp parent root." `
        -ForbiddenParentRules @($forbiddenParentRules) `
        -ShapeRegex '^restore-\d{8}-\d{6}-[0-9a-f]{4}-[0-9a-fA-F]{32}$' `
        -ShapeRejectReason "Path restore temp directory name does not match controlled prefix." `
        -FailureMessage "Cannot allocate a writable Restore-Path temp directory." `
        -Distro $Distro
}

function Invoke-RestorePath {
    param($backupDir)

    if (-not $Script:CurrentDistro) {
        Write-Host "[ERROR] No Distro Selected." -ForegroundColor Red
        return
    }
    if (-not (Test-SafeDistroName -Name $Script:CurrentDistro)) {
        Write-Host "[SECURITY] Cannot restore: Distro name contains unsafe characters." -ForegroundColor Red
        return
    }

    $view = New-RestoreBackupView -BackupInput $backupDir -ExpectedRestoreType "Path"
    if (-not $view.Success) {
        Write-Host "[ERROR] Restore-Path source rejected: $($view.Reason)" -ForegroundColor Red
        return
    }

    $backupDir = $view.BackupDir
    $backupFile = $view.ArchivePath
    $archiveFormat = $view.ArchiveFormat
    if ($view.IsExternal) {
        Write-RestoreBackupViewSummary -View $view
    }
    if ($view.RestoreKind -ne "Path") {
        Write-Host "[ERROR] Restore-Path only handles Path restore sources." -ForegroundColor Red
        Read-Host "Press Enter..."
        return
    }

    if ([string]::IsNullOrWhiteSpace($backupFile)) {
        Write-Host "[ERROR] No supported archive found in backup folder." -ForegroundColor Red
        Read-Host "Press Enter..."
        return
    }

    if ($archiveFormat -notin @("7z", "tar")) {
        if ($Global:DryRun) {
            Write-Host "  DRY RUN: would still run archive integrity before rejecting unsupported Restore-Path archive format." -ForegroundColor Yellow
        }
        else {
            try {
                Test-BackupIntegrity -backupFile $backupFile -archiveKind "PATH"
            }
            catch {
                Write-Host "[ERROR] Restore-Path archive integrity check failed: $($_.Exception.Message)" -ForegroundColor Red
                Write-LogEntry "ERROR" "Restore-Path" "Archive integrity failed before unsupported format rejection: $($_.Exception.Message)" -Distro $Script:CurrentDistro
                Read-Host "Press Enter..."
                return
            }
        }
        Write-Host "[ERROR] Restore-Path supports only .7z and .tar archives in v4.2." -ForegroundColor Red
        Read-Host "Press Enter..."
        return
    }

    $restoreMode = Read-RestorePathMode
    if (-not $restoreMode.Success) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }

    $targetSelection = Read-LinuxPathFromSelectionMenu -DistroName $Script:CurrentDistro -Purpose "Restore-Path"
    if (-not $targetSelection.Success) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }
    if ($restoreMode.Mode -eq "Overwrite" -and $targetSelection.LinuxPath -eq "/") {
        Write-Host "[ERROR] Overwrite existing path refuses to restore to Linux root (/)." -ForegroundColor Red
        Write-Host "        Choose a concrete project path, or use Extract under target directory." -ForegroundColor Yellow
        Read-Host "Press Enter..."
        return
    }

    $previewExpectedFinalPath = if ($restoreMode.Mode -eq "Overwrite") {
        $targetSelection.LinuxPath
    }
    else {
        Join-LinuxPathLiteral -Parent $targetSelection.LinuxPath -Child "<archive-top-level-entry>"
    }

    $tarTool = [pscustomobject]@{ Name = "tar"; Version = "unknown" }
    $strategy = New-ArchiveStrategy -ArchiveFormat $archiveFormat -WorkloadType "Path" -CompressionTool ([pscustomobject]@{ Name = "7z"; Version = $null }) -TarTool $tarTool
    if ($null -eq $strategy) { return }
    $plan = New-RestorePlan `
        -Type "Path" `
        -TargetDistro $Script:CurrentDistro `
        -TargetLinuxPath $targetSelection.LinuxPath `
        -ArchivePath $backupFile `
        -ArchiveStrategy $strategy `
        -RestoreMode $restoreMode.Label `
        -ArchiveTopLevelEntry "<inspected before restore>" `
        -UserInputPath $targetSelection.UserInputPath `
        -ExpectedFinalPath $previewExpectedFinalPath `
        -StripTopLevelEntry ([bool]$restoreMode.StripTopLevelEntry)

    if ($Global:DryRun) {
        Show-RestorePlanDryRun -Plan $plan
        Read-Host "Press Enter..."
        return
    }

    $pathRestoreTempDir = $null
    $pathRestoreTempTar = $null
    $pathRestoreDirectTreeRoot = $null
    $pathRestoreExpectedTarName = "restore-path.tar"

    try {
        $Script:CurrentOperationId = New-OperationId
        Write-OperationIdBanner -OperationId $Script:CurrentOperationId

        Test-BackupIntegrity -backupFile $backupFile -archiveKind "PATH"

        $tarInputPath = $backupFile
        $topLevelInfo = $null
        $isDirect7zTree = $false
        $archiveShape = Get-RestorePathArchiveShape `
            -BackupFile $backupFile `
            -ArchiveFormat $archiveFormat `
            -Distro $Script:CurrentDistro
        if (-not $archiveShape.Success) {
            throw "Restore-Path archive shape detection failed: $($archiveShape.Reason)"
        }

        if ($archiveShape.Shape -eq "TarWrapped7z") {
            $pathRestoreExpectedTarName = [string]$archiveShape.TarEntryLeafName
            $pathRestoreTempInfo = New-PathRestoreTempPathInfo `
                -BackupFile $backupFile `
                -TarName $pathRestoreExpectedTarName `
                -Distro $Script:CurrentDistro
            $expandResult = Expand-RestoreArchiveToTempTar `
                -BackupFile $backupFile `
                -Distro $Script:CurrentDistro `
                -TempPathInfo $pathRestoreTempInfo `
                -TarEntryName ([string]$archiveShape.TarEntryName) `
                -TarSizeBytes ([long]$archiveShape.TarSizeBytes) `
                -MinimumTarSizeBytes 100
            $pathRestoreTempDir = $expandResult.TempDir
            $pathRestoreTempTar = $expandResult.TempTar
            if (-not $expandResult.Success) {
                throw "Failed to extract detected tar entry '$($archiveShape.TarEntryName)' from Restore-Path archive."
            }
            $tarInputPath = $expandResult.TempTar
            $topLevelInfo = Get-WSLPathTarTopLevelInfo -DistroName $Script:CurrentDistro -ArchivePath $tarInputPath
        }
        elseif ($archiveShape.Shape -eq "Direct7zTree") {
            $isDirect7zTree = $true
            $pathRestoreExpectedTarName = "direct-tree.tar"
            $pathRestoreTempInfo = New-PathRestoreTempPathInfo `
                -BackupFile $backupFile `
                -TarName $pathRestoreExpectedTarName `
                -Distro $Script:CurrentDistro
            $pathRestoreTempDir = $pathRestoreTempInfo.TempDir
            $pathRestoreTempTar = $pathRestoreTempInfo.TempTar
            $topLevelInfo = $archiveShape.TopLevelInfo
            Write-Host "Direct .7z path archive detected. Restoring file tree from archive." -ForegroundColor Cyan
            Write-Host "Linux permissions/symlinks depend on how the archive was created." -ForegroundColor Yellow
        }
        else {
            $topLevelInfo = Get-WSLPathTarTopLevelInfo -DistroName $Script:CurrentDistro -ArchivePath $tarInputPath
        }

        if (-not $topLevelInfo.Success) {
            $topLevelFailureIsUnsafe = ([string]$topLevelInfo.Reason) -match '(?i)unsafe|absolute|empty|traversal'
            if ($topLevelFailureIsUnsafe) {
                Write-Host "[ERROR] Restore-Path archive top-level entry is unsafe." -ForegroundColor Red
                Write-Host "        $($topLevelInfo.Reason)" -ForegroundColor Yellow
                Read-Host "Press Enter..."
                return
            }
            if ($restoreMode.Mode -eq "Overwrite") {
                Write-Host "[ERROR] Overwrite existing path requires one safe, unique archive top-level entry." -ForegroundColor Red
                Write-Host "        Cannot identify archive top-level entry: $($topLevelInfo.Reason)" -ForegroundColor Yellow
                Write-Host "        Use Restore-Path mode 2 (Extract under target directory) for this archive." -ForegroundColor Yellow
                Read-Host "Press Enter..."
                return
            }

            Write-Host "[WARN] Could not identify archive top-level entry: $($topLevelInfo.Reason)" -ForegroundColor Yellow
            Write-Host "       Expected final path will be shown as unknown; target directory itself will not be cleared." -ForegroundColor Yellow
            $topLevelInfo = New-WSLPathTarTopLevelInfoResult -Success $false -TopLevelEntry "unknown" -Reason $topLevelInfo.Reason
        }
        if ($restoreMode.Mode -eq "Overwrite" -and -not $topLevelInfo.Unique) {
            Write-Host "[ERROR] Overwrite existing path requires one unique archive top-level entry." -ForegroundColor Red
            Write-Host "        Archive has: $($topLevelInfo.TopLevelEntries -join ', ')" -ForegroundColor Yellow
            Write-Host "        Use Restore-Path mode 2 (Extract under target directory) for this archive." -ForegroundColor Yellow
            Read-Host "Press Enter..."
            return
        }
        if ($restoreMode.Mode -eq "Overwrite" -and -not $topLevelInfo.HasChildEntries -and -not $topLevelInfo.HasDirectoryTopLevelEntry) {
            Write-Host "[ERROR] Overwrite existing path requires a directory-style archive with entries under the top-level directory." -ForegroundColor Red
            Write-Host "        Use Restore-Path mode 2 (Extract under target directory) for this archive." -ForegroundColor Yellow
            Read-Host "Press Enter..."
            return
        }

        $targetContext = Get-RestorePathTargetContext `
            -DistroName $Script:CurrentDistro `
            -RestoreMode $restoreMode `
            -TargetSelection $targetSelection `
            -TopLevelInfo $topLevelInfo
        if (-not $targetContext.Success) {
            Read-Host "Press Enter..."
            return
        }

        $restorePayloadBytes = if ($isDirect7zTree) {
            $backupItem = Get-Item -LiteralPath $backupFile -ErrorAction Stop
            [Math]::Max([long]$archiveShape.TotalSizeBytes, [long]$backupItem.Length)
        }
        else {
            $restorePathTarItem = Get-Item -LiteralPath $tarInputPath -ErrorAction Stop
            [long]$restorePathTarItem.Length
        }
        if (-not (Test-WSLLinuxPathFreeSpaceForRestorePayload `
                    -LinuxPath $targetSelection.LinuxPath `
                    -TarSizeBytes ([long]$restorePayloadBytes) `
                    -DistroName $Script:CurrentDistro `
                    -Label $restoreMode.Label)) {
            Write-Host "[ERROR] Restore-Path cancelled before confirmation, delete, mkdir, or tar extraction." -ForegroundColor Red
            Read-Host "Press Enter..."
            return
        }

        if (-not (Confirm-RestorePathTarget `
                    -DistroName $Script:CurrentDistro `
                    -RestoreModeLabel $restoreMode.Label `
                    -ArchiveTopLevelEntry $topLevelInfo.TopLevelEntry `
                    -UserInputPath $targetSelection.UserInputPath `
                    -NormalizedTargetPath $targetSelection.LinuxPath `
                    -ExpectedFinalPath $targetContext.ExpectedFinalPath `
                    -TargetState $targetContext.TargetState)) {
            Write-Host "Restore cancelled before WSL tar extraction." -ForegroundColor Yellow
            Read-Host "Press Enter..."
            return
        }

        Write-LogEntry "INFO" "Restore-Path" "Started to $($targetSelection.LinuxPath) from $backupFile | OpId=$($Script:CurrentOperationId)" -Distro $Script:CurrentDistro

        $Global:BackupState.IsActive = $true
        $Global:BackupState.IsRunning = $true
        $Global:BackupState.Operation = "Restore-Path"
        $Global:BackupState.CurrentFile = $backupFile
        $Global:BackupState.CurrentDir = $targetSelection.LinuxPath
        $Global:BackupState.ActiveProcess = $null
        $Global:BackupState.StartTime = Get-Date

        Initialize-RestoreLockTargetDirectory -LockTargetDir $view.LockTargetDir
        New-LockFile -OperationType "Restore-Path" -TargetDir $view.LockTargetDir

        $stripTopLevelForWslTar = [bool]$restoreMode.StripTopLevelEntry
        if ($isDirect7zTree) {
            $directExtractResult = Invoke-RestorePathDirect7zTreeExtract `
                -BackupFile $backupFile `
                -TempPathInfo $pathRestoreTempInfo `
                -EstimatedSizeBytes ([long]$archiveShape.TotalSizeBytes) `
                -Distro $Script:CurrentDistro
            $pathRestoreDirectTreeRoot = $directExtractResult.ExtractRoot
            if ($directExtractResult.TimedOut) { throw "Direct .7z tree extraction timed out." }
            if ($directExtractResult.Cancelled) { throw "Direct .7z tree extraction cancelled by user." }
            if (-not $directExtractResult.Success) {
                throw "Direct .7z tree extraction failed: $($directExtractResult.Reason)"
            }

            $directTarResult = Convert-RestorePathDirectTreeToTempTar `
                -ExtractRoot $pathRestoreDirectTreeRoot `
                -TempTar $pathRestoreTempTar `
                -TopLevelInfo $topLevelInfo `
                -StripTopLevelEntry:([bool]$restoreMode.StripTopLevelEntry) `
                -Distro $Script:CurrentDistro
            if ($directTarResult.TimedOut) { throw "Direct .7z tree staging timed out." }
            if ($directTarResult.Cancelled) { throw "Direct .7z tree staging cancelled by user." }
            if (-not $directTarResult.Success) {
                throw "Direct .7z tree staging failed."
            }

            $directTarItem = Get-Item -LiteralPath $pathRestoreTempTar -ErrorAction Stop
            if (-not (Test-WSLLinuxPathFreeSpaceForRestorePayload `
                        -LinuxPath $targetSelection.LinuxPath `
                        -TarSizeBytes ([long]$directTarItem.Length) `
                        -DistroName $Script:CurrentDistro `
                        -Label $restoreMode.Label)) {
                throw "Restore-Path target space check failed after direct .7z staging."
            }

            $tarInputPath = $pathRestoreTempTar
            $stripTopLevelForWslTar = $false
        }

        if ($restoreMode.Mode -eq "Overwrite") {
            Invoke-RestorePathExactReplacePrepare `
                -DistroName $Script:CurrentDistro `
                -TargetLinuxPath $targetSelection.LinuxPath
        }

        $extractResult = Invoke-WSLPathTarExtractArchive `
            -DistroName $Script:CurrentDistro `
            -ArchivePath $tarInputPath `
            -TargetLinuxPath $targetSelection.LinuxPath `
            -StripTopLevelEntry:$stripTopLevelForWslTar

        if ($extractResult.TimedOut) { throw "WSL tar restore timed out." }
        if ($extractResult.Cancelled) { throw "WSL tar restore cancelled by user." }
        if ($null -eq $extractResult.ExitCode) { throw "WSL tar restore did not report an exit code." }
        if (-not $extractResult.Success) {
            $detail = Get-WSLBMFirstOutputLine -Value $extractResult.CombinedOutput
            if ([string]::IsNullOrWhiteSpace($detail)) {
                throw "WSL tar restore failed (exit code $($extractResult.ExitCode))."
            }
            throw "WSL tar restore failed (exit code $($extractResult.ExitCode)): $detail"
        }

        Remove-LockFile
        Write-Host "SUCCESS: Path restored." -ForegroundColor Green
        if ($restoreMode.Mode -eq "ExtractUnder") {
            Write-Host "Extracted under : $($targetSelection.LinuxPath)" -ForegroundColor Cyan
            Write-Host "Restored path   : $($targetContext.ExpectedFinalPath)" -ForegroundColor Cyan
        }
        else {
            Write-Host "Restore mode : Overwrite existing path" -ForegroundColor Cyan
            Write-Host "Final path   : $($targetContext.ExpectedFinalPath)" -ForegroundColor Cyan
        }
        $pathRestoreCompleteMessage = @(
            "Completed mode=$($restoreMode.Mode)"
            "target=$($targetSelection.LinuxPath)"
            "final=$($targetContext.ExpectedFinalPath)"
            "OpId=$($Script:CurrentOperationId)"
        ) -join " | "
        Write-LogEntry "SUCCESS" "Restore-Path" $pathRestoreCompleteMessage -Distro $Script:CurrentDistro
    }
    catch {
        Write-Host "[ERROR] Restore-Path failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[WARN] If extraction had already started, the target may be partially restored." -ForegroundColor Yellow
        Write-LogEntry "ERROR" "Restore-Path" "Failed: $($_.Exception.Message) | OpId=$($Script:CurrentOperationId)" -Distro $Script:CurrentDistro
        Stop-ActiveBackupProcesses
    }
    finally {
        Stop-ActiveBackupProcesses
        Clear-RestorePathDirectTreeExtractedFiles `
            -TempDir $pathRestoreTempDir `
            -ExtractRoot $pathRestoreDirectTreeRoot `
            -Distro $Script:CurrentDistro
        Clear-RestoreTempArtifacts `
            -TempDir $pathRestoreTempDir `
            -TempTar $pathRestoreTempTar `
            -Distro $Script:CurrentDistro `
            -ExpectedTarName $pathRestoreExpectedTarName `
            -ExpectedTempDirRegex '^restore-\d{8}-\d{6}-[0-9a-f]{4}-[0-9a-fA-F]{32}$' `
            -TempDirShapeRejectReason "Restore-Path temp directory name does not match controlled prefix"
        Remove-LockFile
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

function Remove-BatchBackups {
    $scanPath = Get-ValidatedBackupScanPath
    if (-not $scanPath) {
        Read-Host "Press Enter..."
        return
    }

    Clear-Host
    Write-Host "=== BATCH DELETE ($scanPath) ===" -ForegroundColor Red

    if (-not (Test-Path -LiteralPath $scanPath)) {
        Write-Host "Path not found." -ForegroundColor Yellow
        Read-Host "Press Enter..."
        return
    }

    $backups = @(Get-RecognizedBackupFolders -ScanPath $scanPath)

    if ($backups.Count -eq 0) {
        Write-Host "No backups found."
        Read-Host "Press Enter..."
        return
    }

    $currentPage = 1
    $pageSize = 20
    $pageInfo = Get-BackupPageInfo -Backups $backups -Page $currentPage -PageSize $pageSize
    Show-BackupTable -Backups $backups -Page $pageInfo.Page -PageSize $pageSize

    $targets = @()
    while ($true) {
        Write-Host ""
        $deletePromptParts = @("Delete visible number(s)")
        if ($pageInfo.Page -lt $pageInfo.PageCount) { $deletePromptParts += "[N] Next" }
        if ($pageInfo.Page -gt 1) { $deletePromptParts += "[P] Previous" }
        $deletePromptParts += "[0/Q] Cancel"
        $inputStr = Read-Host (($deletePromptParts -join ", ") + ":")

        if ($inputStr -eq "q" -or $inputStr -eq "Q" -or $inputStr -eq "0") {
            return
        }
        if ($inputStr -eq "n" -or $inputStr -eq "N") {
            if ($pageInfo.Page -ge $pageInfo.PageCount) {
                Write-Host "No next page." -ForegroundColor Yellow
                continue
            }
            $currentPage++
            $pageInfo = Get-BackupPageInfo -Backups $backups -Page $currentPage -PageSize $pageSize
            Show-BackupTable -Backups $backups -Page $pageInfo.Page -PageSize $pageSize
            continue
        }
        if ($inputStr -eq "p" -or $inputStr -eq "P") {
            if ($pageInfo.Page -le 1) {
                Write-Host "No previous page." -ForegroundColor Yellow
                continue
            }
            $currentPage--
            $pageInfo = Get-BackupPageInfo -Backups $backups -Page $currentPage -PageSize $pageSize
            Show-BackupTable -Backups $backups -Page $pageInfo.Page -PageSize $pageSize
            continue
        }

        $tokens = @($inputStr -split "," | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($tokens.Count -eq 0) {
            Write-Host "No selections entered." -ForegroundColor Yellow
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
            if ($idxNum -le 0 -or $idxNum -gt $pageInfo.Count) {
                $invalidTokens += "$token (not on current visible page)"
                continue
            }

            $targets += $backups[$pageInfo.StartIndex + $idxNum - 1]
        }

        if ($invalidTokens.Count -gt 0) {
            Write-Host "Invalid selection token(s): $($invalidTokens -join ', ')." -ForegroundColor Red
            Write-Host "Delete uses current page numbers only." -ForegroundColor Yellow
            continue
        }

        if ($targets.Count -eq 0) {
            Write-Host "No valid selections." -ForegroundColor Yellow
            continue
        }

        $protectedSafetyNetTargets = @($targets | Where-Object { Test-WSLBMBackupEntryIsSafetyNet -Entry $_ })
        if ($protectedSafetyNetTargets.Count -gt 0) {
            Write-Host "Safety Net entries are protected and cannot be deleted from this menu." -ForegroundColor Yellow
            foreach ($entry in $protectedSafetyNetTargets) {
                Write-SafetyNetBackupEntryDetails -Entry $entry
            }
            Read-Host "Press Enter..."
            return
        }

        break
    }

    Write-Host ""
    Write-Host "[DELETE WARNING] These backup folders will be permanently deleted:" -ForegroundColor Red
    foreach ($t in $targets) {
        $folderType = Get-BackupFolderTypeDisplayName -FolderType (Get-BackupFolderType -BackupDir $t.FullName)
        $archives = @(Get-SupportedBackupArchivesFromFolder -BackupDir $t.FullName)
        Write-Host ("  - {0} | Type={1} | Archives={2}" -f $t.Name, $folderType, $archives.Count) -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  Protected delete will run after exact DELETE confirmation." -ForegroundColor DarkGray

    $confirm = Read-Host "Type DELETE to confirm"
    if ($confirm -cne "DELETE") {
        Write-Host "Cancelled." -ForegroundColor Yellow
        Read-Host "Press Enter..."
        return
    }

    $Script:CurrentOperationId = New-OperationId
    Write-OperationIdBanner -OperationId $Script:CurrentOperationId
    Write-LogEntry "INFO" "Delete-Batch" "Started batch delete of $($targets.Count) backup(s) | OpId=$($Script:CurrentOperationId)"

    foreach ($t in $targets) {
        $folderType = Get-BackupFolderType -BackupDir $t.FullName
        $deleteResult = Invoke-ProtectedBackupPathDelete `
            -Path $t.FullName `
            -Mode "BatchBackupDelete" `
            -Reason "User confirmed batch backup delete" `
            -AllowedRoot $scanPath `
            -FromRecognizedBackupList

        if ($deleteResult.Success) {
            Write-Host "  Deleted: $($t.Name)" -ForegroundColor Green
            Write-LogEntry "INFO" "Delete-Completed" "Deleted: $($t.Name) | FolderType=$folderType | OpId=$($Script:CurrentOperationId)"
        }
        else {
            Write-Host "  Failed to delete: $($t.Name) - $($deleteResult.Reason)" -ForegroundColor Red
            Write-LogEntry "WARN" "Delete-Failed" "Failed: $($t.Name) | Reason=$($deleteResult.Reason) | FolderType=$folderType | OpId=$($Script:CurrentOperationId)"
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

    if (-not (Test-Path -LiteralPath $scanPath)) {
        Write-Host "Path not found." -ForegroundColor Yellow
        Read-Host "Press Enter..."
        return
    }

    $backups = @(Get-RecognizedBackupFolders -ScanPath $scanPath)

    if ($backups.Count -eq 0) {
        Write-Host "No backups found."
        Read-Host "Press Enter..."
        return
    }

    $currentPage = 1
    $pageSize = 20
    while ($true) {
        $pageInfo = Get-BackupPageInfo -Backups $backups -Page $currentPage -PageSize $pageSize
        Show-BackupTable -Backups $backups -Page $pageInfo.Page -PageSize $pageSize
        $choice = Read-Host (Get-WSLBMBackupPagePrompt -PageInfo $pageInfo)
        if ([string]::IsNullOrWhiteSpace($choice) -or $choice -in @("0", "q", "Q")) {
            return
        }
        if ($choice -in @("n", "N")) {
            if ($pageInfo.Page -lt $pageInfo.PageCount) {
                $currentPage++
            }
            else {
                Write-Host "No next page." -ForegroundColor Yellow
            }
            continue
        }
        if ($choice -in @("p", "P")) {
            if ($pageInfo.Page -gt 1) {
                $currentPage--
            }
            else {
                Write-Host "No previous page." -ForegroundColor Yellow
            }
            continue
        }
        Write-Host "Invalid option." -ForegroundColor Red
    }
}

# =============================================================================
# Logs & Settings Menus
# =============================================================================

function Show-LogsMenu {
    while ($true) {
        $ym = (Get-Date).ToString('yyyy-MM')
        $opsLog = Join-Path $Global:LogRoot "ops-$ym.log"
        $errLog = Join-Path $Global:LogRoot "error-$ym.log"

        Show-WSLBMMenuHeader -Title "Log Viewer"
        Write-WSLBMHostLines -Lines @("[1] View Operations Log", "[2] View Error Log", "[3] Open Log Folder", "[4] Back")
        $choice = Read-Host "Choose"

        switch ($choice) {
            { $_ -in @("q", "Q", "4") } { return }
            "1" {
                if (Test-Path -LiteralPath $opsLog) {
                    Write-Host "--- Last 30 entries ---" -ForegroundColor DarkGray
                    Get-Content -LiteralPath $opsLog -Tail 30
                }
                else {
                    Write-Host "No operations log found." -ForegroundColor Yellow
                }
                Read-Host "Press Enter..."
            }
            "2" {
                if (Test-Path -LiteralPath $errLog) {
                    Write-Host "--- Error Log ---" -ForegroundColor Red
                    Get-Content -LiteralPath $errLog -Tail 20 | ForEach-Object { Write-Host $_ -ForegroundColor Red }
                }
                else {
                    Write-Host "No errors logged. Clean!" -ForegroundColor Green
                }
                Read-Host "Press Enter..."
            }
            "3" {
                if (Test-Path -LiteralPath $Global:LogRoot) {
                    Invoke-Item $Global:LogRoot
                }
                else {
                    Write-Host "Log folder not found." -ForegroundColor Yellow
                    Read-Host "Press Enter..."
                }
            }
            default { }
        }
    }
}

function Show-RecentPathsSummary {
    Write-Host ""
    Write-Host "Recent Linux paths:" -ForegroundColor Cyan
    if ($null -eq $Global:Config.RecentPaths -or $Global:Config.RecentPaths.Count -eq 0) {
        Write-Host "  (none)" -ForegroundColor DarkGray
        return
    }

    foreach ($distroName in ($Global:Config.RecentPaths.Keys | Sort-Object)) {
        Write-Host "  [$distroName]" -ForegroundColor Yellow
        $items = @($Global:Config.RecentPaths[$distroName] | Select-Object -First 10)
        if ($items.Count -eq 0) {
            Write-Host "    (none)" -ForegroundColor DarkGray
            continue
        }

        for ($i = 0; $i -lt $items.Count; $i++) {
            $path = [string]$items[$i].Path
            $lastUsed = [string]$items[$i].LastUsed
            if (-not [string]::IsNullOrWhiteSpace($lastUsed)) {
                try {
                    $lastUsed = ([datetime]$lastUsed).ToString("yyyy-MM-dd HH:mm")
                }
                catch {
                    $null = $_
                    $lastUsed = [string]$items[$i].LastUsed
                }
            }
            if ([string]::IsNullOrWhiteSpace($lastUsed)) {
                $lastUsed = "unknown"
            }
            Write-Host ("    [{0}] {1}  (last used {2})" -f ($i + 1), $path, $lastUsed) -ForegroundColor DarkGray
        }
    }
}

function Show-RecentPathsSettings {
    while ($true) {
        Show-WSLBMMenuHeader -Title "Recent Linux Paths"
        Show-RecentPathsSummary
        Write-WSLBMHostLines -Lines @($null, "[1] Clear recent paths", "[2] Back")

        $choice = Read-Host "Select"
        switch ($choice) {
            "1" {
                $confirm = Read-Host "Clear all recent Linux paths? Type CLEAR to confirm"
                if ($confirm -ceq "CLEAR") {
                    Clear-LinuxRecentPaths
                }
                else {
                    Write-Host "Recent paths were not cleared." -ForegroundColor Yellow
                }
                Read-Host "Press Enter..."
            }
            { $_ -in @("2", "q", "Q") } { return }
            default { }
        }
    }
}

function Edit-Settings {
    while ($true) {
        Show-WSLBMMenuHeader -Title "Settings"
        $settingsCompressionLevel = Get-WSLBMCompressionLevel
        $settingsResourceUsage = Get-WSLBMResourceUsage
        $settingsCompressionMx = Get-WSLBMCompressionMxForLevel -CompressionLevel $settingsCompressionLevel
        Write-WSLBMHostLines -Lines @(
            "[1] Backup Root : $($Global:Config.GlobalBackupRoot)"
            "[2] Install Root: $($Global:Config.InstallRoot)"
            "[3] 7-Zip Path  : $($Global:Config.SevenZipPath)"
            "[4] Compression Level: $settingsCompressionLevel (mx$settingsCompressionMx)"
            "[5] Resource Usage   : $settingsResourceUsage"
            "[6] Disk Threshold (Full): $($Global:Config.DiskThresholds.Full) GB"
            "[7] Recent Linux Paths (view / clear)"
            "[8] Back"
        )
        Write-Host "Note: .wslconfig is global WSL2 configuration and is not managed by these settings." -ForegroundColor DarkGray

        $choice = Read-Host "Select"

        switch ($choice) {
            { $_ -in @("q", "Q", "8") } { return }
            "1" {
                $newPath = Read-Host "Enter new Backup Root path"
                if ([string]::IsNullOrWhiteSpace($newPath)) { continue }
                $brValidation = Assert-WSLBMBackupRootPath -Path $newPath -Label "Backup Root"
                Write-WSLBMPathValidationResult -Result $brValidation -Label "Backup Root"
                if (-not $brValidation.IsValid) { continue }
                if (-not (Test-Path -LiteralPath $newPath)) {
                    $create = Read-Host "Path doesn't exist. Create? [Y/N/Q]"
                    if ($create -eq "Y" -or $create -eq "y") {
                        [System.IO.Directory]::CreateDirectory($newPath) | Out-Null
                    }
                    else { continue }
                }
                if (Test-Path -LiteralPath $newPath) {
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
                if (-not (Test-Path -LiteralPath $newPath)) {
                    $create = Read-Host "Path doesn't exist. Create? [Y/N/Q]"
                    if ($create -eq "Y" -or $create -eq "y") {
                        [System.IO.Directory]::CreateDirectory($newPath) | Out-Null
                    }
                    else { continue }
                }
                if (Test-Path -LiteralPath $newPath) {
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
                if (Test-Path -LiteralPath $newPath -PathType Leaf) {
                    $Global:Config.SevenZipPath = $newPath
                    Save-Config
                    Write-Host "Updated." -ForegroundColor Green
                }
                else {
                    Write-Host "File not found: $newPath" -ForegroundColor Red
                }
            }
            "4" {
                $null = Read-WSLBMCompressionLevelSetting
            }
            "5" {
                $null = Read-WSLBMResourceUsageSetting
            }
            "6" {
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
            "7" {
                Show-RecentPathsSettings
            }
            default { }
        }
    }
}

function Show-ListDeleteBackupsMenu {
    while ($true) {
        Show-WSLBMMenuHeader -Title "List / Delete Backups"
        Write-WSLBMHostLines -Lines @("[1] List backups", "[2] Delete backups", "[3] Back")

        $choice = Read-Host "Select"
        switch ($choice) {
            "1" { Get-BackupList }
            "2" { Remove-BatchBackups }
            { $_ -in @("3", "q", "Q") } { return }
            default { }
        }
    }
}

function Show-MainMenu {
    $scanPath = $Global:Config.GlobalBackupRoot

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $adminTag = if ($isAdmin) { " [ADMIN]" } else { "" }

    Clear-Host
    Write-Host ""
    Show-WSLBMMenuHeader -Title "WSL Backup Manager $(Get-WSLBMScriptVersion)$adminTag" -NoClear
    Write-Host "  DISTRO : $Script:CurrentDistro" -ForegroundColor Green
    Write-WSLBMModeLine
    Write-WSLBMHostLines -Lines @(
        @{ Text = "  SCAN   : $scanPath"; Color = [ConsoleColor]::DarkGray }
        "========================================================"
        "  [1] Backup"
        @{ Text = "  [2] Restore"; Color = [ConsoleColor]::Yellow }
        @{ Text = "  [3] List / Delete backups"; Color = [ConsoleColor]::Red }
        "  [4] Switch distro"
        "  [5] Settings"
        @{ Text = "  [6] Logs"; Color = [ConsoleColor]::Cyan }
        "  [7] Exit"
        $null
    )

    $choice = Read-Host "Choose"

    switch ($choice) {
        { $_ -in @("q", "Q", "7") } { exit }
        "1" { Show-NewBackupMenu }
        "2" { Show-RestoreMenu }
        "3" { Show-ListDeleteBackupsMenu }
        "4" { Select-WSLDistro -Force }
        "5" { Edit-Settings }
        "6" { Show-LogsMenu }
        default { }
    }
}

function Show-NewBackupMenu {
    Show-WSLBMMenuHeader -Title "New Backup"
    Write-WSLBMModeLine -Label "  MODE: "
    Write-WSLBMHostLines -Lines @("  [1] WholeDistro backup (wsl --export)", "  [2] Path backup (Linux absolute path via WSL tar)", "  [0] Cancel", $null)

    $choice = Read-Host "Choose"

    switch ($choice) {
        { $_ -in @("q", "Q", "0") } { return }
        "1" { New-FullBackup }
        "2" { New-PathBackup }
        default { return }
    }
}

# =============================================================================
# Script Entry Point
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
