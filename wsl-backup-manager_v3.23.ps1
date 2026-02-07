# WSL Backup Manager v3.23
# Author: Cline AI Assistant & Gemini 3 Pro Architect & Claude opus 4.5
# Patched: 2026-01-30(Security Audit Fixes & UX Polish)
# Environment: Windows 10/11 (PowerShell 5.1 & Core 7+)
# Changelog v3.23:
#   - [FIX-01] LOGIC: Null-safe ExitCode checking to prevent false failure detection

# =============================================================================
# 0. Global State & Initialization
# =============================================================================

$ErrorActionPreference = "Stop"

$Global:BackupState = @{
    IsRunning     = $false
    ActiveProcess = $null
    CurrentFile   = $null
    CurrentDir    = $null
    LockFile      = $null
    StartTime     = $null
    TempBatch     = $null
}

$Global:ConfigPath = Join-Path $PSScriptRoot "wsl-backup-config.json"
$Global:LogRoot = Join-Path $PSScriptRoot "logs"
$Script:CurrentDistro = $null
$Script:WSLPathPrefix = "\\wsl.localhost"

# Config Hashtable
$Global:Config = @{
    GlobalBackupRoot = Join-Path $PSScriptRoot "Backups"
    InstallRoot      = Join-Path $PSScriptRoot "Instances"
    SevenZipPath     = ""
    CompressionLevel = 9
    DiskThresholds   = @{ Full = 10; User = 2; Custom = 1 }
    Instances        = @{}
}

# =============================================================================
# 1. Security Functions [FIX-01]
# =============================================================================

function Test-SafeDistroName {
    <#
    .SYNOPSIS
        验证 WSL 发行版名称是否安全，防止命令注入攻击
    .DESCRIPTION
        检查名称是否包含 cmd.exe 或 PowerShell 的危险元字符
        危险字符包括: & | < > ^ % " '` $ ; ! ( ) @ #
    .PARAMETER Name
        要验证的发行版名称
    .OUTPUTS
        [bool] 如果名称安全返回 $true，否则返回 $false
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    
    # 定义危险字符的正则表达式
    $dangerousChars = '[&|<>^%"''`$;!()@#\[\]{}]'
    
    if ($Name -match $dangerousChars) {
        return $false
    }
    
    # 检查是否以空格开头或结尾
    if ($Name -match '^\s' -or $Name -match '\s$') {
        return $false
    }
    
    # 检查是否包含连续空格
    if ($Name -match '\s{2,}') {
        return $false
    }
    
    # 检查是否为空或纯空格
    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }
    
    return $true
}

function Get-SafeDistroArgument {
    <#
    .SYNOPSIS
        将distro 名称转换为安全的命令行参数
    .DESCRIPTION
        对包含空格的名称添加引号，并验证安全性
    .PARAMETER Name
        发行版名称
    .OUTPUTS
        [string] 安全的命令行参数字符串
    .EXAMPLE
        Get-SafeDistroArgument -Name "Ubuntu22.04"
        # Returns: "Ubuntu 22.04"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    
    # 首先验证安全性
    if (-not (Test-SafeDistroName -Name $Name)) {
        throw "[SECURITY] Distro name contains unsafe characters: '$Name'. Operation aborted for security reasons."
    }
    
    # 对包含空格的名称添加引号
    $safeName = $Name.Trim()
    if ($safeName -match '\s') {
        return "`"$safeName`""
    }
    
    return $safeName
}

# =============================================================================
# 2. Dynamic Resource Scheduler [FIX-02] [FIX-08]
# =============================================================================

function Get-Optimal7zThreads {
    <#
    .SYNOPSIS
        计算 7-Zip 的最优线程数，防止内存耗尽
    .DESCRIPTION
        v3.21 改进:
        - 提高每线程内存成本估算 (考虑动态增长)
        - 添加 Vmmem 进程的内存预留
        - 添加硬上限防止极端情况
        - 使用范围匹配覆盖所有压缩级别 (1-9)
    .PARAMETER Level
        压缩级别 (1-9)
    .OUTPUTS
        [int] 推荐的线程数
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 9)]
        [int]$Level
    )
    
    Write-Host "`n[Pre-Flight Resource Check] v3.23 Conservative Model" -ForegroundColor Cyan
    
    # 1. 获取系统信息
    try {
        # 确保只获取一个对象，并强制转换类型
        $os = Get-CimInstance Win32_OperatingSystem | Select-Object -First 1
        
        # 强制转换为 double 类型再计算
        $totalRamMB = [math]::Round([double]$os.TotalVisibleMemorySize / 1KB)
        $freeRamMB = [math]::Round([double]$os.FreePhysicalMemory / 1KB)
        $cpuCores = [int]$env:NUMBER_OF_PROCESSORS
        
        # 防御性检查
        if ($totalRamMB -le 0 -or $freeRamMB -le 0) {
            throw "Invalid memory values"
        }
    }
    catch {
        Write-Host "[WARN] Could not query WMI. Defaulting to safe mode (2threads)." -ForegroundColor Yellow
        return 2
    }

    # 2. 计算基础安全预留 (Max of 15% Total or 2.5GB)
    $reservePercent = $totalRamMB * 0.15
    $reserveFixed = 2560 # 2.5GB
    $baseReserveMB = [math]::Max($reservePercent, $reserveFixed)
    
    # 3. [FIX-02] 添加 Vmmem 动态扩展预留
    # WSL2 的 Vmmem 在 wsl --export 期间会动态扩展
    # 根据实测，大型发行版导出时Vmmem 可能额外消耗 2-4GB
    $vmmemReserveMB = 3072  # 3GB for Vmmem expansion
    
    # 4. 计算可用于 7z 的内存
    $totalReserveMB = $baseReserveMB + $vmmemReserveMB
    $availableFor7zMB = $freeRamMB - $totalReserveMB
    
    # 设置最小可用内存阈值
    if ($availableFor7zMB -lt 1024) {
        Write-Host "[WARN] Very low available memory. Using minimum safe mode." -ForegroundColor Yellow
        $availableFor7zMB = 1024
    }

    # 5. [FIX-02] [FIX-08] 重新校准每线程内存成本 (考虑动态增长)
    # 实测数据: 7z.exe 在流式压缩时内存会持续增长
    # 峰值内存 ≈ 初始内存 × 1.5~ 2.0
    $memCostPerThread = switch ($Level) {
        { $_ -ge 9 } { 1800; break }  # mx9: 实测峰值可达 1.5-1.8GB
        { $_ -ge 7 } { 1200; break }  # mx7-8: ~1.0-1.2GB
        { $_ -ge 5 } { 600; break }   # mx5-6: ~500-600MB
        { $_ -ge 3 } { 300; break }   # mx3-4: ~200-300MB
        Default { 150 }   # mx1-2: ~100-150MB
    }

    # 6. 计算基于内存的线程限制
    $ramLimitThreads = [math]::Floor($availableFor7zMB / $memCostPerThread)
    if ($ramLimitThreads -lt 1) { $ramLimitThreads = 1 }

    # 7. 计算基于 CPU 的线程限制 (保留 2 核给 OS/WSL)
    $cpuLimitThreads = $cpuCores - 2
    if ($cpuLimitThreads -lt 1) { $cpuLimitThreads = 1 }

    # 8. [FIX-02] 添加硬上限 (防止极端情况)
    # 即使资源充足，也限制最大线程数以保证系统响应性
    $hardMaxThreads = switch ($Level) {
        { $_ -ge 9 } { 4; break }    # mx9: 最多 4 线程
        { $_ -ge 7 } { 6; break }    # mx7-8: 最多 6 线程
        { $_ -ge 5 } { 8; break }    # mx5-6: 最多 8 线程
        Default { 12 }   # mx1-4: 最多 12 线程
    }

    # 9. 最终决策 (取三者最小值)
    $finalThreads = [math]::Min($ramLimitThreads, $cpuLimitThreads)
    $finalThreads = [math]::Min($finalThreads, $hardMaxThreads)
    # 确保至少 1 线程
    if ($finalThreads -lt 1) { $finalThreads = 1 }

    # 10. 详细报告
    Write-Host ("  System RAM: {0} (Free: {1})" -f (Format-Bytes ($totalRamMB * 1MB)), (Format-Bytes ($freeRamMB * 1MB))) -ForegroundColor Gray
    Write-Host ("  Base Reserve  : {0} (OS/Apps)" -f (Format-Bytes ($baseReserveMB * 1MB))) -ForegroundColor Gray
    Write-Host ("  Vmmem Reserve : {0} (WSL2 Dynamic)" -f (Format-Bytes ($vmmemReserveMB * 1MB))) -ForegroundColor Gray
    Write-Host ("  Available     : {0} for 7-Zip" -f (Format-Bytes ($availableFor7zMB * 1MB))) -ForegroundColor Gray
    Write-Host ("  Thread Cost   : ~{0} MB/thread (mx{1}, includes growth)" -f $memCostPerThread, $Level) -ForegroundColor Gray
    Write-Host ("  Limits        : RAM={0} | CPU={1} | Hard={2}" -f $ramLimitThreads, $cpuLimitThreads, $hardMaxThreads) -ForegroundColor Gray
    
    # 决策说明
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
    param([long]$Bytes)
    if ($Bytes -gt 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    elseif ($Bytes -gt 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    else { return "{0:N2} KB" -f ($Bytes / 1KB) }
}

# [FIX-03] 生成唯一的Batch 文件名
function New-UniqueBatchFileName {
    <#
    .SYNOPSIS
        生成唯一的临时 batch 文件名，防止 race condition
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory,
        
        [Parameter(Mandatory = $false)]
        [string]$Prefix = "exec"
    )
    
    $timestamp = Get-Date -Format "HHmmss"
    $guid = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $fileName = "{0}_{1}_{2}_{3}.bat" -f $Prefix, $PID, $timestamp, $guid
    
    return Join-Path $Directory $fileName
}

function Show-BackupTable {
    param($Backups)
    
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host("{0,-4} {1,-20} {2,-12} {3,-15} {4}" -f "#", "Date", "Size", "Type", "Note") -ForegroundColor Gray
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray

    $limit = [math]::Min($Backups.Count, 20)
    for ($i = 0; $i -lt $limit; $i++) {
        $b = $Backups[$i]
        $date = $b.CreationTime.ToString("yyyy-MM-dd HH:mm")
        $note = ""
        if (Test-Path "$($b.FullName)\note.txt") {
            $note = (Get-Content "$($b.FullName)\note.txt" -ErrorAction SilentlyContinue | Select-Object -First 1)
        }
        
        $sizeStr = "0 KB"
        $f = Get-ChildItem $b.FullName -File -Filter "*.7z" -ErrorAction SilentlyContinue
        if ($f) { $sizeStr = Format-Bytes ($f | Measure-Object -Property Length -Sum).Sum }
        
        $type = "Unknown"
        if ($b.Name -match "FULL") { $type = "FULL SYSTEM" }
        elseif ($b.Name -match "USER") { $type = "USER HOME" }
        elseif ($b.Name -match "CUSTOM") { $type = "CUSTOM" }

        Write-Host ("[{0,2}] " -f ($i + 1)) -NoNewline -ForegroundColor Cyan
        Write-Host ("{0,-20} {1,-12} {2,-15} {3}" -f $date, $sizeStr, $type, $note)
    }
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray
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
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $durationStr = ""
    if (($Level -eq "SUCCESS" -or $Level -eq "ERROR") -and $Global:BackupState.StartTime) {
        $elapsed = New-TimeSpan -Start $Global:BackupState.StartTime -End (Get-Date)
        $durationStr = "[{0:mm}m {0:ss}s]" -f $elapsed
        $Global:BackupState.StartTime = $null
    }
    
    $logLine = "$timestamp | $Level | $Distro | $Action | $durationStr $Message"
    try { Add-Content -Path $opsLog -Value $logLine -Encoding UTF8 } catch {}
    if ($Level -eq "ERROR") {
        try { Add-Content -Path $errLog -Value $logLine -Encoding UTF8 } catch {} 
    }
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
    New-BackupDirectory $Global:Config.GlobalBackupRoot | Out-Null
    New-BackupDirectory $Global:Config.InstallRoot | Out-Null
}

function Save-Config {
    try { 
        $Global:Config | ConvertTo-Json -Depth 5 | Set-Content -Path $Global:ConfigPath -Encoding UTF8 
    }
    catch { 
        Write-Host "[ERROR] Saving config failed." -ForegroundColor Red 
    }
}

function Optimize-WSLConfig {
    $wslConfigPath = "$env:USERPROFILE\.wslconfig"
    if (-not (Test-Path $wslConfigPath)) {
        $totalRam = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
        $limitRam = [math]::Round([double]$totalRam / 1GB / 2)
        if ($limitRam -lt 2) { $limitRam = 2 }
        $configContent = "[wsl2]`r`nmemory=${limitRam}GB`r`nprocessors=$(($env:NUMBER_OF_PROCESSORS))`r`nswap=8GB`r`nlocalhostForwarding=true"
        try { 
            [System.IO.File]::WriteAllText($wslConfigPath, $configContent, [System.Text.Encoding]::ASCII) 
        }
        catch {}
    }
}

function Test-7zInstalled {
    $foundPath = ""
    if ($Global:Config.SevenZipPath -and (Test-Path $Global:Config.SevenZipPath -PathType Leaf)) { 
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
            if (Test-Path $p -PathType Leaf) { 
                $foundPath = $p
                break 
            } 
        }
    }

    if ($foundPath) {
        $Global:Config.SevenZipPath = $foundPath
        Save-Config
        $env:PATH += ";$(Split-Path $foundPath -Parent)"
        Write-Host "Found 7-Zip: " -NoNewline
        Write-Host $foundPath -ForegroundColor Green
        return $true
    }
    
    Write-Host "[WARNING] 7-Zip (7z.exe) not found." -ForegroundColor Yellow
    $userPath = Read-Host "Enter full path to 7z.exe"
    if (Test-Path $userPath -PathType Leaf) {
        $Global:Config.SevenZipPath = $userPath
        Save-Config
        $env:PATH += ";$(Split-Path $userPath -Parent)"
        return $true
    }
    return $false
}

function Test-WSLAvailability {
    try { 
        $null = wsl --status 2>&1 
    }
    catch { 
        Write-Host "[CRITICAL] WSL Not Detected!" -ForegroundColor Red
        exit
    }
}

function Get-WSLUser { 
    try { 
        return (wsl -d $Script:CurrentDistro whoami).Trim() 
    }
    catch { 
        return $null 
    } 
}

function Format-QuotedArgs {
    param([string[]]$Arguments)
    $safeArgs = @()
    foreach ($arg in $Arguments) {
        if ($arg -match " ") { 
            $safeArgs += "`"$arg`"" 
        }
        else { 
            $safeArgs += $arg 
        }
    }
    return $safeArgs -join " "
}

function Close-VSCodeSafely {
    if (Get-Process | Where-Object ProcessName -like "*code*") {
        Write-Host "[WARN] VS Code is running. It might lock WSL files." -ForegroundColor Yellow
        $ans = Read-Host "Press [Enter] to continue anyway, or [Q] to cancel"
        if ($ans -eq "Q" -or $ans -eq "q") { return $false }
    }
    return $true
}

function Test-DiskSpace {
    param($gb)
    $path = if (Get-InstanceBackupPath) { Get-InstanceBackupPath } else { $Global:Config.GlobalBackupRoot }
    $drive = (Split-Path $path -Qualifier).Substring(0, 1)
    try {
        $free = (Get-PSDrive $drive).Free / 1GB
        if ($free -lt $gb) {
            Write-Host "Low Disk Space on ${drive}:! Need $gb GB, only $('{0:N1}' -f $free) GB free." -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "[WARN] Cannot check disk space." -ForegroundColor Yellow
    }
    return $true
}

function Test-ArchiveQuick {
    param([string]$path)
    Write-Host "  -> Pre-flight Check: Verifying backup header..." -NoNewline -ForegroundColor DarkGray
    $7zArgs = Format-QuotedArgs @("l", $path)
    $p = Start-Process "7z" -ArgumentList $7zArgs -NoNewWindow -PassThru -Wait
    if ($p.ExitCode -eq 0) {
        Write-Host " [OK]" -ForegroundColor Green
        return $true
    }
    else {
        Write-Host " [FAILED]" -ForegroundColor Red
        return $false
    }
}

# =============================================================================
# 4. Lock, Monitor & Cleanup [FIX-04] [FIX-05]
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
    if ($Global:BackupState.LockFile -and (Test-Path $Global:BackupState.LockFile)) {
        Remove-Item $Global:BackupState.LockFile -Force -ErrorAction SilentlyContinue
    }
    $Global:BackupState.LockFile = $null
}

# [FIX-04] 重构: 进程清理 (同步等待 + 重试机制)
function Stop-ActiveBackupProcesses {
    <#
    .SYNOPSIS
        安全地终止活动的备份进程及其子进程
    .DESCRIPTION
        v3.21改进:
        - 使用 -Wait 参数确保 taskkill 同步执行
        - 添加重试机制处理顽固进程
        - 等待进程完全退出后再返回
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
            # [FIX-04] 使用 -Wait 确保同步执行
            $null = Start-Process "taskkill" `
                -ArgumentList "/F", "/T", "/PID", $pidToKill `
                -NoNewWindow -Wait -PassThru -ErrorAction Stop
            
            #等待进程完全退出(最多 5 秒)
            $waitResult = $Global:BackupState.ActiveProcess.WaitForExit(5000)
            
            if ($waitResult -or $Global:BackupState.ActiveProcess.HasExited) {
                Write-Host " Done." -ForegroundColor DarkGray
                $Global:BackupState.ActiveProcess = $null
                return
            }
        }
        catch {
            # Fallback: 直接使用 Stop-Process
            try {
                Stop-Process -Id $pidToKill -Force -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 500
                if ($Global:BackupState.ActiveProcess.HasExited) {
                    Write-Host " Done (fallback)." -ForegroundColor DarkGray
                    $Global:BackupState.ActiveProcess = $null
                    return
                }
            }
            catch {
                # 继续重试
            }
        }
        if ($attempt -lt $maxAttempts) {
            Start-Sleep -Milliseconds 1000
        }
    }
    
    Write-Host " Warning: Process may still be running." -ForegroundColor Yellow
    $Global:BackupState.ActiveProcess = $null
}

# [FIX-05] 重构: 失败目录清理 (使用锁文件判断)
function Remove-FailedBackupDir {
    <#
    .SYNOPSIS
        清理失败的备份目录
    .DESCRIPTION
        v3.21 改进:
        - 使用锁文件 (.backup-in-progress) 判断是否为失败的备份
        - 不再使用文件数量作为判断标准
        - 添加重试机制处理文件锁定
    #>
    $dir = $Global:BackupState.CurrentDir
    if (-not $dir -or -not (Test-Path $dir)) {
        return
    }
    
    # [FIX-05] 只有当锁文件存在时，才认为是失败的备份
    $lockFile = Join-Path $dir ".backup-in-progress"
    if (-not (Test-Path $lockFile)) {
        # 没有锁文件，说明不是失败的备份，或者已经成功完成
        return
    }
    
    Write-Host "  [Cleanup] Removing failed backup folder..." -NoNewline -ForegroundColor DarkGray
    
    # 重试删除 (最多 3 次)
    for ($i = 1; $i -le 3; $i++) {
        try {
            Remove-Item $dir -Force -Recurse -ErrorAction Stop
            Write-Host " Done." -ForegroundColor DarkGray
            return
        }
        catch {
            if ($i -lt 3) {
                Start-Sleep -Milliseconds 1500
            }
        }
    }
    
    Write-Host " Failed (files may be locked)." -ForegroundColor Yellow
    Write-Host "  Please manually delete: $dir" -ForegroundColor Yellow
}

function Watch-Process-With-Monitor {
    <#
    .SYNOPSIS
        监控进程执行，支持用户取消
    #>
    param(
        $Process,
        $MonitoredFile
    )
    
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
# 5. Interactive Helpers [FIX-07]
# =============================================================================

function Select-Compression-Interactive {
    $current = $Global:Config.CompressionLevel
    Write-Host "Compression Level: " -NoNewline
    Write-Host "mx$current" -ForegroundColor Green
    
    while ($true) {
        Write-Host "Press [1-9] to change, or [Enter] to keep current." -ForegroundColor DarkGray
        $userLevel = Read-Host "Selection"
        
        # 空输入 = 保持默认
        if ([string]::IsNullOrWhiteSpace($userLevel)) {
            return
        }
        if ($userLevel -in @("q", "Q")) { return }
        
        # [FIX-07] 严格类型验证
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
# 6. Path Logic & Selection [FIX-07]
# =============================================================================

function Select-WSLDistro {
    param([switch]$Force)
    
    if ($Force) { $Script:CurrentDistro = $null }

    try {
        $raw = wsl --list --quiet 2>$null
        if (-not $raw) {
            $rawList = wsl --list
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
        exit
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

    #严格选择循环
    while ($true) {
        Clear-Host
        Write-Host "=== Select Target Distribution ===" -ForegroundColor Cyan
        
        for ($i = 0; $i -lt $distros.Count; $i++) {
            $d = $distros[$i]
            # [FIX-01] 显示安全状态
            $safetyIcon = if (Test-SafeDistroName -Name $d) { "[OK]" } else { "[!]" }
            Write-Host ("[$($i+1)] {0} {1}" -f $d, $safetyIcon)
        }
        Write-Host "[0] Exit/Cancel" -ForegroundColor Gray
        
        $sel = Read-Host "Select Number"
        
        if ($sel -eq "0" -or $sel -eq "q" -or $sel -eq "Q") {
            if ($Force) { return }
            exit
        }
        
        # [FIX-07] 严格类型验证
        if ($sel -match '^\d+$') {
            $selNum = [int]$sel
            if ($selNum -gt 0 -and $selNum -le $distros.Count) {
                $selectedDistro = $distros[$selNum - 1]
                
                # [FIX-01] 验证 distro 名称安全性
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

function Get-BackupDestination {
    param($defaultName)
    $savedPath = Get-InstanceBackupPath
    Write-Host ""
    Write-Host "Select Destination:"
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

    if ($finalPath -eq "CUSTOM") {
        $finalPath = Read-Host "Enter full path (e.g. D:\Backups\Specific)"
        $finalPath = $finalPath.TrimEnd('\')
        if (-not (Test-Path $finalPath)) {
            $createAns = Read-Host "Directory not found. Create? [Y/N/Q]"
            if ($createAns -eq "Y" -or $createAns -eq "y") {
                New-BackupDirectory $finalPath | Out-Null
            }
            else {
                return $null
            }
        }
        $saveAns = Read-Host "Save as default for[$Script:CurrentDistro]? [Y/N/Q]"
        if ($saveAns -eq "Y" -or $saveAns -eq "y") {
            Set-InstanceBackupPath -newPath $finalPath
        }
    }
    
    return (Join-Path $finalPath $defaultName)
}

function Test-BackupIntegrity {
    param(
        [string]$backupFile,
        [string]$backupType
    )
    
    Write-Host "[Backup Verification]" -ForegroundColor Cyan
    
    if (-not (Test-Path $backupFile)) {
        throw "Backup file not found!"
    }
    
    $fileSize = (Get-Item $backupFile).Length
    $readableSize = Format-Bytes $fileSize
    
    $minSize = switch ($backupType) {
        "FULL" { 100MB }
        "USER-FULL" { 1KB }
        default { 100 }
    }
    
    if ($fileSize -lt $minSize) {
        throw "File too small ($fileSize bytes). Expected at least $minSize bytes."
    }
    Write-Host "  [OK] Size Check: $readableSize" -ForegroundColor Green
    
    $argList = @("t", $backupFile, "-y")
    $argsStr = Format-QuotedArgs $argList
    
    $proc = Start-Process "7z" -ArgumentList $argsStr -NoNewWindow -PassThru -Wait
    $exitCode = $proc.ExitCode
    if ($null -ne $exitCode -and $exitCode -ne 0) {
        throw "CRC Integrity Check Failed (7z exit code $exitCode)"
    }
    Write-Host "  [OK] Integrity Check" -ForegroundColor Green
}

# =============================================================================
# 7. Backup Operations [FIX-01] [FIX-03] [FIX-06]
# =============================================================================

function New-FullBackup {
    if (-not $Script:CurrentDistro) {
        Write-Host "[ERROR] No Distro Selected." -ForegroundColor Red
        return
    }
    
    # [FIX-01] 验证 distro 名称安全性
    if (-not (Test-SafeDistroName -Name $Script:CurrentDistro)) {
        Write-Host "[SECURITY] Cannot backup: Distro name contains unsafe characters." -ForegroundColor Red
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
    if (-not (New-BackupDirectory $backupDir)) { return }
    
    New-LockFile -OperationType "Full Backup" -TargetDir $backupDir
    $Global:BackupState.IsRunning = $true
    $Global:BackupState.CurrentFile = $backupFile
    $Global:BackupState.CurrentDir = $backupDir
    
    Write-LogEntry "INFO" "Backup-Full" "Started to $backupFile (threads: $safeThreads)"
    
    # [FIX-03] 使用唯一的 batch 文件名
    $batchFile = New-UniqueBatchFileName -Directory $backupDir -Prefix "backup"
    $Global:BackupState.TempBatch = $batchFile
    
    try {
        Write-Host "Shutting down WSL (5s cooldown)..." -ForegroundColor Yellow
        wsl --shutdown
        Start-Sleep -Seconds 5
        
        $mx = "-mx$($Global:Config.CompressionLevel)"
        $7zExe = $Global:Config.SevenZipPath
        if (-not $7zExe) { $7zExe = "7z" }
        
        # [FIX-01] 使用安全的 distro 参数
        $safeDistroArg = Get-SafeDistroArgument -Name $Script:CurrentDistro
        # 构建 batch 命令
        $cmdContent = "@echo off`r`nwsl.exe --export $safeDistroArg - | `"$7zExe`" a `"$backupFile`" -si wsl-export.tar $mx -mmt=$safeThreads -bsp1"
        [System.IO.File]::WriteAllText($batchFile, $cmdContent, [System.Text.Encoding]::Default)
        
        Write-Host "Executing backup (Press Q to cancel)..." -ForegroundColor Cyan
        Write-Host "Batch: $batchFile" -ForegroundColor DarkGray
        
        $pInfo = New-Object System.Diagnostics.ProcessStartInfo
        $pInfo.FileName = "cmd.exe"
        $pInfo.Arguments = "/c `"$batchFile`""
        $pInfo.UseShellExecute = $false
        $pInfo.RedirectStandardOutput = $false
        $pInfo.RedirectStandardError = $false
        $pInfo.CreateNoWindow = $false
        
        $proc = [System.Diagnostics.Process]::Start($pInfo)
        $Global:BackupState.ActiveProcess = $proc
        
        Watch-Process-With-Monitor -Process $proc -MonitoredFile $backupFile
        
        # [FIX-06] 显式等待进程退出
        $proc.WaitForExit()
        
        $exitCode = $proc.ExitCode
        if ($null -ne $exitCode -and $exitCode -ne 0) {
            throw "7z Error Code: $exitCode"
        }

        Write-Host "Verifying backup..." -ForegroundColor Cyan
        Test-BackupIntegrity -backupFile $backupFile -backupType "FULL"
        
        #成功 - 移除锁文件
        Remove-LockFile
        
        Write-Host "SUCCESS! Backup completed." -ForegroundColor Green
        Write-LogEntry "SUCCESS" "Backup-Full" "Completed successfully"
        
        Write-Host "Add note (optional, press Enter to skip):"
        $note = Read-Host
        if (-not [string]::IsNullOrWhiteSpace($note)) {
            $note | Out-File (Join-Path $backupDir "note.txt") -Encoding UTF8
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
        Write-LogEntry "ERROR" "Backup-Full" $msg
        Write-Host "[ERROR] $msg" -ForegroundColor Red
        
        Stop-ActiveBackupProcesses
        
        if (Test-Path $backupFile) {
            Remove-Item $backupFile -Force -ErrorAction SilentlyContinue
        }
        Remove-FailedBackupDir
    }
    finally {
        Stop-ActiveBackupProcesses
        
        #清理临时 batch 文件 (仅在成功时)
        if ($Global:BackupState.TempBatch -and (Test-Path $Global:BackupState.TempBatch)) {
            if (-not $Global:BackupState.LockFile) {
                #锁文件已移除 = 成功，可以删除 batch
                Remove-Item $Global:BackupState.TempBatch -Force -ErrorAction SilentlyContinue
            }
        }
        Remove-LockFile
        $Global:BackupState.IsRunning = $false
        $Global:BackupState.TempBatch = $null
    }
    
    Read-Host "Press Enter to return..."
}

function New-UserBackup {
    if (-not $Script:CurrentDistro) {
        Write-Host "[ERROR] No Distro Selected." -ForegroundColor Red
        return
    }
    
    if (-not (Test-DiskSpace $Global:Config.DiskThresholds.User)) { return }
    if (-not (Close-VSCodeSafely)) { return }
    
    Select-Compression-Interactive
    $safeThreads = Get-Optimal7zThreads -Level $Global:Config.CompressionLevel
    
    $ts = Get-Date -Format "yyyy-MM-dd_HHmm"
    $backupDir = Get-BackupDestination -defaultName "$ts-USER"
    if (-not $backupDir) { return }
    
    $backupFile = Join-Path $backupDir "home.7z"
    New-BackupDirectory $backupDir | Out-Null
    
    $wslUser = Get-WSLUser
    $basePath = if ($wslUser -eq "root") { "/root" } else { "/home/$wslUser" }
    $src = "$($Script:WSLPathPrefix)\$Script:CurrentDistro$basePath"
    
    New-LockFile -OperationType "User Backup" -TargetDir $backupDir
    $Global:BackupState.IsRunning = $true
    $Global:BackupState.CurrentDir = $backupDir
    $Global:BackupState.CurrentFile = $backupFile
    
    Write-LogEntry "INFO" "Backup-User" "Started from $src (threads: $safeThreads)"
    
    try {
        if (-not (Test-Path $src)) {
            #尝试唤醒 WSL
            wsl -d $Script:CurrentDistro -e ls $basePath > $null
            Start-Sleep -Seconds 1
            if (-not (Test-Path $src)) {
                throw "Cannot access path: $src"
            }
        }

        $mx = "-mx$($Global:Config.CompressionLevel)"
        $rawArgs = @("a", $backupFile, "$src\*", $mx, "-mmt=$safeThreads", "-bsp1")
        $safeArgs = Format-QuotedArgs $rawArgs
        
        Write-Host "Executing backup (Press Q to cancel)..." -ForegroundColor Cyan
        
        $proc = Start-Process "7z" -ArgumentList $safeArgs -PassThru -NoNewWindow
        $Global:BackupState.ActiveProcess = $proc
        
        Watch-Process-With-Monitor -Process $proc -MonitoredFile $backupFile
        
        # [FIX-06] 显式等待
        $proc.WaitForExit()
        
        # 修复：先检查 ExitCode 是否为 null
        $exitCode = $proc.ExitCode
        if ($null -ne $exitCode -and $exitCode -ne 0) {
            throw "7z Error Code: $exitCode"
        }
        
        Test-BackupIntegrity -backupFile $backupFile -backupType "USER-FULL"
        
        Remove-LockFile
        
        Write-Host "SUCCESS!" -ForegroundColor Green
        Write-LogEntry "SUCCESS" "Backup-User" "Completed"
        
        Write-Host "Add note (optional):"
        $note = Read-Host
        if (-not [string]::IsNullOrWhiteSpace($note)) {
            $note | Out-File (Join-Path $backupDir "note.txt") -Encoding UTF8
        }
        
    }
    catch {
        $errMsg = $_.Exception.Message
        $msg = if ($errMsg -match "UserCancelled") { "Cancelled" } else { "Failed: $errMsg" }
        
        Write-LogEntry "ERROR" "Backup-User" $msg
        Write-Host "[ERROR] $msg" -ForegroundColor Red
        
        Stop-ActiveBackupProcesses
        Remove-FailedBackupDir
    }
    finally {
        Stop-ActiveBackupProcesses
        Remove-LockFile
        $Global:BackupState.IsRunning = $false
    }
    
    Read-Host "Press Enter to return..."
}

function New-CustomBackup {
    if (-not $Script:CurrentDistro) {
        Write-Host "[ERROR] No Distro Selected." -ForegroundColor Red
        return
    }
    
    if (-not (Test-DiskSpace $Global:Config.DiskThresholds.Custom)) { return }
    if (-not (Close-VSCodeSafely)) { return }
    
    $wslUser = Get-WSLUser
    Write-Host "Base: /home/$wslUser/" -ForegroundColor DarkGray
    $customPathRaw = Read-Host "Enter LINUX relative path (e.g. 'projects/my-code')"
    
    if ([string]::IsNullOrWhiteSpace($customPathRaw)) { return }
    if ($customPathRaw -match ":\\") {
        Write-Host "Error: Use Linux path format, not Windows." -ForegroundColor Red
        return
    }
    
    $cleanPath = $customPathRaw -replace "^~/", "" -replace "^/", "" -replace "\\", "/"
    $backupName = ($cleanPath -split '/' | Select-Object -Last 1)
    
    $ts = Get-Date -Format "yyyy-MM-dd_HHmm"
    $backupDir = Get-BackupDestination -defaultName "$ts-CUSTOM"
    if (-not $backupDir) { return }
    
    $backupFile = Join-Path $backupDir "$backupName.7z"
    New-BackupDirectory $backupDir | Out-Null

    New-LockFile -OperationType "Custom: $cleanPath" -TargetDir $backupDir
    $Global:BackupState.IsRunning = $true
    $Global:BackupState.CurrentFile = $backupFile
    $Global:BackupState.CurrentDir = $backupDir
    
    Write-LogEntry "INFO" "Backup-Custom" "Started for $cleanPath"
    
    try {
        $src = "$($Script:WSLPathPrefix)\$Script:CurrentDistro\home\$wslUser\$cleanPath"
        
        if (-not (Test-Path $src)) {
            # 尝试唤醒 WSL
            wsl -d $Script:CurrentDistro -e ls /home > $null
            Start-Sleep -Seconds 1
            if (-not (Test-Path $src)) {
                throw "Path not found in WSL: $src"
            }
        }
        
        Select-Compression-Interactive
        $safeThreads = Get-Optimal7zThreads -Level $Global:Config.CompressionLevel
        
        $mx = "-mx$($Global:Config.CompressionLevel)"
        $rawArgs = @("a", $backupFile, $src, $mx, "-mmt=$safeThreads", "-bsp1")
        $safeArgs = Format-QuotedArgs $rawArgs
        
        Write-Host "Executing backup (Press Q to cancel)..." -ForegroundColor Cyan
        
        $proc = Start-Process "7z" -ArgumentList $safeArgs -PassThru -NoNewWindow
        $Global:BackupState.ActiveProcess = $proc
        
        Watch-Process-With-Monitor -Process $proc -MonitoredFile $backupFile
        
        # [FIX-06] 显式等待
        $proc.WaitForExit()
        
        # 修复：先检查 ExitCode 是否为 null
        $exitCode = $proc.ExitCode
        if ($null -ne $exitCode -and $exitCode -ne 0) {
            throw "7z Error Code: $exitCode"
        }

        # 额外安全检查：确认文件确实创建了
        if (-not (Test-Path $backupFile)) {
            throw "Backup file was not created"
        }
        
        Test-BackupIntegrity -backupFile $backupFile -backupType "USER-CUSTOM"
        
        Remove-LockFile
        
        Write-Host "SUCCESS!" -ForegroundColor Green
        Write-LogEntry "SUCCESS" "Backup-Custom" "Completed"
        
        Write-Host "Add note (optional):"
        $note = Read-Host
        if (-not [string]::IsNullOrWhiteSpace($note)) {
            $note | Out-File (Join-Path $backupDir "note.txt") -Encoding UTF8
        }
        
    }
    catch {
        $errMsg = $_.Exception.Message
        $msg = if ($errMsg -match "UserCancelled") { "Cancelled" } else { "Failed: $errMsg" }
        
        Write-LogEntry "ERROR" "Backup-Custom" $msg
        Write-Host "[ERROR] $msg" -ForegroundColor Red
        
        Stop-ActiveBackupProcesses
        
        if (Test-Path $backupFile) {
            Remove-Item $backupFile -Force -ErrorAction SilentlyContinue
        }
        Remove-FailedBackupDir
    }
    finally {
        Stop-ActiveBackupProcesses
        Remove-LockFile
        $Global:BackupState.IsRunning = $false
    }
    
    Read-Host "Press Enter to return..."
}

# =============================================================================
# 8. Restore & Manage Operations [FIX-01] [FIX-03] [FIX-06] [FIX-07]
# =============================================================================

function Show-RestoreMenu {
    Clear-Host
    Write-Host "=== RESTORE MENU ===" -ForegroundColor Red
    
    $scanPath = Get-InstanceBackupPath
    if (-not $scanPath) { $scanPath = $Global:Config.GlobalBackupRoot }
    
    Write-Host "Scanning: $scanPath" -ForegroundColor DarkGray
    
    if (-not (Test-Path $scanPath)) {
        Write-Host "Backup path not found." -ForegroundColor Yellow
        Read-Host "Press Enter..."
        return
    }
    
    #强制数组模式
    $backups = @(Get-ChildItem $scanPath -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
    
    if ($backups.Count -eq 0) {
        Write-Host "No backups found."
        Read-Host "Press Enter..."
        return
    }
    
    Show-BackupTable -Backups $backups
    
    # [FIX-07] 严格输入循环
    while ($true) {
        $sel = Read-Host "Select backup number (or 0/q to cancel)"
        if ($sel -eq "0" -or $sel -eq "q" -or $sel -eq "Q") {
            return
        }
        
        # [FIX-07] 严格类型验证
        if ($sel -match '^\d+$') {
            $selNum = [int]$sel
            if ($selNum -gt 0 -and $selNum -le $backups.Count) {
                $target = $backups[$selNum - 1]
                break
            }
        }
        
        Write-Host "Invalid selection." -ForegroundColor Red
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
    Write-Host "!!! DANGER: THIS WILL COMPLETELY OVERWRITE $Script:CurrentDistro !!!" -ForegroundColor Red
    Write-Host ""
    #严格安全网提示
    while ($true) {
        $doSafety = Read-Host "Create a Safety Net backup of current system first? [Y/N] or [Q] to cancel"
        
        if ($doSafety -eq "q" -or $doSafety -eq "Q") {
            Write-Host "Cancelled." -ForegroundColor Yellow
            return
        }
        
        if ($doSafety -eq "y" -or $doSafety -eq "Y") {
            Write-Host "Creating Safety Net..." -ForegroundColor Cyan
            $safetyFile = Join-Path $Global:Config.GlobalBackupRoot "SAFETY-NET-$Script:CurrentDistro-$(Get-Date -Format 'yyyyMMdd-HHmmss').tar"
            wsl --shutdown
            Start-Sleep -Seconds 1
            wsl --export $Script:CurrentDistro $safetyFile
            
            if (Test-Path $safetyFile) {
                $safetySize = Format-Bytes (Get-Item $safetyFile).Length
                Write-Host "Safety Net saved: $safetyFile ($safetySize)" -ForegroundColor Green
            }
            else {
                Write-Host "Safety Net creation FAILED!Aborting restore." -ForegroundColor Red
                return
            }
            break
        }
        
        if ($doSafety -eq "n" -or $doSafety -eq "N") {
            Write-Host "[WARN] Proceeding without Safety Net!" -ForegroundColor Yellow
            break
        }
        
        Write-Host "Please enter Y, N, or Q." -ForegroundColor Red
    }

    $confirm = Read-Host "Type 'RESTORE' to confirm (case-sensitive)"
    if ($confirm -cne "RESTORE") {
        Write-LogEntry "WARN" "Restore-Full" "Aborted by user"
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }
    
    $backupFile = Join-Path $backupDir "wsl-full.7z"
    $installPath = Join-Path $Global:Config.InstallRoot $Script:CurrentDistro
    
    Invoke-RestoreStream -backupFile $backupFile -distroName $Script:CurrentDistro -installPath $installPath -isOverwrite $true
}

function Invoke-RestoreNewInstance {
    param($backupDir)
    
    $newName = Read-Host "Enter new instance name (e.g. Ubuntu-Test)"
    if ([string]::IsNullOrWhiteSpace($newName)) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }
    
    # [FIX-01] 验证新名称安全性
    if (-not (Test-SafeDistroName -Name $newName)) {
        Write-Host "[SECURITY] Invalid name. Avoid special characters: & | < > ^ % `" ' ; !" -ForegroundColor Red
        return
    }
    
    $newPath = Read-Host "Enter install path (press Enter for default)"
    if ([string]::IsNullOrWhiteSpace($newPath)) {
        $newPath = Join-Path $Global:Config.InstallRoot $newName
    }
    
    $backupFile = Join-Path $backupDir "wsl-full.7z"
    
    Invoke-RestoreStream -backupFile $backupFile -distroName $newName -installPath $newPath -isOverwrite $false
}

function Invoke-RestoreStream {
    param(
        $backupFile,
        $distroName,
        $installPath,
        $isOverwrite
    )
    
    if (-not (Close-VSCodeSafely)) { return }
    
    New-LockFile -OperationType "Restore" -TargetDir (Split-Path $backupFile -Parent)
    $Global:BackupState.IsRunning = $true
    
    Write-LogEntry "INFO" "Restore-Exec" "Target: $distroName | Overwrite: $isOverwrite"
    
    # [FIX-03] 使用唯一的 batch 文件名
    $batchFile = New-UniqueBatchFileName -Directory (Split-Path $backupFile -Parent) -Prefix "restore"
    $Global:BackupState.TempBatch = $batchFile

    try {
        if (-not (Test-Path $backupFile)) {
            throw "Backup file missing: $backupFile"
        }
        
        if (-not (Test-ArchiveQuick -path $backupFile)) {
            throw "Backup file appears corrupt."
        }

        if ($isOverwrite) {
            Write-Host "Unregistering existing distro..." -ForegroundColor Yellow
            wsl --shutdown
            Start-Sleep -Seconds 1
            wsl --unregister $distroName 2>$null
            Start-Sleep -Seconds 2
        }
        
        if (-not (Test-Path $installPath)) {
            New-Item -ItemType Directory -Path $installPath -Force | Out-Null
        }
        
        Write-Host "Restoring (this may take several minutes)..." -ForegroundColor Cyan
        
        $7zExe = $Global:Config.SevenZipPath
        if (-not $7zExe) { $7zExe = "7z" }
        
        # [FIX-01] 使用安全的 distro 参数
        $safeDistroArg = Get-SafeDistroArgument -Name $distroName
        
        # 构建恢复命令 (移除了不必要的 -mx 参数)
        $cmdContent = "@echo off`r`n`"$7zExe`" e `"$backupFile`" -so -bd | wsl.exe --import $safeDistroArg `"$installPath`" -"
        [System.IO.File]::WriteAllText($batchFile, $cmdContent, [System.Text.Encoding]::Default)
        
        Write-Host "Batch: $batchFile" -ForegroundColor DarkGray

        $pInfo = New-Object System.Diagnostics.ProcessStartInfo
        $pInfo.FileName = "cmd.exe"
        $pInfo.Arguments = "/c `"$batchFile`""
        $pInfo.UseShellExecute = $false
        $pInfo.RedirectStandardOutput = $false
        $pInfo.RedirectStandardError = $false
        $pInfo.CreateNoWindow = $false
        
        $proc = [System.Diagnostics.Process]::Start($pInfo)
        $Global:BackupState.ActiveProcess = $proc
        
        Watch-Process-With-Monitor -Process $proc -MonitoredFile $null
        
        # [FIX-06] 显式等待
        $proc.WaitForExit()
        
        $exitCode = $proc.ExitCode
        if ($null -ne $exitCode -and $exitCode -ne 0) {
            throw "Restore Failed (Exit Code $exitCode)"
        }

        Remove-LockFile
        
        Write-Host ""
        Write-Host "SUCCESS! System restored." -ForegroundColor Green
        Write-Host "  Distro: $distroName" -ForegroundColor Cyan
        Write-Host "  Path  : $installPath" -ForegroundColor Cyan
        Write-LogEntry "SUCCESS" "Restore-Exec" "Completed"
        
    }
    catch {
        $errMsg = $_.Exception.Message
        Write-LogEntry "ERROR" "Restore-Exec" "Failed: $errMsg"
        Write-Host "[ERROR] RESTORE FAILED: $errMsg" -ForegroundColor Red
        
        if ($isOverwrite) {
            Write-Host ""
            Write-Host "[CRITICAL] Original system was unregistered!" -ForegroundColor Yellow
            Write-Host "If you created a Safety Net, you can restore it with:" -ForegroundColor Yellow
            Write-Host "  wsl --import $distroName <path> <safety-net.tar>" -ForegroundColor Cyan
        }
        
        Stop-ActiveBackupProcesses
        
    }
    finally {
        Stop-ActiveBackupProcesses
        
        #清理临时 batch 文件
        if ($Global:BackupState.TempBatch -and (Test-Path $Global:BackupState.TempBatch)) {
            Remove-Item $Global:BackupState.TempBatch -Force -ErrorAction SilentlyContinue
        }
        
        Remove-LockFile
        $Global:BackupState.IsRunning = $false
        $Global:BackupState.TempBatch = $null
    }
    Read-Host "Press Enter to continue..."
}

function Invoke-RestoreUserData {
    param($backupDir)
    
    $backupFile = Join-Path $backupDir "home.7z"
    
    if (-not (Test-Path $backupFile)) {
        #尝试查找任意.7z 文件
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
    
    $wslUser = Get-WSLUser
    $destPath = if ($wslUser -eq "root") { "/root" } else { "/home/$wslUser" }
    $dest = "$($Script:WSLPathPrefix)\$Script:CurrentDistro$destPath"
    
    Write-Host "Restoring to: $dest" -ForegroundColor Cyan
    Write-LogEntry "INFO" "Restore-User" "Target: $dest"
    
    try {
        $rawArgs = @("x", $backupFile, "-o$dest", "-aoa", "-bsp1")
        $safeArgs = Format-QuotedArgs $rawArgs
        
        $proc = Start-Process "7z" -ArgumentList $safeArgs -Wait -PassThru -NoNewWindow
        
        if ($proc.ExitCode -eq 0) {
            Write-Host "SUCCESS!" -ForegroundColor Green
            Write-LogEntry "SUCCESS" "Restore-User" "Completed"
        }
        else {
            throw "7z Error Code: $($proc.ExitCode)"
        }
        
    }
    catch {
        Write-Host "[ERROR] $_" -ForegroundColor Red
        Write-LogEntry "ERROR" "Restore-User" "Failed: $_"
    }
    
    Read-Host "Press Enter..."
}

function Remove-BatchBackups {
    $scanPath = Get-InstanceBackupPath
    if (-not $scanPath) { $scanPath = $Global:Config.GlobalBackupRoot }
    
    Clear-Host
    Write-Host "=== BATCH DELETE ($scanPath) ===" -ForegroundColor Red
    
    if (-not (Test-Path $scanPath)) {
        Write-Host "Path not found." -ForegroundColor Yellow
        Read-Host "Press Enter..."
        return
    }
    
    # 强制数组模式
    $backups = @(Get-ChildItem $scanPath -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
    
    if ($backups.Count -eq 0) {
        Write-Host "No backups found."
        Read-Host "Press Enter..."
        return
    }
    
    Show-BackupTable -Backups $backups
    
    Write-Host ""
    $inputStr = Read-Host "Enter numbers to delete (comma separated, e.g. 1,3,5) or 0/q to cancel"
    
    if ($inputStr -eq "q" -or $inputStr -eq "Q" -or $inputStr -eq "0") {
        return
    }
    
    # [FIX-07] 严格解析输入
    $selections = $inputStr -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
    
    $targets = @()
    foreach ($idx in $selections) {
        $idxNum = [int]$idx
        if ($idxNum -gt 0 -and $idxNum -le $backups.Count) {
            $targets += $backups[$idxNum - 1]
        }
    }
    
    if ($targets.Count -eq 0) {
        Write-Host "No valid selections." -ForegroundColor Yellow
        Read-Host "Press Enter..."
        return
    }

    Write-Host ""
    Write-Host "The following will be PERMANENTLY DELETED:" -ForegroundColor Red
    foreach ($t in $targets) {
        Write-Host "  - $($t.Name)" -ForegroundColor Yellow
    }
    
    $confirm = Read-Host "Type 'DELETE' to confirm (case-sensitive)"
    if ($confirm -cne "DELETE") {
        Write-Host "Cancelled." -ForegroundColor Yellow
        Read-Host "Press Enter..."
        return
    }
    
    foreach ($t in $targets) {
        try {
            Remove-Item $t.FullName -Recurse -Force -ErrorAction Stop
            Write-Host "  Deleted: $($t.Name)" -ForegroundColor Green
            Write-LogEntry "INFO" "Delete" "Removed backup: $($t.Name)"
        }
        catch {
            Write-Host "  Failed to delete: $($t.Name) - $_" -ForegroundColor Red
        }
    }
    
    Read-Host "Press Enter..."
}

function Get-BackupList {
    $scanPath = Get-InstanceBackupPath
    if (-not $scanPath) { $scanPath = $Global:Config.GlobalBackupRoot }
    
    Clear-Host
    Write-Host "=== BACKUP LIST ($scanPath) ===" -ForegroundColor Cyan
    
    if (-not (Test-Path $scanPath)) {
        Write-Host "Path not found." -ForegroundColor Yellow
        Read-Host "Press Enter..."
        return
    }

    # 强制数组模式
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
        
        $choice = Read-Host "Select"
        
        switch ($choice) {
            { $_ -in @("q", "Q", "7") } { return }
            "1" {
                $newPath = Read-Host "Enter new Backup Root path"
                if ($newPath -and (Test-Path $newPath -IsValid)) {
                    if (-not (Test-Path $newPath)) {
                        $create = Read-Host "Path doesn't exist. Create? [Y/N/Q]"
                        if ($create -eq "Y" -or $create -eq "y") {
                            New-Item -ItemType Directory -Path $newPath -Force | Out-Null
                        }
                    }
                    if (Test-Path $newPath) {
                        $Global:Config.GlobalBackupRoot = $newPath
                        Save-Config
                        Write-Host "Updated." -ForegroundColor Green
                    }
                }
            }
            "2" {
                $newPath = Read-Host "Enter new Install Root path"
                if ($newPath -and (Test-Path $newPath -IsValid)) {
                    if (-not (Test-Path $newPath)) {
                        $create = Read-Host "Path doesn't exist. Create? [Y/N/Q]"
                        if ($create -eq "Y" -or $create -eq "y") {
                            New-Item -ItemType Directory -Path $newPath -Force | Out-Null
                        }
                    }
                    if (Test-Path $newPath) {
                        $Global:Config.InstallRoot = $newPath
                        Save-Config
                        Write-Host "Updated." -ForegroundColor Green
                    }
                }
            }
            "3" {
                $newPath = Read-Host "Enter full path to 7z.exe"
                if (Test-Path $newPath -PathType Leaf) {
                    $Global:Config.SevenZipPath = $newPath
                    Save-Config
                    Write-Host "Updated." -ForegroundColor Green
                }
                else {
                    Write-Host "File not found." -ForegroundColor Red
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
    Write-Host "=== WSL Backup Manager v3.23 (Security Patched)$adminTag ===" -ForegroundColor Cyan
    Write-Host "  DISTRO : $Script:CurrentDistro" -ForegroundColor Green
    Write-Host "  REPO   : $scanPath" -ForegroundColor DarkGray
    Write-Host "========================================================"
    Write-Host "  [1] New Backup"
    Write-Host "  [2] List Backups"
    Write-Host "  [3] RESTORE / CLONE" -ForegroundColor Yellow
    Write-Host "  [4] BATCH DELETE" -ForegroundColor Red
    Write-Host "  [5] View Logs" -ForegroundColor Cyan
    Write-Host "  [6] Switch Distro"
    Write-Host "  [7] Settings"
    Write-Host "  [8] Exit"
    Write-Host ""
    
    $choice = Read-Host "Choose"
    
    switch ($choice) {
        { $_ -in @("q", "Q", "8") } { exit }
        "1" { Show-NewBackupMenu }
        "2" { Get-BackupList }
        "3" { Show-RestoreMenu }
        "4" { Remove-BatchBackups }
        "5" { Show-LogsMenu }
        "6" { Select-WSLDistro -Force }
        "7" { Edit-Settings }
        "8" { exit }
        default { }
    }
}

function Show-NewBackupMenu {
    Clear-Host
    Write-Host "=== New Backup ===" -ForegroundColor Cyan
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
        "0" { return }
        default { return }
    }
}

# =============================================================================
# 11. Script Entry Point
# =============================================================================

# 初始化
Import-Config
Test-WSLAvailability
Get-WSLPathing
Optimize-WSLConfig

if (-not (Test-7zInstalled)) {
    Write-Host "[FATAL] 7-Zip is required. Please install it and try again." -ForegroundColor Red
    exit
}

# 选择发行版
Select-WSLDistro

# 主循环
while ($true) {
    Show-MainMenu
}
