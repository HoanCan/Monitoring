# C:\Monitoring\Scripts\Server\Monitor-DC01-Service.ps1

<#
.SYNOPSIS
    DC01 Monitoring Service Script
.DESCRIPTION
    Giam sat CPU, Memory, Disk, Network, Services, DHCP, AD Replication,
    Event Logs, Security Events, Connectivity, DCDIAG va gui canh bao real-time qua Telegram.
    Thiet ke de chay duoi Windows Service (NSSM).
.NOTES
    - Khong dung emoji, chi ASCII
    - Log UTF-8
    - Su dung event bookmarking tranh duplicate
#>

[CmdletBinding()]
param(
    [int]$IntervalSeconds = 60,
    [string]$ConfigPath = "C:\Monitoring\Config\monitoring-config.json"
)

#region Encoding
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['Add-Content:Encoding'] = 'utf8'
#endregion

#region Global Vars
$Script:Config             = $null
$Script:ServerName         = $env:COMPUTERNAME
$Script:ServerIP           = "127.0.0.1"
$Script:LogPath            = "C:\Monitoring\Logs\DC01-Health.log"
$Script:DataDirectory      = "C:\Monitoring\Data"
$Script:BookmarkPath       = "C:\Monitoring\Data\event-bookmarks.json"

$Script:CPUThreshold       = 80
$Script:MemoryThreshold    = 80
$Script:DiskThreshold      = 90
$Script:DHCPThreshold      = 90
$Script:DiskQueueWarning   = 2

$Script:NonRestartServices = @("NTDS","ADWS","KDC","Netlogon")
$Script:CriticalServices   = @{
    "DNS"        = "DNS Server"
    "DHCPServer" = "DHCP Server"
    "NTDS"       = "Active Directory Domain Services"
    "ADWS"       = "Active Directory Web Services"
    "Netlogon"   = "Netlogon"
    "KDC"        = "Kerberos Key Distribution Center"
    "W32Time"    = "Windows Time"
    "EventLog"   = "Windows Event Log"
}

$Script:DHCPConfig         = $null
$Script:ConnectivityConfig = $null
$Script:ADConfig           = $null
$Script:AlertConfig        = $null

$Script:EventBookmarks = @{
    Security    = @{ LastRecordId = 0; LastCheck = (Get-Date).ToString("o") }
    System      = @{ LastRecordId = 0; LastCheck = (Get-Date).ToString("o") }
    Application = @{ LastRecordId = 0; LastCheck = (Get-Date).ToString("o") }
}

$Script:CycleCount = 0
#endregion

#region Config Loading
function Load-MonitorConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        if (-not (Test-Path $Path)) {
            throw "Config file not found: $Path"
        }

        $json = Get-Content -Path $Path -Encoding UTF8 -Raw
        if (-not $json.Trim()) {
            throw "Config file is empty: $Path"
        }

        $cfg = $json | ConvertFrom-Json
        $Script:Config = $cfg

        if ($cfg.Server -and $cfg.Server.Name) {
            $Script:ServerName = $cfg.Server.Name
        } else {
            $Script:ServerName = $env:COMPUTERNAME
        }

        if ($cfg.Server -and $cfg.Server.IPAddress) {
            $Script:ServerIP = $cfg.Server.IPAddress
        }

        if ($cfg.Paths) {
            if ($cfg.Paths.LogPath)        { $Script:LogPath       = $cfg.Paths.LogPath }
            if ($cfg.Paths.DataDirectory)  { $Script:DataDirectory = $cfg.Paths.DataDirectory }
            if ($cfg.Paths.BookmarkPath)   { $Script:BookmarkPath  = $cfg.Paths.BookmarkPath }
        }

        if ($cfg.Thresholds) {
            if ($cfg.Thresholds.CPU)             { $Script:CPUThreshold     = [int]$cfg.Thresholds.CPU }
            if ($cfg.Thresholds.Memory)          { $Script:MemoryThreshold  = [int]$cfg.Thresholds.Memory }
            if ($cfg.Thresholds.Disk)            { $Script:DiskThreshold    = [int]$cfg.Thresholds.Disk }
            if ($cfg.Thresholds.DHCPUtilization) { $Script:DHCPThreshold    = [int]$cfg.Thresholds.DHCPUtilization }
            if ($cfg.Thresholds.DiskQueueWarning){ $Script:DiskQueueWarning = [int]$cfg.Thresholds.DiskQueueWarning }
        }

        $Script:NonRestartServices = @()
        if ($cfg.Services -and $cfg.Services.NonRestartable) {
            $Script:NonRestartServices = @($cfg.Services.NonRestartable)
        }

        $Script:CriticalServices = @{}
        if ($cfg.Services -and $cfg.Services.Critical) {
            $Script:CriticalServices = @{}
            $cfg.Services.Critical.PSObject.Properties | ForEach-Object {
                $Script:CriticalServices[$_.Name] = $_.Value
            }
        }

        $Script:DHCPConfig         = $null
        if ($cfg.DHCP)         { $Script:DHCPConfig         = $cfg.DHCP }

        $Script:ConnectivityConfig = $null
        if ($cfg.Connectivity) { $Script:ConnectivityConfig = $cfg.Connectivity }

        $Script:ADConfig           = $null
        if ($cfg.AD)           { $Script:ADConfig           = $cfg.AD }

        $Script:AlertConfig        = $null
        if ($cfg.Alerts)       { $Script:AlertConfig        = $cfg.Alerts }
    }
    catch {
        if (-not $Script:Config) {
            throw "Cannot load initial config: $($_.Exception.Message)"
        } else {
            Write-Host "Failed to reload config: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}
#endregion

#region Secret Helper
function Get-PlainTextFromSecureFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        throw "Secret file not found: $Path"
    }

    $encrypted = Get-Content $Path -ErrorAction Stop
    $secure    = ConvertTo-SecureString $encrypted

    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}
#endregion

#region Alert Helper
function Test-ShouldSendAlertLevel {
    param(
        [Parameter(Mandatory)][string]$Level,
        [Parameter(Mandatory)][string]$MinLevel
    )

    $order = @("INFO","SUCCESS","WARNING","ERROR","CRITICAL")
    $levelIndex = $order.IndexOf($Level.ToUpper())
    $minIndex   = $order.IndexOf($MinLevel.ToUpper())

    if ($levelIndex -lt 0 -or $minIndex -lt 0) { return $false }
    return ($levelIndex -ge $minIndex)
}
#endregion

#region Logging
function Write-MonitorLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","WARNING","ERROR","SUCCESS","CRITICAL")]
        [string]$Level = "INFO",
        [switch]$SkipAlert
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $LogEntry  = "[$Timestamp] [$($Script:ServerName)] [$Level] $Message"

    $Color = switch ($Level) {
        "ERROR"    { "Red" }
        "CRITICAL" { "Magenta" }
        "WARNING"  { "Yellow" }
        "SUCCESS"  { "Green" }
        default    { "White" }
    }

    Write-Host $LogEntry -ForegroundColor $Color

    $logDir = Split-Path $Script:LogPath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    $sw = New-Object System.IO.StreamWriter($Script:LogPath, $true, [System.Text.Encoding]::UTF8)
    $sw.WriteLine($LogEntry)
    $sw.Close()

    if (-not $SkipAlert) {
        if ($Level -in @("WARNING","ERROR","CRITICAL")) {
            Send-TelegramAlert -Message $Message -Level $Level
        }
    }
}
#endregion

#region Telegram Alert
function Send-TelegramAlert {
    param(
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$Level
    )

    if (-not $Script:AlertConfig -or -not $Script:AlertConfig.Telegram) {
        return
    }

    $tgConfig = $Script:AlertConfig.Telegram
    if (-not $tgConfig.Enabled) { return }

    if ($tgConfig.MinLevel) {
        if (-not (Test-ShouldSendAlertLevel -Level $Level -MinLevel $tgConfig.MinLevel)) {
            return
        }
    }

    if ($tgConfig.SendFor -and ($Level -notin $tgConfig.SendFor)) {
        return
    }

    try {
        $tokenFile  = $tgConfig.TokenFile
        $chatIdFile = $tgConfig.ChatIdFile

        if (-not (Test-Path $tokenFile) -or -not (Test-Path $chatIdFile)) {
            Write-MonitorLog "Telegram secret files not found. Skip alert." "ERROR" -SkipAlert
            return
        }

        $token  = Get-PlainTextFromSecureFile -Path $tokenFile
        $chatId = Get-PlainTextFromSecureFile -Path $chatIdFile

        $text = "[{0}][{1}] {2}" -f $Script:ServerName, $Level, $Message

        $body = @{
            chat_id = $chatId
            text    = $text
        }

        Invoke-RestMethod -Uri ("https://api.telegram.org/bot{0}/sendMessage" -f $token) `
                          -Method Post -Body $body -ErrorAction Stop
    }
    catch {
        Write-MonitorLog "Failed to send Telegram alert: $($_.Exception.Message)" "ERROR" -SkipAlert
    }
}
#endregion

#region Log Rotation
function Rotate-LogFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxSizeMB = 100
    )

    if (Test-Path $Path) {
        $logFile = Get-Item $Path
        $sizeMB  = $logFile.Length / 1MB

        if ($sizeMB -gt $MaxSizeMB) {
            $archiveDir = "C:\Monitoring\Archives"
            if (-not (Test-Path $archiveDir)) {
                New-Item -Path $archiveDir -ItemType Directory -Force | Out-Null
            }

            $archiveFile = Join-Path $archiveDir ("DC01-Health-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".log")
            Move-Item -Path $Path -Destination $archiveFile -Force
            Write-MonitorLog "Log rotated. Archived to: $archiveFile" "INFO" -SkipAlert
        }
    }
}
#endregion

#region Event Bookmark
function Save-EventBookmark {
    param(
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][long]$RecordId
    )

    $Script:EventBookmarks[$LogName].LastRecordId = $RecordId
    $Script:EventBookmarks[$LogName].LastCheck    = (Get-Date).ToString("o")

    $bookmarkDir = Split-Path $Script:BookmarkPath -Parent
    if (-not (Test-Path $bookmarkDir)) {
        New-Item -Path $bookmarkDir -ItemType Directory -Force | Out-Null
    }

    $Script:EventBookmarks | ConvertTo-Json -Depth 3 | Out-File -FilePath $Script:BookmarkPath -Encoding UTF8
}
#endregion

#region Health Check Core
function Get-DC01Health {
    $Health = @{
        Timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ServerName = $Script:ServerName
        IPAddress  = $Script:ServerIP
    }

    # CPU and queue
    try {
        $CPU = Get-Counter "\Processor(_Total)\% Processor Time" -SampleInterval 2 -MaxSamples 1
        $Health.CPU = [Math]::Round($CPU.CounterSamples[0].CookedValue, 2)

        $CPUQueue = Get-Counter "\System\Processor Queue Length" -ErrorAction SilentlyContinue
        $Health.CPUQueue = if ($CPUQueue) { [Math]::Round($CPUQueue.CounterSamples[0].CookedValue, 2) } else { 0 }
    }
    catch {
        $Health.CPU      = -1
        $Health.CPUQueue = 0
    }

    # Memory
    try {
        $OS = Get-CimInstance Win32_OperatingSystem
        $TotalMemoryMB = $OS.TotalVisibleMemorySize / 1KB
        $FreeMemoryMB  = $OS.FreePhysicalMemory / 1KB
        $UsedMemoryMB  = $TotalMemoryMB - $FreeMemoryMB

        $PageFaults = Get-Counter "\Memory\Page Faults/sec" -ErrorAction SilentlyContinue
        $PagesPerSec = Get-Counter "\Memory\Pages/sec" -ErrorAction SilentlyContinue

        $usedPercent = if ($TotalMemoryMB -gt 0) {
            [Math]::Round(($UsedMemoryMB / $TotalMemoryMB) * 100, 2)
        } else {
            0
        }

        $Health.Memory = @{
            TotalMB         = [Math]::Round($TotalMemoryMB, 2)
            UsedMB          = [Math]::Round($UsedMemoryMB, 2)
            FreeMB          = [Math]::Round($FreeMemoryMB, 2)
            UsedPercent     = $usedPercent
            PageFaultsPerSec= if ($PageFaults) { [Math]::Round($PageFaults.CounterSamples[0].CookedValue, 2) } else { 0 }
            PagesPerSec     = if ($PagesPerSec) { [Math]::Round($PagesPerSec.CounterSamples[0].CookedValue, 2) } else { 0 }
        }
    }
    catch {
        $Health.Memory = @{ UsedPercent = -1 }
    }

    # Disk
    $Health.Disks = @()
    try {
        $DiskQueue   = Get-Counter "\PhysicalDisk(_Total)\Avg. Disk Queue Length" -ErrorAction SilentlyContinue
        $DiskLatency = Get-Counter "\PhysicalDisk(_Total)\Avg. Disk sec/Transfer" -ErrorAction SilentlyContinue
        $DiskTime    = Get-Counter "\PhysicalDisk(_Total)\% Disk Time" -ErrorAction SilentlyContinue

        $Health.DiskPerformance = @{
            AvgQueueLength = if ($DiskQueue)   { [Math]::Round($DiskQueue.CounterSamples[0].CookedValue, 2) } else { 0 }
            AvgLatencyMs   = if ($DiskLatency) { [Math]::Round($DiskLatency.CounterSamples[0].CookedValue * 1000, 2) } else { 0 }
            DiskTimePercent= if ($DiskTime)    { [Math]::Round($DiskTime.CounterSamples[0].CookedValue, 2) } else { 0 }
        }

        $Disks = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        foreach ($Disk in $Disks) {
            if ($Disk.Size -gt 0) {
                $UsedPercent = [Math]::Round((($Disk.Size - $Disk.FreeSpace) / $Disk.Size) * 100, 2)
                $Health.Disks += @{
                    Drive       = $Disk.DeviceID
                    TotalGB     = [Math]::Round($Disk.Size / 1GB, 2)
                    FreeGB      = [Math]::Round($Disk.FreeSpace / 1GB, 2)
                    UsedPercent = $UsedPercent
                }
            }
        }
    }
    catch {
        Write-MonitorLog "Error collecting disk information: $($_.Exception.Message)" "ERROR"
    }

    # Network throughput
    try {
        $NetworkBytes = Get-Counter "\Network Interface(*)\Bytes Total/sec" -ErrorAction SilentlyContinue
        if ($NetworkBytes) {
            $sumBytes = ($NetworkBytes.CounterSamples | Measure-Object -Property CookedValue -Sum).Sum
            $Health.Network = @{
                BytesPerSec = [Math]::Round($sumBytes, 2)
                MBPerSec    = [Math]::Round($sumBytes / 1MB, 2)
            }
        }
        else {
            $Health.Network = @{ BytesPerSec = 0; MBPerSec = 0 }
        }
    }
    catch {
        $Health.Network = @{ BytesPerSec = 0; MBPerSec = 0 }
    }

    # Services
    $Health.Services = @()
    foreach ($key in $Script:CriticalServices.Keys) {
        $ServiceName = $key
        $DisplayName = $Script:CriticalServices[$key]
        try {
            $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($Service) {
                $Health.Services += @{
                    Name       = $ServiceName
                    DisplayName= $DisplayName
                    Status     = $Service.Status.ToString()
                    IsRunning  = ($Service.Status -eq "Running")
                    CanRestart = ($ServiceName -notin $Script:NonRestartServices)
                }
            }
            else {
                $Health.Services += @{
                    Name       = $ServiceName
                    DisplayName= $DisplayName
                    Status     = "NotFound"
                    IsRunning  = $false
                    CanRestart = ($ServiceName -notin $Script:NonRestartServices)
                }
            }
        }
        catch {
            Write-MonitorLog "Error checking service $($ServiceName): $($_.Exception.Message)" "WARNING"
        }
    }

    # Network info
    try {
        $NetAdapter = Get-NetIPAddress | Where-Object { $_.IPAddress -eq $Script:ServerIP }
        $Health.NetworkInfo = @{
            IPAddress      = $Script:ServerIP
            InterfaceAlias = $NetAdapter.InterfaceAlias
            PrefixLength   = $NetAdapter.PrefixLength
        }
    }
    catch {
        $Health.NetworkInfo = @{
            IPAddress = $Script:ServerIP
            Status    = "Unknown"
        }
    }

    # DHCP
    try {
        if ($Script:DHCPConfig -and $Script:DHCPConfig.ScopeId) {
            $scopeId = $Script:DHCPConfig.ScopeId
            $DHCPStats = Get-DhcpServerv4ScopeStatistics -ScopeId $scopeId -ErrorAction SilentlyContinue
            if ($DHCPStats) {
                $total = $DHCPStats.AddressesFree + $DHCPStats.AddressesInUse
                $Health.DHCP = @{
                    ScopeId           = $scopeId
                    ScopeRange        = $Script:DHCPConfig.ScopeRange
                    TotalAddresses    = $total
                    InUse             = $DHCPStats.AddressesInUse
                    Free              = $DHCPStats.AddressesFree
                    UtilizationPercent= [Math]::Round($DHCPStats.PercentageInUse, 2)
                    Status            = if ($DHCPStats.PercentageInUse -gt $Script:DHCPThreshold) {
                                            "CRITICAL"
                                         } elseif ($DHCPStats.PercentageInUse -gt ($Script:DHCPThreshold - 10)) {
                                            "WARNING"
                                         } else {
                                            "OK"
                                         }
                }
            }
            else {
                $Health.DHCP = @{ Status = "Unable to query" }
            }
        }
    }
    catch {
        $Health.DHCP = @{ Status = "Error"; Message = $_.Exception.Message }
    }

    return $Health
}
#endregion

#region EventLog Errors
function Check-EventLogErrors {
    param(
        [int]$MinutesBack = 5
    )

    $StartTime = (Get-Date).AddMinutes(-$MinutesBack)
    $AllErrors = @()

    # System
    try {
        $lastRecordId = $Script:EventBookmarks.System.LastRecordId
        $SystemErrors = Get-WinEvent -FilterHashtable @{
            LogName   = "System"
            Level     = 1,2
            StartTime = $StartTime
        } -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object { $_.RecordId -gt $lastRecordId }

        if ($SystemErrors) {
            $AllErrors += $SystemErrors
            $maxRecordId = ($SystemErrors | Measure-Object -Property RecordId -Maximum).Maximum
            Save-EventBookmark -LogName "System" -RecordId $maxRecordId
        }
    }
    catch {}

    # Application
    try {
        $lastRecordId = $Script:EventBookmarks.Application.LastRecordId
        $AppErrors = Get-WinEvent -FilterHashtable @{
            LogName   = "Application"
            Level     = 1,2
            StartTime = $StartTime
        } -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object { $_.RecordId -gt $lastRecordId }

        if ($AppErrors) {
            $AllErrors += $AppErrors
            $maxRecordId = ($AppErrors | Measure-Object -Property RecordId -Maximum).Maximum
            Save-EventBookmark -LogName "Application" -RecordId $maxRecordId
        }
    }
    catch {}

    return ,$AllErrors
}
#endregion

#region Security Events
function Check-CriticalSecurityEvents {
    $StartTime    = (Get-Date).AddMinutes(-5)
    $lastRecordId = $Script:EventBookmarks.Security.LastRecordId

    # Account lockout 4740
    try {
        $Lockouts = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = 4740
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue | Where-Object { $_.RecordId -gt $lastRecordId }

        if ($Lockouts) {
            foreach ($event in $Lockouts) {
                $accountName   = $event.Properties[0].Value
                $callerComputer= $event.Properties[1].Value
                Write-MonitorLog "Account Lockout Detected - User: $accountName, Source: $callerComputer" "CRITICAL"
            }
            $maxRecordId = ($Lockouts | Measure-Object -Property RecordId -Maximum).Maximum
            Save-EventBookmark -LogName "Security" -RecordId $maxRecordId
            $lastRecordId = $maxRecordId
        }
    }
    catch {}

    # Kerberos pre-auth failures 4771
    try {
        $KerbFailures = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = 4771
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue | Where-Object { $_.RecordId -gt $lastRecordId }

        if ($KerbFailures -and $KerbFailures.Count -gt 5) {
            $grouped = $KerbFailures |
                Group-Object { $_.Properties[0].Value } |
                Where-Object { $_.Count -gt 5 } |
                Sort-Object Count -Descending

            foreach ($group in $grouped) {
                Write-MonitorLog "Kerberos Pre-auth Failures - User: $($group.Name), Count: $($group.Count)" "WARNING"
            }
        }

        if ($KerbFailures) {
            $maxRecordId = ($KerbFailures | Measure-Object -Property RecordId -Maximum).Maximum
            Save-EventBookmark -LogName "Security" -RecordId $maxRecordId
        }
    }
    catch {}
}
#endregion

#region AD Replication
function Check-DomainReplication {
    try {
        $ReplStatus = Get-ADReplicationPartnerMetadata -Target $Script:ServerName -Scope Server -ErrorAction SilentlyContinue
        if ($ReplStatus) {
            $Failed = $ReplStatus | Where-Object { $_.LastReplicationResult -ne 0 }
            if ($Failed) {
                return @{
                    Status     = "Warning"
                    FailedCount= $Failed.Count
                    Message    = "Found $($Failed.Count) replication issues"
                }
            }
            return @{ Status = "OK"; Message = "All replications successful" }
        }
        else {
            return @{ Status = "Unknown"; Message = "No replication data" }
        }
    }
    catch {
        return @{ Status = "Unknown"; Message = "Unable to check replication: $($_.Exception.Message)" }
    }
}
#endregion

#region Connectivity
function Get-ConnectivityStatus {
    $result = @{
        Gateway          = $null
        GatewayReachable = $null
        InternetReachable= $null
        Status           = "Unknown"
        Details          = @()
    }

    $cfg = $Script:ConnectivityConfig
    if (-not $cfg -or -not $cfg.CheckEnabled) {
        $result.Status = "Disabled"
        return $result
    }

    if ($cfg.GatewayCheck) {
        try {
            $gwRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" |
                       Sort-Object RouteMetric |
                       Select-Object -First 1

            $gateway = $gwRoute.NextHop
            $result.Gateway = $gateway

            if ($gateway) {
                $gwOk = Test-Connection -ComputerName $gateway -Count 2 -Quiet -ErrorAction SilentlyContinue
                $result.GatewayReachable = $gwOk
                if (-not $gwOk) {
                    $result.Details += "Cannot ping default gateway $gateway"
                }
            }
            else {
                $result.Details += "No default gateway found"
                $result.GatewayReachable = $false
            }
        }
        catch {
            $result.Details += "Error checking gateway: $($_.Exception.Message)"
            $result.GatewayReachable = $false
        }
    }

    $internetOk = $true
    if ($cfg.PingTargets) {
        foreach ($t in $cfg.PingTargets) {
            try {
                $ok = Test-Connection -ComputerName $t -Count 2 -Quiet -ErrorAction SilentlyContinue
                if (-not $ok) {
                    $internetOk = $false
                    $result.Details += "Ping failed to $t"
                }
            }
            catch {
                $internetOk = $false
                $result.Details += "Error pinging $($t): $($_.Exception.Message)"
            }
        }
    }
    $result.InternetReachable = $internetOk

    if ($cfg.GatewayCheck -and $result.GatewayReachable -eq $false) {
        $result.Status = "CRITICAL"
    }
    elseif ($internetOk -eq $false) {
        $result.Status = "WARNING"
    }
    else {
        $result.Status = "OK"
    }

    return $result
}
#endregion

#region DCDIAG
function Check-DcDiag {
    param(
        [string]$ServerName = $Script:ServerName
    )

    try {
        $output   = dcdiag /s:$ServerName /q 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0 -and ([string]::IsNullOrWhiteSpace(($output -join "")))) {
            return @{ Status = "OK"; Message = "dcdiag /q returned no errors" }
        }
        else {
            return @{
                Status    = "Warning"
                Message   = "dcdiag reported issues"
                RawOutput = $output
            }
        }
    }
    catch {
        return @{
            Status  = "Unknown"
            Message = "Failed to run dcdiag: $($_.Exception.Message)"
        }
    }
}
#endregion

#region Save Health
function Save-HealthData {
    param(
        [Parameter(Mandatory)][hashtable]$Health
    )

    try {
        if (-not (Test-Path $Script:DataDirectory)) {
            New-Item -Path $Script:DataDirectory -ItemType Directory -Force | Out-Null
        }

        $fileName = "DC01-Health-{0}.json" -f (Get-Date -Format "yyyyMMdd")
        $filePath = Join-Path $Script:DataDirectory $fileName

        $Health | ConvertTo-Json -Depth 5 | Out-File -FilePath $filePath -Append -Encoding UTF8
    }
    catch {
        Write-MonitorLog "Failed to save health data: $($_.Exception.Message)" "ERROR"
    }
}
#endregion

#region Main

# Load config initial
try {
    Load-MonitorConfig -Path $ConfigPath
}
catch {
    Write-Host "FATAL: Cannot load monitoring config: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Load bookmarks from file
if (Test-Path $Script:BookmarkPath) {
    try {
        $bookJson = Get-Content $Script:BookmarkPath -Encoding UTF8 -Raw
        if ($bookJson.Trim()) {
            $Script:EventBookmarks = $bookJson | ConvertFrom-Json -AsHashtable
        }
    }
    catch {
        # Giá»¯ default náº¿u lá»—i
    }
}

Rotate-LogFile -Path $Script:LogPath -MaxSizeMB 100

Write-MonitorLog "=== DC01 Health Monitoring Service Started ===" "SUCCESS" -SkipAlert
Write-MonitorLog "Server: $($Script:ServerName) ($($Script:ServerIP))" "INFO" -SkipAlert
Write-MonitorLog "Monitoring Interval: $IntervalSeconds seconds" "INFO" -SkipAlert
Write-MonitorLog "Thresholds - CPU: $($Script:CPUThreshold)%, Memory: $($Script:MemoryThreshold)%, Disk: $($Script:DiskThreshold)%, DHCP: $($Script:DHCPThreshold)%" "INFO" -SkipAlert
Write-MonitorLog "Non-Restart Services: $($Script:NonRestartServices -join ', ')" "INFO" -SkipAlert

while ($true) {
    try {
        $Script:CycleCount++

        # Reload config má»—i vÃ²ng Ä‘á»ƒ apply thay Ä‘á»•i ngÆ°á»¡ng Ä‘á»™ng
        Load-MonitorConfig -Path $ConfigPath | Out-Null

        Write-MonitorLog "--- Monitoring Cycle #$($Script:CycleCount) ---" "INFO"

        Rotate-LogFile -Path $Script:LogPath -MaxSizeMB 100

        $Health = Get-DC01Health

        # CPU
        if ($Health.CPU -ge 0) {
            if ($Health.CPU -gt $Script:CPUThreshold) {
                Write-MonitorLog "HIGH CPU USAGE: $($Health.CPU)% (Queue Length: $($Health.CPUQueue))" "WARNING"
            }
            else {
                Write-MonitorLog "CPU: $($Health.CPU)% (Queue Length: $($Health.CPUQueue))" "INFO"
            }
        }

        # Memory
        if ($Health.Memory -and $Health.Memory.UsedPercent -ge 0) {
            if ($Health.Memory.UsedPercent -gt $Script:MemoryThreshold) {
                Write-MonitorLog "HIGH MEMORY USAGE: $($Health.Memory.UsedPercent)% (Free: $($Health.Memory.FreeMB)MB, Page Faults: $($Health.Memory.PageFaultsPerSec)/sec)" "WARNING"
            }
            else {
                Write-MonitorLog "Memory: $($Health.Memory.UsedPercent)% used (Free: $($Health.Memory.FreeMB)MB, Page Faults: $($Health.Memory.PageFaultsPerSec)/sec)" "INFO"
            }
        }

        # Disk performance
        if ($Health.DiskPerformance) {
            if ($Health.DiskPerformance.AvgQueueLength -gt $Script:DiskQueueWarning) {
                Write-MonitorLog "HIGH DISK QUEUE: $($Health.DiskPerformance.AvgQueueLength) (Latency: $($Health.DiskPerformance.AvgLatencyMs)ms, DiskTime: $($Health.DiskPerformance.DiskTimePercent)%)" "WARNING"
            }
            else {
                Write-MonitorLog "Disk performance: Queue=$($Health.DiskPerformance.AvgQueueLength), Latency=$($Health.DiskPerformance.AvgLatencyMs)ms, DiskTime=$($Health.DiskPerformance.DiskTimePercent)%" "INFO"
            }
        }

        # Disk space
        foreach ($Disk in $Health.Disks) {
            if ($Disk.UsedPercent -gt $Script:DiskThreshold) {
                Write-MonitorLog "HIGH DISK USAGE on $($Disk.Drive): $($Disk.UsedPercent)% (Free: $($Disk.FreeGB)GB)" "WARNING"
            }
        }

        # Services
        $DownServices = $Health.Services | Where-Object { -not $_.IsRunning }
        if ($DownServices) {
            foreach ($Service in $DownServices) {
                if ($Service.CanRestart) {
                    Write-MonitorLog "SERVICE DOWN: $($Service.DisplayName) [$($Service.Name)] - Status: $($Service.Status)" "ERROR"
                    try {
                        Write-MonitorLog "Attempting to restart $($Service.Name)..." "INFO"
                        Start-Service -Name $Service.Name -ErrorAction Stop
                        Write-MonitorLog "Successfully restarted $($Service.Name)" "SUCCESS"
                    }
                    catch {
                        Write-MonitorLog "Failed to restart $($Service.Name): $($_.Exception.Message)" "ERROR"
                    }
                }
                else {
                    Write-MonitorLog "CRITICAL AD SERVICE DOWN: $($Service.DisplayName) [$($Service.Name)] - ESCALATION REQUIRED - DO NOT AUTO-RESTART" "CRITICAL"
                }
            }
        }
        else {
            Write-MonitorLog "All critical services are running." "INFO"
        }

        # DHCP
        if ($Health.DHCP) {
            if ($Health.DHCP.Status -eq "CRITICAL") {
                Write-MonitorLog "DHCP SCOPE CRITICAL: Utilization at $($Health.DHCP.UtilizationPercent)% ($($Health.DHCP.InUse)/$($Health.DHCP.TotalAddresses) used)" "CRITICAL"
            }
            elseif ($Health.DHCP.Status -eq "WARNING") {
                Write-MonitorLog "DHCP SCOPE WARNING: Utilization at $($Health.DHCP.UtilizationPercent)% ($($Health.DHCP.InUse)/$($Health.DHCP.TotalAddresses) used)" "WARNING"
            }
            elseif ($Health.DHCP.UtilizationPercent) {
                Write-MonitorLog "DHCP: $($Health.DHCP.InUse)/$($Health.DHCP.TotalAddresses) addresses in use ($($Health.DHCP.UtilizationPercent)% )" "INFO"
            }
            else {
                Write-MonitorLog "DHCP status: $($Health.DHCP.Status)" "INFO"
            }
        }

        # AD Replication
        $ReplStatus = Check-DomainReplication
        if ($ReplStatus.Status -eq "Warning") {
            Write-MonitorLog "AD Replication: $($ReplStatus.Message)" "WARNING"
        }
        elseif ($ReplStatus.Status -eq "OK") {
            Write-MonitorLog "AD Replication: OK" "INFO"
        }
        else {
            Write-MonitorLog "AD Replication: $($ReplStatus.Message)" "WARNING"
        }

        # Connectivity
        if ($Script:ConnectivityConfig -and $Script:ConnectivityConfig.CheckEnabled) {
            $connectivity = Get-ConnectivityStatus
            if ($connectivity.Status -eq "CRITICAL") {
                Write-MonitorLog "Network connectivity CRITICAL: Gateway unreachable ($($connectivity.Gateway))" "CRITICAL"
            }
            elseif ($connectivity.Status -eq "WARNING") {
                Write-MonitorLog "Internet connectivity WARNING: some external targets unreachable" "WARNING"
            }
            elseif ($connectivity.Status -eq "OK") {
                Write-MonitorLog "Connectivity OK (Gateway: $($connectivity.Gateway))" "INFO"
            }
        }

        # DCDIAG
        if ($Script:ADConfig -and $Script:ADConfig.RunDcDiag) {
            $every = if ($Script:ADConfig.DcDiagEveryCycles) { [int]$Script:ADConfig.DcDiagEveryCycles } else { 12 }
            if ($Script:CycleCount % $every -eq 0) {
                $dcdiag = Check-DcDiag -ServerName $Script:ServerName
                if ($dcdiag.Status -eq "Warning") {
                    Write-MonitorLog "DCDIAG detected AD issues: $($dcdiag.Message)" "CRITICAL"
                    if ($dcdiag.RawOutput) {
                        $lines = $dcdiag.RawOutput -split "`r?`n"
                        $preview = ($lines | Where-Object { $_ } | Select-Object -First 5)
                        foreach ($line in $preview) {
                            $short = $line
                            if ($short.Length -gt 120) {
                                $short = $short.Substring(0,120) + "..."
                            }
                            Write-MonitorLog "  +-- $short" "WARNING"
                        }
                    }
                }
                elseif ($dcdiag.Status -eq "OK") {
                    Write-MonitorLog "DCDIAG: OK" "INFO"
                }
                else {
                    Write-MonitorLog "DCDIAG: Unknown - $($dcdiag.Message)" "WARNING"
                }
            }
        }

        # Critical Security Events
        Check-CriticalSecurityEvents

        # EventLog Errors
        $minutesBack = [int][Math]::Ceiling($IntervalSeconds / 60.0) + 1
        $RecentErrors = Check-EventLogErrors -MinutesBack $minutesBack
        if ($RecentErrors -and $RecentErrors.Count -gt 0) {
            Write-MonitorLog "Found $($RecentErrors.Count) new System/Application errors in Event Logs" "WARNING"
            foreach ($Error in ($RecentErrors | Select-Object -First 3)) {
                $ErrorMsg = $Error.Message
                if ($ErrorMsg.Length -gt 100) {
                    $ErrorMsg = $ErrorMsg.Substring(0, 100) + "..."
                }
                Write-MonitorLog "  +-- Event ID $($Error.Id) [$($Error.ProviderName)]: $ErrorMsg" "WARNING"
            }
        }

        # Summary
        $RunningServices = ($Health.Services | Where-Object { $_.IsRunning }).Count
        $TotalServices   = $Health.Services.Count
        $NetMB           = if ($Health.Network) { $Health.Network.MBPerSec } else { 0 }

        Write-MonitorLog "Status Summary - CPU: $($Health.CPU)%, Memory: $($Health.Memory.UsedPercent)%, Services: $RunningServices/$TotalServices running, Network: $NetMB MB/s" "SUCCESS"

        # Save health
        Save-HealthData -Health $Health
    }
    catch {
        Write-MonitorLog "Error in monitoring cycle: $($_.Exception.Message)" "ERROR"
        Write-MonitorLog "Stack Trace: $($_.ScriptStackTrace)" "ERROR"
    }

    Write-MonitorLog "Waiting $IntervalSeconds seconds until next check..." "INFO"
    Start-Sleep -Seconds $IntervalSeconds
}
#endregion


