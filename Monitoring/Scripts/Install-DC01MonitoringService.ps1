<#
.SYNOPSIS
    Cai dat Windows Service cho DC01 Monitoring su dung NSSM
#>

[CmdletBinding()]
param(
    [string]$ServiceName = "DC01-Monitoring-Service",
    [string]$NssmPath = "C:\Monitoring\Tools\nssm.exe",
    [string]$ScriptPath = "C:\Monitoring\Scripts\Server\Monitor-DC01-Service.ps1",
    [int]$IntervalSeconds = 300
)

if (-not (Test-Path $NssmPath)) {
    Write-Error "Khong tim thay NSSM tai $NssmPath"
    exit 1
}

if (-not (Test-Path $ScriptPath)) {
    Write-Error "Khong tim thay script monitor tai $ScriptPath"
    exit 1
}

$psExe = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
$arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -IntervalSeconds $IntervalSeconds"

Write-Host "Dang cai service $ServiceName..." -ForegroundColor Cyan

& $NssmPath install $ServiceName $psExe $arguments

& $NssmPath set $ServiceName AppDirectory (Split-Path $ScriptPath -Parent)
& $NssmPath set $ServiceName Start SERVICE_AUTO_START
& $NssmPath set $ServiceName AppStdout "C:\Monitoring\Logs\Service-$ServiceName-stdout.log"
& $NssmPath set $ServiceName AppStderr "C:\Monitoring\Logs\Service-$ServiceName-stderr.log"
& $NssmPath set $ServiceName AppRotateFiles 1

Write-Host "Da cai service $ServiceName." -ForegroundColor Green
Write-Host "Mo services.msc de cai dat account chay service (nen dung account domain co quyen AD/DHCP)." -ForegroundColor Yellow
Write-Host "Sau do start service: net start $ServiceName" -ForegroundColor Yellow
