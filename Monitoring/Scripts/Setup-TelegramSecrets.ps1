<#
.SYNOPSIS
    Setup SecureString secrets cho Telegram Bot (Token và ChatId)
.DESCRIPTION
    Chạy script này bằng đúng account sẽ chạy Windows Service
#>

[CmdletBinding()]
param(
    [string]$SecureFolder = "C:\Monitoring\Secure"
)

if (-not (Test-Path $SecureFolder)) {
    New-Item -Path $SecureFolder -ItemType Directory -Force | Out-Null
}

Write-Host "Nhap Telegram Bot Token (vi du: 1234567890:ABC...):" -ForegroundColor Cyan
$tokenSecure = Read-Host "Bot Token" -AsSecureString
$tokenSecure | ConvertFrom-SecureString | Set-Content (Join-Path $SecureFolder "telegram-bot-token.txt")

Write-Host "Nhap Telegram Chat ID (vi du: 123456789):" -ForegroundColor Cyan
$chatSecure = Read-Host "Chat ID" -AsSecureString
$chatSecure | ConvertFrom-SecureString | Set-Content (Join-Path $SecureFolder "telegram-chatid.txt")

Write-Host "Da luu secrets Telegram tai $SecureFolder" -ForegroundColor Green
