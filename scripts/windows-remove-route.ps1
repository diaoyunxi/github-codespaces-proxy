<#
.SYNOPSIS
    删除由 windows-add-route.ps1 添加的代理服务器静态路由。

.EXAMPLE
    .\windows-remove-route.ps1 -ServerIp 203.0.113.10
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerIp
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '请以管理员身份运行本脚本。'
}

Write-Host "[action] 删除 $ServerIp/32 的持久化路由 ..." -ForegroundColor Yellow
Remove-NetRoute -DestinationPrefix "$ServerIp/32" -Confirm:$false -ErrorAction SilentlyContinue
Write-Host '[done] 已清理。' -ForegroundColor Green
