<#
.SYNOPSIS
    一键设置 / 清除 Windows 系统手动代理为本地 HTTP 代理。

.DESCRIPTION
    等价于「设置 → 网络和 Internet → 代理 → 手动设置代理」。
    只改当前用户的 Internet Settings，不写注册表全局策略。

.PARAMETER Address
    代理地址，默认 127.0.0.1

.PARAMETER Port
    代理端口，默认 8080

.PARAMETER Bypass
    绕过代理的地址列表，默认绕过本机回环

.PARAMETER Clear
    清除代理设置（关闭手动代理）

.EXAMPLE
    .\windows-set-system-proxy.ps1

.EXAMPLE
    .\windows-set-system-proxy.ps1 -Clear
#>

[CmdletBinding()]
param(
    [string]$Address = '127.0.0.1',
    [int]$Port = 8080,
    [string]$Bypass = '<local>;localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2?.*;172.30.*;172.31.*;192.168.*',
    [switch]$Clear
)

$ErrorActionPreference = 'Stop'

$regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

if ($Clear) {
    Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 0
    Remove-ItemProperty -Path $regPath -Name ProxyServer -ErrorAction SilentlyContinue
    Write-Host '[done] 已关闭系统手动代理。' -ForegroundColor Green
} else {
    Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 1
    Set-ItemProperty -Path $regPath -Name ProxyServer -Value "$Address`:$Port"
    Set-ItemProperty -Path $regPath -Name ProxyOverride -Value $Bypass
    Write-Host "[done] 系统手动代理已设为 http://$Address`:$Port" -ForegroundColor Green
}

# 通知 WinINET / WinHTTP 立即刷新（部分应用不刷新会沿用旧设置）
$signature = @'
[DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
try {
    $wininet = Add-Type -MemberDefinition $signature -Name WinINet -Namespace PInvoke -PassThru
    # 39 = INTERNET_OPTION_SETTINGS_CHANGED, 37 = INTERNET_OPTION_REFRESH
    $wininet::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
    $wininet::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
    Write-Host '[done] 已通知系统刷新代理设置。' -ForegroundColor Green
} catch {
    Write-Host '[warn] 自动刷新失败，可能需要重启浏览器或应用才能生效。' -ForegroundColor Yellow
}
