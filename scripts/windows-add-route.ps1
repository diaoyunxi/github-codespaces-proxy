<#
.SYNOPSIS
    为代理服务器公网 IP 添加永久静态路由，使其走物理网卡网关，
    从而绕过系统 VPN 的 TUN 网卡。

.DESCRIPTION
    方案固定项：客户端访问代理服务器的流量必须走物理网卡出站。
    本脚本不创建虚拟网卡、不装驱动、不接管全局路由，只添加一条 /32 主机路由。

    原理：
      - 找到物理网卡的默认网关（排除 VPN 虚拟网卡）
      - 为代理服务器 IP 添加 /32 路由，指向该物理网关
      - 用 -p 参数持久化，重启后依然生效
      - 用较低 metric 保证优先级高于 VPN 的路由

.PARAMETER ServerIp
    代理服务器的公网 IPv4 地址，例如 203.0.113.10

.PARAMETER PhysicalInterfaceIndex
    物理网卡接口索引。不指定时脚本自动推断（取默认路由中 metric 最小的非虚拟网卡）。

.PARAMETER Remove
    删除已添加的路由，而不是添加。

.EXAMPLE
    # 需要管理员权限
    .\windows-add-route.ps1 -ServerIp 203.0.113.10

.EXAMPLE
    # 删除
    .\windows-add-route.ps1 -ServerIp 203.0.113.10 -Remove

.NOTES
    必须以管理员身份运行 PowerShell。
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')]
    [string]$ServerIp,

    [int]$PhysicalInterfaceIndex = 0,

    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '请以管理员身份运行本脚本（右键 → 以管理员身份运行 PowerShell）。'
    }
}

# 虚拟网卡（VPN / TUN / 隧道）名称特征，用于排除
$VirtualAdapterPattern = 'TAP|TUN|VPN|WireGuard|OpenVPN|Tailscale|ZeroTier|Wintun|Clash|Mihomo|utun|虚拟|隧道'

function Get-PhysicalInterfaceIndex {
    # 取默认路由中 metric 最小的、非虚拟网卡的接口
    $candidates = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -ne '0.0.0.0' } |
        Sort-Object RouteMetric, ifIndex

    foreach ($route in $candidates) {
        $adapter = Get-NetAdapter -InterfaceIndex $route.ifIndex -ErrorAction SilentlyContinue
        if ($null -eq $adapter) { continue }
        if ($adapter.Status -ne 'Up') { continue }
        if ($adapter.InterfaceDescription -match $VirtualAdapterPattern) { continue }
        if ($adapter.Name -match $VirtualAdapterPattern) { continue }
        return $route.ifIndex
    }
    throw '未能自动识别物理网卡，请用 -PhysicalInterfaceIndex 手动指定（Get-NetAdapter 可查看）。'
}

function Get-PhysicalGateway([int]$IfIndex) {
    $route = Get-NetRoute -InterfaceIndex $IfIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -ne '0.0.0.0' } |
        Sort-Object RouteMetric |
        Select-Object -First 1
    if (-not $route) {
        throw "接口 $IfIndex 上没有找到默认网关。"
    }
    return $route.NextHop
}

Assert-Administrator

if ($PhysicalInterfaceIndex -le 0) {
    $PhysicalInterfaceIndex = Get-PhysicalInterfaceIndex
    Write-Host "[info] 自动识别物理网卡接口索引: $PhysicalInterfaceIndex" -ForegroundColor Cyan
}

$adapter = Get-NetAdapter -InterfaceIndex $PhysicalInterfaceIndex -ErrorAction Stop
Write-Host "[info] 物理网卡: $($adapter.Name) ($($adapter.InterfaceDescription))" -ForegroundColor Cyan

if ($Remove) {
    Write-Host "[action] 删除路由 $ServerIp/32 ..." -ForegroundColor Yellow
    Remove-NetRoute -DestinationPrefix "$ServerIp/32" -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "[done] 已删除（若原本不存在则忽略）。" -ForegroundColor Green
    exit 0
}

$gateway = Get-PhysicalGateway -IfIndex $PhysicalInterfaceIndex
Write-Host "[info] 物理网关: $gateway" -ForegroundColor Cyan

# 先清理同名旧路由，避免重复堆积
Remove-NetRoute -DestinationPrefix "$ServerIp/32" -Confirm:$false -ErrorAction SilentlyContinue

# -p 持久化；metric 设为 1，保证优先于 VPN 下发的路由
New-NetRoute `
    -DestinationPrefix "$ServerIp/32" `
    -InterfaceIndex $PhysicalInterfaceIndex `
    -NextHop $gateway `
    -RouteMetric 1 `
    -PolicyStore PersistentStore | Out-Null

Write-Host "[done] 已添加永久静态路由：$ServerIp/32 -> $gateway (ifIndex=$PhysicalInterfaceIndex)" -ForegroundColor Green
Write-Host '[verify] 用以下命令确认:' -ForegroundColor Cyan
Write-Host "         Get-NetRoute -DestinationPrefix '$ServerIp/32'" -ForegroundColor Gray
Write-Host "         Find-NetRoute -RemoteIPAddress $ServerIp | Select-Object -First 1 IPAddress, InterfaceAlias" -ForegroundColor Gray
