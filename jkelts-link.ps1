<#
JKELTS LINK DISCOVERY

Windows LLDP/CDP helper. Uses TShark when available because Windows PowerShell
cannot capture and decode Layer 2 LLDP/CDP frames by itself.
#>

[CmdletBinding()]
param(
    [int]$Duration = 60
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
$Script:TitleWidth = 68

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-Administrator {
    if (Test-IsAdministrator) { return }
    if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { return }

    $scriptPath = if ($PSCommandPath) { $PSCommandPath } elseif ($MyInvocation.MyCommand.Path) { $MyInvocation.MyCommand.Path } else { $null }
    if (-not $scriptPath) {
        Write-Host 'Administrator rights are required, but the script path could not be detected.' -ForegroundColor Red
        exit 1
    }

    $argsList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$scriptPath`"", '-Duration', $Duration)
    Write-Host 'Requesting Administrator rights for link discovery...' -ForegroundColor Cyan
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList ($argsList -join ' ')
    exit
}

function Write-ColorLine {
    param([string]$Text = '', [string]$Color = 'Gray')
    Write-Host $Text -ForegroundColor $Color
}

function Format-CenteredTitle {
    param([string]$Title)
    if ($Title.Length -ge $Script:TitleWidth) { return $Title }
    $left = [math]::Floor(($Script:TitleWidth - $Title.Length) / 2)
    (' ' * $left) + $Title
}

function Write-Title {
    param([string]$Title)
    Write-ColorLine ('=' * $Script:TitleWidth) Cyan
    Write-ColorLine (Format-CenteredTitle $Title) Cyan
    Write-ColorLine ('=' * $Script:TitleWidth) Cyan
}

function Find-TShark {
    $cmd = Get-Command tshark.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $paths = @(
        "$env:ProgramFiles\Wireshark\tshark.exe",
        "${env:ProgramFiles(x86)}\Wireshark\tshark.exe"
    )
    foreach ($path in $paths) {
        if ($path -and (Test-Path -LiteralPath $path)) { return $path }
    }
    return $null
}

function Get-Adapters {
    try {
        @(Get-NetAdapter -ErrorAction Stop | Sort-Object -Property Status, Name)
    } catch {
        @()
    }
}

function Show-Adapters {
    Write-Title 'LOCAL NETWORK ADAPTERS'
    $adapters = Get-Adapters
    if (-not $adapters -or $adapters.Count -eq 0) {
        Write-ColorLine 'No adapters were found through Get-NetAdapter.' Yellow
        return
    }

    $index = 1
    foreach ($adapter in $adapters) {
        Write-Host ("{0}. {1}" -f $index, $adapter.Name) -ForegroundColor White
        Write-Host ("   Status       : {0}" -f $adapter.Status)
        Write-Host ("   Interface    : {0}" -f $adapter.InterfaceDescription)
        Write-Host ("   MAC Address  : {0}" -f $adapter.MacAddress)
        Write-Host ("   Link Speed   : {0}" -f $adapter.LinkSpeed)
        $index++
    }
}

function Get-TSharkInterfaces {
    param([string]$TShark)
    $raw = & $TShark -D 2>$null
    @($raw | ForEach-Object {
        if ($_ -match '^(\d+)\.\s+(.+)$') {
            [pscustomobject]@{
                Number = [int]$matches[1]
                Name = $matches[2]
                Raw = $_
            }
        }
    })
}

function Show-TSharkInterfaces {
    param([array]$Interfaces)
    Write-Title 'TSHARK CAPTURE INTERFACES'
    foreach ($item in $Interfaces) {
        Write-Host $item.Raw
    }
}

function ConvertTo-LinkRows {
    param([string[]]$Lines)
    $rows = @()
    foreach ($line in $Lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $cols = $line -split "`t", -1
        while ($cols.Count -lt 11) { $cols += '' }

        $protocol = $cols[1]
        $device = if ($cols[5]) { $cols[5] } elseif ($cols[7]) { $cols[7] } else { 'Unknown' }
        $port = if ($cols[3]) { $cols[3] } elseif ($cols[8]) { $cols[8] } else { 'Unknown' }
        $portDesc = if ($cols[4]) { $cols[4] } else { 'Unavailable' }
        $platform = if ($cols[9]) { $cols[9] } elseif ($cols[6]) { $cols[6] } else { 'Unavailable' }
        $vlan = if ($cols[10]) { $cols[10] } else { 'Unavailable' }

        $rows += [pscustomobject]@{
            Time = $cols[0]
            Protocol = $protocol
            Device = $device
            Port = $port
            PortDescription = $portDesc
            Platform = $platform
            Vlan = $vlan
        }
    }
    $rows
}

function Capture-LinkData {
    param([string]$TShark, [int]$InterfaceNumber)

    Write-Title 'LISTENING FOR LLDP / CDP'
    Write-ColorLine ("Listening for up to {0} seconds. Switches usually advertise every 30-60 seconds." -f $Duration) Yellow
    Write-ColorLine 'A valid IP address is not required, but LLDP/CDP must be enabled on the switch port.' Gray
    Write-ColorLine ''

    $args = @(
        '-i', $InterfaceNumber,
        '-a', "duration:$Duration",
        '-Y', 'lldp or cdp',
        '-T', 'fields',
        '-E', "separator=`t",
        '-e', 'frame.time',
        '-e', '_ws.col.Protocol',
        '-e', 'lldp.chassis.id',
        '-e', 'lldp.port.id',
        '-e', 'lldp.port.desc',
        '-e', 'lldp.system.name',
        '-e', 'lldp.system.desc',
        '-e', 'cdp.deviceid',
        '-e', 'cdp.portid',
        '-e', 'cdp.platform',
        '-e', 'cdp.native_vlan'
    )

    $output = & $TShark @args 2>$null
    $rows = @(ConvertTo-LinkRows $output)

    Write-Title 'LINK DISCOVERY RESULT'
    if ($rows.Count -eq 0) {
        Write-ColorLine 'No LLDP/CDP advertisement was received.' Yellow
        Write-ColorLine ''
        Write-ColorLine 'Possible reasons:' Gray
        Write-ColorLine '- Wrong adapter selected' Gray
        Write-ColorLine '- LLDP/CDP is disabled on the switch port' Gray
        Write-ColorLine '- Connected through Wi-Fi, dock, unmanaged switch, or adapter that does not pass discovery frames' Gray
        Write-ColorLine '- Npcap capture driver is missing or not working' Gray
        return
    }

    foreach ($row in $rows | Select-Object -First 5) {
        Write-Host ("Protocol          : {0}" -f $row.Protocol)
        Write-Host ("Switch / Device   : {0}" -f $row.Device)
        Write-Host ("Port ID           : {0}" -f $row.Port)
        Write-Host ("Port Description  : {0}" -f $row.PortDescription)
        Write-Host ("Platform / Desc   : {0}" -f $row.Platform)
        Write-Host ("Native VLAN       : {0}" -f $row.Vlan)
        Write-Host ("Frame Time        : {0}" -f $row.Time)
        Write-ColorLine ('-' * $Script:TitleWidth) DarkGray
    }

    $save = Read-Host 'Save result to a text file? Type YES to save'
    if ($save -eq 'YES') {
        $path = Join-Path $env:USERPROFILE ("Desktop\jkelts-link-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        $rows | Format-List | Out-File -LiteralPath $path -Encoding UTF8
        Write-ColorLine ("Saved: {0}" -f $path) Green
    }
}

function Show-Requirements {
    Write-Title 'REQUIREMENTS'
    Write-ColorLine 'To capture LLDP/CDP, install Wireshark with TShark and Npcap.' Yellow
    Write-ColorLine ''
    Write-Host 'Recommended install:'
    Write-Host 'https://www.wireshark.org/download.html'
    Write-ColorLine ''
    Write-Host 'During install, keep Npcap selected.'
    Write-Host 'Then rerun this command:'
    Write-ColorLine 'irm https://jkasalavia.github.io/jlink/r|iex' Cyan
}

Request-Administrator
Clear-Host
Write-Title 'JKELTS LINK DISCOVERY'
Write-Host ("Computer      : {0}" -f $env:COMPUTERNAME)
Write-Host ("Administrator : {0}" -f ($(if (Test-IsAdministrator) { 'YES' } else { 'NO' })))
Write-ColorLine ''

Show-Adapters
Write-ColorLine ''

$tshark = Find-TShark
if (-not $tshark) {
    Show-Requirements
    return
}

Write-Title 'CAPTURE ENGINE'
Write-Host ("TShark found : {0}" -f $tshark)
Write-ColorLine ''

$interfaces = @(Get-TSharkInterfaces $tshark)
if ($interfaces.Count -eq 0) {
    Write-ColorLine 'TShark did not return any capture interfaces. Check Npcap installation.' Yellow
    return
}

Show-TSharkInterfaces $interfaces
Write-ColorLine ''
$choice = Read-Host 'Enter TShark interface number to listen on'
if (-not ($choice -as [int])) {
    Write-ColorLine 'Invalid interface number.' Red
    return
}

Capture-LinkData -TShark $tshark -InterfaceNumber ([int]$choice)
