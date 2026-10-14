#Requires -Version 5.1
param(
    [switch]$DesktopShortcut,
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "Programs\GreyLog"),
    [string]$DataRoot = (Join-Path $env:LOCALAPPDATA "GreyLog"),
    [string]$Gateway = "auto",
    [string]$GatewayInterface = "",
    [ValidateRange(0, 3600)][int]$GatewayPingInterval = 0,
    [ValidateRange(0, 65535)][int]$SyslogPort = 0,
    [string]$SyslogBind = "0.0.0.0",
    [switch]$NoRegistration
)

$ErrorActionPreference = "Stop"
$sourceExe = Join-Path $PSScriptRoot "GreyLog-windows-x64.exe"
$versionFile = Join-Path $PSScriptRoot "VERSION"
if (-not (Test-Path -LiteralPath $sourceExe -PathType Leaf)) {
    throw "GreyLog-windows-x64.exe must be beside the installer. Extract the entire installable ZIP first."
}
if (-not (Test-Path -LiteralPath $versionFile -PathType Leaf)) {
    throw "VERSION must be beside the installer. Extract the entire installable ZIP first."
}
$version = (Get-Content -LiteralPath $versionFile -Raw).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+$') {
    throw "Invalid GreyLog version in VERSION"
}
$gatewayIp = $null
if ($Gateway -ne "auto" -and -not [System.Net.IPAddress]::TryParse($Gateway, [ref]$gatewayIp)) {
    throw "Gateway must be auto or an IP address"
}
if ($GatewayInterface -and $Gateway -eq "auto") {
    throw "GatewayInterface requires an explicit Gateway IP"
}
if ($GatewayInterface.Contains('"')) {
    throw "GatewayInterface cannot contain a quote"
}
if ($GatewayPingInterval -gt 0 -and $GatewayPingInterval -lt 30) {
    throw "GatewayPingInterval must be 30 to 3600 seconds or 0 (off)"
}
$parsedIp = $null
if (-not [System.Net.IPAddress]::TryParse($SyslogBind, [ref]$parsedIp) -or
    $parsedIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw "SyslogBind must be an IPv4 address"
}
if ($SyslogPort -gt 0 -and $Gateway -ne "auto" -and
    $gatewayIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw "UDP syslog requires an IPv4 gateway"
}

$installDir = [System.IO.Path]::GetFullPath($InstallRoot)
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
$dataDir = [System.IO.Path]::GetFullPath($DataRoot)
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
$database = Join-Path $dataDir "greylog.db"
$installedExe = Join-Path $installDir "GreyLog.exe"
Copy-Item -LiteralPath $sourceExe -Destination $installedExe -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "Uninstall-GreyLog.ps1") `
    -Destination (Join-Path $installDir "Uninstall-GreyLog.ps1") -Force

if (-not $NoRegistration) {
    $programs = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
    New-Item -ItemType Directory -Path $programs -Force | Out-Null
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut((Join-Path $programs "GreyLog.lnk"))
    $shortcut.TargetPath = $installedExe
    $shortcut.WorkingDirectory = $installDir
    $shortcut.Arguments = "serve --db `"$database`""
    if ($Gateway -ne "auto") {
        $shortcut.Arguments += " --gateway $Gateway"
        if ($GatewayInterface) {
            $shortcut.Arguments += " --gateway-interface `"$GatewayInterface`""
        }
    }
    if ($SyslogPort -gt 0) {
        $shortcut.Arguments += " --syslog-port $SyslogPort --syslog-bind $SyslogBind"
    }
    if ($GatewayPingInterval -gt 0) {
        $shortcut.Arguments += " --gateway-ping-interval $GatewayPingInterval"
    }
    $shortcut.Description = "Start GreyLog dashboard and local gateway route monitor"
    $shortcut.Save()
    $desktop = [Environment]::GetFolderPath("Desktop")
    $desktopPath = Join-Path $desktop "GreyLog.lnk"
    $ownedDesktopShortcut = (Test-Path -LiteralPath $desktopPath -PathType Leaf) -and
        $shell.CreateShortcut($desktopPath).TargetPath -eq $installedExe
    if ($DesktopShortcut -or $ownedDesktopShortcut) {
        if ((Test-Path -LiteralPath $desktopPath -PathType Leaf) -and -not $ownedDesktopShortcut) {
            throw "A different GreyLog desktop shortcut already exists: $desktopPath"
        }
        $desktopShortcut = $shell.CreateShortcut($desktopPath)
        $desktopShortcut.TargetPath = $installedExe
        $desktopShortcut.WorkingDirectory = $installDir
        $desktopShortcut.Arguments = $shortcut.Arguments
        $desktopShortcut.Description = $shortcut.Description
        $desktopShortcut.Save()
    }
    $uninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\GreyLog"
    New-Item -Path $uninstallKey -Force | Out-Null
    $uninstallCommand = '"{0}" -NoProfile -ExecutionPolicy Bypass -File "{1}" -InstallRoot "{2}"' -f `
        (Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"), `
        (Join-Path $installDir "Uninstall-GreyLog.ps1"), $installDir
    New-ItemProperty -Path $uninstallKey -Name DisplayName -Value "GreyLog" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name DisplayVersion -Value $version -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name Publisher -Value "GreyNOC" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name InstallLocation -Value $installDir -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name UninstallString -Value $uninstallCommand -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name NoModify -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name NoRepair -Value 1 -PropertyType DWord -Force | Out-Null
}

Write-Host "GreyLog $version installed at $installedExe"
if (-not $NoRegistration) {
    Write-Host "Open GreyLog from Start to launch the dashboard."
}
if ($SyslogPort -gt 0) {
    Write-Host "UDP syslog configured on ${SyslogBind}:$SyslogPort; configure your router to forward logs to this PC."
} else {
    Write-Host "UDP syslog is off. To receive router logs, reinstall with -SyslogPort PORT."
}
if ($GatewayPingInterval -gt 0) {
    Write-Host "Gateway ICMP availability check configured every $GatewayPingInterval seconds."
}
Write-Host "CLI: & `"$installedExe`" --help"
