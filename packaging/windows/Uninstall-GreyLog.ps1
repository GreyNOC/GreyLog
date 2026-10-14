#Requires -Version 5.1
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "Programs\GreyLog"),
    [switch]$NoRegistration
)

$ErrorActionPreference = "Stop"
$installDir = [System.IO.Path]::GetFullPath($InstallRoot)
foreach ($name in @("GreyLog.exe", "Uninstall-GreyLog.ps1")) {
    $path = Join-Path $installDir $name
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        for ($attempt = 0; $attempt -lt 20; $attempt++) {
            try {
                Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                break
            } catch {
                if ($attempt -eq 19) {
                    throw "Could not remove $path. Close GreyLog and run the uninstaller again. $($_.Exception.Message)"
                }
                Start-Sleep -Milliseconds 250
            }
        }
    }
}
if (Test-Path -LiteralPath $installDir -PathType Container) {
    # Remove only an empty install directory; never remove the database or user files.
    Remove-Item -LiteralPath $installDir -ErrorAction SilentlyContinue
}

if (-not $NoRegistration) {
    $uninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\GreyLog"
    if (Test-Path -LiteralPath $uninstallKey) {
        $registered = (Get-ItemProperty -LiteralPath $uninstallKey).InstallLocation
        if ($registered -eq $installDir) {
            Remove-Item -LiteralPath $uninstallKey
        }
    }
    $startShortcut = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\GreyLog.lnk"
    $shell = New-Object -ComObject WScript.Shell
    if ((Test-Path -LiteralPath $startShortcut -PathType Leaf) -and
        $shell.CreateShortcut($startShortcut).TargetPath -eq (Join-Path $installDir "GreyLog.exe")) {
        Remove-Item -LiteralPath $startShortcut -Force
    }
    $desktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "GreyLog.lnk"
    if (Test-Path -LiteralPath $desktopShortcut -PathType Leaf) {
        if ($shell.CreateShortcut($desktopShortcut).TargetPath -eq (Join-Path $installDir "GreyLog.exe")) {
            Remove-Item -LiteralPath $desktopShortcut -Force
        }
    }
}

Write-Host "GreyLog uninstalled. User data was not removed."
