#Requires -Version 5.1
param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$dist = Join-Path $root "dist\windows"
$work = Join-Path $root "build\pyinstaller"
$exe = Join-Path $dist "GreyLog-windows-x64.exe"
$zip = Join-Path $dist "GreyLog-windows-x64-installable.zip"

New-Item -ItemType Directory -Path $dist -Force | Out-Null
New-Item -ItemType Directory -Path $work -Force | Out-Null

& $Python -m PyInstaller --noconfirm --clean --onefile --console `
    --name GreyLog-windows-x64 `
    --paths $root `
    --add-data "$(Join-Path $root 'greylog\web');greylog\web" `
    --distpath $dist --workpath $work --specpath $work `
    (Join-Path $PSScriptRoot "portable.py")
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed with exit code $LASTEXITCODE"
}

$projectFile = Join-Path $root "pyproject.toml"
$version = (& $Python -c 'import pathlib,sys,tomllib; p=pathlib.Path(sys.argv[1]); print(tomllib.loads(p.read_text(encoding="utf-8"))["project"]["version"])' $projectFile).Trim()
if ($LASTEXITCODE -ne 0 -or -not $version) {
    throw "Could not read version from pyproject.toml"
}
$versionFile = Join-Path $dist "VERSION"
[System.IO.File]::WriteAllText($versionFile, "$version`n", [System.Text.Encoding]::ASCII)

$bundleFiles = @(
    $exe,
    $versionFile,
    (Join-Path $PSScriptRoot "Install-GreyLog.cmd"),
    (Join-Path $PSScriptRoot "Install-GreyLog.ps1"),
    (Join-Path $PSScriptRoot "Uninstall-GreyLog.ps1")
)
Compress-Archive -LiteralPath $bundleFiles -DestinationPath $zip -Force
Write-Host "Portable EXE: $exe"
Write-Host "Installable bundle: $zip"
