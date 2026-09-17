# Build FailKeep installer with Inno Setup
# Requires: cargo release build; ISCC.exe in PATH or $env:INNO_ISCC
# Optional UI: publish WinUI to ui\FailKeep.Ui\publish first

param(
    [string]$Version = "0.2.0",
    [switch]$SkipRust,
    [switch]$SkipUi
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not $SkipRust) {
    Write-Host "==> cargo build --release"
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
}

if (-not $SkipUi) {
    $uiProj = Join-Path $root "ui\FailKeep.Ui\FailKeep.Ui.csproj"
    if (Test-Path $uiProj) {
        Write-Host "==> publish WinUI (optional)"
        Push-Location (Join-Path $root "ui\FailKeep.Ui")
        try {
            dotnet publish -c Release -r win-x64 --self-contained false -o publish
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "UI publish failed; installer will skip UI files"
            }
        } finally {
            Pop-Location
        }
    }
}

$iscc = $env:INNO_ISCC
if (-not $iscc) {
    $candidates = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "ISCC.exe"
    )
    foreach ($c in $candidates) {
        if (Get-Command $c -ErrorAction SilentlyContinue) { $iscc = $c; break }
        if (Test-Path $c) { $iscc = $c; break }
    }
}
if (-not $iscc) {
    throw "ISCC.exe not found. Install Inno Setup 6 or set INNO_ISCC."
}

New-Item -ItemType Directory -Force -Path (Join-Path $root "dist") | Out-Null
$iss = Join-Path $root "installer\failkeep.iss"
Write-Host "==> $iscc $iss"
& $iscc "/DMyAppVersion=$Version" $iss
if ($LASTEXITCODE -ne 0) { throw "ISCC failed" }

Write-Host "OK: dist\FailKeep-setup-$Version.exe"
