# Self-elevate to Administrator if necessary.
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdmin) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$provisioner = Join-Path $scriptDir "ms_provisioner.exe"

if (-not (Test-Path $provisioner)) {
    Write-Error "ms_provisioner.exe not found."
    exit 1
}

Write-Host "Installing DecayFmt TPM provisioner service..."
& $provisioner --install

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install DecayFmt TPM provisioner service."
    exit 1
}

Write-Host "Starting DecayFmt TPM provisioner service..."
Start-Service -Name "DecayFmtProvisioner"

Write-Host ""
Write-Host "DecayFmt TPM provisioner installed and running."