# Install trapsnmp so Windows starts it at boot. Run from an elevated prompt.
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$bat = Join-Path $here "start-trapsnmp.bat"

$python = $null
$py = Get-Command py -ErrorAction SilentlyContinue
if ($py) {
    $python = (& py -3 -c "import sys; print(sys.executable)").Trim()
}
if (-not $python) {
    $found = Get-Command python -ErrorAction SilentlyContinue
    if ($found) { $python = $found.Source }
}
if (-not $python -or -not (Test-Path -LiteralPath $python)) {
    throw "Python 3.10+ was not found. Install it, then run this again from that account."
}

Set-Content -LiteralPath (Join-Path $here "python.path") -Value $python -Encoding ascii
New-Item -ItemType Directory -Force -Path (Join-Path $root "data") | Out-Null

$action = New-ScheduledTaskAction -Execute $bat -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtStartup
$trigger.Delay = "PT30S"
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "trapsnmp" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName "trapsnmp"
Write-Host "trapsnmp is registered and started."
Write-Host "Python: $python"
Write-Host "Console: https://127.0.0.1:8888/"
Write-Host "Log: $root\data\trapsnmp.log"
