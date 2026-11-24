# Register trapsnmp as a Windows service. Run elevated.
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here

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
    throw "Python 3.10+ was not found. Install it, then run this again."
}

Set-Content -LiteralPath (Join-Path $here "python.path") -Value $python -Encoding ascii
New-Item -ItemType Directory -Force -Path (Join-Path $root "data") | Out-Null

& $python -m pip install pywin32
& $python -m pywin32_postinstall -install

$task = Get-ScheduledTask -TaskName "trapsnmp" -ErrorAction SilentlyContinue
if ($task) {
    Unregister-ScheduledTask -TaskName "trapsnmp" -Confirm:$false
    Write-Host "Removed the trapsnmp startup task so it does not run twice."
}

$script = Join-Path $here "trapsnmp_service.py"
$previous = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $python $script stop
& $python $script remove
$ErrorActionPreference = $previous
& $python $script --startup auto install
& sc.exe description trapsnmp "Receives SNMP traps and publishes them on OPC UA." | Out-Null
& sc.exe failure trapsnmp reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
& $python $script start

Write-Host "trapsnmp service is installed and started."
Write-Host "Python: $python"
Write-Host "Console: https://127.0.0.1:8888/"
Write-Host "Log: $root\data\trapsnmp.log"
Write-Host "services.msc shows it as trapsnmp. It starts at boot as Local System."
