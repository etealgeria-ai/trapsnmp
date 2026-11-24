# Register the Windows service named trapsnmp. Run elevated.
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
New-Item -ItemType Directory -Force -Path (Join-Path $root "data") | Out-Null
$log = Join-Path $root "data\service-install.log"

function Write-InstallLog([string]$Message) {
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -LiteralPath $log -Value $line
    Write-Host $line
}

try {
    $python = $null
    $pathFile = Join-Path $here "python.path"
    if (Test-Path -LiteralPath $pathFile) {
        $python = (Get-Content -LiteralPath $pathFile -Raw).Trim()
    }
    if (-not $python -or -not (Test-Path -LiteralPath $python)) {
        $py = Get-Command py -ErrorAction SilentlyContinue
        if ($py) {
            $python = (& py -3 -c "import sys; print(sys.executable)").Trim()
        }
    }
    if (-not $python -or -not (Test-Path -LiteralPath $python)) {
        $found = Get-Command python -ErrorAction SilentlyContinue
        if ($found) { $python = $found.Source }
    }
    if (-not $python -or -not (Test-Path -LiteralPath $python)) {
        throw "Python 3.10+ was not found. The service was not created."
    }
    Set-Content -LiteralPath $pathFile -Value $python -Encoding ascii
    Write-InstallLog "Using $python"

    & $python -m pip install pywin32
    & $python -m pywin32_postinstall -install

    $task = Get-ScheduledTask -TaskName "trapsnmp" -ErrorAction SilentlyContinue
    if ($task) {
        Unregister-ScheduledTask -TaskName "trapsnmp" -Confirm:$false
        Write-InstallLog "Removed the trapsnmp startup task so it does not run twice."
    }

    $script = Join-Path $here "trapsnmp_service.py"
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $python $script stop
    & $python $script remove
    $ErrorActionPreference = $previous
    & $python $script --startup auto install
    if (-not (Get-Service -Name trapsnmp -ErrorAction SilentlyContinue)) {
        throw "The trapsnmp service was not registered. See the messages above."
    }
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\trapsnmp" -Name Environment -PropertyType MultiString -Value @(
        "PYTHONPATH=$here;$root",
        "TRAPSNMP_DATA=$root\data",
        "TRAPSNMP_SERVICE=1"
    ) -Force | Out-Null
    & sc.exe description trapsnmp "Receives SNMP traps and publishes them on OPC UA." | Out-Null
    & sc.exe failure trapsnmp reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
    & $python $script start
    Write-InstallLog "Service trapsnmp is installed. Open services.msc and look for trapsnmp."
}
catch {
    Write-InstallLog $_.Exception.Message
    Write-Host $_.Exception.Message
    pause
    exit 1
}
