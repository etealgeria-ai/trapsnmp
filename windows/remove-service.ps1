$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = $null
$pathFile = Join-Path $here "python.path"
if (Test-Path -LiteralPath $pathFile) {
    $python = (Get-Content -LiteralPath $pathFile -Raw).Trim()
}
if (-not $python -or -not (Test-Path -LiteralPath $python)) {
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) { $python = (& py -3 -c "import sys; print(sys.executable)").Trim() }
}
if (-not $python) { throw "Python was not found." }
$script = Join-Path $here "trapsnmp_service.py"
& $python $script stop
& $python $script remove
Write-Host "trapsnmp service removed."
