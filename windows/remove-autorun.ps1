$ErrorActionPreference = "Stop"
Unregister-ScheduledTask -TaskName "trapsnmp" -Confirm:$false
Write-Host "trapsnmp no longer starts with Windows."
