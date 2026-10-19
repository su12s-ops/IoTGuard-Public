param(
    [Parameter(Mandatory=$true)][string]$PythonExe,
    [string]$Repository = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path,
    [string]$TaskName = 'IoTGuard-API'
)
$ErrorActionPreference = 'Stop'
$pythonPath = (Resolve-Path -LiteralPath $PythonExe).Path
$entry = Join-Path $Repository 'scripts/run_local_backend.py'
if (-not (Test-Path -LiteralPath $entry)) { throw 'API service entrypoint not found' }
if ($entry.Contains('"')) { throw 'Unsupported path' }
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute $pythonPath -Argument ('"' + $entry + '"') -WorkingDirectory $Repository
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
$principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
# Existing task replacement is explicit and inspectable through Task Scheduler.
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'IoTGuard read-only API; per-user login start and failure restart' -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName,State
