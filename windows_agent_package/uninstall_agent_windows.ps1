<#
.SYNOPSIS
    Uninstaller for the Windows PowerShell SLA Monitoring Agent - FINAL PRODUCTION VERSION
.DESCRIPTION
    This script self-elevates to Administrator and completely removes the agent,
    including the scheduled task, installation directory, and all related files.
    This version includes improved error handling and user feedback.
#>
param()

# --- Self-Elevation to Administrator ---
if (-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting Administrator privileges..."
    $arguments = "-ExecutionPolicy Bypass -File `"$($myInvocation.mycommand.definition)`""
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    exit
}

Write-Host "Starting Windows SLA Monitor Agent Uninstallation (Running as Administrator)..." -ForegroundColor Yellow

# --- Configuration ---
$AgentInstallDir = "C:\SLA_Monitor_Agent"
$TaskName = "InternetSLAMonitorAgent"
$LockFile = Join-Path -Path $env:TEMP -ChildPath "sla_monitor_agent.lock"

# --- 1. Stop and Remove Scheduled Task ---
Write-Host "Step 1: Removing Scheduled Task '$TaskName'..." -ForegroundColor Cyan
try {
    $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($Task) {
        Write-Host "- Task found. Stopping it..."
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue # Ignore error if not running
        
        Write-Host "- Unregistering task..."
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
        Write-Host "- Scheduled Task successfully removed." -ForegroundColor Green
    } else {
        Write-Host "- Scheduled Task not found. No action needed."
    }
} catch {
    Write-Warning "An error occurred while trying to remove the scheduled task. You may need to remove it manually using Task Scheduler. Error: $($_.Exception.Message)"
}

# --- 2. Remove Installation Directory ---
Write-Host "`nStep 2: Removing installation directory '$AgentInstallDir'..." -ForegroundColor Cyan
if (Test-Path $AgentInstallDir) {
    Write-Host "- Directory found. Deleting..."
    try {
        Remove-Item -Path $AgentInstallDir -Recurse -Force -ErrorAction Stop
        Write-Host "- Directory successfully removed." -ForegroundColor Green
    } catch {
        Write-Error "A critical error occurred while trying to remove the directory '$AgentInstallDir'. Error: $($_.Exception.Message)"
        Write-Warning "You may need to delete the folder manually. Please ensure no files inside are in use."
    }
} else {
    Write-Host "- Directory not found. No action needed."
}

# --- 3. Remove Stale Lock File ---
Write-Host "`nStep 3: Cleaning up temporary files..." -ForegroundColor Cyan
if (Test-Path $LockFile) {
    Write-Host "- Stale lock file found. Removing..."
    try {
        Remove-Item $LockFile -Force -ErrorAction SilentlyContinue
        Write-Host "- Lock file removed." -ForegroundColor Green
    } catch {
        Write-Warning "Could not remove lock file at '$LockFile'. This is a minor issue."
    }
} else {
    Write-Host "- No lock file found. No action needed."
}

Write-Host "`nUninstallation process complete." -ForegroundColor Green
Read-Host "Press Enter to exit"
