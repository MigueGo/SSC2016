Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue

Write-Host "Running Compliance High Priority Policy Processing and Compliance Dar Processing Timer Jobs"
#Compliance Hi Priority Processing Timer Job & DAR Processing Timer jobs are jobs should be running
Get-SPTimerJob | Where-Object{($_.Name -like "HiPriPolicy*") -or ($_.Name -like "DarProcessing*")} | Start-SPTimerJob

Read-Host -Prompt "Press [Enter] to close this window"


