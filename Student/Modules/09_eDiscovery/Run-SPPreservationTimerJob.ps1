#Add the SharePoint Snap-in and drop the error in the event it is already loaded
Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue
 
Write-Host "Running eDiscovery Preservation Timer Jobs"
Get-SPTimerJob | Where-Object{$_.Name -like "Preservation*"} | Start-SPTimerJob

Read-Host -Prompt "Press [Enter] to close this window"