#Add the SharePoint Snap-in and drop the error in the event it is already loaded
Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue
 
Get-SPTimerJob | Where-Object{$_.Name -like "Preservation*"} | Start-SPTimerJob