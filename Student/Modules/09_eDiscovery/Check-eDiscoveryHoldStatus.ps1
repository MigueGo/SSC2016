Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue

$site = get-spsite https://research.wingtip.com 
$feature = get-spfeature –site $site | where{$_.DisplayName –eq “Preservation”} 

Write-Host "Preservation feature status" $feature.status

Write-Host "Preservation Event Recievers"
$site.eventreceivers | select name

$list = $site.RootWeb.lists | where{$_.Title –eq “Preservation Hold Settings”} 
Write-Host "Preservation Hold List:" $list.title

$record = New-Object Microsoft.Office.RecordsManagement.Preservation.HoldSettings($site) 
Write-Host "Preservation Holds"
$record.getallholds()

Read-Host -Prompt "Press [Enter] to close this window"