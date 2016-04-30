Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue

#Note: DO NOT use this script in a multi-server farm!!!
# http://www.harbar.net/archive/2016/03/21/The-Playbook-Imperative-and-Changing-the-Distributed-Cache-Service-Identity.aspx


$farm = Get-SPFarm
$cacheService = $farm.Services | where {$_.Name -eq "AppFabricCachingService"}
$serviceAccount = Get-SPManagedAccount -Identity wingtip\sp_services
$cacheService.ProcessIdentity.CurrentIdentityType = "SpecificUser"
$cacheService.ProcessIdentity.ManagedAccount = $serviceAccount
$cacheService.ProcessIdentity.Update()
Write-Host "This is the part that takes time..."
$cacheService.ProcessIdentity.Deploy()
Write-Host "Configuration complete" 
