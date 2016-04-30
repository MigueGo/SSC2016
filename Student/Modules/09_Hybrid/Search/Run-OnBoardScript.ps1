#Edit these values
$o365Admin = "admin@yourtenant.onmicrosoft.com"
$tenantUrl = "https://yourtenant.sharepoint.com/"

#Don't change this stuff
$cred = Get-Credential -Message "MSOL Global Admin" -Username $o365Admin
. .\Onboard-CloudHybridSearch.ps1 -PortalUrl $tenantUrl -CloudSsaId "Cloud Search Service Application" -Credential $cred 
