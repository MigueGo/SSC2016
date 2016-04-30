#ForestDnsName = wingtip.com
#ForestCredential = wingtip\sp_mim
#OrganizationalUnit = 'ou=Wingtip Users,dc=wingtip,dc=com'
#SharePointUrl https://wingtipserver:9999
#SharePointCredentail wingtip\sp_mim

### Load the SharePoint Sync Module
Import-Module "C:\Student\Modules\07_UserProfileService\UserProfile.MIMSync\SharePointSync.psm1" -Force

### Install the SharePoint Sync Configuration
Install-SharePointSyncConfiguration `
  -Path "C:\Student\Modules\07_UserProfileService\UserProfile.MIMSync" `
  -ForestDnsName wingtip.com `
  -ForestCredential (Get-Credential wingtip\sp_mim) `
  -OrganizationalUnit 'ou=Wingtip Users,dc=wingtip,dc=com' `
  -SharePointUrl http://wingtipserver:9999 `
  -SharePointCredential (Get-Credential wingtip\sp_farm) `
  -Verbose 

### Run the Synchronization Service management agents
#Start-SharePointSync -Verbose -WhatIf 