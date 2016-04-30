Import-Module "C:\Student\Modules\07_UserProfileService\UserProfile.MIMSync\SharePointSync.psm1" -Force

### Test Run the Synchronization Service management agents
#Start-SharePointSync -Verbose -WhatIf 

### Run the Synchronization Service management agents without confirmation
Start-SharePointSync -Verbose -Confirm:$false

### Run the Synchronization Service management agents in Delta (incremental) mode without that anoying confirmation
#Start-SharePointSync -Delta -Confirm:$false
