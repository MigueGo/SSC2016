Import-Module MSOnline

$cred = Get-Credential -UserName admin@MOD257693.onmicrosoft.com -Message "Enter the Office 365 Admin Account"

Connect-MsolService -Credential $cred 


Get-MsolUser | Where-Object {$_.UserPrincipalName -like "*.criticalpathlabs.com"}