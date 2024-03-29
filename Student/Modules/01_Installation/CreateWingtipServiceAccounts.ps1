Import-Module ActiveDirectory
Write-Host 

$WingtipDomain = "DC=wingtip,DC=com"
$ouWingtipServiceAccountsName = "Wingtip Service Accounts"
$ouWingtipServiceAccountsPath = "OU={0},{1}" -f $ouWingtipServiceAccountsName, $WingtipDomain
$ouWingtipServiceAccounts = Get-ADOrganizationalUnit -Filter { name -eq $ouWingtipServiceAccountsName}
if($ouWingtipServiceAccounts -ne $null){
  Write-Host ("The Organization Unit {0} has already been created" -f $ouWingtipServiceAccountsName)
}
else
{
  Write-Host ("Creating {0} Organization Unit" -f $ouWingtipServiceAccountsName)
  New-ADOrganizationalUnit -Name $ouWingtipServiceAccountsName -Path $WingtipDomain -ProtectedFromAccidentalDeletion $false 
}


$UserPassword = ConvertTo-SecureString -AsPlainText "Password1" -Force

Write-Host

# create farm service account 
$UserName = "SP_Farm"
Write-Host ("Adding User: {0}" -f $UserName)
New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true

# create service app service account 
$UserName = "SP_Services"
Write-Host ("Adding User: {0}" -f $UserName)
New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true

# create web app service account 
$UserName = "SP_Content"
Write-Host ("Adding User: {0}" -f $UserName)
New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true
Add-ADGroupMember -Identity "Performance Log Users" -Members $UserName

# create user profile synchronization account 
$UserName = "SP_MIM"
Write-Host ("Adding User: {0}" -f $UserName)
New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true

# create search crawler account 
$UserName = "SP_Crawler"
Write-Host ("Adding User: {0}" -f $UserName)
New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true

# create workflow manager service account 
$UserName = "SP_Workflow"
Write-Host ("Adding User: {0}" -f $UserName)
New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true

# create user profile synchronization account 
$UserName = "SP_AADSync"
Write-Host ("Adding User: {0}" -f $UserName)
New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true

Write-Host 
Write-Host "Press ENTER to continue"
Read-Host

