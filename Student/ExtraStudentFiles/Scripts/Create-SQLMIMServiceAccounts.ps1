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
# create SQL Server service account 
$UserName = "SQL_Server"
Write-Host ("Adding User: {0}" -f $UserName)
New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true

# create AD Connect Service account 
$UserName = "ADC_Server"
Write-Host ("Adding User: {0}" -f $UserName)
New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true


# create MIM service account 
$UserName = "MIM_Server"
Write-Host ("Adding User: {0}" -f $UserName)
New-ADUser -Path $ouWingtipServiceAccountsPath -SamAccountName $UserName -Name $UserName -DisplayName $UserName -AccountPassword $UserPassword -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $true

Write-Host ("Adding MIM Support Groups")
New-ADGroup -Path $ouWingtipServiceAccountsPath -SamAccountName FIMSyncAdmins -Name FIMSyncAdmins -Description "FIM Sync Admins" -GroupCategory Security -GroupScope Global 
New-ADGroup -Path $ouWingtipServiceAccountsPath -SamAccountName FIMSyncOperators -Name FIMSyncOperators -Description "FIM Sync Operators" -GroupCategory Security -GroupScope Global 
New-ADGroup -Path $ouWingtipServiceAccountsPath -SamAccountName FIMSyncJoiners -Name FIMSyncJoiners -Description "FIM Sync Joiners" -GroupCategory Security -GroupScope Global 
New-ADGroup -Path $ouWingtipServiceAccountsPath -SamAccountName FIMSyncBrowse -Name FIMSyncBrowse -Description "FIM Sync Browse" -GroupCategory Security -GroupScope Global 
New-ADGroup -Path $ouWingtipServiceAccountsPath -SamAccountName FIMSyncPasswordSet -Name FIMSyncPasswordSet -Description "FIM Sync Password Set" -GroupCategory Security -GroupScope Global 
Add-ADGroupMember -Identity FIMSyncAdmins -Members "administrator"
