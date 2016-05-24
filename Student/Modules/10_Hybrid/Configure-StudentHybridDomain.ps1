#Get the Student##
$studentid = "student00.criticalpathlabs.com"
#Set the forest UPN
Set-ADForest -Identity wingtip.com -UPNSuffixes @{Add="$($studentid)"} 

#for each user...set the UPN
#Get-ADUser -Filter * | Select SamAccountName, DistinguishedName, UserPrincipalName
$users = Get-ADUser -SearchBase "OU=Wingtip Users,DC=wingtip,DC=com" -Filter * #| Select SamAccountName, DistinguishedName, UserPrincipalName
foreach ($user in $users){
    $upn = -join ($user.SamAccountName, "@", $studentid)
    Write-host $user.SamAccountName "($upn)" 
    Set-ADUser -Identity $user.SID -UserPrincipalName $upn
}
