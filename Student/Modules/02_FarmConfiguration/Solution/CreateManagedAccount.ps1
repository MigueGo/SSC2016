Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue

$credential = Get-Credential "WINGTIP\SP_Content" -Message “Enter the content account credentials”
New-SPManagedAccount -Credential $credential
