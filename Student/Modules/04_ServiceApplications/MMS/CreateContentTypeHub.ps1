Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue

$webapp = Get-SPWebApplication -Identity "https://intranet.wingtip.com"
$siteUrl = "https://intranet.wingtip.com/sites/ContentTypeHub"
$siteTitle = "Wingtip Content Type Hub"
$siteAdmin = "wingtip\administrator"
$siteTemplate = "STS#0"

$site = New-SPSite -Url $siteUrl -Name $siteTitle -OwnerAlias $siteAdmin -Template $siteTemplate