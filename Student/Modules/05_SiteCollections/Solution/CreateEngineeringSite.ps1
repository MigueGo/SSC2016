Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue

$contentDatabaseName = "SharePoint_Content_Wingtip_Engineering"
$webappurl = "https://intranet.wingtip.com"

#Create a new content database
New-SPContentDatabase $contentDatabaseName -WebApplication $webappurl

$siteUrl = "https://intranet.wingtip.com/sites/engineering"
$siteTitle = "Wingtip Engineering Site"
$siteAdmin = "wingtip\administrator"
$siteTemplate = "STS#0"

$site = New-SPSite -Url $siteUrl -Name $siteTitle -OwnerAlias $siteAdmin -Template $siteTemplate -ContentDatabase $contentDatabaseName


