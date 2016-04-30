Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue

$webapp = Get-SPWebApplication -Identity "http://wingtipserver"
$siteUrl = "http://www.wingtip.com"
$siteTitle = "Wingtip Toys"
$siteAdmin = "wingtip\administrator"
$siteTemplate = "BLANKINTERNET#0"

$site = New-SPSite -HostHeaderWebApplication $webapp -Url $siteUrl -Name $siteTitle -OwnerAlias $siteAdmin -Template $siteTemplate

if ($site.IISAllowsAnonymous){
    Write-Host "Enabling anonymous access"
    $web = $site.RootWeb
    $web.AnonymousState = [Microsoft.SharePoint.SPWeb+WebAnonymousState]::On
    $web.Update()
}
else{
  Write-Host "Cannot enable anonymous access because Web Application does not allow"
}

