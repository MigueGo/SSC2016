Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue

$webapp = Get-SPWebApplication -Identity "http://wingtipserver"
$siteUrl = "http://blog.wingtip.com"
$siteTitle = "Wingtip Blog Site"
$siteAdmin = "wingtip\administrator"
$siteTemplate = "BLOG#0"

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

