Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue

#The Measure-Command function is used to time the script.
$time = Measure-Command {
    New-SPSite https://intranet.wingtip.com/sites/RegularBlankSite -Template STS#1 -ContentDatabase SharePoint_Content_Wingtip_Engineering -CompatibilityLevel 15 -OwnerAlias wingtip\administrator -Name "Regular Blank Site"
}
write-host "Without FSC that took: $($time.TotalSeconds) seconds"

$time = Measure-Command {
    New-SPSite https://intranet.wingtip.com/sites/FastBlankSite -Template STS#1 -ContentDatabase SharePoint_Content_Wingtip_Engineering -CompatibilityLevel 15 -CreateFromSiteMaster -OwnerAlias wingtip\administrator -Name "Fast Blank Site"
}
write-host "With FSC that took: $($time.TotalSeconds) seconds"
