Add-PSSnapin Microsoft.SharePoint.POwerShell -ErrorAction SilentlyContinue

$mms = Get-SPMetadataServiceApplication "Managed Metadata Service Application"

Set-SPMetadataServiceApplication -Identity $mms -HubURI "https://intranet.wingtip.com/sites/contenttypehub"