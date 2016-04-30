Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue

#To enable Fast Site Collection Creation enter Enable-SPWebTemplateForSiteMaster -Template <TEMPLATENAME> -CompatibilityLevel 15
Enable-SPWebTemplateForSiteMaster -Template STS#1 -CompatibilityLevel 15
#Get-SPWebTemplatesEnabledForSiteMaster

#To create a new Site Master enter New-SPSiteMaster -ContentDatabase <CONTENTDB> -Template <TEMPLATENAME> at the prompt.
New-SPSiteMaster -ContentDatabase SharePoint_Content_Wingtip_Engineering -Template STS#1
#Provisioning of new Site Collections using Fast Site Collection Creation is achieved through including the new parameter –CreateFromSiteMaster with the New-SPSite Windows PowerShell CmdLet as shown in the example below:
#New-SPSite https://intranet.wingtip.com/sites/<SITE> -Template <TEMPLATE> -ContentDatabase <CONTENTDB> -CompatibilityLevel 15 -CreateFromSiteMaster -OwnerAlias <OWNER>



