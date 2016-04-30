Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue

#Get-SPEnterpriseSearchService | Select PerformanceLevel

Set-SPEnterpriseSearchService -PerformanceLevel Reduced

net stop OSearch16
net stop SPSearchHostController

net start OSearch16
net start SPSearchHostController

#C:\Program Files\Microsoft Office Servers\15.0\Search\Runtime\1.0\noderunner.exe.config
#<nodeRunnerSettings memoryLimitMegabytes="0" />