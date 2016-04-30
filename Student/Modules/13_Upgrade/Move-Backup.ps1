# Move the Backup File to the default backup directory for SQL Server
Move-Item -Path "C:\Student\Modules\13_Upgrade\SharePoint_Content_Operations_Web.bak" -Destination "C:\Data\SharePoint\Backup"

Write-Host "Database moved, press any key to exit"
Read-Host