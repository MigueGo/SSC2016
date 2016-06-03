#You need the WebPICmd
#& '\\wingtipapps\c$\WorkflowManagerFiles\WebPI\WebPlatformInstaller_amd64_en-US.msi'
#Read-Host "Click here when installation is complete"
# The WF Installation files are located on the WF Server
& 'C:\Program Files\Microsoft\Web Platform Installer\WebpiCmd.exe' /Install  /AcceptEula /Products:WorkflowClient /XML:\\wingtipapps\c$\WFSources\Client\feeds\latest\webproductlist.xml /SuppressPostFinish

