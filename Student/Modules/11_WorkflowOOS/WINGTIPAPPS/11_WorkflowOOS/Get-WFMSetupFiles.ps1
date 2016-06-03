#Pull the Workflow Manager files from the Internet and copy them locally for an offline installation
Start-Process Webpicmd "/offline /Products:ServiceBus /Path:C:\WFSources\ServiceBus" -NoNewWindow -Wait
Start-Process Webpicmd "/offline /Products:WorkflowClient /Path:C:\WFSources\Client" -NoNewWindow -Wait
Start-Process Webpicmd "/offline /Products:WorkflowManagerRefresh /Path:C:\WFSources\Manager" -NoNewWindow -Wait

Read-Host "Press [Enter] to copy the patch file"
Copy-Item -Path C:\Student\11_WorkflowOOS\ServiceBus-KB2799752-x64-EN.exe -Destination C:\WFSources