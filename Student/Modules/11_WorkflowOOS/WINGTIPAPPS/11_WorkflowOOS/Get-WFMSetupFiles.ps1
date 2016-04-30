#Pull the Workflow Manager files from the Internet and copy them locally for an offline installation
Webpicmd /offline /Products:ServiceBus /Path:C:\WFSources\ServiceBus
Webpicmd /offline /Products:WorkflowClient /Path:C:\WFSources\Client
Webpicmd /offline /Products:WorkflowManagerRefresh /Path:C:\WFSources\Manager
Copy-Item -Path C:\Student\11_WorkflowOOS\ServiceBus-KB2799752-x64-EN.exe -Destination C:\WFSources