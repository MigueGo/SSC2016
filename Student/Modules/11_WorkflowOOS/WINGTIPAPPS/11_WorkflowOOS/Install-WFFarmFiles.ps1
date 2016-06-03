Start-Process WebpiCmd.exe "/Install /Products:ServiceBus /XML:C:\WFSources\ServiceBus\feeds\latest\webproductlist.xml /AcceptEula /SuppressPostFinish" -NoNewWindow -Wait

Start-Process C:\WFSources\ServiceBus-KB2799752-x64-EN.exe

Read-Host "Wait for the Cumulative Update to complete, then hit Enter to continue..."

Start-Process WebpiCmd.exe "/Install /Products:WorkflowClient /XML:C:\WFSources\Client\feeds\latest\webproductlist.xml /AcceptEula /SuppressPostFinish" -NoNewWindow -Wait

Start-Process WebpiCmd.exe "/Install /Products:WorkflowManagerRefresh /XML:C:\WFSources\Manager\feeds\latest\webproductlist.xml /AcceptEula /SuppressPostFinish" -NoNewWindow -Wait
Write-Host "Workflow installation Complete" -ForegroundColor Green