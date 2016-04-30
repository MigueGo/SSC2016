function Start-SearchServices {
[CmdletBinding()]
	param 
	(  
		[Parameter(Mandatory=$true, Position=0)]
		[ValidateNotNullOrEmpty()]
		[string]$SettingsFile
	)

	cls
    Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue

	[xml]$settings = Get-Content $SettingsFile
    $config = $settings.config

    if (!$config)
    {
        Write-Host "Configuration script not found"
        Read-Host "Press enter to exit."
        Exit
    }

	#Get the service and crawl Creds for use at the end of the scripts
	$servicecred = Get-Credential -UserName $config.ServiceAccountUser -Message "Search Service Account Password"
	$crawlcred = Get-Credential -UserName $config.CrawlUser -Message "Crawl Account Password"
	
    #Does the index location exist?
    if (!(Test-Path -Path $config.IndexLocation))
    {
        New-Item -Path $config.IndexLocation -Type Directory
    }


	Write-Host -ForegroundColor Yellow "Checking if Search Application Pool exists" 
    $SPAppPool = Get-SPServiceApplicationPool -Identity $config.SearchAppPoolName -ErrorAction SilentlyContinue

    if (!$SPAppPool) 
    { 
        Write-Host -ForegroundColor Green "Creating Search Application Pool" 
        $spAppPool = New-SPServiceApplicationPool -Name $config.SearchAppPoolName -Account $config.SearchAppPoolAccountName 
    }

	Write-Host "Setting search service properties..."
    while ($true) {
    	Get-SPEnterpriseSearchService | Set-SPEnterpriseSearchService `
    		-ServiceAccount $servicecred.Username `
    		-ServicePassword $servicecred.Password `
    		-ContactEmail $svcConfig.ContactEmail `
    		-ErrorAction SilentlyContinue -ErrorVariable err
    	if ($err) {
            if ($err[0].Exception.Message -like "*update conflict*") { Write-Warning "An update conflict occurred"; Start-Sleep 2; continue; }
    		throw $err
    	}
        break
	}
	
	

    # Start Services search service instance 
    Write-host -ForegroundColor Yellow "Start Search Service instances...." $config.AdminServer
    Start-SPEnterpriseSearchServiceInstance $config.AdminServer -ErrorAction SilentlyContinue 
    Start-SPEnterpriseSearchQueryAndSiteSettingsServiceInstance $config.AdminServer -ErrorAction SilentlyContinue


    Write-Host -ForegroundColor Yellow "Checking if Search Service Application exists" 
    $ServiceApplication = Get-SPEnterpriseSearchServiceApplication -Identity $config.ServiceAppName -ErrorAction SilentlyContinue

    if (!$ServiceApplication) 
    { 
        Write-Host -ForegroundColor Green "Creating Search Service Application" 
        $ServiceApplication = New-SPEnterpriseSearchServiceApplication -Partitioned -Name $config.ServiceAppName -ApplicationPool $spAppPool.Name -DatabaseServer $config.DatabaseServer -DatabaseName $config.DatabaseName 
    }


    Write-Host -ForegroundColor Yellow "Checking if Search Service Application Proxy exists" 
    $Proxy = Get-SPEnterpriseSearchServiceApplicationProxy -Identity $config.SearchServiceProxyName -ErrorAction SilentlyContinue

    if (!$Proxy) 
    { 
        Write-Host -ForegroundColor Green "Creating Search Service Application Proxy" 
        $Proxy = New-SPEnterpriseSearchServiceApplicationProxy -Partitioned -Name $config.SearchServiceProxyName -SearchApplication $ServiceApplication 
    }

   

    $OldTopology = $ServiceApplication.ActiveTopology 
    Write-Host -ForegroundColor Green "Active Topology ID:" $OldTopology.TopologyId.ToString()


    # Clone the default Topology (which is empty) and create a new one and then activate it 
    Write-Host -ForegroundColor Yellow "Configuring Search Component Topology...." 
    $clone = $ServiceApplication.ActiveTopology.Clone() 
    $SSI = Get-SPEnterpriseSearchServiceInstance $config.AdminServer 

    if ($SSI.Status -ne "Online")
    {
        $SSI | Start-SPServiceInstance
    }

    # Build out Admin Component
    $admin = $ServiceApplication | Get-SPEnterpriseSearchAdministrationComponent
    $admin | Set-SPEnterpriseSearchAdministrationComponent -SearchServiceInstance $SSI
    $admin = ($ServiceApplication | Get-SPEnterpriseSearchAdministrationComponent)

    while (-not $admin.Initialized)
    {
        Start-Sleep 10
        $admin = ($ServiceApplication | Get-SPEnterpriseSearchAdministrationComponent)
    }

    #
    $adminSearchInstance = Get-SPEnterpriseSearchServiceInstance $config.AdminServer
    $adminComponent = New-SPEnterpriseSearchAdminComponent -SearchTopology $clone -SearchServiceInstance $adminSearchInstance 


    Write-Host -ForegroundColor Cyan "  Create a crawl component"
    $config.CrawlServers.Server | ForEach-Object {
        Write-Host -ForegroundColor Green "    Assigning Crawl Server " $_.Name
        $crawlInstance = Get-SPEnterpriseSearchServiceInstance $_.Name
		
		#Online?
		if ($crawlInstance.Status -ne "Online")
		{
			$crawlInstance | Start-SPServiceInstance | Out-Null
		}
		while ($crawlInstance.Status -ne "Online")
		{
			Start-Sleep 10
			$crawlInstance = Get-SPEnterpriseSearchServiceInstance $_.Name
		}
			
        $crawlComponent = New-SPEnterpriseSearchCrawlComponent -SearchTopology $clone -SearchServiceInstance $crawlInstance | Out-Null
    }


    Write-Host -ForegroundColor Cyan "  Create a query processing component"
    $config.QueryServers.Server | ForEach-Object {
        Write-Host -ForegroundColor Green "    Assigning Query Server " $_.Name
        $queryInstance = Get-SPEnterpriseSearchServiceInstance $_.Name
		#Online?
		if ($queryInstance.Status -ne "Online")
		{
			$queryInstance | Start-SPServiceInstance | Out-Null
		}
		while ($queryInstance.Status -ne "Online")
		{
			Start-Sleep 10
			$queryInstance = Get-SPEnterpriseSearchServiceInstance $_.Name
		}
	
        $queryComponent = New-SPEnterpriseSearchQueryProcessingComponent -SearchTopology $clone -SearchServiceInstance $queryInstance | Out-Null
    }

		
    Write-Host -ForegroundColor Cyan "  Create an index component at "$config.IndexLocation
    #Do you need to create the index directories?
    #Remove-Item -Recurse -Force -LiteralPath $config.IndexLocation -ErrorAction SilentlyContinue 
    #mkdir -Path $config.IndexLocation -Force

    $indexInstance = Get-SPEnterpriseSearchServiceInstance $config.IndexServer
	#Online?
	if ($indexInstance.Status -ne "Online")
	{
		$indexInstance | Start-SPServiceInstance | Out-Null
	}
	while ($indexInstance.Status -ne "Online")
	{
		Start-Sleep 10
		$indexInstance = Get-SPEnterpriseSearchServiceInstance $config.IndexServer
	}
	
	Write-Host -ForegroundColor Green "    Assigning Index Server " $config.IndexServer
    $indexComponent = New-SPEnterpriseSearchIndexComponent -SearchTopology $clone -SearchServiceInstance $indexInstance -RootDirectory $config.IndexLocation | Out-Null

    Write-Host -ForegroundColor Cyan "  Create an analytics component"
    $analyticsInstance = Get-SPEnterpriseSearchServiceInstance $config.AnalyticsServer
	#Online?
	if ($analyticsInstance.Status -ne "Online")
	{
		$analyticsInstance | Start-SPServiceInstance | Out-Null
	}
	while ($analyticsInstance.Status -ne "Online")
	{
		Start-Sleep 10
		$analyticsInstance = Get-SPEnterpriseSearchServiceInstance $config.AnalyticsServer
	}
	Write-Host -ForegroundColor Green "    Assigning Analytics Server " $config.AnalyticsServer
    $analyticsComponent = New-SPEnterpriseSearchAnalyticsProcessingComponent -SearchTopology $clone -SearchServiceInstance $analyticsInstance | Out-Null

    Write-Host -ForegroundColor Cyan "  Create a content processing component"
    $contentProcessingInstance = Get-SPEnterpriseSearchServiceInstance $config.ContentProcessingServer
	#Online?
	if ($contentProcessingInstance.Status -ne "Online")
	{
		$contentProcessingInstance | Start-SPServiceInstance | Out-Null
	}
	while ($contentProcessingInstance.Status -ne "Online")
	{
		Start-Sleep 10
		$contentProcessingInstance = Get-SPEnterpriseSearchServiceInstance $config.ContentProcessingServer
	}
	Write-Host -ForegroundColor Green "    Assigning Content Processing Server " $config.ContentProcessingServer
    $contentProcessingComponent = New-SPEnterpriseSearchContentProcessingComponent -SearchTopology $clone -SearchServiceInstance $contentProcessingInstance | Out-Null

    #Test the Clone before we activate it.
    if ($clone.ComponentCount -ne 0)
    {
        Write-Host -ForegroundColor Yellow "Activating new topology ..."
        $clone.Activate()
	    Write-Host -ForegroundColor Green "New topology activated"
        #Set Default Crawl Account
	    Write-Host -ForegroundColor Yellow "Setting default content access account"
        $ServiceApplication | Set-SPEnterpriseSearchServiceApplication -DefaultContentAccessAccountName $crawlcred.UserName -DefaultContentAccessAccountPassword $crawlcred.Password

        #Provide the location of the global Search Center
	    Write-Host -ForegroundColor Yellow "Setting default global search center"
        $ServiceApplication = Get-SPEnterpriseSearchServiceApplication
        $ServiceApplication.SearchCenterUrl = $config.SearchCenterUrl
        $ServiceApplication.Update()

        Write-host -ForegroundColor Green "Your search service application $serviceAppName is now ready"

        Write-Host
        Write-Host
	    #Optionally remove the old topology here
        $title = "Delete old Topology?"
        $message = "Do you want to delete the old topology?"

        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
            "Deletes the old topology."

        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
            "Retains the old topology in an inactive state."

        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

        $result = $host.ui.PromptForChoice($title, $message, $options, 0) 

        if ($result -eq 0)
        {
            Remove-SPEnterpriseSearchTopology -Identity $OldTopology -Confirm:$false
        }
		
		
		#Open the Browser
		#Get the URL to Central Administration
		$caUrl = Get-spwebapplication -includecentraladministration | where {$_.IsAdministrationWebApplication} | select Url -First 1
		$navigateUrl = $caUrl.Url + $ServiceApplication.ManageLink.Url
		Write-Host "Launching IE"
		$ie = New-Object -com "InternetExplorer.Application"
		$ie.Navigate($navigateUrl)
		$ie.Visible = $true

    }
    else
    {
        Write-Host -ForegroundColor Red "Error with Topology, Component Count is 0"
    }

    
	
}

Start-SearchServices -SettingsFile .\cptsearchconfig.xml