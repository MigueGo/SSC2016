cls

function Get-ServiceApplicationPoolName{
    $applicationPoolName = "Wingtip Service Applications"    
    $applicationPool = Get-SPServiceApplicationPool -Identity $applicationPoolName -ErrorAction SilentlyContinue
    if (!$applicationPool) {
        Write-Host "Creating service application pool for all Wingtip service applications"
        $serviceAppPoolAccountName = "WINGTIP\SP_Services"
        $applicationPool = New-SPServiceApplicationPool -Name $applicationPoolName -Account $serviceAppPoolAccountName 
    }
    return $applicationPool.Name
}

function Grant-ServiceApplicationPermission($app, $user, $permission, $admin){
    
    $sec = $app | Get-SPServiceApplicationSecurity -Admin:$admin
    $claim = New-SPClaimsPrincipal -Identity $user -IdentityType WindowsSamAccountName
    $sec | Grant-SPObjectSecurity -Principal $claim -Rights $permission
    $app | Set-SPServiceApplicationSecurity -ObjectSecurity $sec -Admin:$admin

}

function Create-BCSApplication{

    $service = Get-SPServiceInstance | where {$_.TypeName -eq "Business Data Connectivity Service"}
    if ($service.Status -ne "Online") {
        Write-Host "Starting Business Data Connectivity Service..."
        $service | Start-SPServiceInstance | Out-Null
    }

    $serviceApplicationName = "Business Connectivity Service Application"
    $serviceApplication = Get-SPServiceApplication | where {$_.Name -eq $serviceApplicationName}

    if($serviceApplication -eq $null) {
        Write-Host "Creating the Business Connectivity Service Application..."
        $serviceApplicationDB = "SharePoint_Service_Business_Connectivity"
        $serviceApplication = New-SPBusinessDataCatalogServiceApplication `
                                  -Name $serviceApplicationName `
                                  -DatabaseServer $sqlserver `
                                  -DatabaseName $serviceApplicationDB `
                                  -ApplicationPool $serviceAppPoolName
 
    }
}

function Create-ManagedMetadataService{

    $service = Get-SPServiceInstance | where {$_.TypeName -eq "Managed Metadata Web Service"}
    if ($service.Status -ne "Online") {
        Write-Host "Starting Managed Metadata Service..."
        $service | Start-SPServiceInstance | Out-Null
    }

    $serviceApplicationName = "Managed Metadata Service Application"
	$serviceApplicationDB = "SharePoint_Service_Managed_Metadata"
    $serviceApplication = Get-SPServiceApplication | where {$_.Name -eq $serviceApplicationName}

    if($serviceApplication -eq $null) {
        Write-Host "Creating the Managed Metadata Service Application..."
        $serviceApplication = New-SPMetadataServiceApplication `
                                  -Name $serviceApplicationName `
                                  -ApplicationPool $serviceAppPoolName `
                                  -DatabaseServer $sqlserver `
                                  -DatabaseName $serviceApplicationDB
    
        $serviceApplicationProxyName = "Managed Metadata Service Application Proxy"
        Write-Host "Creating the Managed Metadata Service Application Proxy..."
        $serviceApplicationProxy = New-SPMetadataServiceApplicationProxy `
                                       -Name $serviceApplicationProxyName `
                                       -ServiceApplication $serviceApplication `
                                       -DefaultProxyGroup

                                       
        # configure proxy to automatically create new term set for managed navigation for each new publishing site
        $serviceApplicationProxy = Get-SPServiceApplicationProxy | Where-Object { $_.Name -eq $serviceApplicationProxyName}
        $serviceApplicationProxy.Properties.IsDefaultSiteCollectionTaxonomy = $true 
        $serviceApplicationProxy.Update()

        Grant-ServiceApplicationPermission $serviceApplication "WINGTIP\Administrator" "Full Control" $true
    }

}

function Create-SiteSubscriptionSettingsService{

    # assign root domain name to configure URL used to access app webs
    Set-SPAppDomain "wingtipapps.com" –confirm:$false 

    $subscriptionSettingsService = Get-SPServiceInstance | where {$_.TypeName -like "Microsoft SharePoint Foundation Subscription Settings Service"}

    if($subscriptionSettingsService.Status -ne "Online") { 
        Write-Host "Starting Subscription Settings Service" 
        Start-SPServiceInstance $subscriptionSettingsService | Out-Null
    } 

    # wait for subscription service to start" 
    while ($service.Status -ne "Online") {
      # delay 5 seconds then check to see if service has started   sleep 5
      $service = Get-SPServiceInstance | where {$_.TypeName -like "Microsoft SharePoint Foundation Subscription Settings Service"}
    } 

    $subscriptionSettingsServiceApplicationName = "Site Subscription Settings Service Application"
    $subscriptionSettingsServiceApplication = Get-SPServiceApplication | where {$_.Name -eq $subscriptionSettingsServiceApplicationName} 

    # create an instance Subscription Service Application and proxy if they do not exist 
    if($subscriptionSettingsServiceApplication -eq $null) { 
      Write-Host "Creating Subscription Settings Service Application..." 
      
      $subscriptionSettingsServiceDB= "SharePoint_Service_Site_Subscription_Settings"
      $subscriptionSettingsServiceApplication = New-SPSubscriptionSettingsServiceApplication `
                                                    -ApplicationPool $serviceAppPoolName `
                                                    -Name $subscriptionSettingsServiceApplicationName `
                                                    -DatabaseServer $sqlserver `
                                                    -DatabaseName $subscriptionSettingsServiceDB 

      Write-Host "Creating Subscription Settings Service Application Proxy..." 
      $subscriptionSettingsServicApplicationProxy = New-SPSubscriptionSettingsServiceApplicationProxy `
                                                      -ServiceApplication $subscriptionSettingsServiceApplication

    }

    # assign name to default tenant to configure URL used to access web apps 
    Set-SPAppSiteSubscriptionName -Name "Wingtip" -Confirm:$false
}


# load in SharePoint snap-in
Add-PSSnapin Microsoft.SharePoint.PowerShell -WarningAction SilentlyContinue

# create variables used in this script
$sqlserver = "SPSQL"

$serviceAppPoolName = Get-ServiceApplicationPoolName

Create-BCSApplication

Create-ManagedMetadataService

Create-SiteSubscriptionSettingsService