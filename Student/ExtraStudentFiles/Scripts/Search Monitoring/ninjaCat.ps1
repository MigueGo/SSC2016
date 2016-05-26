Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue

$SSA = Get-SPEnterpriseSearchServiceApplication

$components = $SSA.ActiveTopology.GetComponents() | Sort ServerName | SELECT ServerName, Name

$servers = $components.ServerName | SELECT -Unique

foreach ($hostname in $servers) {
    Write-Host ("---[$hostname]---") -ForegroundColor Cyan

    Write-Host ("Components deployed to this server...") 
    $crawler = $components | Where {($_.Servername -ieq $hostname) -and ($_.Name -match "Crawl") } 
    if ($crawler -ne $null) {
        Write-Host ("    " + $crawler.Name + ":") -ForegroundColor White
        $mssearch = (Get-Process mssearch -ComputerName $hostname -ErrorAction SilentlyContinue)
        Write-Host ("        " + $mssearch.ProcessName + "[PID: " + $mssearch.Id + "]")
        $mssdmn = (Get-Process mssdmn -ComputerName $hostname -ErrorAction SilentlyContinue)
        $mssdmn | ForEach {
            Write-Host ("        " + $_.ProcessName + "[PID: " + $_.Id + "]")
        }
    }

    $junoComponents = $components | Where {($_.Servername -ieq $hostname) -and ($_.Name -notMatch "Crawl") }     
    $noderunnerProcesses = (Get-Process noderunner -ComputerName $hostname -ErrorAction SilentlyContinue)

    foreach ($node in $noderunnerProcesses) {
        $node | Add-Member -Force -MemberType NoteProperty -Name _ProcessCommandLine -Value $(
		    (Get-WmiObject Win32_Process -ComputerName $hostname -Filter $("processId=" + $node.id)).CommandLine
	    )

        $junoComponents | Where {$_.Servername -ieq $hostname} | ForEach {
            $component = $($_).Name
            if ($node._ProcessCommandLine -like $("*" + $component + "*")) {
                Write-Host ("    " + $component + ":") -ForegroundColor White
                Write-Host ("        " + $node.ProcessName + "[PID: " + $node.Id + "]")
            }
        }
    }

    #if this is a custom object, wrap it in an array object so we can get a count in the step below
    if ($junoComponents -is [PSCustomObject]) { $junoComponents = @($junoComponents) } 

    if ($junoComponents.Count  -gt $noderunnerProcesses.Count) {
        Write-Host ("One or more noderunner processes is not running for components") -ForegroundColor Yellow 
    }

    Write-Host
    $services = Get-Service -ComputerName $hostname -Name SPTimerV4, SPAdminV4, OSearch15, SPSearchHostController 
    $running = $services | Where {$_.Status -eq "Running"}
    if ($running) {
        Write-Host ("Service Instances...") -ForegroundColor Green
        $running | ft -AutoSize
    }
    $stopped = $services | Where {$_.Status -eq "Stopped"}
    if ($stopped) {
        Write-Host ("`"Stopped`" Services...") -ForegroundColor Red
        $stopped | ft -AutoSize
    }
    $other   = $services | Where {($_.Status -ne "Running") -and ($_.Status -ne "Stopped")}
    if ($other) {
        Write-Host ("Service in an abnormal or transient state...") -ForegroundColor Yellow
        $other | ft -AutoSize
    }

}
