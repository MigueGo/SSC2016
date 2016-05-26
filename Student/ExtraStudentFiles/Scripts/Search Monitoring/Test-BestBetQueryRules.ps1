<#
.SYNOPSIS
  This script may be used to validate and delete Promoted Result (Best Bet) 
  Query Rules from a SharePoint 2013 search environment.  
  The script can also delete Query Rules, that are not system rules, that 
  don't have any Actions.
.DESCRIPTION
  This script may be used to test, log and delete Promoted Result (Best Bet) 
  Query Rules from a SharePoint 2013 search environment.  It is important to 
  run this script with permissions sufficient to access all the content refered
  to in the Query Rule.  
  The script has three modes which may be run in combination with the Log or 
  Delete parameter.  There is also a Status parameter which will output the
  count of Query Rules at a given level. 
  When this script is executed using the Log parameter, the first mode, 
  InvalidRules, tests the URL of a Promoted Result. If the URL isn't opened 
  succesfully, the rule is logged as invalid. Note, the account you use to 
  run the script must have sufficient permissions to view the target URL.
  The second mode, HighRankRules, tests Promoted Results with exact match 
  conditions ("contains" and exact match dictionary conditions are not handled). 
  If the term produces a result in the top results (configurable), the rule is 
  logged.  Note that HighRankRules requires a site against which it will run
  the tests.  Query Rules inherited from higher levels (SSA, Site Collection) 
  may behave differently at each site.
  The third mode, QueryRulesWithoutActions, logs query rules, that are not
  system rules, which do not have any Actions.
  Each mode may also be separately run with the Delete parameter which will 
  delete rules that were logged.
  If the parent Query Rule of an invalid Best Bet does not have any other 
  Promoted Results, Result Blocks or Change Query Actions, the parent Query 
  Rule will also be deleted when the -DeleteRuleWithoutActions switch is used. 
  It's like running the HighRankRules or InvalideRules with 
  QueryRulesWithoutActions at the same time. 
  
  An example procedure for using this script is:
  
  1. Use -Log parameter with the InvalidRules mode to create a .csv file listing 
  all the invalid Best Bets.
  PS C:>.\Test-BestBetQueryRules.ps1 -Status -Level SSA
  
  2. Review the .csv file created in step 1. Use the Delete parameter and 
  InvalidRules mode to delete all the invalid Best Bets. Use the -WhatIf 
  parameter to test and view what Rules will be deleted. Optionally, add the 
  -DeleteRuleWithoutActions to also delete parent rules without actions.
  PS C:>.\Test-BestBetQueryRules.ps1 -Delete -Mode InvalidRules -DeleteRuleWithoutActions -PathToCSV .\InvalidBestBetQueryRules-default-SSA.csv -WhatIf
  
  3. Use the HighRankRules mode to create a .csv file listing all the Best Bets
  which appear in the top 5 results by setting the RankThreshold parameter equal
  to 5 (default is 3).  Optionally use -DeleteRuleWithoutActions.
  PS C:>.\Test-BestBetQueryRules.ps1 -Log -Mode HighRankRules -SearchURL http://mysite/sites/search
  
  4. Repeat step 2 with the .cvs file created in step 3.
  PS C:>.\Test-BestBetQueryRules.ps1 -Delete -Mode InvalidRules -PathToCSV .\InvalidBestBetQueryRules-default-SSA.csv 
  
  5. Use the Log parameter and QueryRulesWithoutActions mode to discover any 
  actionless Query Rules.
  PS C:>.\Test-BestBetQueryRules.ps1 -Log -Mode RulesWithoutActions -Level SSA 
  
  6. Repeat step 2 with the .cvs created in step 5.
  PS C:>.\Test-BestBetQueryRules.ps1 -Delete -Mode RulesWithoutActions -PathToCSV .\RulesWithoutActions-SSA.csv
  
.EXAMPLE
  .\Test-BestBetQueryRules.ps1 -Status -Level SSA
  
  .\Test-BestBetQueryRules.ps1 -Log -Mode InvalidRules -Level SSA
  
  .\Test-BestBetQueryRules.ps1 -Log -Mode InvalidRules -Level Site -SiteURL http://mysite/path
  
  .\Test-BestBetQueryRules.ps1 -Delete -Mode InvalidRules -DeleteRuleWithoutActions -PathToCSV .\InvalidBestBetQueryRules-default-SSA.csv -WhatIf
  
  .\Test-BestBetQueryRules.ps1 -Delete -Mode InvalidRules -PathToCSV .\InvalidBestBetQueryRules-default-SSA.csv 
  
  .\Test-BestBetQueryRules.ps1 -Log -Mode HighRankRules -SearchURL http://mysite/sites/search
  
.LINK
  http://gallery.technet.microsoft.com/ScriptCenter
.NOTES
  File Name : Test-BestBetQueryRules.ps1
  Author  : Eric Dixon
  Tags   : SharePoint 2013, Enterprise Search, SP2013ES, SP2013
 
#>

param(
	[Parameter(Mandatory=$True, ParameterSetName='Status')]
    [switch]$Status=$false, 
    
	[Parameter(Mandatory=$True, ParameterSetName='DeleteRules')]
    [switch]$Delete=$false, 
	[Parameter(Mandatory=$True, ParameterSetName='DeleteRules')]
    [ValidateNotNullOrEmpty()][string]$PathToCSV="", 
	[Parameter(ParameterSetName='DeleteRules')]
    [switch]$DeleteRuleWithoutActions=$False,
    [Parameter(ParameterSetName='DeleteRules')]
    [switch]$Confirm=$False,

	[Parameter(Mandatory=$True, ParameterSetName='LogRules')]
    [switch]$Log=$false, 

	[Parameter(Mandatory=$True, ParameterSetName='DeleteRules')]
	[Parameter(Mandatory=$True, ParameterSetName='LogRules')]
	[ValidateSet('InvalidRules', 'HighRankRules', 'RulesWithoutActions')]
	[string]$Mode,

	[Parameter(Mandatory=$True, ParameterSetName='Status')]
	[Parameter(Mandatory=$True, ParameterSetName='LogRules')]
	[ValidateSet('SSA', 'Tenant', 'SiteCollection', 'Site')]
	[string]$Level,

	[Parameter(ParameterSetName='Status')]
	[Parameter(ParameterSetName='LogRules')]
    [string]$SiteURL="N/A", 

	[Parameter(ParameterSetName='Status')]
	[Parameter(ParameterSetName='LogRules')]
    [ValidateNotNullOrEmpty()]
    [string]$SearchURL, 

	[Parameter(ParameterSetName='LogRules')]
    [int]$RankThreshold=3,

    [switch]$WhatIf=$False
)

Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue

function Init
{
    CheckVersion
	if($Delete)
	{
		if(-not (Test-Path $PathToCSV))
		{
			Log -message "Cannot find file '$PathToCSV'. Aborting script." -color "Red"
			exit
		}
		
		$global:logFile = $PathToCSV
		$content = Get-Content -Path $global:logFile
		$arr = $content[0].Split('#')
		$p = $arr[2].Split()
        if(-not $Confirm)
        {
       	    AreYouSure -site $p[1] -level $p[2]
        }
        $SiteURL = $p[1]
        $Level = $p[2]
	}
    elseif($Log)
	{
        switch($Mode)
        {
            "InvalidRules"
            {
                $logfilename = "InvalidBestBetQueryRules"
            }
            "HighRankRules"
            {
                if($SearchURL)
                {
                    $logfilename = "HighRankBestBetQueryRules"
                }
                else
                {
		            Log -message "SearchURL parameter must have a value. Aborting script." -color "Red"
		            exit
                }
            }
            "RulesWithoutActions"
            {
                $logfilename = "RulesWithoutActions"
            }
	        default
	        {
		        Log -message "Not a valid mode. Aborting script." -color "Red"
		        exit
	        }
        }

        if($SiteURL -eq "N/A")
        {
            if($Level -ne "SSA")
            {
    			Log -message "You must enter a value for SiteURL when Level is set to Site, SiteCollection or Tenant. Aborting script." -color "Red"
                exit            
            }
    	    $global:logFile = "{0}-{1}.csv" -f $logfilename, $Level
        }
        else
        {
            $site = ([System.Uri]$SiteURL).Host + (([System.Uri]$SiteURL).LocalPath -replace '/', '_')
    	    $global:logFile = "{0}-{1}-{2}.csv" -f $logfilename, $site.Trim("_"), $Level
        }
		if(Test-Path $global:logFile)
		{
            $newFile = [System.IO.Path]::GetFileNameWithoutExtension($global:logFile) + "-" + $(Get-Date -f "yyyyMMdd-HHmmss") + [System.IO.Path]::GetExtension($global:logFile)
			Log -Message "Found existing log file.  Renaming to $newFile" -color "yellow"
            Rename-Item $global:logFile $newFile
		}
	}
    elseif($Status)
    {
        if($SiteURL -eq "N/A")
        {
            if($Level -ne "SSA")
            {
    			Log -message "You must enter a value for SiteURL when Level is set to Site, SiteCollection or Tenant. Aborting script." -color "Red"
                exit            
            }
        }
    }
    else
    {
    	Log -message "How did you get here? Aborting script." -color "Red"
        exit            
    }	

	# get the SSA 
	$global:ssa = GetSSA
	switch($Level)
	{
		"SSA" 
		{	
			$level = "SSA"
			$searchObjectOwner = New-Object Microsoft.Office.Server.Search.Administration.SearchObjectOwner("SSA")
		}
		"Tenant"
		{
			$ownerLevel = "SPSiteSubscription"
			$web = Get-SPWeb $SiteURL 
			$searchObjectOwner = New-Object Microsoft.Office.Server.Search.Administration.SearchObjectOwner($ownerLevel, $web)
		}
		"SiteCollection"
		{
			$ownerLevel = "SPSite"
			$web = Get-SPWeb $SiteURL 
			$searchObjectOwner = New-Object Microsoft.Office.Server.Search.Administration.SearchObjectOwner($ownerLevel, $web)
		}
		"Site"
		{
			$ownerLevel = "SPWeb"
			$web = Get-SPWeb $SiteURL 
			$searchObjectOwner = New-Object Microsoft.Office.Server.Search.Administration.SearchObjectOwner($ownerLevel, $web)
		}
		default 
        {
            Log("You didn't enter an excepted level. Aborting script.")
            exit
        }
	}
	$global:searchObjectFilter = New-Object Microsoft.Office.Server.Search.Administration.SearchObjectFilter($searchObjectOwner)

	# create a new QueryRuleManager instance
	# http://msdn.microsoft.com/en-us/library/jj268134(v=office.15).aspx
	$global:ruleManager = New-Object Microsoft.Office.Server.Search.Query.Rules.QueryRuleManager($ssa)  
	# printOMReference $ruleManager 
	# http://msdn.microsoft.com/en-us/library/microsoft.office.server.search.query.rules.queryrulemanager.getqueryrules(v=office.15).aspx
	
	#$global:rules = $null
	$global:progressCount = 0
	$global:progressCountMax = 0
}

function CheckVersion
{
    if($PSVersionTable.PSVersion.Major -lt 3)
    {
        Write-Warning "You are running an older version of PowerShell which may not support the commands used in this script."
    }
}

Function AdministrativeRightsCheck
{
	if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		Write-Warning "Not running as Administrator. Administrative rights maybe required to fully execute this script."
	}
}


function Select-TextItem  
{  
PARAM   
(  
    [Parameter(Mandatory=$true)]  
    $options,  
    $displayProperty  
)  
  
    [int]$optionPrefix = 1  
    # Create menu list  
    foreach ($option in $options)  
    {  
        if ($displayProperty -eq $null)  
        {  
            Write-Host ("{0,3}: {1}" -f $optionPrefix, $option)  
        }  
        else  
        {  
            Write-Host ("{0,3}: {1}" -f $optionPrefix, $option.$displayProperty)  
        }  
        $optionPrefix++  
    }  
    Write-Host ("{0,3}: {1}" -f 0, "To cancel")   

    [int]$response = Read-Host "Enter Selection"  

    $val = $null  
    if ($response -gt 0 -and $response -le $options.Count)  
    {  
        $val = $options[$response-1]  
    }  

    return $val  
}     
  
function GetSSA
{
    $ssas = @(Get-SPEnterpriseSearchServiceApplication)
    if(($ssas -eq $null) -or ($ssas.Count -eq 0))
    {
        Log -message  "Search Service Application not found. Aborting script." -color "Red"
        exit
    }
    elseif ($ssas.Count -gt 1)
    {
        $ssa = Select-TextItem $ssas "DisplayName" 
        if($ssa -eq $null)
        {
            Log -message "Not a valid selection. Aborting script." -color "Red"
            exit
        } 
    }
    else
    {
        $ssa = $ssas[0]
    }

    if ($ssa.Status -ne "Online")
    {
        $ssaStat = $ssa.Status
        Log -message "Expected SSA to have status 'Online', found status: $ssaStat. Aborting script." -color "Red"
        exit
    }

    return $ssa
}

function AreYouSure($site,$level)
{
	switch($Mode)
	{
		"InvalidRules" 
		{
			$title = "Delete invalid Best Bets"
		}
		"HighRankRules" 
		{
			$title = "Delete high ranked Best Bets"
		}
		"RulesWithoutActions" 
		{
			$title = "Delete Query Rules without Actions"
		}
	}

	$message = "Are you sure you want to delete all the items logged in $($global:logFile)`nSite: $site`nLevel: $level"
	$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
		""
	$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
		""
	$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
	$result = $host.ui.PromptForChoice($title, $message, $options, 0) 

	switch ($result)
	{
		0 {return}
		1 {Log -message "Aborting script" -color "Red"; exit}
	}
}

function WriteProgress($activity,$operation)
{
    $p = [System.Convert]::ToInt32(($global:progressCount/$global:progressCountMax) * 100)
    Write-Progress -Activity $activity -Status "$p %" -CurrentOperation $operation -percentComplete $p
	$global:progressCount++
}

function Log($message, $color=$null)
{
	if([string]::IsNullOrEmpty($color))
	{
		Write-Host $message
	}
	else
	{
		Write-Host $message -Foregroundcolor $color
	}
}


function IsValidURL($url)
{
	$urlIsValid = $false
	try
	{
		$request = [System.Net.WebRequest]::Create($url)
		$request.Method = 'HEAD'
    	$request.Credentials = [System.Net.CredentialCache]::DefaultCredentials	
        $response = $request.GetResponse()
		$httpStatus = $response.StatusCode
		$urlIsValid = ($httpStatus -eq 'OK')
		$response.Close()
	}
	catch [System.Exception] 
	{
		$urlIsValid = $false
        $httpStatus = "Exception: $_"
	}

    $Obj = New-Object PSObject
    $Obj | Add-Member -MemberType NoteProperty -Name IsValid -Value $urlIsValid
    $Obj | Add-Member -MemberType NoteProperty -Name StatusCode -Value $httpStatus

	return $Obj
}

function ExecQuery($query, $sourceId)
{
    $site = New-Object Microsoft.SharePoint.SPSite $SearchURL

    $request = New-Object Microsoft.Office.Server.Search.Query.KeywordQuery($site)
    $request.QueryText = $query

    $request.ResultTypes = [Microsoft.Office.Server.Search.Query.ResultType]::RelevantResults
    $request.TrimDuplicates = $true
    $n = $request.SelectProperties.Add("DocId")
    $n = $request.SelectProperties.Add("Title")
    $n = $request.SelectProperties.Add("Path")
    $request.RowLimit = $RankThreshold
    $request.SourceId = $sourceId
    $resultTables = $request.Execute()
    $relevantResults = $resultTables[1]
    $results = $relevantResults.Table

    return $results
}

function IsRankedResult($term, $sourceId, $url)
{
    $isRanked = $false
    $pos = 1
    $results = ExecQuery -query $term -sourceId $sourceId

    foreach($r in $results)
    {
        if($r.Path -eq $url)
        {
            $isRanked = $true
            break
        }   
        $pos++
    }
    if(-not $isRanked)
    {
        $pos = -1
    }

    $Obj = New-Object PSObject
    $Obj | Add-Member -MemberType NoteProperty -Name IsRanked -Value $isRanked
    $Obj | Add-Member -MemberType NoteProperty -Name Position -Value $pos

	return $Obj

}

function TestRules_Empty($rules)
{
    $ruleList = @()
	foreach($r in $rules)
	{
        $operation = "Rule: " + $r.DisplayName
		WriteProgress -activity "Validating" -operation $operation
		if((-not $r.IsSystem) -and (IsEmptyRule -queryrule $r))
		{
            $csvObj = New-Object PSObject
            $csvObj | Add-Member -MemberType NoteProperty -Name DisplayName -Value $r.DisplayName
            $csvObj | Add-Member -MemberType NoteProperty -Name Id -Value $r.Id

            $ruleLIst += $csvObj
		}
    }

    WriteRulestoCSVFile -ruleList $ruleList
	Log("Wrote $($ruleList.Count) Query Rules with no Actions to file $($global:logFile)")
}

function TestRules_Rank($rules)
{
    $ruleList = @()
	foreach($r in $rules)
	{
		$operation = $r.Title + ": " + $r.Url.AbsoluteUri
		WriteProgress -activity "Validating" -operation $operation
        

        if(-not $global:ruleHash.ContainsKey($r.Id))
        {
            continue
        }

        $p = $global:queryRules | ? {$_.Id -eq $global:ruleHash[$r.Id].ParentId}
        if($p.QueryConditions.MatchingOptions -ne "FullQuery")
        {
            # only handle exact match rules
            continue
        }

        $terms = $p.QueryConditions.Terms
        $sourceId = $p.ContextConditions.SourceId

        foreach($t in $terms)
        {
		    $Obj = IsRankedResult -term $t -sourceId $sourceId -url $r.Url.AbsoluteUri
		    if($Obj.IsRanked)
		    {
                $csvObj = New-Object PSObject
                $csvObj | Add-Member -MemberType NoteProperty -Name URI -Value $r.Url.AbsoluteUri
                $csvObj | Add-Member -MemberType NoteProperty -Name Title -Value $r.Title
                $csvObj | Add-Member -MemberType NoteProperty -Name Id -Value $r.Id
                $csvObj | Add-Member -MemberType NoteProperty -Name Position -Value $Obj.Position
                $csvObj | Add-Member -MemberType NoteProperty -Name ParentId -Value $global:ruleHash[$r.Id].ParentId
                $csvObj | Add-Member -MemberType NoteProperty -Name CanDeleteParent -Value $global:ruleHash[$r.Id].CanDeleteParent

                $ruleLIst += $csvObj
		    }
        }
	}

    WriteRulestoCSVFile -ruleList $ruleList
	Log("Wrote $($ruleList.Count) ranked Best Bet Query Rules to file $($global:logFile)")
}

function TestRules_URL($rules)
{
    $ruleList = @()
	foreach($r in $rules)
	{
		$operation = $r.Title + ": " + $r.Url.AbsoluteUri
		WriteProgress -activity "Validating" -operation $operation
		
		$Obj = IsValidURL($r.Url.AbsoluteUri)
		if(-not ($Obj.IsValid))
		{
            $csvObj = New-Object PSObject
            $csvObj | Add-Member -MemberType NoteProperty -Name URI -Value $r.Url.AbsoluteUri
            $csvObj | Add-Member -MemberType NoteProperty -Name Title -Value $r.Title
            $csvObj | Add-Member -MemberType NoteProperty -Name Id -Value $r.Id
            $csvObj | Add-Member -MemberType NoteProperty -Name StatusCode -Value $Obj.StatusCode
            $csvObj | Add-Member -MemberType NoteProperty -Name ParentId -Value "<not found>"
            $csvObj | Add-Member -MemberType NoteProperty -Name CanDeleteParent -Value $false

            if($global:ruleHash.ContainsKey($r.Id))
            {
                $csvObj.ParentId = $global:ruleHash[$r.Id].ParentId
                $csvObj.CanDeleteParent = $global:ruleHash[$r.Id].CanDeleteParent
            }

            $ruleLIst += $csvObj
		}
	}

    WriteRulestoCSVFile -ruleList $ruleList
	Log("Wrote $($ruleList.Count) invalid Best Bet Query Rules to file $($global:logFile)")
}

function WriteRulestoCSVFile($ruleList)
{
    $ruleList | Export-CSV $global:logFile
	$content = Get-Content -Path $global:logFile
    if($content.Length -gt 0)
    {
	    $content[0] += "# $SiteURL $Level ### Do not edit or remove this line! ###"
    }
    else
    {
        $content = "## $SiteURL $Level ### Do not edit or remove this line! ###"
    }
	$content | Set-Content -Path $global:logFile
}

function DeleteRules_QueryRules($rulesToRemove, $queryRules)
{
    $count1 = 0
	foreach($r in $rulesToRemove)
	{
        $qr = $queryRules | ? {$_.Id -eq $r.Id}
        if($qr -ne $null)
        {
            $r | Add-Member -MemberType NoteProperty -Name Status -Value "Begin..."
            if(-not $WhatIf)
            {
                $queryRules.RemoveQueryRule($qr)
                $r.Status += "  Query Rule Deleted."
            }
            else
            {
    		    Log -message "What if: Would be deleting Query Rule '$($r.DisplayName)'" -color "Yellow"
            }
            $count1++
        }
        else
        {
   			Log -message "Query Rule not found [Id:$($r.Id)]" -color "Red"
            $r.Status += " Id not found."
            continue
        }
		if($WhatIf)
		{
            $activity = "What if: Would be deleting '$($r.DisplayName)'"
		}
		else
		{
            $activity = "Deleted"
		}
        $r.Status += " End."
		WriteProgress -activity $activity -operation $r.DisplayName
	}
	if($WhatIf)
	{
		Log -message "What if: Would have deleted $count1 Query Rules" -color "Yellow"
	}
	else
	{
		Log("Deleted $count1 Query Rules")
        $processedFile = "{0}.processed" -f [System.IO.Path]::GetFileNameWithoutExtension($global:logFile)
		if(Test-Path $processedFile)
		{
            $newFile = [System.IO.Path]::GetFileNameWithoutExtension($processedFile) + "-" + $(Get-Date -f "yyyyMMdd-HHmmss") + [System.IO.Path]::GetExtension($processedFile)
			Log -Message "Found existing processed file.  Renaming to $newFile" -color "yellow"
            Rename-Item $processedFile $newFile
		}
        $rulesToRemove | Export-Csv -Path $processedFile
	    $content = Get-Content -Path $processedFile
	    $content[0] += "# $SiteURL $Level"
	    $content | Set-Content -Path $processedFile
	}
}

function DeleteRules($rulesToRemove, $rules, $queryRules)
{
    $count1 = 0
    $count2 = 0
	foreach($r in $rulesToRemove)
	{
        $r | Add-Member -MemberType NoteProperty -Name Status -Value "Begin..."
    	$bb = $rules | ? {$_.Id -eq $r.Id}
        if($bb -ne $null)
        {
            if(-not $WhatIf)
            {
		        $rules.RemoveBestBet($bb)
                $r.Status += "  Best Bet Deleted."
            }
            else
            {
    			Log -message "What if: Would be deleting Best Bet '$($r.Title)'" -color "Yellow"
            }
            $count1++
        }
        else
        {
   			Log -message "Best Bet not found [Id:$($r.Id)]" -color "Red"
            $r.Status += " Best bet not found." 
            continue
        }
        if($DeleteRuleWithoutActions)
        {
            if($global:ruleHash.ContainsKey([guid]$r.Id))
            {
                $obj = $global:ruleHash[[guid]$r.Id]
                if($obj.CanDeleteParent)
                {
                    $qr = $queryRules | ? {$_.Id -eq $obj.ParentId}
                    if($qr -ne $null)
                    {
                        if(-not $WhatIf)
                        {
                            $queryRules.RemoveQueryRule($qr)
                            $r.Status += " Query Rule Deleted."
                        }
                        else
                        {
                   			Log -message "What if: Would be deleting Query Rule '$($qr.Displayname)'" -color "Yellow"
                        }
                        $count2++
                    }
                    else
                    {
               			Log -message "Query Rule not found [Id:$($qr.Id)]" -color "Red"
                        $r.Status += " Query Rule not found."
                    }
                }
                else
                {
                    $r.Status += " Query Rule has Actions."
                }
            }
            else
            {
       			Log -message "Best Bet not found in Query Rules [Id:$($r.Id)]" -color "Red"
                $r.Status += " Best Bet not found in Query Rules."
            }
        }
		if($WhatIf)
		{
            $activity = "What if: Would be deleting '$($r.Title)'"
		}
		else
		{
            $activity = "Deleted"
		}
        
        $r.Status += " End."
		WriteProgress -activity $activity -operation $r.Title
	}
	if($WhatIf)
	{
		Log -message "What if: Would have deleted $count1 Best Bets and $count2 Query Rules" -color "Yellow"
	}
	else
	{
		Log("Deleted $count1 Best Bets and $count2 Query Rules")
        $processedFile = "{0}.processed" -f [System.IO.Path]::GetFileNameWithoutExtension($global:logFile)
		if(Test-Path $processedFile)
		{
            $newFile = [System.IO.Path]::GetFileNameWithoutExtension($processedFile) + "-" + $(Get-Date -f "yyyyMMdd-HHmmss") + [System.IO.Path]::GetExtension($processedFile)
			Log -Message "Found existing processed file.  Renaming to $newFile" -color "yellow"
            Rename-Item $processedFile $newFile
		}
        $rulesToRemove | Export-Csv -Path $processedFile
	    $content = Get-Content -Path $processedFile
	    $content[0] += "# $SiteURL $Level"
	    $content | Set-Content -Path $processedFile
	}
}

function IsEmptyRule($queryrule)
{
	if(($queryrule.AssignBestBetsAction -ne $null) -and ($queryrule.AssignBestBetsAction.BestBetIds -ne $null) -and ($queryrule.AssignBestBetsAction.BestBetIds.Count -gt 0))
    {
        return $false
    } 
    
    if(($queryrule.CreateResultBlockActions -ne $null) -and ($queryrule.CreateResultBlockActions.Count -gt 0))
    {
        return $false
	}

    if(($queryrule.ChangeQueryAction -ne $null) -and ($queryrule.ChangeQueryAction.Count -gt 0))
    {
        return $false
    }

    return $true
}

function CanDeleteRule($queryrule)
{
	$CanDelete = -not $queryRule.IsSystem
	if($CanDelete -and (($queryrule.AssignBestBetsAction.BestBetIds.Count -gt 1) -or ($queryrule.CreateResultBlockActions.Count -gt 0))) 
    {
		$CanDelete = $false
	}
    if($CanDelete -and (($queryrule.ChangeQueryAction -ne $null) -and ($queryrule.ChangeQueryAction.Count -gt 0)))
    {
        $CanDelete = $false
    }

    return $CanDelete
}

function GetRulesHash
{
	$global:ruleHash = @{}
	
	foreach($qr in $global:queryRules)
	{
		$CanDeleteParent = CanDeleteRule -queryrule $qr
		foreach($id in $qr.AssignBestBetsAction.BestBetIds)
		{
			$Obj = New-Object PSObject
			$Obj | Add-Member -MemberType NoteProperty -Name ParentId -Value $qr.Id
			$Obj | Add-Member -MemberType NoteProperty -Name CanDeleteParent -Value $CanDeleteParent
			$global:ruleHash[$id] = $Obj
		}
	}
}

function GetRules
{
	$global:rules = $global:ruleManager.GetBestBets($global:searchObjectFilter)
	$global:queryRules = $global:ruleManager.GetQueryRules($global:searchObjectFilter)

    if(-not $Delete)
    {
        Log -message "Found $($global:queryRules.Count) query rules and $($global:rules.Count) Best Bets at $Level level"
    }
	if($Status)
	{
		exit
	}

    GetRulesHash
}


function GetRulesToDelete
{
    $ids = Import-Csv -Path $global:logFile
    if($ids -eq $null -or $ids.Count -eq 0)
    {
		Log -message "File '$global:logFile' has no nothing to delete.  Aborting script." -color "Red"
		exit
    }

    $global:progressCountMax = if($ids.Count -gt 0){$ids.Count}else{1}
	return $ids 
}

function Main
{
	Init
    GetRules

    if($Delete)
    {
		$rulesToDelete = GetRulesToDelete 

        Log -message "Found $($rulesToDelete.Count) query rules to delete in file $($global:logFile)"

        if($Mode -eq "RulesWithoutActions")
        {
            DeleteRules_QueryRules -rulesToRemove $rulesToDelete -queryRules $global:queryRules
        }
        else
        {
    		DeleteRules -rulesToRemove $rulesToDelete  -rules $global:rules -queryRules $global:queryRules
        }
    }
    elseif($Log)
    {
        switch($Mode)
        {
	        "InvalidRules"
            {
			    $global:progressCountMax = $global:rules.Count
			    TestRules_URL($global:rules)
	        }
            "HighRankRules"
	        {
			    $global:progressCountMax = $global:rules.Count
    		    TestRules_Rank($global:rules)
	        }
	        "RulesWithoutActions"
	        {
			    $global:progressCountMax = $global:queryRules.Count
                TestRules_Empty($global:queryRules)
	        }
            default {Log("You didn't enter an acceptable mode. Aborting script."); exit}
        }
    }     

    Log -message "Done." 
}

Main
