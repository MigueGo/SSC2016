Add-SPSolution -LiteralPath 'C:\SharePoint Build\LargeLoop.wsp'
Install-SPSolution -Identity c616e3ce-3bae-4ad0-a3d9-3838b517d10f -WebApplication http://operations -GACDeployment -CompatibilityLevel {15}


