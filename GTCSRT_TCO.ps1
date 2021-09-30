#! /usr/bin/env bash
#
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

function Load-Findings {

    $exists =Test-Path "$AppPath$($PathSep)findings.csv"
    if (!$exists)
    {
        write-warning "No findings.csv to process--exiting"
        exit 1
    }
    $f = Import-Csv "$AppPath$($PathSep)findings.csv"
    Write-Output $f
}
function Load-GCPOnDemandPricing {

    $exists =Test-Path "$AppPath$($PathSep)TCO_Rules.csv"
    if (!$exists)
    {
        write-warning "No On Demand Pricing file to process--exiting"
        exit 1
    }
    $f = Import-Csv "$AppPath$($PathSep)GCP_Ondemand_Pricing.csv"
    Write-Output $f
}
function Load-TCORules {

    $exists =Test-Path "$AppPath$($PathSep)TCO_Rules.csv"
    if (!$exists)
    {
        write-warning "No TCO rules to process--exiting"
        exit 1
    }
    $f = Import-Csv "$AppPath$($PathSep)TCO_Rules.csv"
    Write-Output $f
}
function Load-TCOResults {

    $exists =Test-Path "$AppPath$($PathSep)TCO_Results.csv"
    if (!$exists)
    {
        write-warning "No TCO results to process--exiting"
        exit 1
    }
    $f = Import-Csv "$AppPath$($PathSep)TCO_Results.csv"
    Write-Output $f
}
function Load-StaticCosts {

    $exists =Test-Path "$AppPath$($PathSep)Static_Costs.csv"
    if (!$exists)
    {
        write-warning "No Static Costs results to process--exiting"
        exit 1
    }
    $f = Import-Csv "$AppPath$($PathSep)Static_Costs.csv"
    Write-Output $f
}
function New-TCOResults {
  
    $f = Load-TCORUles
    $columns = """GCE_Instance"",""Notes"","
    foreach ($rule in $f)
    {
        if (!$columns.Contains($rule.RuleName))
        {
            $columns+= """"+ ($rule.RuleName.Replace(" ","_")) +""","
        }
    }
    $columns = $columns.Substring(0, $columns.length-1 );
    Add-Content -Path "$AppPath$($PathSep)TCO_Results.csv" -Value $columns -Force
}
function Archive-TCOResults
{
  $exists =Test-Path "$AppPath$($PathSep)TCO_Results.csv"
  if ($exists)
   {
     rename-item "$AppPath$($PathSep)TCO_Results.csv" "$AppPath$($PathSep)TCO_Results.csv_$(get-date -uformat "%s")"
   }
}
function Get-FindingsForVM
{
    [CmdletBinding()]
    param
    (
        # All findings
        [Parameter(Mandatory = $true)]
        $Findings,
        [Parameter(Mandatory = $true)]
        $VMInstanceID
    )
    $f =@()
    foreach ($finding in $Findings)
    {
        if ($finding.VMInstanceID -eq $VMInstanceID)
        {
            $f+=$finding
        }
    }
    Write-Output $f
}
# Returns a single value based on a set of findings. The findings should be for 1 VM
#    a static field is the hard coded columns in the Rules.csv  vs. description field in findings.csv
#    which could be anything
function Get-FindingValue
{
    [CmdletBinding()]
    param
    (
        # One VMs findings (e.g. Get-FindingsForVM)
        [Parameter(Mandatory = $true)]
        $Findings,
        [Parameter(Mandatory = $true)]
        $Description
    )
    $staticField, $result =""

    #Gets the header for the CSV
    $finding = $Findings[0]

    $objValue = $Finding | get-member | where Name -eq $Description
    $staticFieldObj = $objValue -split '='
    if ($staticFieldObj.Count -gt 1)
    {
       write-output $staticFieldObj[1]
       return
    }
    # Get the first reuslt back that had a captured result (i.e. some step # have multiple rules to get the same info)
    foreach ($finding in $Findings | Sort-Object {$_.Result -ne "None"})
    {
        if ($finding.Description.Trim() -eq $Description)
        {
            if ( ![string]::IsNullOrWhiteSpace($finding.Result.Trim())) {$result=$finding.Result}
        }
    }
    Write-Output $result
}
function Save-TCOResults
{
    param
    (
        # One VMs findings (e.g. Get-FindingsForVM)
        [Parameter(Mandatory = $true)]
        $TCOResults
    )
    $TCOResults | Export-Csv "$AppPath$($PathSep)TCO_Results.csv" -Force
}
function Write-TCOResultInstanceID
{
    param
    (
        # One VMs findings (e.g. Get-FindingsForVM)
        [Parameter(Mandatory = $true)]
        $VMInstanceID
    )
    Add-Content -Path "$AppPath$($PathSep)TCO_Results.csv" -Value """$VMInstanceID""" 
}
function Get-VMInstances
{
    $vmInstances = @()
    foreach ($finding in $global:Findings)
    {
        if ( !$vmInstances.Contains($finding.VMInstanceID))
        {
            $vmInstances +=$finding.VMInstanceID
        }
    }
    Write-Output $vmInstances
}
function Write-GCECPUMonthlyCost
{
    param (
        [Parameter(Mandatory = $true)]
        $Findings,
        [Parameter(Mandatory = $true)]
        $VMInstanceID
    )

    $cores = Get-FindingValue -Findings $Findings -Description "Cores"
    $ram = Get-FindingValue -Findings $findings -Description "RAM (In GB)"
    $instGen = Get-FindingValue -Findings $findings -Description "Instance Generation"
    $instType = Get-FindingValue -Findings $findings -Description "Instance Type"
    $searchpart1=""
    
    Switch ($instGen)
    {
        a2 {$searchpart1="a2 " }
        c2 {$searchpart1="compute optimized core " }
        e2 {$searchpart1="e2 " }
        n1 { $searchpart1="n2 "}
        n2 {$searchpart1="n2 " }
        n2d {$searchpart1="n2d amd " }
    }
    Switch ($instType)
    {
        micro {$searchpart2="instance core "}
        medium {$searchpart2="instance core "}
        custom {$searchpart2="custom instance core "}
        standard {$searchpart2="instance core"}
        highcpu {$searchpart2="instance core"}
        highmem {$searchpart2="instance core"}
    }
    if ($searchpart1.Contains("optimized")){$searchpart2=""}
    $searchString = $searchpart1 + $searchpart2     
    
    $tcoResults = Load-TCOResults
    $proc = $MyInvocation.MyCommand.Name
    $tcoRule = $TCORules | where {$_.RuleProcedure -eq $proc }
    $ruleVariables = $tcoRule.RuleVariables.Split(",")

    $newTCOResults =@()
    foreach ($sku in $OnDemandPricing)
    {        
        if ($sku.Description.ToLower().Contains($searchString))
        {
            $pricing =[int]$cores * [float]$sku.PricePerUsageUnit * [float]$tcoRule.RatioOfOnDemand * $ruleVariables[0].Split("=")[1]
            break;
        }
    }
    foreach ($tcoResult in $tcoResults)
    {                
         if ($tcoResult.GCE_Instance -eq $VMInstanceID)
        {
             $tcoResult.GCE_CPU_Monthly_Cost  = [Math]::Round($pricing,2)
        }
        $newTCOResults += $tcoResult
    }
    Save-TCOResults -TCOResults $newTCOResults
}
function Write-GCERAMMonthlyCost
{
    param (
        [Parameter(Mandatory = $true)]
        $Findings,
        [Parameter(Mandatory = $true)]
        $VMInstanceID
    )
    $cores = Get-FindingValue -Findings $findings -Description "Cores"
    $ram = Get-FindingValue -Findings $findings -Description "RAM (In GB)"
    $instGen = Get-FindingValue -Findings $findings -Description "Instance Generation"
    $instType = Get-FindingValue -Findings $findings -Description "Instance Type"
    $searchpart1=""

    Switch ($instGen)
    {
        a2 {$searchpart1="a2 " }
        c2 {$searchpart1="compute optimized ram " }
        e2 {$searchpart1="e2 " }
        n1 {$searchpart1="n2 " }
        n2 {$searchpart1="n2 " }
        n2d {$searchpart1="n2d amd " }
        
    }
    Switch ($instType)
    {
        micro {$searchpart2="instance ram "}
        medium {$searchpart2="instance ram "}
        custom {$searchpart2="custom instance ram"}
        standard {$searchpart2="instance ram "}
        highcpu {$searchpart2="instance ram "}
        highmem {$searchpart2="instance ram "}
    }
    if ($searchpart1.Contains("optimized")){$searchpart2=""}
    $searchString = $searchpart1 + $searchpart2     
    
    $proc = $MyInvocation.MyCommand.Name
    $tcoRule = $TCORules | where {$_.RuleProcedure -eq $proc }
    $ruleVariables = $tcoRule.RuleVariables.Split(",")

    $newTCOResults =@()
    foreach ($sku in $OnDemandPricing)
    {        
        if ($sku.Description.ToLower().Contains($searchString) )
        {
            $pricing = [int]$ram * [float]$sku.PricePerUsageUnit * [float]$tcoRule.RatioOfOnDemand * $ruleVariables[0].Split("=")[1]
            break;
        }
    }
    $tcoResults = Load-TCOResults
        
    foreach ($tcoResult in $tcoResults)
    {                
         if ($tcoResult.GCE_Instance -eq $VMInstanceID)
        {
             $tcoResult.GCE_RAM_Monthly_Cost  = [Math]::Round($pricing,2)
        }
        $newTCOResults += $tcoResult
    }
    Save-TCOResults -TCOResults $newTCOResults
}
function Write-GCEStorageMonthlyCost
{
    param (
        [Parameter(Mandatory = $true)]
        $Findings,
        [Parameter(Mandatory = $true)]
        $VMInstanceID
    )
    $cores = Get-FindingValue -Findings $findings -Description "Cores"
    $ram = Get-FindingValue -Findings $findings -Description "RAM (In GB)"
    $instGen = Get-FindingValue -Findings $findings -Description "Instance Generation"
    $instType = Get-FindingValue -Findings $findings -Description "Instance Type"
    $instStorageGB =  Get-FindingValue -Findings $findings -Description "Total VM Storage (In GB)"
    $instStorageType =  Get-FindingValue -Findings $findings -Description "Storage Type"
    
    $proc = $MyInvocation.MyCommand.Name
    $tcoRule = $TCORules | where {$_.RuleProcedure -eq $proc }
    $ruleVariables = $tcoRule.RuleVariables.Split(",")
    $prov_iops = $ruleVariables[1].Split("=")[1]
   
    $skuSearchString=""
    switch ($instStorageType)
    {
        'pd-standard' { $skuSearchString="storage pd capacity" }
        'pd-balanced' { $skuSearchString="balanced pd capacity" }
        'pd-ssd' { $skuSearchString="ssd backed pd" }
        'pd-extreme' { $skuSearchString="extreme pd capacity" }
    }

    $newTCOResults =@()
    foreach ($sku in $OnDemandPricing)
    {        
        if ($sku.Description.ToLower().Contains($skuSearchString) )
        {
            $pricing = [float]$sku.PricePerUsageUnit * [int]$instStorageGB * [float]$tcoRule.RatioOfOnDemand
            if ($instStorageType -eq "pd-extreme")
            {
                foreach ($sku in $OnDemandPricing)
                {
                    if ($sku.Description.ToLower().Contains("extreme pd iops") )
                    {
                        $pricing+= [int]$prov_iops * [float]$tcoRule.RatioOfOnDemand * [float] $sku.PricePerUsageUnit
                    }
                }    
            }
            break;
        }
    }
    $tcoResults = Load-TCOResults
        
    foreach ($tcoResult in $tcoResults)
    {                
         if ($tcoResult.GCE_Instance -eq $VMInstanceID)
        {
             $tcoResult.GCE_Storage_Monthly_Cost  = [Math]::Round($pricing,2)
        }
        $newTCOResults += $tcoResult
    }
    Save-TCOResults -TCOResults $newTCOResults
}
function Write-GCEOSLicMonthlyCost        
{
    param (
        [Parameter(Mandatory = $true)]
        $Findings,
        [Parameter(Mandatory = $true)]
        $VMInstanceID
    )
    $cores = Get-FindingValue -Findings $findings -Description "Cores"
    $ram = Get-FindingValue -Findings $findings -Description "RAM (In GB)"
    $instGen = Get-FindingValue -Findings $findings -Description "Instance Generation"
    $instType = Get-FindingValue -Findings $findings -Description "Instance Type"
    $osImage = Get-FindingValue -Findings $findings -Description "Windows OS Image"
    $isBYOL = Get-FindingValue -Findings $findings -Description "Is BYOL"
    
    if (!$instType -eq "custom")
    {
        $instType=""
    }
    $proc = $MyInvocation.MyCommand.Name
    $tcoRule = $TCORules | where {$_.RuleProcedure -eq $proc }
    $ruleVariables = $tcoRule.RuleVariables.Split(",")

    $newTCOResults =@()
    if ($isBYOL -eq "no")
    {
        foreach ($sku in $OnDemandPricing)
        {        
            if ($sku.Description.ToLower() -eq "licensing fee for windows server 2019 datacenter edition (cpu cost)" )
            {
                $pricing = [int]$cores*[float]$sku.PricePerUsageUnit * [float]$tcoRule.RatioOfOnDemand * $ruleVariables[0].Split("=")[1]
                break;
            }
        }
    }
    else {
        $pricing =0;
    }
    $tcoResults = Load-TCOResults
        
    foreach ($tcoResult in $tcoResults)
    {                
         if ($tcoResult.GCE_Instance -eq $VMInstanceID)
        {
             $tcoResult.GCE_OS_Lic_Monthly_Cost  = [Math]::Round($pricing,2)
        }
        $newTCOResults += $tcoResult
    }
    Save-TCOResults -TCOResults $newTCOResults
}
function Write-GCESQLicMonthlyCost        
{
    param (
        [Parameter(Mandatory = $true)]
        $Findings,
        [Parameter(Mandatory = $true)]
        $VMInstanceID
    )
    $cores = Get-FindingValue -Findings $findings -Description "Cores"
    $ram = Get-FindingValue -Findings $findings -Description "RAM (In GB)"
    $instGen = Get-FindingValue -Findings $findings -Description "Instance Generation"
    $instType = Get-FindingValue -Findings $findings -Description "Instance Type"
    $osImage = Get-FindingValue -Findings $findings -Description "Windows OS Image"
    $isBYOL = Get-FindingValue -Findings $findings -Description "Is BYOL"
    $version = Get-FindingValue -Findings $findings -Description "Version Complexity"
    $sqlLic = Get-FindingValue -Findings $findings -Description "SQL Edition"
    
    # Currently the billing API is missing SKUs for 2019
    if ($version -eq "2019") {$version=""}

    $sqlLicMatch = $sqlLic -match "(\w+)\s"
    $searchPart1 = $version + " " + $Matches[1].ToLower() + " on "
    
    if ($instType -eq "fi-micro") 
    { 
        $searchPart2= "f1-micro" 
    }
    elseif ($instType -eq "g1-small") 
    {
        $searchPart2 =" g1-small" 
    }
    else 
    {
        $searchPart2 ="vm with "
    }

    if ([int]$cores -lt 5)
    {
        $searchPart3="1 to 4 vcpu"
    }else 
    {
        $searchPart3 =$cores + " vcpu"
    }

    if ($instType -eq "f1-micro" -or $instType -eq "g1-micro") {$searchPart3=""}
    
    $searchString = $searchPart1 + $searchPart2 + $searchPart3 
    
   
    $proc = $MyInvocation.MyCommand.Name
    $tcoRule = $TCORules | where {$_.RuleProcedure -eq $proc }
    $ruleVariables = $tcoRule.RuleVariables.Split(",")

    $newTCOResults =@()
    if ($isBYOL -eq "no")
    {
        foreach ($sku in $OnDemandPricing)
        {        
            if ($sku.Description.ToLower().Contains($searchString))
            {
                $pricing =[float]$sku.PricePerUsageUnit * [float]$tcoRule.RatioOfOnDemand * $ruleVariables[0].Split("=")[1] 
                break;
            }
        }
    }
    else {
        $pricing =0;
    }
    $tcoResults = Load-TCOResults
        
    foreach ($tcoResult in $tcoResults)
    {                
         if ($tcoResult.GCE_Instance -eq $VMInstanceID)
        {
             $tcoResult.GCE_SQL_Lic_Monthly_Cost = [Math]::Round($pricing,2)
        }
        $newTCOResults += $tcoResult
    }
    Save-TCOResults -TCOResults $newTCOResults
}
function Get-StaticCost
{
    param (
    [Parameter(Mandatory = $true)]
    $Cost_Type)

    foreach ($line in $global:StaticCosts)
    {
        if ($line.CostType.Trim() -eq $Cost_Type.Trim())
        {
            Write-Output $line
            break
        }
    }
}
function Write-GCEDBMaintMonthlyCost        
{
    param (
        [Parameter(Mandatory = $true)]
        $Findings,
        [Parameter(Mandatory = $true)]
        $VMInstanceID
    )
    $cores = Get-FindingValue -Findings $findings -Description "Cores"
    $ram = Get-FindingValue -Findings $findings -Description "RAM (In GB)"
    $instGen = Get-FindingValue -Findings $findings -Description "Instance Generation"
    $instType = Get-FindingValue -Findings $findings -Description "Instance Type"
    $osImage = Get-FindingValue -Findings $findings -Description "Windows OS Image"
    $isBYOL = Get-FindingValue -Findings $findings -Description "Is BYOL"
    $dbs = Get-FindingValue -Findings $findings -Description "Number of User Databases"
    
    
    if (!$instType -eq "custom")
    {
        $instType=""
    }
    $proc = $MyInvocation.MyCommand.Name
    $tcoRule = $TCORules | where {$_.RuleProcedure -eq $proc }
    
    $ruleVariables = $tcoRule.RuleVariables.Split(",")
    $laborHoursPerMonth = $ruleVariables[0].Split("=")[1]

    $newTCOResults =@()
    $pricing = $(get-StaticCost "DB Admin Labor").Cost
    
    $tcoResults = Load-TCOResults
        
    foreach ($tcoResult in $tcoResults)
    {                
         if ($tcoResult.GCE_Instance -eq $VMInstanceID)
        {
             $tcoResult.GCE_DB_Maint_Labor_Monthly_Cost  = [Math]::Round($pricing,2) * [int]$dbs  * [float]$laborHoursPerMonth
        }
        $newTCOResults += $tcoResult
    }
    Save-TCOResults -TCOResults $newTCOResults
}
function Write-CSQLCPUMonthlyCost        
{
    param (
        [Parameter(Mandatory = $true)]
        $Findings,
        [Parameter(Mandatory = $true)]
        $VMInstanceID
    )
    $cores = Get-FindingValue -Findings $findings -Description "Cores"
    $ram = Get-FindingValue -Findings $findings -Description "RAM (In GB)"
    $instGen = Get-FindingValue -Findings $findings -Description "Instance Generation"
    $instType = Get-FindingValue -Findings $findings -Description "Instance Type"
    $osImage = Get-FindingValue -Findings $findings -Description "Windows OS Image"
    $isBYOL = Get-FindingValue -Findings $findings -Description "Is BYOL"
    $version = Get-FindingValue -Findings $findings -Description "Version Complexity"
    $sqlLic = Get-FindingValue -Findings $findings -Description "SQL Edition"
    
    # Currently the billing API is missing SKUs for 2019
    if ($version -eq "2019") {$version=""}
       
    $sqlLicMatch = $sqlLic -match "(\w+)\s"
    $searchString = "sql server: zonal - vcpu"
    
   
    $proc = $MyInvocation.MyCommand.Name
    $tcoRule = $TCORules | where {$_.RuleProcedure -eq $proc }
    $ruleVariables = $tcoRule.RuleVariables.Split(",")

    [float]$cores = [float]$cores * [float]$tcoRule.CSQLUnitRatio

    $newTCOResults =@()
    
    foreach ($sku in $OnDemandPricing)
    {        
       if ($sku.Description.ToLower().Contains($searchString))
       {
            $pricing = [float]$sku.PricePerUsageUnit * [float]$tcoRule.RatioOfOnDemand * [Math]::Round([float]$cores) * $ruleVariables[0].Split("=")[1] 
            break;
        }
    }
    $tcoResults = Load-TCOResults
        
    foreach ($tcoResult in $tcoResults)
    {                
         if ($tcoResult.GCE_Instance -eq $VMInstanceID)
        {
             $tcoResult.CSQL_CPU_Monthly_Cost = [Math]::Round($pricing,2)
        }
        $newTCOResults += $tcoResult
    }
    Save-TCOResults -TCOResults $newTCOResults
}
function Write-CSQLRAMMonthlyCost        
{
    param (
        [Parameter(Mandatory = $true)]
        $Findings,
        [Parameter(Mandatory = $true)]
        $VMInstanceID
    )
    $cores = Get-FindingValue -Findings $findings -Description "Cores"
    $ram = Get-FindingValue -Findings $findings -Description "RAM (In GB)"
    $instGen = Get-FindingValue -Findings $findings -Description "Instance Generation"
    $instType = Get-FindingValue -Findings $findings -Description "Instance Type"
    $osImage = Get-FindingValue -Findings $findings -Description "Windows OS Image"
    $isBYOL = Get-FindingValue -Findings $findings -Description "Is BYOL"
    $version = Get-FindingValue -Findings $findings -Description "Version Complexity"
    $sqlLic = Get-FindingValue -Findings $findings -Description "SQL Edition"
    
    # Currently the billing API is missing SKUs for 2019
    if ($version -eq "2019") {$version=""}
       
    $sqlLicMatch = $sqlLic -match "(\w+)\s"
    $searchString = "sql server: zonal - ram"
       
    $proc = $MyInvocation.MyCommand.Name
    $tcoRule = $TCORules | where {$_.RuleProcedure -eq $proc }
    $ruleVariables = $tcoRule.RuleVariables.Split(",")

    [float]$ram = [float]$ram * [float]$tcoRule.CSQLUnitRatio

    $newTCOResults =@()
    
    foreach ($sku in $OnDemandPricing)
    {        
       if ($sku.Description.ToLower().Contains($searchString))
       {
            $pricing = [float]$sku.PricePerUsageUnit * [float]$tcoRule.RatioOfOnDemand * [Math]::Round([float]$ram) * $ruleVariables[0].Split("=")[1] 
            break;
        }
    }
    $tcoResults = Load-TCOResults
        
    foreach ($tcoResult in $tcoResults)
    {                
         if ($tcoResult.GCE_Instance -eq $VMInstanceID)
        {
             $tcoResult.CSQL_RAM_Monthly_Cost = [Math]::Round($pricing,2)
        }
        $newTCOResults += $tcoResult
    }
    Save-TCOResults -TCOResults $newTCOResults
}
function Write-CSQLLicMonthlyCost        
{
    param (
        [Parameter(Mandatory = $true)]
        $Findings,
        [Parameter(Mandatory = $true)]
        $VMInstanceID
    )
    $cores = Get-FindingValue -Findings $findings -Description "Cores"
    $ram = Get-FindingValue -Findings $findings -Description "RAM (In GB)"
    $instGen = Get-FindingValue -Findings $findings -Description "Instance Generation"
    $instType = Get-FindingValue -Findings $findings -Description "Instance Type"
    $osImage = Get-FindingValue -Findings $findings -Description "Windows OS Image"
    $isBYOL = Get-FindingValue -Findings $findings -Description "Is BYOL"
    $version = Get-FindingValue -Findings $findings -Description "Version Complexity"
    $sqlLic = Get-FindingValue -Findings $findings -Description "SQL Edition"
    
    $proc = $MyInvocation.MyCommand.Name
    $tcoRule = $TCORules | where {$_.RuleProcedure -eq $proc }
    $ruleVariables = $tcoRule.RuleVariables.Split(",")
    
    [float]$cores = [Math]::Round([float]$cores * [float]$tcoRule.CSQLUnitRatio)
        
    # Currently the billing API is missing SKUs for 2019
    if ($version -eq "2019") {$version=""}

    $sqlLicMatch = $sqlLic -match "(\w+)\s"
    $searchPart1 = $version + " " + $Matches[1].ToLower() + " on "
    
    if ($instType -eq "fi-micro") 
    { 
        $searchPart2= "f1-micro" 
    }
    elseif ($instType -eq "g1-small") 
    {
        $searchPart2 =" g1-small" 
    }
    else 
    {
        $searchPart2 ="vm with "
    }

    if ([int]$cores -lt 5)
    {
        $searchPart3="1 to 4 vcpu"
    }else 
    {
        $searchPart3 =[string]$cores + " vcpu"
    }

    if ($instType -eq "f1-micro" -or $instType -eq "g1-micro") {$searchPart3=""}
    
    $searchString = $searchPart1 + $searchPart2 + $searchPart3 
   
    $newTCOResults =@()
    
    foreach ($sku in $OnDemandPricing)
    {        
       if ($sku.Description.ToLower().Contains($searchString))
       {
            $pricing = [float]$sku.PricePerUsageUnit * [float]$tcoRule.RatioOfOnDemand * $ruleVariables[0].Split("=")[1] 
            break;
       }
    }
    $tcoResults = Load-TCOResults
        
    foreach ($tcoResult in $tcoResults)
    {                
         if ($tcoResult.GCE_Instance -eq $VMInstanceID)
        {
             $tcoResult.CSQL_SQL_Server_Monthly_Lic_Cost = [Math]::Round($pricing,2)
        }
        $newTCOResults += $tcoResult
    }
    Save-TCOResults -TCOResults $newTCOResults
}
function Write-CSQLStorageMonthlyCost
{
    param (
        [Parameter(Mandatory = $true)]
        $Findings,
        [Parameter(Mandatory = $true)]
        $VMInstanceID
    )
    $cores = Get-FindingValue -Findings $findings -Description "Cores"
    $ram = Get-FindingValue -Findings $findings -Description "RAM (In GB)"
    $instGen = Get-FindingValue -Findings $findings -Description "Instance Generation"
    $instType = Get-FindingValue -Findings $findings -Description "Instance Type"
    $instStorageGB =  Get-FindingValue -Findings $findings -Description "Total VM Storage (In GB)"
    $instStorageType =  Get-FindingValue -Findings $findings -Description "Storage Type"
    [int]$dbUsedStorage = Get-FindingValue -Findings $findings -Description "SQL Server Storage Used (in GB)"

        
    $proc = $MyInvocation.MyCommand.Name
    $tcoRule = $TCORules | where {$_.RuleProcedure -eq $proc }
    $ruleVariables = $tcoRule.RuleVariables.Split(",")
    [int]$dbUsedStorage = [int]$dbUsedStorage * [float]$tcoRule.CSQLUnitRatio
    if ($dbUsedStorage -lt 10) {$dbUsedStorage = 10}
   
    $skuSearchString=""
    
    $skuSearchString ="sql server: zonal - standard storage"
    $newTCOResults =@()
    foreach ($sku in $OnDemandPricing)
    {        
        if ($sku.Description.ToLower().Contains($skuSearchString) )
        {
            $pricing = [float]$sku.PricePerUsageUnit  * [float]$tcoRule.RatioOfOnDemand * [float]$dbUsedStorage
            break;
        }
    }
    $tcoResults = Load-TCOResults
        
    foreach ($tcoResult in $tcoResults)
    {                
         if ($tcoResult.GCE_Instance -eq $VMInstanceID)
        {
             $tcoResult.CSQL_Storage_Monthly_Cost  = [Math]::Round($pricing,2)
        }
        $newTCOResults += $tcoResult
    }
    Save-TCOResults -TCOResults $newTCOResults
}
function Write-TotalGCEInstanceCost
{
    $results = Load-TCOResults
    $newTCOResults =@()
    foreach ($result in $results)
    {   
        $cols = $result | Get-Member
        $gceCost=0
        # Columns will only be tabulated if they begin with 'GCE'
        foreach ($col in $cols | where {$_.Name.StartsWith("GCE")})
        {
            if ($col.Name -eq "GCE_Instance"){continue}
            $def = $col.Definition.Split("=")[1]
            $gceCost += [float]$def
        }
        $result.Total_GCE_Instance_Cost = [Math]::Round($gceCost,2)
        $newTCOResults += $result
    }
    Save-TCOResults -TCOResults $newTCOResults
}
function Write-TotalCSQLInstanceCost
{
    $results = Load-TCOResults
    $newTCOResults =@()

    foreach ($result in $results)
    {        
        $cols = $result | Get-Member
        $csqlCost=0
        # Columns will only be tabulated if they begin with 'CSQL'
        foreach ($col in $cols | where {$_.Name.StartsWith("CSQL")})
        {
            $def = $col.Definition.Split("=")[1]
            $csqlCost += [float]$def
        }
        $result.Total_CSQL_Instance_Cost = [Math]::Round($csqlCost,2)
        $newTCOResults += $result
    }
    Save-TCOResults -TCOResults $newTCOResults
}
function Write-GCEMinusCSQLCost
{
    $results = Load-TCOResults
    $newTCOResults =@()
    foreach ($result in $results)
    {  
        $result.Diff_GCE_Minus_CSQL_Cost = [Math]::Round([float]$result.Total_GCE_Instance_Cost - [float]$result.Total_CSQL_Instance_Cost,2)
        $newTCOResults += $result
    }
    Save-TCOResults -TCOResults $newTCOResults
}
function Write-GCEVSCSQLTCO
{
    $results = Load-TCOResults
    $newTCOResults =@()
    foreach ($result in $results)
    {  
        $result.PCT_GCE_vs_CSQL_TCO = [Math]::Round((($result.Diff_GCE_Minus_CSQL_Cost ) / $result.Total_GCE_Instance_Cost) *100,1)
        $newTCOResults += $result
    }
    Save-TCOResults -TCOResults $newTCOResults
}
function Write-TotalGCECost
{
    $results = Load-TCOResults
    $newTCOResults =@()
    $total=0
    foreach ($result in $results)
    {  
        $total += [float]$result.Total_GCE_Instance_Cost
    }
    foreach ($result in $results)
    {  
        $result.Total_GCE_Cost = [Math]::Round($total,2)
        $newTCOResults += $result
    }
    Save-TCOResults -TCOResults $newTCOResults
}
function Write-TotalCSQLCost
{
    $results = Load-TCOResults
    $newTCOResults =@()
    $total=0
    foreach ($result in $results)
    {  
        $total += [float]$result.Total_CSQL_Instance_Cost
    }
    foreach ($result in $results)
    {  
        $result.Total_CSQL_Cost = [Math]::Round($total,2)
        $newTCOResults += $result
    }
    Save-TCOResults -TCOResults $newTCOResults
}
function Write-TotalGCEMinusCSQL
{
    $results = Load-TCOResults
    $newTCOResults =@()
    $diff = [MATH]::Round($results[0].Total_GCE_Cost - $results[0].Total_CSQL_Cost,2)
    
    foreach ($result in $results)
    {  
        $result.Total_GCE_Minus_CSQL_Cost = $diff
        $newTCOResults += $result
    }
    Save-TCOResults -TCOResults $newTCOResults
}
function Write-TotalGCEVSSQLTCO
{
    $results = Load-TCOResults
    $newTCOResults =@()
    $pct = [MATH]::Round( ($results[0].Total_GCE_Minus_CSQL_Cost / $results[0].Total_GCE_Cost) * 100,1)
    
    foreach ($result in $results)
    {  
        $result.Total_GCE_vs_CSQL_TCO = $pct
        $newTCOResults += $result
    }
    Save-TCOResults -TCOResults $newTCOResults
}
function Write-TcoNote
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory = $true)]
        $VMInstanceID,

        [Parameter(Mandatory = $true)]
        $Note
    )
    $results = Load-TCOResults 
    $newResults=@()

    foreach ($result in $results)
    {
        if ($result.GCE_Instance -eq $VMInstanceID)
        {
            $result.Notes = $Note
        }
        $newResults+=$result
    }
    Save-TCOResults -TCOResults $newResults
}
$global:AppPath = $myinvocation.mycommand.Path | Split-Path -Parent
$global:PathSep = (join-path -Path "a" -ChildPath "b").Substring(1, 1);
$global:OnDemandPricing = Load-GCPOnDemandPricing
$global:Findings = Load-Findings
$global:TCORules = Load-TCORUles
$global:StaticCosts = Load-StaticCosts

# Backup old previous result file
Archive-TCOResults
# Create a new results file
New-TCOResults

# Get all VM Instances IDs from the findings file
$vmInstances = Get-VMInstances

# Iterate through each VM Instance
foreach ($vmInstance in $vmInstances)
{
    # Add a result line item for the VM Instance so that results can all be written to a single line
    Write-TCOResultInstanceID $vmInstance
    
    # Iterate though all rules for the VM and dynamically execute the TCO function
    foreach ($rule in $TCORules)
    {
        $vmFindings = Get-FindingsForVM -Findings $Findings -VMInstanceID $vmInstance 
        
        # If ram or cores is not compatible with Cloud SQL do not include it as part of TCO
        $coreScore = $vmFindings | where {$_.Description -eq "Cores"} | select {$_.Score}
        $ramScore = $vmFindings | where {$_.Description -eq "RAM (In GB)"} | select {$_.Score}
        if ($ramScore.'$_.Score' -eq "3" -or $coreScore.'$_.Score' -eq "3") {
            Write-TcoNote -VMInstanceID $vmInstance -Note "GCE instance shape not compatible with Cloud SQL. TCO will not be provided for this instance."
            break
        }
        
        if ($rule.RuleProcedure -ne "")
        {
            Invoke-Expression "$($rule.RuleProcedure)  -Findings `$vmFindings -VMInstanceID `$vmInstance"
        }
    }
 }


