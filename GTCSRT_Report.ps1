<#
Copyright 2021 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
#>
##! /usr/bin/env bash

# Version 1.0
# 4/3/2021

# Loads the findings .csv file from disk
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
function Load-TCOResults {

    $exists =Test-Path "$AppPath$($PathSep)TCO_Results.csv"
    if (!$exists)
    {
        write-warning "No TCO_Results.csv to process--exiting"
        exit 1
    }
    $f = Import-Csv "$AppPath$($PathSep)TCO_Results.csv"
    Write-Output $f
}

# Loads the html report template that has the placeholders for sections and data fields
function Get-ReportTemplate
{
   $o = (Get-Content "$AppPath$($PathSep)GTCSRT_Template.html") -join ""
   Write-Output $o;
}
# Gets all the findings for the specified VM
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
# Gets all findings that have a score greater than 0
function Get-ScoredFindings
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $Findings,
        [Parameter(Mandatory = $true)]
        $VMInstanceID
    )
    $scoredFindings = $Findings | where {$_.VMInstanceID -eq $VMInstanceID -and `
        $_.Score -gt 0}
    Write-Output $scoredFindings
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
# Returns whether the findings indicate SQL was installed. Findings should be for 1 VM
function Get-IsSQLInstalled
{
    [CmdletBinding()]
    param
    (
        # Findings for single VM
        [Parameter(Mandatory = $true)]
        $Findings
    )
    if ( (Get-FindingValue $Findings "SQL Service is Running") -ne "None" `
        -or (Get-FindingValue $Findings "SQL Server Installed") -ne "None")
        {
            return $true
        }
        else {return $false}
}
function Convert-TemplateBlock
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $Findings,

        # The tempalted HTML with placehoders
        [Parameter(Mandatory = $true)]
        $HTMLBlock,

        # These are any dynamic replacements (i.e. from the runtime report code )
        [Parameter(Mandatory = $false)]
        [Array[]]
        $DynFields
    )
    # The updateded HTML Block
    $updatedBlock= $HTMLBlock

    # Replace the dynamic, runitme fields first
    foreach ($dyn  in $DynFields)
    {
        $keyVal = $dyn -split '='
        $updatedBlock = $updatedBlock.Replace($keyVal[0],$keyVal[1])
    }

    # Get all the field replacement tokens
    $lines = $HTMLBlock -split "\]\]"

    foreach ($line in $lines)
    {
        $result=""

        # The field to be replaced
        $field = $line -split '\[\['
        if ($field.Count -gt 1 -and $Findings.Count -eq 1)
        {
            $searchfield=$field[1].Replace("Repeat_","")
        }
        elseif ($field.Count -gt 1 )
        {
            $searchfield=$field[1]
        }
        if ($searchfield -like "dyn_*"){continue}

        if ($field.Count -gt 1)
        {
            $result  = (Get-FindingValue $Findings $searchfield)
            if ( ![string]::IsNullOrWhiteSpace($result))
            {
                $fieldToken ="[[$($field[1])]]"
                $updatedBlock = $updatedBlock.Replace($fieldToken, $result)
            }
        }
   }
   Write-Output $updatedBlock
}
# Saves the final HTML report
function Save-Report
{
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        $Report
    )
    $Report | set-content "$AppPath$($PathSep)GCE_To_Cloud_SQL_Recommendations.html" -Force
}
function Insert-HTMLBlock
{
    [CmdletBinding()]
    param
    (
        # Templated HTML with section tokens (i.e. HTML comments)
        [Parameter(Mandatory = $true)]
        $OriginalHTML,

        # The new HTML to replace the entire section with
        [Parameter(Mandatory = $true)]
        $HTMLToInsert,

        # The starting token (i.e. HTML Comment). END token must match START token (replace 'start' with 'end')
        [Parameter(Mandatory = $true)]
        $StartToken
    )

    $startTokenLoc = $OriginalHTML.indexOf($StartToken)
    $endTokenLoc = $OriginalHTML.indexOf($StartToken.Replace("START","END"))
    $endHtml = $OriginalHTML.Substring($endTokenLoc + $StartToken.Replace("START","END").Length)

    $newHTML = $OriginalHTML.Substring(0,$startTokenLoc) + $HTMLToInsert + $endHtml

    Write-Output $newHTML
}
# For a set of findings for the same VM and step #, get the one with highest score
function Get-HightestScoreForStep
{
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        $Findings,
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        $Step
    )
    Write-Output $Findings | Where-Object {$_.Step -eq $Step} |Sort-Object -Property Score -Descending  | Select-Object -First 1
}
# Gets the number of VMs from all the findings that are considered easy migrations
function Get-EasyVMMigrations
{
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        $Findings,

        # the weighted migration difficulty threshold to call a migration easy
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        $PCTEasyThreshold
    )

    # Get list of VMs from findings
    $uniqueVMs = $Findings |  Select-Object  {$_.VMInstanceID, $_.ProjectID, $_.Zone} -Unique

   $easyCounter
   foreach ($vm in $uniqueVMs)
   {
       $vmFindings = Get-FindingsForVM $Findings $vm.'$_.VMInstanceID, $_.ProjectID, $_.Zone'[0]

       # Gets the weighted migration difficulty score
       $effort = Get-VMEffort $vmFindings
       if ( $effort -le $PCTEasyThreshold -and $effort -gt -1  ) {$easyCounter++}
   }
   Write-Output $easyCounter
}
# Returns the Percent of difficulty to migrate a VM based on weighted scoring
function Get-VMEffort
{
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        $Findings
    )

    # Only look at scored findings
    $filteredFindings = $Findings | where-object {$_.Scored -eq "yes"}

    # If no fidings with scores then return
    if ($filteredFindings.Count -eq 0)
    {
        Write-Output -1
        return
    }
    $lastStep=""; $scoredCount=0

    $baseWeight = 10

    foreach ($finding in $filteredFindings)
    {
        # Some steps have multiple findings due  variations on suspported SQL versions, only count the highest result
        if ($finding.Step -ne $lastStep)
        {
            $highScore = (Get-HightestScoreForStep $filteredFindings $finding.Step).Score
            Switch ($highScore)
            {
                0  {$weightedScore = 0}
                1  {$weightedScore = $baseWeight} # e.g. 10
                2  {$weightedScore = $baseWeight * 100} # e.g. 1000
                3  {$weightedScore = $baseWeight * 1000} # e.g. 10,000
            }
            $scoredCount++
            $totalWeighted+=$weightedScore
        }
        $lastStep=$finding.Step
    }
    # This should match the highest weighted value
    $totalScore = $baseWeight * 1000 * $scoredCount
    $effortPercent = [math]::round([float]($totalWeighted / $totalScore)*100)
    Write-Output $effortPercent
}
# Zips the css, images, and HTML report into  compressed zip file for easy download
function package-html
{
    # x-platform path seperator (Windows/Linux)
    $PathSep = (join-path -Path "a" -ChildPath "b").Substring(1, 1);
    $paths = @("$($AppPath)$($PathSep)css","$($AppPath)$($PathSep)images")

     Compress-Archive -LiteralPath $paths -DestinationPath "$($AppPath)$($PathSep)Recommendations.zip" -Force
     $html = Get-ChildItem -path "$($AppPath)$($PathSep)" | where-object {$_.name -like "*Recommendations.html" -or `
        $_.name -eq "TCO_Results.csv" -or $_.name -eq "findings.csv"} 
     $html | Compress-Archive -update -DestinationPath "$($AppPath)$($PathSep)Recommendations.zip"
}
# Converts the findings.csv results into an HTML report
function Convert-FindingsHTML {
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        $Findings
    )
    # These are the section tokens to be replaced in the HTML template
    $resultsStartToken ="<!-- START RESULTS -->"
    $projectStartToken ="<!-- START PROJECT -->"
    $VMStartToken  = "<!-- START VM -->"
    $findingsStartToken  = "<!-- START FINDINGS -->"

    # Comgine text array into one string
    $template= Get-ReportTemplate -join ""

    # Start index of Project block
    $startProjBlock = $template.indexOf($projectStartToken)

    # End index of Project block
    $endProjBlock = $template.indexOf($projectStartToken.Replace("START","END"))

    # The block of HTML that makes up  repeating project block
    $projBlock= $template.Substring($startProjBlock +$projectStartToken.Length, $endProjBlock - $startProjBlock-$projectStartToken.Length )

    $lastProject=""; $allProjects="" ;$allVMsBlock="";$lastVM ="";$newProjBlock=""
    $projCounter=0

    foreach ($finding in $Findings)
    {
        # Findings are created serially in order. This identifies when a new VM is started
        if ($finding.VMInstanceID -eq $lastVM){continue;}

        # Gets findings only for this VM
        $vmFindings = Get-FindingsForVM $Findings $finding.VMInstanceID

        # Identifies if VM has SQL Installed. If it doesn't then don't report it.
        $isSQL = Get-IsSQLInstalled $vmFindings
        if (!$isSQL)
        {
            continue
        }

        # Findings are created serially in order. This identifies when a new project is started
        if ($finding.VMInstanceID -eq $lastVM){continue;}

        # New project started
        if ($finding.ProjectID -ne $lastProject )
        {
            # Skip the first project so that a blank section isn't created
            if ($projCounter -gt 0 )
            {
                # Builds the project section with the included VM sections
                $allProjects += Insert-HTMLBlock $newProjBlock $allVMsBlock $VMStartToken
                $newProjBlock = $projBlock.Replace("[[ProjectID]]", $finding.ProjectID)
                $allVMsBlock=""
            }
            else {
                $firstProj = $Findings[0].ProjectID
                $newProjBlock = $projBlock.Replace("[[ProjectID]]", $firstProj )
            }
            $projCounter++
        }
        # New VM started
        if ($finding.VMInstanceID -ne $lastVM)
        {
            # Start index of the VM section
            $startVMBlock = $newProjBlock.indexOf($VMStartToken)

            # End index of the VM section
            $endVMBlock = $newProjBlock.indexOf($VMStartToken.Replace("START","END"))

            # The block of templated HTML that makes the repeating VM
            $vmBlock = $newProjBlock.Substring($startVMBlock + $VMStartToken.Length, $endVMBlock - $startVMBlock-$VMStartToken.Length )

            # Sets the the dynamic CSS coloring for the VM section
            $vmEffort = [int](Get-VMEffort $vmFindings)
            Switch ($vmEffort)
            {
                {$PSItem -le 10} {$effortColor="green"}
                {$PSItem -gt 10 -and $PSItem -le 80} {$effortColor="yellow"}
                {$PSItem -gt 50} {$effortColor="red"}
            }
            # Build single VM section with dynamic field replacements
            $newVMBlock  = Convert-TemplateBlock $vmFindings $vmBlock @("[[Dyn_Diffifuclty_PCT]]=$vmEffort","[[EffortColor]]=$effortColor")

            # Start index for findings section
            $startFindingBlock = $newVMBlock.indexOf($findingsStartToken)

            # End index for findings section
            $endFindingBlock = $newVMBlock.indexOf($findingsStartToken.Replace("START","END"))

            # The vlock of templated HTML that makes the repeating findings
            $findingBlock = $newVMBlock.Substring($startFindingBlock + $findingsStartToken.Length, $endFindingBlock - $startFindingBlock-$findingsStartToken.Length )

            # Only report findings for VM that have a score
            $vmScoredFindings =  Get-ScoredFindings $Findings $finding.VMInstanceID

            $newFindingBlock=""
            foreach ($vmScore in $vmScoredFindings)
            {
                switch ($vmScore.Score)
                {
                    1 {$scoreText="Easy"}
                    2 {$scoreText="Moderate"}
                    3 {$scoreText="Hard"}
                }
                #Builds the repeated findings block
                $newFindingBlock += Convert-TemplateBlock $vmScore $findingBlock @("[[Dyn_ScoreText]]=$scoreText")
            }

            #Add VM to cumulative VM section with included findings
            $allVMsBlock += Insert-HTMLBlock $newVMBlock $newFindingBlock $findingsStartToken
        }

        # Record the ladt proj / VM so that we can catch a new proj or new VM
        $lastProject = $finding.ProjectID
        $lastVM= $finding.VMInstanceID
    }

    # Adds project to cumulative projects section with all of their VMs (and nested findings)
    $allProjects += Insert-HTMLBlock $newProjBlock $allVMsBlock $VMStartToken

    # Insert all projects w/VMs w/findings into the results section
    $page=Insert-HTMLBlock $template $allProjects $resultsStartToken

    $easyMigrations = Get-EasyVMMigrations  $Findings -PCTEasyThreshold 10

    # Update any page-level dynamic fields
    $page = Convert-TemplateBlock  $Findings  $page @("[[Dyn_NumberOFEasy]]=$easyMigrations" )
    
    # Add TCO Summart as Dynamic Links
    $tcoResults = Load-TCOResults
    $tcoStats = $tcoResults[0]
    $gceCost = ([int]$tcoStats.Total_GCE_Cost)  *12
    $page = Convert-TemplateBlock  $Findings  $page @("[[Total_GCE_Cost]]=$('{0:C}' -f $gceCost )" )
    
    $csqlCost = ([int]$tcoStats.Total_CSQL_Cost)  *12
    $page = Convert-TemplateBlock  $Findings  $page @("[[Total_SQL_Cost]]=$('{0:C}' -f $csqlCost )" )

    $csqBenefit = ([int]$tcoStats.Total_GCE_vs_CSQL_TCO)  
    $page = Convert-TemplateBlock  $Findings  $page @("[[Total_GCE_vs_CSQL_TCO]]=$($csqBenefit)%" )

    $page = Convert-TemplateBlock  $Findings  $page @("[[TCO Link]]=TCO_Results.csv" )

    $page = Convert-TemplateBlock  $Findings  $page @("[[Findings Link]]=findings.csv" )
    

    Write-Output $page
}
$global:AppPath = $myinvocation.mycommand.Path | Split-Path -Parent
$global:PathSep = (join-path -Path "a" -ChildPath "b").Substring(1, 1);

# Fet all findings from finding.csv
$findings = Load-Findings

# Convert findings into HTML report
Convert-FindingsHTML $findings | Save-Report

# Zip HTML files for easy download
package-html
