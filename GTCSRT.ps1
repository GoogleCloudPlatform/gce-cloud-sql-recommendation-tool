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
#! /usr/bin/env bash

# Version 1.1
# 4/23/2021

# Sends SSH commands over SAC Channel
function Send-SACCommand {
  [CmdletBinding()]
  param(
    # Has all needed information to use gcloud for compute APIs
    [Parameter(Mandatory = $true)]
    [PSTypeName('GCPDetails')]
    $GCPDetails,

    # The text to send over SAC channel
    [Parameter(Mandatory = $true)]
    $SendText,

    # Assocates a remark with the next command to be sent (i.e. Windows REM)
    [Parameter(Mandatory = $true)]
    $Remark
  )

  # establishes an SSH connection to the SAC serial port
  $sshString = "ssh -T -p 9600 -i {0} -o CheckHostIP=no -o ControlPath=none -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile={1} {2}.{3}.{4}.{5}.Port=2@ssh-serialport.googleapis.com" -f `
    $GCPDetails.PrivateKeyLocation , $GCPDetails.KnownHostsLocation, `
    $GCPDetails.ProjectID, $GCPDetails.Zone, $GCPDetails.VMInstanceID, $GCPDetails.GCPUser;

  $remarkString = "rem ~~~{0}" -f , $Remark;
  $sacRemarkString = "echo '{0}'|{1}" -f $remarkString, $sshString
  $sacSendTextString = "echo '{0}'|{1}" -f $SendText, $sshString

  $result = ""

  # If a remarkeis provded, send remark  and then send command
  if ($Remark -ne "") {
    $zz = Invoke-Expression $sacRemarkString *>&1 # *>&1 redirects the output for silent console interaction
    $result = Invoke-Expression $sacSendTextString *>&1
  }
  else {
    $result = Invoke-Expression $sacSendTextString *>&1
  }
  # Indicates that SAC connection/authentication failure
  if ($result -eq $null) { $result = "No Result" }

  # Strip out the VT TTY control characters
  $result = $result -replace '\e\[\d+;*\d+?[ABCDHJKfmsu]', '' -replace '\e\[K', '' -replace '\e\[\d+', ''
  Write-Output $result
}
# Sends the SAC authentincation and command completes the channel negoation process on VM
function Login-SAC {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [PSTypeName('GCPDetails')]
    $GCPDetails,

    # The Windows administrative user on the VM OS
    [Parameter(Mandatory = $true)]
    $VMUser,

    [Parameter(Mandatory = $true)]
    $VMPass
  )

  $zz = Send-SACCommand $GCPDetails "exit$EOL" ""   # $EOL is a global variable that supports x-platform (linux line feed)
  $zz = Send-SACCommand $GCPDetails "exit$EOL" ""

  if ($zz -eq "No Result")
  {
   Write-Host -nonewline "Attempting connection to serial console on: $($GCPDetails.VMInstanceID) to generate keys. "; write-host "You will need to exit and restart the script." -ForegroundColor "Yellow"

   # A common reason this would fail is that there wasn't an RSA SSH key present. This command automatically
   #    and propogates the SSH key. The script will need to be restarted.
   $createSSHKeys = invoke-expression "gcloud compute ssh $($GCPDetails.VMInstanceID) --force-key-file-overwrite --zone $($GCPDetails.Zone)" *>&1
   if ( $global:LASTEXITCODE -gt 0) {
     Write-Error "Failed to connect to serial console on: $($vm.name)"
     Remove-SACConfig $InstanceID $GCPDetails.Zone $true
     return
     }
  }

  # Empty SAC commands are entered so that the TTY buffer can be read back
  $status = Send-SACCommand $GCPDetails "$EOL" ""
  if ($status -eq "No Result") {Write-Output "failed SAC login"; return}

  # If stuck in an authentication loop, will exit back to the SAC control channel
  if ($status[$status.length - 1].Contains("authenticate")) {
    $zz = Send-SACCommand $GCPDetails "`e`t" ""
  }

  # Request a SAC command channel
  $zz = Send-SACCommand $GCPDetails "cmd" ""
  $resultStep1 = Send-SACCommand $GCPDetails "" ""

  # Extracts the channel ID
  $step1CmdChannel = Get-MatchResult -SACOutput $resultStep1 -RegexToMAtch 'Channel: (Cmd\d\d\d\d)'

  # Opens command channel
  $zz = Send-SACCommand $GCPDetails "ch -sn $step1CmdChannel" ""

  # To supports x-platform, sends appropriate "press any key" and the Windows user ID
  $zz = Send-SACCommand $GCPDetails "$AnyKey$VMUser" ""

  $zz = Send-SACCommand $GCPDetails "" ""
  $zz = Send-SACCommand $GCPDetails "$VMPass" ""

  # Takes time to complete SAC-OS negotiation
  Start-Sleep -Seconds 2

  $zz = Send-SACCommand $GCPDetails "$EOL" ""

}
function Get-MatchResult {
  [CmdletBinding()]
  param
  (
    # The result fomr the TTY session
    [Parameter(Mandatory = $true)]
    $SACOutput,

    # A regex to match result against
    [Parameter(Mandatory = $true)]
    $RegexToMatch
  )

  foreach ($result in $SACOutput) {
    $match = $result.ToString() -match $RegexToMatch
    if ($match) {
      $matchGroup = $Matches[1]

    }
  }
  if ($matchGroup -eq $null) {
    Write-Output "failed SAC login"
  }
  # Returns the regex match group
  else { Write-Output $matchGroup }

}
# Returns the SAC settings to their original value upon error or script completion
function Remove-SACConfig {
  [CmdletBinding()]
  param
  (
    # VM ID
    [Parameter(Mandatory = $false)]
    $InstanceID,

    # VM Zone
    [Parameter(Mandatory = $false)]
    $Zone,

    # The original state of the SAC configuration
    [Parameter(Mandatory = $false)]
    [bool]$SACWasAlreadyEnabled
  )

  # Closes the progress dialogue so that the output screen is not corrupted
  Write-Progress -Activity "$InstanceID Analysis Progress" -Completed
  if (![string]::IsNullOrWhiteSpace($instanceID))
  {

   # If a user was not provided as an arg, then delete the GTCSRTSACUser account from the VM
    if ($UserProvided -eq $false)
   {
      Send-SACCommand $GCPDetails "net user GTCSRTSACUser /delete$($EOL)" "Delete SAC User"
      Write-Host "Deleting GTCSRTSACUser: User that was created at beginning of script execution" -ForegroundColor Green
   }

    if (!$SACWasAlreadyEnabled) {
      $disableSAC = Invoke-Expression "gcloud compute instances remove-metadata $InstanceID  --zone $Zone --keys=serial-port-enable " *>&1
      Write-Host "Disabling SAC: Setting back to the original setting at the beginning of script execution" -ForegroundColor Green
    }
    else {
      Write-Host "Leaving SAC Enabled: This was the setting at the beginning of script execution" -ForegroundColor Green
    }

  }
}
# Exits the SAC Command session
function Exit-SAC{
  Send-SACCommand $GCPDetails "exit$($EOL)" ""
}

# Returns the rules.csv rows
function Get-Rules {
  $r = Import-Csv "$AppPath$($PathSep)Rules.csv"
  Write-Output $r
}

# If the script has been executed several times, thia will rename the previous findings.csv file so data is not lost
function Archive-FindingsFile
{
  $exists =Test-Path "$AppPath$($PathSep)findings.csv"
  if ($exists)
   {
     rename-item "$AppPath$($PathSep)findings.csv" "$AppPath$($PathSep)findings.csv_$(get-date -uformat "%s")"
   }
}

# Creates new finding file or appends result to and to the findings.csv file
function Add-Finding {
  [CmdletBinding()]
  param (
    [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
    [PSTypeName('Finding')]
    $Finding
  )
  $finding | Export-Csv "$AppPath$($PathSep)findings.csv"  -Append -Force
}

# Iterates over the Rules.csv and executes the command steps and captures results
#      as mapped in each rule.
function Process-Rules {
  [CmdletBinding()]
  param
  (
    # All rules in rows
    [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
    $Rules,

    # VM JSON object returned by gcloud compute
    [Parameter(Mandatory = $true)]
    $VM
  )
  $IsSQLVM = $false # As rules get exexuted will set if SQL matches are found
  $SQLInstance = "" # The SQL instance ID that gets retained for use accross rules

  # Matches the project ID for the VM
  $pmatch = $vm.selfLink -match "^.+/projects/([a-z0-9-]+)/.+$"
  $projID = $Matches[1]

  # Matches the zone for the VM
  $zm = $vm.zone -match "^.+/zones/([a-z0-9-]+)$"
  $zone = $Matches[1]

 # Custom Ojject that represents a finding as stored in findings.csv
  $finding = [PSCustomObject]@{
    PSTypeName     = 'Finding'
    ProjectID      = $projID
    Zone           = $zone
    VMInstanceID   = $VM.Name
    Step           = 0
    Category       = ""
    Description    = ""
    Scored         = "no"
    Score          = 0
    Result         = ""
    Recommendation = ""
  }

  # Matches the machine instnace type
  $mtm = $vm.machineType -match "^.+/machineTypes/([a-z0-9-]+)$"
  $machineType = $Matches[1];
  $finding.Category = "VM"
  $finding.Description = "Machine Type"
  $finding.Result = $machineType
  $finding | Add-Finding

  # Matches the machine OS image type. Disk 0 is always the OS disk
  $osm = $vm.disks[0].licenses[0] -match "^.+/licenses/([a-z0-9-]+)$"
  $OSImage = $Matches[1]
  $finding.Category = "VM"
  $finding.Description = "OS Image"
  $finding.Result = $OSImage
  $finding | Add-Finding

  # Used for the progress bar calculation
  $counter=0
  $ruleCount = $Rules.Count

  foreach ($rule in $Rules) {

    # VM analysis progress bar
    $pct =  [math]::Round( $counter/$ruleCount*100)
    Write-Progress -Activity "$($finding.VMInstanceID) Analysis Progress" -Status "$pct% Complete:" -PercentComplete $pct

    $finding.Category = $rule.Category
    $finding.Step = $rule.step
    $finding.Description = $rule.description
    $finding.Scored = $rule.has_score
    $finding.Recommendation = ""

    #If a rule is not enabled skip to the next rule
    if ($rule.step_enabled -eq "no") { continue }

    # Step 1 rules are  used to determine if the VM has SQL--if not skip to the next VM
    if ($rule.step -gt 1 -and $IsSQLVM -eq $false ) { return }

    # This is a dynamic rule that captures Is_BYOL for an  info finding
    if ($rule.description -like "*BYOL*") {
      if ($vm.disks[0].licenses[0] -notlike "*sql*" -and $IsSQLVM) { $finding.Result = "Yes" } Else { $finding.Result = "No" }
      $finding | Add-Finding
      continue
    }

    # Dynamic field used for any commands that need the instance name
    $rule.Command = $rule.Command.Replace("[[SQLInstance]]",$SQLInstance)

    # TTL serial comms sometimes fail--retry as needed
    $tries=0

  # START DO
    do
    {
      $tries++

      # TTY buffer maxes-out at 10K characters. There is no command to clear the buffer
      #    the only way to clear the buffer is to establish a new command channel
      if ($queryResult.Length -gt 0 -and $queryResult[$queryResult.Length - 1].length -gt 8000) {
       Login-SAC $GCPDetails $user $sacPw
      }

      # Need to fill the TTY buffer so that the results can be read back
      $queryResult += Send-SACCommand $GCPDetails "$EOL" ""
      $queryResult += Send-SACCommand  $GCPDetails "$($rule.command)$($EOL)" "$($rule.description)$($EOL)"
      $queryResult += Send-SACCommand $GCPDetails "$EOL" ""
      $queryResult += Send-SACCommand $GCPDetails "$EOL" ""

      # If the SAC prompt is returned, this means that the command channel session failed to be established
      if ( ($queryResult[$queryResult.length - 1]) -like "*SAC>*") {Login-SAC $GCPDetails $user $sacPw }

      if ($tries -gt 5)
      {
        Remove-SACConfig $vm.Name $zone $SACEnabled
        Write-Warning "SAC session failed on $($vm.name). Was the correct user/pass provided?"
        Send-SACCommand $GCPDetails "exit$($EOL)" ""
        return
      }
    }
    # If the last command is not found in the buffer keep trying until it is
    while (-not ($queryResult[$queryResult.length - 1]).Contains($rule.Description.Trim()))
  # END DO

    # Script Use commands are for rules that need a 2 step process
    #   e.g. 1) send asynch command and 2) return saved result
    #   Rules with the Script Use category do not return regex match
    if ($rule.Category -eq "Script Use") { continue }

    # Get end of TTY terminal buffer
    $trimmedResult1 = $queryResult[$queryResult.length - 1]

    # This marks  the last command result in the buffer
    $lastRemark = $trimmedResult1.lastindexof('~')

    # if no command is found read the entire buffer
    if ($lastRemark -eq -1){$lastRemark =0}

    # stips out all former command results in the buffer
    $trimmedResult2 = $trimmedResult1.Substring($lastRemark)

    # Strips out the command that was sent to prevent regex false positives
    #   TODO: need to make this strip out previous commands more reliably
    $trimmedResult = $trimmedResult2.Replace($rule.command,"")

    # Strips out the command prompt from the result
    $trimmedResult = $trimmedResult -replace "\w:\\Windows\\system32>", ' '

    # Match the result against the Rule's regex
    $matchSuccess = $trimmedResult -match "$($rule.regex)"
    $matchResult = "None"

    if ($matchSuccess) {

      # Get the capture group from the successful regex match
      if ($Matches -ne $null -and $Matches.Count -gt 0) { $matchResult = $Matches[1].Trim() }

      # Depending on the SQL version the command may fail.  Capture the instance name in either step
      if ($rule.description -eq "SQL Server Installed") {
        $SQLInstance = $matchResult
       }
       if ($rule.description -eq "SQL Instance Name") {
        $SQLInstance = $matchResult
       }

      $finding.Result = $matchResult

      if ($rule.has_score -eq "no") {
        $finding.Score = 0
      } #END IF: Rule doesn't have a score
      else {
        $finding.Score = 0

        # If the result is a number don't quote it
        if ($matchResult.Trim() -match "^\d*\.*\d+$") {
          $quotes = ""
        }
        else { $quotes = """" }

        # Dynamic condition created in a script block so that Powershell can be evaluated as listed in rule
        #  This matches low impact finding
        $cond1 = "if ($($quotes)$matchResult$($quotes) $($rule.low_impact_result1)){write-output 1}"
        $sb1 = [scriptblock]::Create( $cond1 )
        $oc1 = &($sb1)
        if ($oc1 -eq 1) {
          $finding.Score = 1
          $finding.Recommendation = $rule.low_recommendation
        }

        # This mactches a medium impact finding
        $cond2 = "if ($($quotes)$matchResult$($quotes) $($rule.med_impact_result2)){write-output 2}"
        $sb2 = [scriptblock]::Create( $cond2 )
        $oc2 = &($sb2)
        if ($oc2 -eq 2) {
          $finding.Score = 2
          $finding.Recommendation = $rule.med_recommendation
        }

        # This matches a high impact finding
        $cond3 = "if ($($quotes)$matchResult$($quotes) $($rule.high_impact_result3)){write-output 3}"
        $sb3 = [scriptblock]::Create( $cond3 )
        $oc3 = &($sb3)
        if ($oc3 -eq 3) {
          $finding.Score = 3
          $finding.Recommendation = $rule.high_recommendation
        }
      } # END ELSE: Rule has a score

    } #END IF: Match Success
    else {
      $finding.Score = 0
      $finding.Result = $matchResult
    } # END ELSE: No Match

    # Step 1 rules determine if SQL Server is installed/running
    if ($rule.Step -eq 1) {
      if ($finding.Result -like "*SQL*") { $IsSQLVM = $true }
    }
    $finding | Add-Finding
    $counter++
  }
  # VM analysis progress bar
  Write-Progress -Activity "$($finding.VMInstanceID) Analysis Progress" -Completed
}

########### START CORE SCRIPT ######################
$global:AnyKey = ""; # X-platform "press any key" charachter (Windows/Linux)
$global:EOL = ""; # X-platform linefeed charachter (Windows/Linux)
$global:GcpUser = "" # the gcloud API authenticated user
$global:PathSep = (join-path -Path "a" -ChildPath "b").Substring(1, 1); # X-platform path seperator character
$global:SACEnabled = $true # Was SAC enabled on VM at start of analysis/
$global:AppPath = $myinvocation.mycommand.Path | Split-Path -Parent # Path the script is executing out of
$global:sacPw = "" # The existing Windows user password or the new one created for GCTSRTSACUser
$global:projectID = ""
$global:instanceID = ""
$global:UserProvided = $false
$global:user="" # THe user passed in as a command line argument or GCTSRTSACUser if not

# Get the command line arguments
foreach ($arg in $args)
{
  $argKeyVal = $arg -split "="
  if ($argKeyVal[0].ToLower().Trim() -eq "projectid") {$projectID =$argKeyVal[1].Trim() }
  if ($argKeyVal[0].ToLower().Trim() -eq "instanceid") {$instanceID =$argKeyVal[1].Trim() }
  if ($argKeyVal[0].ToLower().Trim() -eq "user") {$user =$argKeyVal[1].Trim() }
}

if ($user -eq "")
{
  # This is the consent notification for auto-generating an administrative user
  write-host "You did not provide an existing credential. By answering 'Yes' using your GCP permissions, the script will create an administrative user (GTCSRTSACUser). `
  This user will be deleted at the end of the VM scan. This temporary admin user's password is randomly auto-generated. The password is not written or stored anywhere. `
  Do you consent to this? (YES/NO): " -ForegroundColor Red -NoNewline
  $consent = Read-Host
  if ($consent.ToLower() -eq "y" -or $consent.ToLower() -eq "Yes") {} else {return}      
}

# If user arg was sent get the password and ensure one was provided
if(![string]::IsNullOrWhiteSpace($user))
{
  $sacPwSS = Read-Host "Enter password" -AsSecureString
  $temp = New-Object PSCredential ("Decrypt", $sacPwSS)
  $sacPw = $temp.GetNetworkCredential().Password

  # Check if the password was provided and exit if not
  if (![string]::IsNullOrWhiteSpace($sacPw))
  {
    $UserProvided = $true
  }
  else
  {
    Write-Warning "A user was provided without a password"
    return
  }
}

# Sets the x-platform source SSH environment characters needed for Winodws/Linux
if ($IsLinux) {
  $AnyKey = " ";
  $EOL = "`r";
}

# Gets the gcloud authenticated user
$GCPFullyQualAccount = (Invoke-Expression "gcloud auth list --filter=status:ACTIVE --format json *>&1" | ConvertFrom-Json).account
if ( $global:LASTEXITCODE -gt 0) {
  Write-Error "Failed to list current authenticated account user"
  Remove-SACConfig $InstanceID  $zone $SACEnabled
  return
}

# If Linux get user ID from string and replace hypens with underscores
if ($IsLinux) {
  $GCPUser = $GCPFullyQualAccount.Substring(0, $GCPFullyQualAccount.indexOf("@")).Replace("-", "_").Replace(".","_")
}
# if Windows user get the authenticated user ID
else {
  $GCPUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
  if ($GCPUser.Contains($PathSep)) { $GCPUser = $GcpUser.Split($PathSep)[1] }
}

# Get the RSA SSH key locations for Windows or Linux
$privKeyLocation = """$home$($PathSep).ssh$($PathSep)google_compute_engine"""
$knownHostsLocation = """$home$($PathSep).ssh$($PathSep)google_compute_known_hosts"""

# Get all projects that the gcloud user has permissions to
$projects = Invoke-Expression "gcloud projects list --format json *>&1" | convertfrom-json
if ( $global:LASTEXITCODE -gt 0) {
  Write-Error "Failed to list projects under user: $gcpUser"
  Remove-SACConfig $InstanceID  $zone $true
  return
}

# If any findings.csv already exist rename them
$zz=Archive-FindingsFile

# Iterate through each project
for ($proj = 0; $proj -lt $projects.count; $proj++) {
  # Project Loop

  $project = $projects[$proj]


  # If a project ID is provided as an arg ignore any that does not match
  if ($projectID -ne "" -and $project.projectid -ne $projectID) { continue; }

  Write-host "Looking for Windows VMs in project:$($project.projectId)"

  $zz =  Invoke-Expression "gcloud config set project $($project.projectId)" *>&1

  # Sends 'Y' if prompted for confirmation
  $vms = Invoke-Expression "'Y' | gcloud compute instances list --format json" *>&1 | ConvertFrom-Json
  if ( $global:LASTEXITCODE -gt 0) {
    Write-Error "Failed to list compute instances for project:  $($project.projectId)"
    Remove-SACConfig $InstanceID $zone $true
    return
  }

  # If there are no VMs in project then move to the next project
  if ($vms -eq $null){continue}

  for ($v = 0; $v -lt $vms.count; $v++) {
    # VM Loop

    $vm = $vms[$v]

    # If an InstanceID is passed to the script as an argument skip if there is no match
    if ($instanceID -ne "" -and $vm.Name -ne $instanceID) { continue }

    # Gets the OS and SQL license of disk 0 which is the default OS disk at VM creation
    $lisc = @()
    $d1 = $vm.disks[0].licenses[0] -match "^.+/licenses/([a-z0-9-]+)$"
    if ($d1 -eq $true) { $lisc += $Matches[1] }
    $d2 = $vm.disks[0].licenses[1] -match "^.+/licenses/([a-z0-9-]+)$"
    if ($d2 -eq $true) { $lisc += $Matches[1] }

    # Skip VM if neither license is Windows
    if ($lisc[0] -notlike "windows*" -and $lisc[1] -notlike "windows*" ) {
      Write-host "Will not analyze $($vm.Name). Disk image: $($lisc[1] ?? $lisc[0])"
      continue;
    }
    elseif ($lisc[0] -like ("sql*")) {
      Write-host "Analyzing $($vm.Name). Premium SQL disk image: $lisc[0]"
    }
    else {
      Write-host "Analyzing $($vm.Name). Disk image: $lisc[0]"
    }

    # Capture the zone from the VM
    $zm = $vm.zone -match "^.+/zones/([a-z0-9-]+)$"
    $zone = $Matches[1]

    # If a user and pass was not provided -- will create SAC User on VM
    if ([string]::IsNullOrWhiteSpace($user) -or $user  -eq "GTCSRTSACUser")
    {
      $user="GTCSRTSACUser"
      write-Warning "Adding GTCSRTSACUser to instance: $($vm.Name)"

      # Will send 'Y' confirmation to user password resest prompt
      $GTCSRTSACUser = Invoke-Expression "'Y' | gcloud compute reset-windows-password $($vm.name) --user=$user --zone=$zone *>&1"

      # Captures the new password returned for the new SAC User
      $passmatch = $GTCSRTSACUser -match "password: (.+)"
      $sacPw = $passmatch[0].Substring($passmatch[0].IndexOf(": ") + 2, $passmatch[0].Length - $passmatch[0].IndexOf(": ") - 2).Trim()

      if ( $global:LASTEXITCODE -gt 0) {
        Write-Error "Failed to add Windows GTCSRTSACUser account"
        continue
      }
    }

    write-host "Checking if VM Serial Access Console (SAC) is enabled on instance: $($vm.Name)"

    # Adding the instance metadata that enables SAC connections
    $enableSAC = Invoke-Expression "gcloud compute instances add-metadata $($vm.Name) --metadata=serial-port-enable=TRUE --zone $($vm.zone) "  *>&1
    if ( $global:LASTEXITCODE -gt 0) {
      Write-Error "Unable to check/set instance metadata for $($vm.Name)"
      Remove-SACConfig $vm.Name $zone $true
      continue
    }

    # If "updated" is returned that means SAC was not previously enabled
    if ($enableSAC -like "Updated*") {
      Write-Warning "SAC was not enabled. Temporaily enabling for this analysis"
      $SACEnabled = $false
    }
    # Will return "no change" if SAC was already enabled
    else {
      Write-host "SAC was already enabled--no action taken."
      $SACEnabled = $true
    }

    $GCPDetails = [PSCustomObject]@{
      PSTypeName         = 'GCPDetails'
      ProjectID          = $project.projectId
      Zone               = $zone
      VMInstanceID       = $vm.Name
      GCPUser            = $GCPUser
      PrivateKeyLocation = $privKeyLocation
      KnownHostsLocation = $knownHostsLocation
    }

    # Negotiates, authenticates, and establishes SAC command session
    $o = Login-SAC $GCPDetails $user $sacPw
    if ($o -eq "failed SAC login") {
      Write-Error "Failed SAC Login"
      Remove-SACConfig $vm.Name $zone $SACEnabled
      return
    }

    # Loads the Rules.csv file from disk
    $rules = Get-Rules

    # Processes rules and creates findings
    $zz = Process-Rules  -Rules $rules -VM $vm

    # Resets SAC config to original state
    $zz = Remove-SACConfig $vm.name $zone $SACEnabled

    # Exits the SAV session for the VM
    $zz = Exit-SAC

  } # End VM Loop

} # End Project Loop
