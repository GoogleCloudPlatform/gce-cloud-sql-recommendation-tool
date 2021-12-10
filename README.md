<!--
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
-->

## GCE Cloud SQL Recommendations Tool is an open-source project and not an officially supported Google product. For any bugs you encounter, please open an Issue on Github.



# Solution Overview
This tool provides modernization recommendations for migrating self-managed SQL Server instances on Google Compute Engine to fully managed Cloud SQL instances. The tool will identify features not available in MS SQL Server on Linux and make recommendations for how to implement them on Google Cloud, as well as a score for "ease of migration."

- [Solution Overview](#solution-overview)
- [GCE to Cloud SQL Recommendation Tool Usage](#gce-to-cloud-sql-recommendation-tool-usage)
- [Prerequisites](#prerequisites)
  - [Google Cloud Permissions](#google-cloud-permissions)
  - [RSA SSH Key](#rsa-ssh-key)
  - [OS Configuration](#os-configuration)
- [Application Flow](#application-flow)
- [Security Considerations](#security-considerations)
- [Optional Features & Configuration](#optional-features--configuration)
  - [Single Project Analysis (all VMs in project analyzed)](#single-project-analysis-all-vms-in-project-analyzed)
  - [Single VM Analysis](#single-vm-analysis)
  - [Use Existing Windows Admin User](#use-existing-windows-admin-user)
  - [Alternate SQL Port](#alternate-sql-port)

# GCE to Cloud SQL Recommendation Tool Usage
All of the functions included in the GCE to Cloud SQL Recommendation Tool can be run directly from Github.

- Step 1: Login to GCP Console

- Step 2: Launch Cloud Shell in Console
  !["Image of Cloud Shell Console highlighting an icon with a greater-than and underscore"](Readme/CloudShell.png)

- Step 3: Login with an account that has permissions to the projects containing SQL VMs
  ```
  gcloud auth login
  ```

- Step 4: Download Powershell Installation Script
```
wget --header 'Authorization: token b1a941a9a2c7beb70e518671502c5b56722cd9d4' https://raw.githubusercontent.com/GoogleCloudPlatform/gce-cloud-sql-recommendation-tool/master/launch_recommendation_tool.sh
```

- Step 5: Run script to install Powershell on Cloud Shell and automatically run the tool on all the projects that you have access to.   
   Note: To run the tool on a single project see the section "Optional Features & Configuration".
```
bash launch_recommendation_tool.sh
```

- Below is a screenshot of the tool running:
!["Image of Cloud Shell Console highlighting a progress bar showing the status of the analysis"](Readme/progress.png)

- Step 6: When the script completes, click the Cloud Shell ellipse and select **download** to download the results of the tool analysis
 !["Image of Cloud Shell Console highlighting an ellipse and the download dropdown option"](Readme/CloudShellDownload.png)

- Step 7: Enter **Recommendations.zip** and click the **Download** button
!["Image of a textbox with the text Recoomendations.zip and a highlighted download button"](Readme/CloudShellDownload2.png)

- Step 8: Unzip the **Recommendations.zip** file to a temporary folder

- Step 9: Open the uncompressed **GCE_To_Cloud_SQL_Recommendations.html** file to view the results of the analysis

# Prerequisites
## Google Cloud Permissions
- The account running the script must have:
  - Compute.admin permission
  - "Service Account User" permission on the service account that runs Compute Engine
- The policy **compute.disableSerialPortAccess** must not be enabled
## RSA SSH Key
- The script user should have an RSA SSH key at the project or instance level. The script will attempt to create one for the script user if one is not present; however, this may fail based on policy configuration.

## OS Configuration
- SQL Server must have **Windows Auth** or **Mixed Mode** enabled
- **SQLCmd** must be installed and enabled on the SQL Server default instance

# Application Flow
1. Script iterates over all projects the script user has access to
2. Script iterates through all VMs on each project
3. Script looks at the OS image to determine if it is a Windows OS
4. If Windows OS, it adds the GTCSRTSAC administrative user to the VM (stores password in memory only). **Note:** if the **User=** parameter is passed the script will use this administrative user.
5. Records the state of the Serial Access Console (SAC) configuration
6. If SAC is not enabled on the VM, script enables SAC access
7. Script executes commands for each step in the Rules.csv definition (if marked as enabled)
8. Results for each step's commands are stored in the Findings.csv file
9. After all steps have completed the GTCSRTSAC administrative user is deleted from the VM
10. The SAC configuration is returned to its original configuration for the VM (no changes if it was already enabled)
11. The Findings.csv file is parsed to generate an HTML report of the recommendations
12. The css, images and HTML are compressed into a Zip file for easy download

# Security Considerations
The analysis of SQL Server configurations requires administrative access to each VM to be evaluated for potential migrations to Cloud SQL. All commands to be executed on the VM through the SAC port are stored in the Rules.csv files (**Note:** net user /delete GTCSRTSACUser is not listed in the rules). 

Administrative Windows access is required to:
- Access the Serial Access Console on each VM
- The GTCSRTSACUser administrative Windows user will have access to run queries that read metadata about the SQL Server Database using SQLCmd. **Note:** if the **User=** parameter is passed the script will use this administrative user.
- The GTCSRTSACUser administrative user is able to list running processes to search for SQL-related processes. **Note:** if the **User=** parameter is passed the script will use this user instead.
- The GTCSRTSACUser administrative user is able to query the registry for installed apps. **Note:** if the **User=** parameter is passed the script will use this user instead.
- The GTCSRTSACUser administrative user is able to capture performance counters related to SQL Server. **Note:** if the **User=** parameter is passed the script will use this user instead.
- The results of each command are stored in the Findings.csv (i.e. this is the only place results are stored). The majority of results are counts of database objects or performance counters (i.e. numeric data).

# Optional Features & Configuration
## Note about running the commands below
When you run the command "**bash launch_recommendation_tool.sh**", it will download the code, install Powershell and analyze all your projects. The commands in this section expect that you already downloaded the code and installed Powershell. If you have not run the launch_recommendation_tool.sh yet, you can run it with the "-d" parameter to just download the code and install Powershell without analyzing all your projects. See example below:
```
bash launch_recommendation_tool.sh -d
````
You are now ready to run the commands in this section. 

## Single Project Analysis (all VMs in project analyzed)
- At the Cloud Shell prompt start the GTCSRT tool with the following command line arguments
```
pwsh GTCSRT.ps1 projectid=[Project ID]
```
## Single VM Analysis
- At the Cloud Shell prompt start the GTCSRT tool with the following command line arguments
```
pwsh GTCSRT.ps1 projectid=[Project ID] instanceid=[VM Instance Name]
```
## Use Existing Windows Admin User
- An existing Windows administrative user can be used in single VM, single project, or all project/all VM analysis mode. If the user belongs to a Windows AD domain then also specify the domain as another parameter.
```
pwsh GTCSRT.ps1 user=[Windows Admin User] domain=[Windows AD Domain]
```
## Alternate SQL Port
- In the Rules.csv file do a search and replace to replace **1433** with the desired SQL port
- Then execute the script
```
pwsh GTCSRT.ps1
```
## Generate the report
- After running any of the commands above, run this command to generate the report and save it as an archive called Recommendations.zip.
```
pwsh GTCSRT_Report.ps1
```
