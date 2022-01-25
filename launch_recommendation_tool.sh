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


# Check if we only want to download the code and install Powershell
while getopts ":d" opt; do
  case ${opt} in
    d ) download=true
      ;;
    \? ) echo "Usage: bash launch_recommendation_tool.sh [-d]"
         echo " [-d] : Download code and install Powershell but don't run the scripts"
         exit
      ;;
  esac
done

set -x

# Install Powershell
sudo dpkg --remove packages-microsoft-prod
wget -nc https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo apt install powershell -y

# Download scripts
wget -nc https://raw.githubusercontent.com/GoogleCloudPlatform/gce-cloud-sql-recommendation-tool/master/GTCSRT.ps1
wget -nc https://raw.githubusercontent.com/GoogleCloudPlatform/gce-cloud-sql-recommendation-tool/master/GTCSRT_Report.ps1
wget -nc https://raw.githubusercontent.com/GoogleCloudPlatform/gce-cloud-sql-recommendation-tool/master/Rules.csv
wget -nc https://raw.githubusercontent.com/GoogleCloudPlatform/gce-cloud-sql-recommendation-tool/master/GTCSRT_Template.html
wget -nc -P css/ https://raw.githubusercontent.com/GoogleCloudPlatform/gce-cloud-sql-recommendation-tool/master/css/simpleGridTemplate.css
wget -nc -P images/ https://raw.githubusercontent.com/GoogleCloudPlatform/gce-cloud-sql-recommendation-tool/master/images/google-cloud-sql.png

# Exit if we just want to download the scripts
if [[ "${download}" == "true" ]] ; then
  exit
fi

# Run the recommendation tool and generate a report
pwsh ./GTCSRT.ps1 && pwsh ./GTCSRT_Report.ps1
