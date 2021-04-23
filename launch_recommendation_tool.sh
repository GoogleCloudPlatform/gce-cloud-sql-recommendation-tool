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


set -x

sudo dpkg --remove packages-microsoft-prod

wget https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo apt install powershell -y
wget --header 'Authorization: token b1a941a9a2c7beb70e518671502c5b56722cd9d4' https://raw.githubusercontent.com/GoogleCloudPlatform/gce-cloud-sql-recommendation-tool/master/GTCSRT.ps1
wget --header 'Authorization: token b1a941a9a2c7beb70e518671502c5b56722cd9d4' https://raw.githubusercontent.com/GoogleCloudPlatform/gce-cloud-sql-recommendation-tool/master/GTCSRT_Report.ps1
wget --header 'Authorization: token b1a941a9a2c7beb70e518671502c5b56722cd9d4' https://raw.githubusercontent.com/GoogleCloudPlatform/gce-cloud-sql-recommendation-tool/master/Rules.csv
wget --header 'Authorization: token b1a941a9a2c7beb70e518671502c5b56722cd9d4' https://raw.githubusercontent.com/GoogleCloudPlatform/gce-cloud-sql-recommendation-tool/master/GTCSRT_Template.html
wget -P css/ --header 'Authorization: token b1a941a9a2c7beb70e518671502c5b56722cd9d4' https://raw.githubusercontent.com/GoogleCloudPlatform/gce-cloud-sql-recommendation-tool/master/css/simpleGridTemplate.css
wget -P images/ --header 'Authorization: token b1a941a9a2c7beb70e518671502c5b56722cd9d4' https://raw.githubusercontent.com/GoogleCloudPlatform/gce-cloud-sql-recommendation-tool/master/images/google-cloud-sql.png
pwsh ./GTCSRT.ps1
pwsh ./GTCSRT_Report.ps1
