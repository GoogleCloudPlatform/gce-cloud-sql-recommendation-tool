#! /usr/bin/env bash

set -x

sudo dpkg --remove packages-microsoft-prod

wget https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo apt install powershell -y
wget --header 'Authorization: token b1a941a9a2c7beb70e518671502c5b56722cd9d4' https://raw.githubusercontent.com/steve-kurtz-google/Cloud-SQL-Recommendation-Tool/master/GTCSRT.ps1
wget --header 'Authorization: token b1a941a9a2c7beb70e518671502c5b56722cd9d4' https://raw.githubusercontent.com/steve-kurtz-google/Cloud-SQL-Recommendation-Tool/master/GTCSRT_Report.ps1
wget --header 'Authorization: token b1a941a9a2c7beb70e518671502c5b56722cd9d4' https://raw.githubusercontent.com/steve-kurtz-google/Cloud-SQL-Recommendation-Tool/master/Rules.csv
wget --header 'Authorization: token b1a941a9a2c7beb70e518671502c5b56722cd9d4' https://raw.githubusercontent.com/steve-kurtz-google/Cloud-SQL-Recommendation-Tool/master/GTCSRT_Template.html
wget -P css/ --header 'Authorization: token b1a941a9a2c7beb70e518671502c5b56722cd9d4' https://raw.githubusercontent.com/steve-kurtz-google/Cloud-SQL-Recommendation-Tool/master/css/simpleGridTemplate.css
wget -P images/ --header 'Authorization: token b1a941a9a2c7beb70e518671502c5b56722cd9d4' https://raw.githubusercontent.com/steve-kurtz-google/Cloud-SQL-Recommendation-Tool/master/images/google-cloud-sql.png
pwsh ./GTCSRT.ps1
pwsh ./GTCSRT_Report.ps1
