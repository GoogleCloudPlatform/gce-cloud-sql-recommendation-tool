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

$global:PathSep = (join-path -Path "a" -ChildPath "b").Substring(1, 1); # X-platform path seperator character
$global:AppPath = $myinvocation.mycommand.Path | Split-Path -Parent # Path the script is executing out of

$apiKey ="";


foreach ($arg in $args)
{
  $argKeyVal = $arg -split "="
  if ($argKeyVal[0].ToLower().Trim() -eq "apikey") {$apiKey =$argKeyVal[1].Trim() }
}

$servicesResp = Invoke-WebRequest -URI https://cloudbilling.googleapis.com/v1/services?key=$apiKey | ConvertFrom-Json 

$svcs = $servicesResp.services | where {$_.displayName -eq "Compute Engine"}
$computeResp, $skus="" 
foreach ($svc in $svcs)
{
    $npt=$null
    do {
        
        if (!$npt) {
            $computeResp = Invoke-WebRequest -URI https://cloudbilling.googleapis.com/v1/services/$($svc.serviceId)/skus?key=$apiKey | ConvertFrom-Json 
            $skus=$computeResp.skus
        } 
        else 
        {
            $computeResp = Invoke-WebRequest -URI "https://cloudbilling.googleapis.com/v1/services/$($svc.serviceId)/skus?key=$apiKey&pageToken=$npt" | ConvertFrom-Json 
            $skus+=$computeResp.skus
        }
        $npt = $computeResp.nextPageToken
    } while ($npt -ne "")   
}
$skus = $skus | where  {$_.category.usageType -eq "OnDemand" -and `
  ($_.serviceRegions -contains "us-east4" `
   -or ($_.category.resourceFamily -eq "License" -and ($_.description -like "*Windows*" -or $_.description -like "*SQL*") ))  }  
  
$csqlResp = ""

$svcs = $servicesResp.services | where {$_.displayName -eq "Cloud SQL"}
foreach ($svc in $svcs)
{
    $ntp=$null
    do {
        
        if (!$npt) {
            $csqlResp = Invoke-WebRequest -URI https://cloudbilling.googleapis.com/v1/services/$($svc.serviceId)/skus?key=$apiKey | ConvertFrom-Json 
            $skus+=$csqlResp.skus 
        } 
        else 
        {
            $csqlResp = Invoke-WebRequest -URI "https://cloudbilling.googleapis.com/v1/services/$($svc.serviceId)/skus?key=$apiKey&pageToken=$npt" | ConvertFrom-Json 
            $skus+=$csqlResp.skus 
        }
        $npt = $computeResp.nextPageToken
    } while ($npt -ne "")   
}
$skus = $skus | where {$_.category.usageType -eq "OnDemand" -and `
($_.serviceRegions -contains "us-east4" `
   -or ($_.category.resourceFamily -eq "License" -and ($_.description -like "*Windows*" -or $_.description -like "*SQL*") ))  }  
  
[System.Collections.ArrayList]$gcpSkus = @()

for ($counter = 0; $counter -lt $skus.length; $counter++)
{
    $GCPPricing = [PSCustomObject]@{
        PSTypeName         = 'GCPPricing'
        SkuId              = $skus[$counter].skuId
        Description        = $skus[$counter].description
        ServiceDisplayName = $skus[$counter].category.serviceDisplayName
        ResourceFamily     = $skus[$counter].category.resourceFamily
        ResourceGroup      = $skus[$counter].category.resourceGroup
        ServiceRegion      = $skus[$counter].serviceRegions[0]
        UsageUnitDescription = $skus[$counter].pricingInfo.pricingExpression.UsageUnitDescription
        BaseUnitDescription = $skus[$counter].pricingInfo.pricingExpression.baseUnitDescription
        BaseUnitConversionFactor = $skus[$counter].pricingInfo.pricingExpression.baseUnitConversionFactor
        StartUsageAmount =  $skus[$counter].pricingInfo.pricingExpression.tieredRates[0].startUsageAmount
        DisaplayQuantity = $skus[$counter].pricingInfo.pricingExpression.displayQuantity
        CurrencyCode =  $skus[$counter].pricingInfo.pricingExpression.tieredRates[0].unitPrice.currencyCode
        Unit =  $skus[$counter].pricingInfo.pricingExpression.tieredRates[0].unitPrice.units
        Nanos = $skus[$counter].pricingInfo.pricingExpression.tieredRates[0].unitPrice.nanos
        GeoTaxonomy = $skus[$counter].geoTaxonomy.type
        PricePerUsageUnit = [float]0.0
    }
    $GCPPricing.PricePerUsageUnit = [int]$GCPPricing.Unit +  ( [int]$GCPPricing.Nanos/1000000000)
    $gcpSkus.Add($GCPPricing) >$null 2>&1
}
$gcpSkus | Export-Csv "$AppPath$($PathSep)GCP_Ondemand_Pricing.csv" -Force

Write-Output ""
