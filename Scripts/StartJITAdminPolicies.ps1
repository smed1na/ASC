<#
.SYNOPSIS

Create a new Azure Security Center Just-In-Time admin request to open ports and connect to Azure VMs

.DESCRIPTION

Execute this script in the client computer from which you want to allow traffic to the Azure VMs in a specified resource group
Requires virtual machine contains tag "jitPolicy"
It requires AzureRM.Security module (version Preview 0.2.0 or higher)

.PARAMETER RGName
Name of the Resource Group containing VMs

.PARAMETER Hours
(Optional) Number of hours to request access. Default value = 1. Maximum value defined during policy creation using SetJITAdminPolicies.ps1

.EXAMPLE

PS C:> .\StartJITAdminRequest.ps1 -RGName MYRG -Hours 2

	
Name             : Microsoft Azure (aaaaaaaa-bbbb-cccc-dddd-1234567890ab) - user@domain.com
Account          : user@domain.com
SubscriptionName : Microsoft Azure 
TenantId         : 12345678-90ab-cdcd-dddd-aaaabbbbcccc
Environment      : AzureCloud


VirtualMachines   : {/subscriptions/aaaaaaaa-bbbb-cccc-dddd-1234567890ab/resourceGroups/MYRG/providers/Microsoft.Compute/virtualMachines/WindowsVM1,
	                /subscriptions/aaaaaaaa-bbbb-cccc-dddd-1234567890ab/resourceGroups/MYRG/providers/Microsoft.Compute/virtualMachines/LinuxVM1}
StartTimeUtc    : 10/10/2018 11:35:47
Requestor       : user@domain.com

#>

Param 
(
	[Parameter(Mandatory=$true,
	ValueFromPipeline=$true)]
	[String]
	$RGName,

	[Int]
	$Hours = 1,

	[Parameter(Mandatory=$true)]
	[ValidatePattern('\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b')] # Match IPv4 address
	[String]
	$SourceAddress
)

# Introduce here your subscription ID and location
$subscriptionId = "aaaaaaaa-bbbb-cccc-dddd-1234567890ab"
$location = "westeurope"

Write-Host "Using the following subscription $subscriptionId" -ForegroundColor Green
Select-AzureRmSubscription -SubscriptionId $subscriptionId

$jitPolicyResourceId = (Get-AzureRmJitNetworkAccessPolicy | Where-Object {$_.Id -like "*/$RGName/*"}).Id
if ($jitPolicyResourceId -eq $null) 
{
	Write-Error "The Resource Group parameter provided has not a valid JIT policy. Use SetJITAdminPolicies.ps1 to create it."
	exit
}

$endTime = (Get-Date).ToUniversalTime().AddHours($Hours).ToString("o")
Write-Host "Requesting access for source IP address $SourceAddress until UTC time $endTime for the following virtual machines" -ForegroundColor Green

if (-Not (Get-AzureRmResourceGroup -Name $RGName)) 
{ 
	Write-Error "Provided RGName parameter is not a valid Resource Group in Subscription $subscriptionID"
	exit
}

$vmList = Get-AzureRmVM -ResourceGroupName $RGName 
$JitPolicyArr = $null
ForEach ($vm in $vmList) {
	$vmName = $vm.Name
	$vmJitPolicy = $vm.Tags.jitPolicy
	Write-Host "$vmName with JIT Policy $vmJitPolicy" -ForegroundColor Green
	Switch ($vmJitPolicy)
	{
		"jitWindows"
		{
			Write-Host "    adding Windows VM rules" -ForegroundColor Green
			$JitPolicy = (@{
				id="/subscriptions/$subscriptionId/resourceGroups/$RGName/providers/Microsoft.Compute/virtualMachines/$vmName"
				ports=(
					@{
					number=3389;
					endTimeUtc=$endTime;
					allowedSourceAddressPrefix=@("$SourceAddress")},
					@{
					number=443;
					endTimeUtc=$endTime;
					allowedSourceAddressPrefix=@("$SourceAddress")}
				)
			})
			$JitPolicyArr+=@($JitPolicy)
			Continue
		}
		"jitLinux"
		{
			Write-Host "    adding Linux VM rules" -ForegroundColor Green
			$JitPolicy = (@{
				id="/subscriptions/$subscriptionId/resourceGroups/$RGName/providers/Microsoft.Compute/virtualMachines/$vmName"
				ports=(
					@{
					number=22;
					endTimeUtc=$endTime;
					allowedSourceAddressPrefix=@("$SourceAddress")},
					@{
					number=1521;
					endTimeUtc=$endTime;
					allowedSourceAddressPrefix=@("$SourceAddress")}
				)
			})
			$JitPolicyArr+=@($JitPolicy)
			Continue
		}
	}
}

Start-AzureRmJitNetworkAccessPolicy -ResourceId $jitPolicyResourceId -VirtualMachine $JitPolicyArr
