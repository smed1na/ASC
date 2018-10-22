<#
.SYNOPSIS

Create a new Azure Security Center Just-In-Time policy to allow connecting to Azure VMs when required

.DESCRIPTION

Execute this script from a client computer with a PowerShell session to Azure RM.
allow traffic to the Azure VMs in a specified resource group
Requires virtual machine contains tag "jitPolicy"
It requires AzureRM.Security module (version Preview 0.2.0 or higher)

.PARAMETER RGName
Name of the Resource Group containing VMs

.EXAMPLE

PS C:> .\SetJITAdminPolicies.ps1 -RGName MYRG
Using the following subscription aaaaaaaa-bbbb-cccc-dddd-1234567890ab
	
Name             : Microsoft Azure (aaaaaaaa-bbbb-cccc-dddd-1234567890ab) - user@domain.com
Account          : user@domain.com
SubscriptionName : Microsoft Azure 
TenantId         : 12345678-90ab-cdcd-dddd-aaaabbbbcccc
Environment      : AzureCloud
	
Creating Azure Security Center Just-In-Time Admin policy for the following virtual machines
WindowsVM1 with JIT Policy Windows
	adding Windows VM rules
LinuxVM1 with JIT Policy Linux
	adding Windows VM rules
	
Id                : /subscriptions/aaaaaaaa-bbbb-cccc-dddd-1234567890ab/resourceGroups/MYRG/providers/Microsoft.Security/locations/westeurope/jitNetworkAccessPolicies/default
Name              : default
Kind              : Basic
VirtualMachines   : {/subscriptions/aaaaaaaa-bbbb-cccc-dddd-1234567890ab/resourceGroups/MYRG/providers/Microsoft.Compute/virtualMachines/WindowsVM1,
	                /subscriptions/aaaaaaaa-bbbb-cccc-dddd-1234567890ab/resourceGroups/MYRG/providers/Microsoft.Compute/virtualMachines/LinuxVM1}
Requests          : {}
ProvisioningState : Succeeded

#>
Param 
(
	[Parameter(Mandatory=$true,
	ValueFromPipeline=$true)]
	[String]
	$RGName
)

# Introduce here your subscription ID and location
$subscriptionId = "aaaaaaaa-bbbb-cccc-dddd-1234567890ab"
$location = "westeurope"

Write-Host "Using the following subscription $subscriptionId" -ForegroundColor Green
Select-AzureRmSubscription -SubscriptionId $subscriptionId

if (-Not (Get-AzureRmResourceGroup -Name $RGName)) 
{ 
	Write-Error "Provided RGName parameter is not a valid Resource Group in Subscription $subscriptionID"
	exit
}

Write-Host "Creating Azure Security Center Just-In-Time Admin policy for the following virtual machines" -ForegroundColor Green

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
					protocol="*";
					allowedSourceAddressPrefix=@("*");
					maxRequestAccessDuration="PT12H"},
					@{
					number=443;
					protocol="*";
					allowedSourceAddressPrefix=@("*");
					maxRequestAccessDuration="PT12H"}
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
					protocol="*";
					allowedSourceAddressPrefix=@("*");
					maxRequestAccessDuration="PT12H"},
					@{
					number=1521;
					protocol="*";
					allowedSourceAddressPrefix=@("*");
					maxRequestAccessDuration="PT12H"}
				)
			})
			$JitPolicyArr+=@($JitPolicy)
			Continue
		}
	}
}

Set-AzureRmJitNetworkAccessPolicy -Kind "Basic" -Name "default" -ResourceGroupName $RGName -Location $location -VirtualMachine $JitPolicyArr
