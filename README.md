# Azure Security Center scripts

Just-In-Time VM admin scripts

Requires installing AzureRM.Security module version 0.2.0 Preview or higher:
Install-Module -Name AzureRM.Security -AllowPrerelease

SetJITAdminPolicies.ps1
Creates a JIT admin policy based on the VM tags. 
The script includes 2 base scenarios for Windows and Linux virtual machines. It reads VM tags looking for tag "jitPolicy" with values "jitWindows" or "jitLinux" to set the appropiate JIT policy.

StartJITAdminRequest.ps1
Starts a JIT admin request to create NSG rules from the source IP address specified. It can be used combined with IPify.org service to automate the source IP address detection. Usage example:
PS C:> $myIP = $(Invoke-WebRequest https://api.ipify.org).Content
PS C:> .\StartJITAdminRequest.ps1 -RGName MYRG -Hours 1 -SourceAddress $myIP

