<#
    .SYNOPSIS
    Install-Exchange.ps1
   
    Version 1.0, September 14, 2016
    Version 1.1, Feb 17, 2017

    .DESCRIPTION
    This script will install Exchange and copy the required files to the installation location.

    .LINK
    .NOTES
    Requirements:
    
    Revision History
    --------------------------------------------------------------------------------
    1.0     Initial release
                
    .PARAMETER $Server
    Specifies the directory of the installation media.

    .PARAMETER Phase
    Internal Use Only :)

    .EXAMPLE
    .\Install-Exchange.ps1
	
#>

$Server = $env:COMPUTERNAME
$ServerType = ($env:COMPUTERNAME).Split("-")[1]
$Datacenter = ($env:COMPUTERNAME).Split("-")[0]
$StatusFile = "C:\Temp\ExchangeInstallStatus.txt"

##############################################
#####   These may need to be adjusted    #####
##############################################
$BinarySourcepath = "\\" + $Datacenter + "-dcur-01\Exchange\Binaries"

Function Install-MailboxServer {
    Add-Content $StatusFile "`nInstalling Exchange on a Mailbox server"
    Write-Host ""
    Write-Host "Deploying a mailbox server named $server from the $Datacenter datacenter" -ForegroundColor Yellow
    & $BinarySourcepath\setup.exe /m:install /r:ClientAccess, Mailbox, ManagementTools /IAcceptExchangeServerLicenseTerms /InstallWindowsComponents /TargetDir:E:\Exchange /donotstarttransport /dbfilepath:E:\ExchangeVolumes\ExVol1\SystemMBX\SystemMBX.edb /logfolderpath:E:\ExchangeVolumes\ExVol1\SystemMBX.Logs /mdbname:SystemMailboxes.edb
    Write-Host ""
    Write-Host ""
    Start-Sleep 15
}

Function Install-JournalServer {
    Add-Content $StatusFile "`nInstalling Exchange on a Journal server"
    Write-Host ""
    Write-Host "Deploying a Journaling server named $Server from the $Datacenter datacenter." -ForegroundColor Yellow
    Write-Host "$BinarySourcepath\setup.exe" -ForegroundColor Yellow
    & $BinarySourcepath\setup.exe /m:install /r:Mailbox, ManagementTools /IAcceptExchangeServerLicenseTerms /InstallWindowsComponents /TargetDir:E:\Exchange /donotstarttransport /dbfilepath:E:\ExchangeVolumes\ExVol1\SystemMBX\SystemMBX.edb /logfolderpath:E:\ExchangeVolumes\ExVol1\SystemMBX.Logs /mdbname:SystemMailboxes.edb
    Write-Host ""
    Start-Sleep 15
}

Function InstallServer {
	if ($ServerType -eq "mbx") {
    Install-MailboxServer
    Start-Sleep 15
    } else {
    Install-JournalServer
    Start-Sleep 15
    Get-MailboxDatabase -Server $server | Set-MailboxDatabase -IsExcludedFromProvisioning $true -IsExcludedFromProvisioningBySchemaVersionMonitoring $true -IsExcludedFromInitialProvisioning $true -IsExcludedFromProvisioningBySpaceMonitoring $true -IndexEnabled $false
	}
}

Function CheckAdmin {
	# Self Elevating Permission
	# Get the ID and security principal of the current user account
	$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
	$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

	# Get the security principal for the Administrator role
	$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator

	# Check to see if we are currently running "as Administrator"
	If ($myWindowsPrincipal.IsInRole($adminRole)) {
		Clear-Host
    } else {
		Write-Host ""
		Write-Host "PowerShell was not started as an administrator." -ForegroundColor Red
		Write-Host "Close this window and reopen PowerShell as an administrator." -ForegroundColor Red
		Write-Host ""
		Exit
	}
}

function CheckOrgManagement {
    $OrgAdmin = "Organization Management"
    $user = $env:USERNAME
    $user = (Get-ADUser $user).name
    $OA = Get-ADGroupMember -Identity $OrgAdmin | Select -ExpandProperty Name
    If ($OA -notcontains $user) {
        Write-Host "$user is not a member of $OrgAdmin" -ForegroundColor Red
        Exit
        }
}

# Make sure the person running the script is in Org Management
CheckOrgManagement

# Checking to make sure we are running as admin
CheckAdmin

# Install Exchange
InstallServer

Write-Host "Rebooting Server" -ForegroundColor Yellow
Start-Sleep 15

Add-Content $StatusFile "Install-Exchange.ps1 Completed"

Restart-Computer -Force
