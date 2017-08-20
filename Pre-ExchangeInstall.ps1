<#
    .SYNOPSIS
    Pre-ExchangeInstall.ps1
   
    Version 1.1, August 17, 2017

    .DESCRIPTION
    This script will set the initial server settings and install all the
	prereq software. It configures the drives and sets mount points.

    .LINK
    .NOTES
    Requirements:
    
    Revision History
    --------------------------------------------------------------------------------
    1.0     Initial release
    1.1     Updated with information from the DaaS 1.0 build and updated to support
            Exchange 2013 CU17.
                
    .PARAMETER $Server
    Specifies the directory of the installation media.

    .PARAMETER Phase
    Internal Use Only :)

    .EXAMPLE
    .\Pre-ExchangeInstall.ps1
	
#>

clear

function Test-Reboot {
    $AutoUpdateKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
    $CBSKeyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\"
    if ((Test-Path -Path "$AutoUpdateKeyPath\RebootRequired") -or (Test-Path -Path "$CBSKeyPath\RebootPending") -eq $true ) {
        Set-Location -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        Set-ItemProperty -Path . -Name Pre-ExchangeInstallStep2 -Value $RunOnceValue
        Write-Host "Rebooting to clear a pending reboot" -ForegroundColor Yellow
        Start-Sleep 10
        Restart-Computer -Force
    }
}

Test-Reboot

# Installing RSAT tools
$RSATADDS = (Get-WindowsFeature RSAT-ADDS).installstate
if ($RSATADDS -eq "Available") {
    Add-WindowsFeature RSAT-ADDS
}

$Server = $env:COMPUTERNAME
$ServerType = ($env:COMPUTERNAME).Split("-")[1]
$Datacenter = ($env:COMPUTERNAME).Split("-")[0]
$DomainName = (Get-ADDomain).netbiosname
$StatusFile = "C:\Temp\Pre-ExchangeInstallStatus.txt"
$RunningStatusFile = "C:\Temp\RunningStatus.txt"
$ForegroundNormal = "Green"
$ForeGroundError = "Red"
$ComputerCreationDate = (Get-ADComputer $Server -Properties whencreated).whencreated
$TargetDate = (Get-Date).AddDays(-2)

##############################################
#####   These may need to be adjusted    #####
##############################################
$PrereqSourcepath = "\\" + $Datacenter + "-dcur-01\Exchange\Prereqs"
$ScriptPath = "\\" + $Datacenter + "-dcur-01\Exchange\Scripts"
$BinariesPath = "\\" + $Datacenter + "-dcur-01\Exchange\Binaries"
$RunOnceValue = 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe "\\ppd-dcur-01\exchange\scripts\Pre-ExchangeInstall.ps1"'


Function Check-Admin {
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

Function Run-Diskpart {
	Param ([Array]$Commands)
	$Tempfile = [System.IO.Path]::GetTempFileName()
	Foreach ($Com in $Commands)
	{
		$CMDLine = $CMDLine + $Com + ", "
		Add-Content $Tempfile $Com
	}
		If ([bool]$WhatIfPreference) {
			Write-Host "What if: Performing the operation `"Diskpart /s $CMDLine`""
		}
	If (![bool]$WhatIfPreference) {
		Write-Host "Diskpart /s $CMDLine" -ForegroundColor $ForeGroundNormal
		$Output = DiskPart /s $Tempfile
		$Output
		}
	Remove-Item $Tempfile -WhatIf:$False
}

Function PrepareBinariesDisk {  
    $BinDiskNum = "3"
    Initialize-Disk $BinDiskNum | Out-File -FilePath $RunningStatusFile -Append -NoClobber
    New-Partition -DiskNumber $BinDiskNum -UseMaximumSize | Out-File -FilePath $RunningStatusFile -Append -NoClobber
    Start-Sleep 5
    Get-Partition -DiskNumber $BinDiskNum -PartitionNumber 2 | Format-Volume -FileSystem NTFS -NewFileSystemLabel Binaries -Confirm:$False | Out-File -FilePath $RunningStatusFile -Append -NoClobber
    Set-Partition -DiskNumber $BinDiskNum -PartitionNumber 2 -NewDriveLetter E | Out-File -FilePath $RunningStatusFile -Append -NoClobber
	New-Item -Path "E:\Exchange" -ItemType Directory | Out-File -FilePath $RunningStatusFile -Append -NoClobber
	Add-Content -Path $StatusFile "Binaries disk created on disk $BinDiskNum"
	Start-Sleep 5
}	

Function PrepareRestore {
    $RestoreDiskNum = "4"
    Initialize-Disk $RestoreDiskNum | Out-File -FilePath $RunningStatusFile -Append -NoClobber
    New-Partition -DiskNumber $RestoreDiskNum -UseMaximumSize | Out-File -FilePath $RunningStatusFile -Append -NoClobber
    Start-Sleep 5
    Get-Partition -DiskNumber $RestoreDiskNum -PartitionNumber 2 | Format-Volume -FileSystem NTFS -NewFileSystemLabel Restore -Confirm:$False | Out-File -FilePath $RunningStatusFile -Append -NoClobber
    Set-Partition -DiskNumber $RestoreDiskNum -PartitionNumber 2 -NewDriveLetter R | Out-File -FilePath $RunningStatusFile -Append -NoClobber
	Add-Content -Path $StatusFile "Restore disk created on disk $RestoreDiskNum" | Out-File -FilePath $RunningStatusFile -Append -NoClobber
	Start-Sleep 5
}

Function ChangeCDROMDrive {
    Run-Diskpart "Select volume 0","assign letter=z" | Out-File -FilePath $RunningStatusFile -Append -NoClobber
    Write-Host "CDRom drive letter changed from D: to Z:" -ForegroundColor Green
	Add-Content -Path $StatusFile "Changed CD-Rom drive letter"
}

Function Create-TempDir {
	if ((test-path c:\Temp) -eq $false) {
		New-Item -Path C:\Temp -ItemType Directory | Out-Null
		Write-Host ""
		Write-Host "Created C:\TEMP directory." -ForegroundColor Green
	}
}

Function PrepareDBVolumes {
    $DBDisks = Get-Disk | ? operationalstatus -NotLike "online"
    $DBDisks = $DBDisks.Number
    foreach ($Disk in $DBDisks) {
        $Format = "Format FS=NTFS UNIT=64k Label=ExVol" + $Disk + " QUICK"
        Run-Diskpart "select disk $Disk","clean"
        Run-Diskpart "select disk $Disk","online disk"
        Run-Diskpart "select disk $Disk","attributes disk clear readonly","convert MBR"
        Run-Diskpart "select disk $Disk","offline disk"
        $VolPath = "E:\ExchangeVolumes\ExVol" + $Disk
        If ((Test-Path $VolPath) -eq $False) {
	        New-Item $VolPath -type Directory -WhatIf:$([bool]$WhatIfPreference)
        }
        $Mount = 'assign mount="' + $Volpath + '"'	
        Run-Diskpart "select disk $Disk","attributes disk clear readonly","online disk","convert GPT noerr","create partition primary","$Format","$Mount"
        if ($Disk -eq "1") {
            New-Item -Path $VolPath\DB01 -ItemType Directory | Out-File -FilePath $RunningStatusFile -Append -NoClobber
            New-Item -Path $VolPath\DB01.Logs -ItemType Directory | Out-File -FilePath $RunningStatusFile -Append -NoClobber
            New-Item -Path $VolPath\DB02 -ItemType Directory | Out-File -FilePath $RunningStatusFile -Append -NoClobber
            New-Item -Path $VolPath\DB02.Logs -ItemType Directory | Out-File -FilePath $RunningStatusFile -Append -NoClobber
        } else {
            $1Dir = $Disk + 1
            $2Dir = $Disk + 2
            $1DBDir = "DB" + $1Dir
            $2DBDir = "DB" + $2Dir
            New-Item -Path $VolPath\$1DBDir -ItemType Directory | Out-File -FilePath $RunningStatusFile -Append -NoClobber
            New-Item -Path $VolPath\$1DBDir.Logs -ItemType Directory | Out-File -FilePath $RunningStatusFile -Append -NoClobber
            New-Item -Path $VolPath\$2DBDir -ItemType Directory | Out-File -FilePath $RunningStatusFile -Append -NoClobber
            New-Item -Path $VolPath\$2DBDir.Logs -ItemType Directory | Out-File -FilePath $RunningStatusFile -Append -NoClobber
        }
    }
}	

Function Enable-PerformanceCounters {
	# Turns on the Performance Counters on the server.
    logman -start "Server Manager Performance Monitor" | Out-File -FilePath $RunningStatusFile -Append -NoClobber
    schtasks /Change /TN "\Microsoft\Windows\PLA\Server Manager Performance Monitor" /ENABLE | Out-File -FilePath $RunningStatusFile -Append -NoClobber
    Add-Content -Path $RunningStatusFile "Enabled Performance Counters, first time"
}

function EnableSmartScreen {
    $KeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    New-ItemProperty -Path $KeyPath -Name EnableSmartScreen -Value 2 -PropertyType DWord -Force | Out-File -FilePath $RunningStatusFile -Append -NoClobber
    Add-Content -Path $RunningStatusFile "Enabled Smart Screen"
}

function DotNetInstall {
	Write-Host "Installing .NET Framework" -ForegroundColor Green
	Start-Process -FilePath "$PrereqSourcepath\NDP462-KB3151800-x86-x64-AllOS-ENU.exe" -ArgumentList "/norestart /passive" -NoNewWindow -Wait
	Add-Content -Path $RunningStatusFile "Installed .NET Framework"
}

function CheckComputerObject {
	if ($ComputerCreationDate -le $TargetDate ) {
		Write-Host "The computer object is more than 2 days old and needs to be deleted." -ForegroundColor Red
		Write-Host "Delete the computer object and wait 15 minutes and run the script again." -ForegroundColor Red
		exit
		}
}

# Step 1
if ((Test-Path C:\Temp\Pre-EchangeInstall-Step1.txt) -eq $false) {
    # Check the age of the computer object. If it is more than 2 days old, it needs to be deleted and recreated.
    CheckComputerObject

    # Check to see if we are running as admin
    Check-Admin

    # Importing Windows modules
    Import-Module BitsTransfer,ServerManager

    # Perform drive actions
    Create-TempDir
    ChangeCDROMDrive
    PrepareBinariesDisk
    PrepareRestore
    PrepareDBVolumes

    # Server settings
    Enable-PerformanceCounters
    EnableSmartScreen
    Enable-PerformanceCounters # Yes, sometimes it needs to be run twice.

    # Activating Windows Server Roles & Features for all Exchange roles except Edge
    Write-Host ""
    Write-Host "Adding Windows Features" -ForegroundColor Green
    Install-WindowsFeature AS-HTTP-Activation, Desktop-Experience, NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, Web-Mgmt-Console, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation, RSAT-Feature-Tools-BitLocker-BdeAducExt, Failover-Clustering, BitLocker
    Add-Content -Path $RunningStatusFile "Install Windows Features"
    
    # Server Manager properties
    Set-ItemProperty HKCU:\Software\Microsoft\ServerManager -Name CheckedUnattendLaunchSetting -Value 0
    Set-ItemProperty HKLM:\SOFTWARE\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon -Value 1
    Add-Content -Path $RunningStatusFile "Set Server Manager Properties"
    New-Item -Path "C:\Temp" -Name "Pre-EchangeInstall-Step1.txt" -ItemType File
    Add-Content -Path $RunningStatusFile "Created place holder file"

    # Add run once key to continue after rebooting
    Set-Location -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    Set-ItemProperty -Path . -Name Pre-ExchangeInstallStep2 -Value $RunOnceValue
    Add-Content -Path $RunningStatusFile "Installed Stage 1, rebooting and moving to stage 2."
    Restart-Computer
}

# Step 2
# Install UCMA Runtime
Write-Host ""
Write-Host "Installing UCMA Runtime" -ForegroundColor Green
Start-Process -FilePath "$PrereqSourcepath\UcmaRuntimeSetup.exe" -ArgumentList "/passive /norestart" -NoNewWindow -Wait
Add-Content -Path $RunningStatusFile "Installed UCMA Runtime"

# Install .NET 4.6.2 if needed
DotNetInstall

Write-Host ""
Write-Host "Rebooting Server" -ForegroundColor Yellow
Add-Content $StatusFile "Pre-ExchangeInstall.ps1 Completed"
Start-Sleep 15

Restart-Computer
