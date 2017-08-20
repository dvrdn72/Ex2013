<#
    .SYNOPSIS
    Post-ExchangeInstall.ps1
   
    Version 1.1, June 6, 2017

    .DESCRIPTION
    This script will set all the post installation configurations.

    .LINK
    .NOTES
    Requirements:
    
    Revision History
    --------------------------------------------------------------------------------
    1.0     Initial release
    1.1     Updated with STIG information and settings
                
    .PARAMETER $Server
    Specifies the directory of the installation media.

    .PARAMETER Phase
    Internal Use Only :)

    .EXAMPLE
    .\Post-ExchangeInstall.ps1
	
#>

clear
$Server = $env:COMPUTERNAME
$ServerType = ($env:COMPUTERNAME).Split("-")[1]
$Datacenter = ($env:COMPUTERNAME).Split("-")[0]
$DomainName = (Get-ADDomain).netbiosname
$StatusFile = "C:\Temp\ExchangePostInstallStatus.txt"
$UrlPathFile = "C:\Temp\URL-Output.txt"
$Date = (Get-Date).addminutes(3)
$Key = "HWY43-FY882-FM8YG-GR2XV-QH6DC"
$InputFile = "$ScriptPath\Organizations.psd1"
$config = Invoke-Expression (Get-Content $InputFile | Out-String)
$OrgName = $config.Organization.galname

##############################################
#####   These may need to be adjusted    #####
##############################################
$BinarySourcepath = "\\" + $Datacenter + "-mbx-01\Exchange\Binaries"
$ScriptPath = "\\" + $Datacenter + "-mbx-01\Exchange\Scripts"

if ($DomainFQDN -eq $USR) {
    $SmtpDomain = "dte.ic.gov"
    } elseif ($DomainFQDN -eq $USRD) {
        $SmtpDomain = "dtf.eng.zone"
    } elseif ($DomainFQDN -eq $USRP) {
        $SmtpDomain = "ppd.dte.ic.gov"
    } elseif ($DomainFQDN -eq $FORNR) {
        $SmtpDomain = "2pi.dte.ic.gov"
    } elseif ($DomainFQDN -eq $FORNRD) {
        $SmtpDomain = "2pi.dtf.eng.zone"
    } elseif ($DomainFQDN -eq $FORNRP) {
        $SmtpDomain = "2pi.ppd.dte.ic.gov" }

function Set-VDirectories {
	if ($DomainName -eq "US-R") {
		$autodiscover = "autodiscover.dte.ic.gov"
		$UrlName = "mail.dte.ic.gov"
		} elseif ($DomainName -eq "US-RD") {
			$autodiscover = "autodiscover.dtf.eng.zone"
			$UrlName = "mail.dtf.eng.zone"
		} elseif ($DomainName -eq "US-RP") {
			$autodiscover = "autodiscover.ppd.dte.ic.gov"
			$UrlName = "mail.ppd.dte.ic.gov"
		} elseif ($DomainName -eq "FORN-R") {
			$autodiscover = "autodiscover.2pi.dte.ic.gov"
			$UrlName = "mail.2pi.dte.ic.gov"
		} elseif ($DomainName -eq "FORN-RD") {
			$autodiscover = "autodiscover.2pi.dtf.eng.zone"
			$UrlName = "mail.2pi.dtf.eng.zone"
		} elseif ($DomainName -eq "FORN-RP") {
			$autodiscover = "autodiscover.2pi.ppd.dte.ic.gov"
			$UrlName = "mail.2pi.ppd.dte.ic.gov"
		}
	
	Write-Host "Configuring Directories for $Server.." -Foregroundcolor Green
	
	Get-WebservicesVirtualDirectory -Server $Server | Set-WebservicesVirtualDirectory -InternalURL https://$UrlName/EWS/Exchange.asmx -ExternalURL https://$UrlName/EWS/Exchange.asmx -Force | Out-File -FilePath $UrlPathFile
	Get-OwaVirtualDirectory -Server $Server | Set-OwaVirtualDirectory -InternalURL https://$UrlName/owa -ExternalURL https://$UrlName/owa -Confirm:$False | Out-File -FilePath $UrlPathFile -Append -NoClobber
	Get-ecpVirtualDirectory -Server $Server | Set-ecpVirtualDirectory -InternalURL https://$UrlName/ecp -ExternalURL https://$UrlName/ecp -Confirm:$False | Out-File -FilePath $UrlPathFile -Append -NoClobber
	Get-ActiveSyncVirtualDirectory -Server $Server | Set-ActiveSyncVirtualDirectory -InternalURL https://$UrlName/Microsoft-Server-ActiveSync -ExternalURL https://$UrlName/Microsoft-Server-ActiveSync -Confirm:$False | Out-File -FilePath $UrlPathFile -Append -NoClobber
	Get-OABVirtualDirectory -Server $Server | Set-OABVirtualDirectory -InternalUrl https://$UrlName/OAB -ExternalURL https://$UrlName/OAB -Confirm:$False | Out-File -FilePath $UrlPathFile -Append -NoClobber
	Set-ClientAccessServer $Server -autodiscoverServiceInternalUri https://$autodiscover/autodiscover/autodiscover.xml -Confirm:$False | Out-File -FilePath $UrlPathFile -Append -NoClobber
	Set-OutlookAnywhere -Identity "$Server\Rpc (Default Web Site)" -InternalHostname $UrlName -ExternalHostName $UrlName -InternalClientAuthenticationMethod ntlm -InternalClientsRequireSsl:$True -ExternalClientAuthenticationMethod ntlm -ExternalClientsRequireSsl:$True -Confirm:$False | Out-File -FilePath $UrlPathFile -Append -NoClobber
	Get-WebservicesVirtualDirectory -Server $Server |Fl internalURL,ExternalURL | Out-File -FilePath $UrlPathFile -Append -NoClobber
	Get-OWAVirtualDirectory -Server $Server | Fl internalUrl,ExternalURL | Out-File -FilePath $UrlPathFile -Append -NoClobber
	Get-ECPVirtualDirectory -Server $Server | Fl InternalURL,ExternalURL | Out-File -FilePath $UrlPathFile -Append -NoClobber
	Get-ActiveSyncVirtualDirectory -Server $Server | Fl InternalURL,ExternalURL | Out-File -FilePath $UrlPathFile -Append -NoClobber
	Get-OABVirtualDirectory -Server $Server | Fl InternalURL,ExternalURL | Out-File -FilePath $UrlPathFile -Append -NoClobber
	Get-ClientAccessServer $Server | Fl autodiscoverServiceInternalUri | Out-File -FilePath $UrlPathFile -Append -NoClobber
	Get-OutlookAnywhere -Identity "$Server\rpc (Default Web Site)" |fl internalhostname,internalclientauthenticationmethod,internalclientsrequiressl,externalhostname,externalclientauthenticationmethod,externalclientsrequiressl | Out-File -FilePath $UrlPathFile -Append -NoClobber
	Write-Host ""
	Write-Host "The Powershell URLs have not been set as part of this script." -ForegroundColor Yellow
}

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

function Create-PublicFolderHierarchy {
	if (((get-mailbox -PublicFolder -Identity masterhierarchy).name) -eq "masterhierarchy") {
		Write-Host "Public folder hierarchy exists" -ForegroundColor Green
		} else {
			New-Mailbox -PublicFolder -Name MasterHierarchy
            Start-Sleep 20
		}
	}

function Create-PublicFoldersForOrganizations {
	foreach ($org in $OrgName) {
		New-PublicFolder -Name $org -Path \
	}
}

function SetActiveSync {
    $TempId = $Server + "\Microsoft-Server-ActiveSync (Default Web Site)"
	Set-ActiveSyncVirtualDirectory -Identity $TempId -BasicAuthEnabled:$false -WindowsAuthEnabled:$false -ClientCertAuth Required -InternalAuthenticationMethods 'Certificate' -ExternalAuthenticationMethods 'Certificate'
}

function SetReceiveConnector {
    Get-ReceiveConnector -Server $Server | ? name -Like "client proxy*" | Set-ReceiveConnector -PermissionGroups ExchangeServers,ExchangeUsers
    Get-ReceiveConnector -Server $Server | ? name -Like "outbound proxy*" | Set-ReceiveConnector -PermissionGroups ExchangeServers
    Get-ReceiveConnector -Server $Server | ? name -Like "client frontend*" | Set-ReceiveConnector -PermissionGroups ExchangeUsers
    Get-ReceiveConnector -Server $Server | ? name -Like "default $Datacenter*" | Set-ReceiveConnector -PermissionGroups ExchangeServers,ExchangeUsers,ExchangeLegacyServers
    Get-ReceiveConnector -Server $Server | ? name -Like "default frontend*" | Set-ReceiveConnector -PermissionGroups ExchangeServers,ExchangeLegacyServers
    Get-ReceiveConnector -Server $Server | Set-ReceiveConnector -AuthMechanism 'tls' -Banner $null
}

function SetSendConnector {
    Get-SendConnector | Set-SendConnector -DomainSecureEnabled:$true -TlsDomain $SmtpDomain -TlsAuthLevel DomainValidation
}

# Check to see if we are running as admin
Check-Admin

# Start the installation
if ($ServerType -eq "mbx") {
        Set-VDirectories

	    New-UMDialPlan -Name $Datacenter -VoIPSecurity "Secured" -NumberOfDigitsInExtension 7 -URIType "SipName" -CountryOrRegionCode 1
	    Set-UMDialPlan $Datacenter -ConfiguredInCountryOrRegionGroups "Anywhere,*,*,*" -AllowedInCountryOrRegionGroups "Anywhere"
	    Get-UMMailboxPolicy | Set-UMMailboxPolicy -AllowedInCountryOrRegionGroups "Anywhere" -MinPINLength "4" -AllowCommonPatterns $true
	    Set-UmService -Identity $Server -UMStartupMode "Dual"
	    Set-UMCallRouterSettings -Server $Server -UMStartupMode "Dual"
	    & c:\Windows\SysWOW64\InetSrv\appcmd.exe unlock config /section:clientCertificateMappingAuthentication 
	    & c:\Windows\SysWOW64\InetSrv\appcmd.exe set config 'Default Web Site/Microsoft-Server-ActiveSync' -section:clientCertificateMappingAuthentication /enabled:true
	
        SetActiveSync
    
        Get-OutlookAnywhere | Set-OutlookAnywhere -ExternalClientAuthenticationMethod Ntlm -InternalClientAuthenticationMethod Ntlm
	
        Add-Content -Path $StatusFile "Post-ExchangeInstall.ps1 on a mailbox server."
	    Start-Sleep 15
    
    } else {
   	
        & c:\Windows\SysWOW64\InetSrv\appcmd.exe unlock config /section:clientCertificateMappingAuthentication 
	    & c:\Windows\SysWOW64\InetSrv\appcmd.exe set config 'Default Web Site/Microsoft-Server-ActiveSync' -section:clientCertificateMappingAuthentication /enabled:true
        
	    Add-Content -Path $StatusFile "Post-ExchangeInstall.ps1 on a journal server."
	    Start-Sleep 15	    
}

# This is not being set due to email flow issues, needs to be researched and adjusted.
# SetReceiveConnector
# SetSendConnector


Create-PublicFolderHierarchy
Create-PublicFoldersForOrganizations
Set-AdminAuditLogConfig -AdminAuditLogEnabled $true
Set-ExchangeServer -ErrorReportingEnabled:$False -Identity $Server -ProductKey $Key
Get-OwaVirtualDirectory -Server $Server | Set-OwaVirtualDirectory -WindowsAuthentication:$true 
Get-EcpVirtualDirectory -Server $Server | Set-EcpVirtualDirectory -WindowsAuthentication:$True
Get-EventLogLevel | ? EventLevel -ne "lowest" | Set-EventLogLevel -Level Lowest
Get-TransportConfig | Set-TransportConfig -MaxReceiveSize "50 MB" -MaxSendSize "50 MB" -MaxRecipientEnvelopeLimit 5000

Set-ExecutionPolicy RemoteSigned -Force

Restart-Computer