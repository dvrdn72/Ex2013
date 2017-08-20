<#
    .SYNOPSIS
    Prepare-SchemaForestDomain.ps1
   
    Version 1.0, September 14, 2016
    Version 1.1, August 17, 2017

    .DESCRIPTION
    This script is used to prepare any forest that will hold Exchange. It will run
	preparations for the Forest, Domain, and Schema.

    
    .LINK
    .NOTES
    Requirements:
    - Windows Server 2012 R2;
    - Domain-joined system;
    - Dell R730 Server

    Revision History
    --------------------------------------------------------------------------------
    1.0     Initial release
    1.1     Updated with information learned from the production build.
                
    .PARAMETER Source
    Specifies the directory of the installation media.

    .PARAMETER Phase
    Internal Use Only :)

    .EXAMPLE
    .\Prepare-SchemaForestDomain.ps1 
	
#>

clear
$ServerType = ($env:COMPUTERNAME).Split("-")[1]
$Datacenter = ($env:COMPUTERNAME).Split("-")[0]
$Sourcepath = "\\" + $Datacenter + "-mbx-01\Exchange\binaries"
$SchemaMaster = (Get-ADForest).SchemaMaster
$Domain = Get-ADDomain
$DomainName = $Domain.name
$Version = "15312"
$OrgName = "DTE-" + $DomainName

# Checking to see if the current user is a member of the Schema Admins, Enterprise Admins, and Domain Admins groups
Function Check-GroupMemebership {
$DAGroup = "Domain Admins"
$EAGroup = "Enterprise Admins"
$SAGroup = "Schema Admins"
$user = $env:USERNAME
$user = (Get-ADUser $user).name
$DA = Get-ADGroupMember -Identity $DAGroup | Select -ExpandProperty Name
$EA = Get-ADGroupMember -Identity $EAGroup | Select -ExpandProperty Name
$SA = Get-ADGroupMember -Identity $SAGroup | Select -ExpandProperty Name

    If ($DA -contains $user) {
        Write-Host "$user is a member of $DAGroup" -ForegroundColor Green
        } Else {
        Write-Host "$user is not a member of $DAGroup" -ForegroundColor Red
		Exit
    }

    If ($EA -contains $user) {
        Write-Host "$user is a member of $EAGroup" -ForegroundColor Green
        } Else {
        Write-Host "$user is not a member of $EAGroup" -ForegroundColor Red
		Exit
    }
    If ($SA -contains $user) {
        Write-Host "$user is a member of $SAGroup" -ForegroundColor Green
        } Else {
        Write-Host "$user is not a member of $SAGroup" -ForegroundColor Red
		Exit
    }
}

# Install RSAT Tools if needed
$RsatFeature = Get-WindowsFeature rsat-adds
if ($RsatFeature.InstallState -eq "installed") {
    Write-Host ""
    Write-Host "RSAT Tools are already installed." -ForegroundColor Green
	Write-Host ""
    } else {
    Write-Host ""
    Write-Host "Installing RSAT Tools" -ForegroundColor Yellow
	Add-WindowsFeature RSAT-ADDS
	Write-Host ""
}


Function Extend-Schema {
	Import-Module ActiveDirectory
	$ADInfo = Get-ADDomain
	$PDC = $ADInfo.PDCEmulator
	$ADDomainDistinguishedName = $ADInfo.DistinguishedName
	$DomainName = $ADInfo.name
	$ExchangeSchemaVer = repadmin /showattr $PDC “cn=ms-exch-schema-version-pt,cn=Schema,cn=Configuration,$ADDomainDistinguishedName” /atts:rangeupper
	$ExchangeSchemaArray = $ExchangeSchemaVer -split (“rangeUpper: “)
	$ExchangeSchemaVersion = $ExchangeSchemaArray[3]

	if ($ExchangeSchemaVersion -lt $Version) {
		Write-Host "Extending schema in $DomainName" -ForegroundColor Yellow
		Write-Host ""
        Start-Process -FilePath "$Sourcepath\setup.exe" -ArgumentList "/PrepareSchema /IAcceptExchangeServerLicenseTerms /dc:$SchemaMaster" -NoNewWindow -Wait
	} else {
		Write-Host "Schema has already been extended." -ForegroundColor Yellow
		Write-Host ""
}
}

# Checking group memberships
Check-GroupMemebership
Write-Host ""

# Prepare environment
Extend-Schema
Write-Host ""

# Prepare the Organization
Write-Host "Preparing the Forest and Organization"
Start-Process -FilePath "$Sourcepath\setup.exe" -ArgumentList "/P /ON:$OrgName /IAcceptExchangeServerLicenseTerms /DomainController:$SchemaMaster" -NoNewWindow -Wait

# Prepare the domain
Write-Host ""
Write-Host "Preparing the domain $DomainName" -ForegroundColor Yellow
Write-Host ""
& $Sourcepath\setup.exe /pd /IAcceptExchangeServerLicenseTerms /DomainController:$SchemaMaster
Start-Process -FilePath "$Sourcepath\setup.exe" -ArgumentList "/pd /IAcceptExchangeServerLicenseTerms /DomainController:$SchemaMaster" -NoNewWindow -Wait

Write-Host ""
Write-Host "Logoff and wait 30 minutes before proceeding with the installation." -ForegroundColor Yellow
Write-Host ""

Set-ExecutionPolicy RemoteSigned -Force
