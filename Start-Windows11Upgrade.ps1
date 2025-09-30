<#PSScriptInfo

.VERSION 2025.9.1

.GUID 309659cf-0358-4996-9992-34f8a7dc09b9

.AUTHOR Martin Olsson

.COMPANYNAME Conmodo

.COPYRIGHT (c) Conmodo. All rights reserved.

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES


.PRIVATEDATA

#>

<# 

.DESCRIPTION 
 Upgrade from Windows 10 to Windows 11 

#> 
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateNotNull()]
    [string]$InstallerURL = 'https://go.microsoft.com/fwlink/?linkid=2171764',

    [switch]$Force
)

function Get-ScriptVersion {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [string]$FilePath
    )

    if ([string](Get-Content -Path $FilePath) -match '\.VERSION (\d+\.\d+\.\d+)') {
        $currentScriptVersion = $Matches[1]
    }
    if ([string]::IsNullOrEmpty($currentScriptVersion)) {
        $currentScriptVersion = 'UNKNOWN'
    }

    return $currentScriptVersion
}

function Get-OneDriveSyncState {
    $syncDiagnosticsFilePath = Join-Path -Path $env:LOCALAPPDATA -ChildPath '\Microsoft\OneDrive\logs\Business1\SyncDiagnostics.log'
    $stateValue = $null

    if (Test-Path -Path $syncDiagnosticsFilePath) {
        $progressState = Get-Content -Path $syncDiagnosticsFilePath -ErrorAction SilentlyContinue | Where-Object { $_.Contains("SyncProgressState") } | ForEach-Object { -split $_ | Select-Object -Index 1 }
        if ($progressState) {
            switch ($progressState){
                0 { $stateValue = "Healthy" }
                10 { $stateValue = "File merge conflict" }
                42{ $stateValue = "Healthy" }
                256 { $stateValue = "File locked" }
                258 { $stateValue = "File merge conflict" }
                8456 { $stateValue = "You don't have permission to sync this library" }
                16777216 { $stateValue = "Healthy" }
                12544 { $stateValue = "Healthy" }
                65536 { $stateValue = "Paused" }
                32786 { $stateValue = "File merge conflict" }
                4106 { $stateValue = "File merge conflict" }
                20480 { $stateValue = "File merge conflict" }
                24576 { $stateValue = "File merge conflict" }
                25088 { $stateValue = "File merge conflict" }
                8449 { $stateValue = "File locked" }
                8194 { $stateValue = "Disabled" }
                1854 { $stateValue = "Unhealthy" }
                12290 { $stateValue = "Access permission" }
                default { $stateValue = "Unknown: $progressState" }
            }
        }
        else {
            $stateValue = 'Invalid sync state'
        }

        if ((Get-Item -Path $syncDiagnosticsFilePath).LastWriteTime -le (Get-Date).Date.AddDays(-1)) {
            $stateValue = 'Not recently synced'
        }
    }
    else {
        $stateValue = 'No sync state'
    }

    return $stateValue
}

function Out-LogFile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [string]$ScriptVersion,

        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [string]$Content
    )

    if (-not (Test-Path -Path (Split-Path -Path $FilePath -Parent))) {
        Write-Verbose 'Creating log directory...'
        New-Item -Path (Split-Path -Path $FilePath -Parent) -ItemType Directory
    }

    ('[{0} | v{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $ScriptVersion, $Content) | Out-File -FilePath $FilePath -Append -ErrorAction Continue
}

$systemDrive = $env:SystemDrive
if ([string]::IsNullOrEmpty($systemDrive)) {
    $systemDrive = 'C:'
}

$scriptVersion = Get-ScriptVersion -FilePath (Join-Path -Path $PSScriptRoot -ChildPath $PSCmdlet.MyInvocation.MyCommand)
$tempDirectoryPath = Join-Path -Path $systemDrive -ChildPath 'Temp'
$logFilePath = Join-Path -Path $tempDirectoryPath -ChildPath 'Start-Windows11Upgrade.log'
$installerFilePath = Join-Path -Path $tempDirectoryPath -ChildPath 'Windows11InstallationAssistant.exe'

$logParams = @{
    FilePath = $logFilePath
    ScriptVersion = $scriptVersion
}

# Write-Verbose "Logs will be stored in: $logFilePath"

if (-not (Test-Path -Path $tempDirectoryPath)) {
    Write-Verbose 'Creating temp directory...'
    New-Item -Path $tempDirectoryPath -ItemType Directory
}

# Require run-as-admin.
$WindowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$WindowsPrincipal = [Security.Principal.WindowsPrincipal] $WindowsIdentity
$AdminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $WindowsPrincipal.IsInRole($AdminRole)) {
    Out-LogFile @logParams -Content 'The script needs to run as an administrator.'
    throw 'The script needs to run as an administrator.'
}

# Determine if the system is eligible for upgrade.
$isSystemEligibleForUpgrade = $false
$osName = (Get-ComputerInfo).OsName
if ($osName -match 'Windows 10') {
    $isSystemEligibleForUpgrade = $true
}

# Only upgrade if the system is eligible for upgrade (or if using the Force parameter).
if ($isSystemEligibleForUpgrade -or $Force) {
    # Check free storage space.
    $properties = @(
        @{ Name = 'FreeSpaceGB'; Expression = { [float]($_.FreeSpace / 1GB) } }
    )
    $diskInfo = Get-WmiObject -Class Win32_LogicalDisk -ComputerName LOCALHOST | Where-Object { ($_.DriveType -eq 3) -and ($_.DeviceID -eq $systemDrive) } | Select-Object -Property $properties
    $requiredDiskSpace = 40
    if ($diskInfo.FreeSpaceGB -lt $requiredDiskSpace) {
        $freeDiskSpaceRounded = [Math]::Floor($diskInfo.FreeSpaceGB)
        Out-LogFile @logParams -Content "Windows requires at least $freeDiskSpaceRounded GB free disk space to be able to upgrade. Currently available: $freeDiskSpaceRounded GB"
        throw "Windows requires at least $freeDiskSpaceRounded GB free disk space to be able to upgrade. Currently available: $freeDiskSpaceRounded GB"
    }

    # Check OneDrive sync state.
    $oneDriveSyncState = Get-OneDriveSyncState
    if ($oneDriveSyncState -ne 'Healthy') {
        Write-Warning "OneDrive sync state is degraded. Status from diagnostics log: $oneDriveSyncState"
        Out-LogFile @logParams -Content "OneDrive sync state is degraded. Status from diagnostics log: $oneDriveSyncState"
        Write-Warning 'Make sure your OneDrive is enabled and synchronized.'
        Read-Host 'Press <Enter> to proceed with the upgrade anyway or <Ctrl+C> to cancel'
    }

    # Check if secure boot is enabled.
    if ((Get-Command -Name 'Confirm-SecureBootUEFI' -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0) {
        try {
            if (-not (Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
                Write-Warning "Secure Boot is disabled. It's recommended (but not required) to enable it in the BIOS settings."
                Out-LogFile @logParams -Content "Secure Boot is disabled. It's recommended (but not required) to enable it in the BIOS settings."
            }
        }
        catch {
            Write-Warning 'Unable to validate if Secure Boot is enabled. The upgrade can proceed anyway.'
        }
    }

    # Check if TPM is active.
    $tpm = Get-WmiObject -Namespace 'Root\CIMv2\Security\MicrosoftTpm' -Class Win32_Tpm
    if (($null -eq $tpm) -or (-not $tpm.IsEnabled_InitialValue) -or (-not $tpm.IsActivated_InitialValue)) {
        Out-LogFile @logParams -Content 'TPM is not enabled (or not activated). Enable/activate the TPM in the BIOS settings to be able to upgrade.'
        throw 'TPM is not enabled (or not activated). Enable/activate the TPM in the BIOS settings to be able to upgrade.'
    }

    # Allow upgrade on older devices.
    $tpmMajorVersion = $tpm.SpecVersion.Split(',')[0] -as [int]
    if ($tpmMajorVersion -lt 2) {
        Write-Warning 'The script determined that this is an older device but will try to allow the upgrade anyway.'
        try {
            $registrySystemSetupPath = 'HKLM:\SYSTEM\Setup\MoSetup'
            if (-not (Test-Path -Path $registrySystemSetupPath)) {
                Write-Verbose 'Creating system setup registry key...'
                New-Item -Path $registrySystemSetupPath -ErrorAction Stop
            }
            
            if (Test-Path -Path $registrySystemSetupPath) {
                $registryAllowUpgradeName = 'AllowUpgradesWithUnsupportedTPMOrCPU'
                if ($null -eq (Get-ItemProperty -Path $registrySystemSetupPath -Name $registryAllowUpgradeName -ErrorAction SilentlyContinue)) {
                    Write-Verbose 'Creating system setup registry value...'
                    New-ItemProperty -Path $registrySystemSetupPath -Name $registryAllowUpgradeName -PropertyType 'DWORD' -Value 1 -ErrorAction Stop | Out-Null
                    Out-LogFile @logParams -Content 'Added value to the registry to allow upgrade on an older device.'
                }
                elseif ((Get-ItemProperty -Path $registrySystemSetupPath -Name $registryAllowUpgradeName -ErrorAction SilentlyContinue).($registryAllowUpgradeName) -ne 1) {
                    Write-Verbose 'Updating existing system setup registry value...'
                    Set-ItemProperty -Path $registrySystemSetupPath -Name $registryAllowUpgradeName -Value 1 -ErrorAction Stop | Out-Null
                    Out-LogFile @logParams -Content 'Updated value in the registry to allow upgrade on an older device.'
                }
            }
            else {
                Write-Error "Failed to find the registry key '$registrySystemSetupPath'."
                Out-LogFile @logParams -Content "Failed to find the registry key '$registrySystemSetupPath'."
            }
        }
        catch {
            Write-Error "Failed to configure the registry to allow upgrade on an older device. $PSItem"
            Out-LogFile @logParams -Content "Failed to configure the registry to allow upgrade on an older device. $PSItem"
        }
    }

    # Stop any currently running Windows upgrade processes.
    $installationAssistantProcessName = 'Windows10UpgraderApp'
    $installationAssistantProcess = Get-Process -Name $installationAssistantProcessName -ErrorAction SilentlyContinue
    $installationAssistantProcessCount = ($installationAssistantProcess | Measure-Object).Count
    if ($installationAssistantProcessCount -gt 0) {
        Stop-Process -Name $installationAssistantProcessName
    }

    # Upgrade the OS, then automatically restart the system.
    if ($PSCmdlet.ShouldProcess("URL: $InstallerURL", 'Download installer')) {
        try {
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($InstallerURL, $installerFilePath)
            Out-LogFile @logParams -Content "Downloaded the Windows 11 installation assistant to '$installerFilePath'."
        }
        catch {
            Write-Error "Failed to download the Windows 11 installation assistant. $PSItem"
            Out-LogFile @logParams -Content "Failed to downloaded the Windows 11 installation assistant. $PSItem"
        }
    }

    if ($PSCmdlet.ShouldProcess("File: $installerFilePath", 'Start Windows 11 upgrade')) {
        try {
            $startDateTime = Get-Date
            Write-Verbose "Started the Windows 11 upgrade at $($startDateTime.ToShortTimeString()). The upgrade should take approximately 30-45 minutes."
            Write-Verbose 'The computer will automatically reboot when the upgrade has finished.'
            Write-Verbose 'Installing Windows 11...'
            Out-LogFile @logParams -Content 'Started the Windows 11 upgrade.'
            Start-Process -FilePath $installerFilePath -ArgumentList @('/QuietInstall /SkipEULA /Auto Upgrade /NoRestartUI /CopyLogs {0}' -f $tempDirectoryPath) -Wait

            $stopDateTime = Get-Date
            $upgradeTotalMinutes = ($stopDateTime - $startDateTime).TotalMinutes
            Write-Verbose "Exited the upgrade process at $($stopDateTime.ToShortTimeString())."
            Out-LogFile @logParams -Content "Exited the upgrade process at $($stopDateTime.ToShortTimeString())."

            if ($upgradeTotalMinutes -lt 15) {
                Write-Warning "The upgrade has probably failed. The process time was very short ($upgradeTotalMinutes minutes)."
                Out-LogFile @logParams -Content "The upgrade has probably failed. The process time was very short ($upgradeTotalMinutes minutes)."
            }
            else {
                Start-Sleep -Seconds 60
                Write-Warning 'The upgrade has probably failed. The computer should have restarted itself by now.'
                Out-LogFile @logParams -Content 'The upgrade has probably failed. The computer should have restarted itself by now.'
            }
        }
        catch {
            Out-LogFile @logParams -Content "The Windows 11 upgrade failed. $PSItem"
            throw "The Windows 11 upgrade failed. $PSItem"
        }
    }
}
else {
    if (Test-Path -Path $installerFilePath -PathType Leaf) {
        Remove-Item -Path $installerFilePath
    }
    throw "The script has determined that this isn't a Windows 10 system. Use the Force parameter if you want to bypass this check and run the upgrade anyway."
}
