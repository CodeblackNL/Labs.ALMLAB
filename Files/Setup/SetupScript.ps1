
#######################################
# Update LocalConfigurationManager
#######################################
Write-Log "INFO" "Updating LocalConfigurationManager with RebootNodeIfNeeded"
configuration LCM_RebootNodeIfNeeded {
    node localhost {
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
        }
    }
}

LCM_RebootNodeIfNeeded -OutputPath "$setupFolder\LCM_RebootNodeIfNeeded" | Out-Null
Set-DscLocalConfigurationManager -Path "$setupFolder\LCM_RebootNodeIfNeeded" -Verbose -ComputerName localhost
Write-Log "INFO" "Finished updating LocalConfigurationManager with RebootNodeIfNeeded"

#######################################
# Configure DSC Pull
#######################################
Write-Log "INFO" "Configuring DSC Pull"
[DSCLocalConfigurationManager()]
configuration DSCPullNode {
    param (
        [string]$PullServerUrl,
        [string]$RegistrationKey
    )

    Node localhost {
        Settings {
            ConfigurationMode = 'ApplyAndAutoCorrect'
            ConfigurationModeFrequencyMins = 15
            RefreshMode = 'Pull'
            RefreshFrequencyMins = 30
            RebootNodeIfNeeded = $true
        }

        ConfigurationRepositoryWeb DSCPullServer {
            ServerURL = $PullServerUrl
            AllowUnsecureConnection = $true
            RegistrationKey = $RegistrationKey
            ConfigurationNames = @($env:COMPUTERNAME)
        }

        ReportServerWeb DSCReportServer {
            ServerURL = $PullServerUrl
            AllowUnsecureConnection = $true
            RegistrationKey = $RegistrationKey
        }
    }
}

$configurationPath = Join-Path -Path $PSScriptRoot -ChildPath 'DSCPullNode'
$pullServerUrl = $configuration.AllProperties.DscPullServerUrl
$registrationKey = $configuration.AllProperties.DscPullServerRegistrationKey

$configurationData = @{
    AllNodes = @(
        @{
            NodeName = '*'
            PSDscAllowPlainTextPassword = $true
            RebootNodeIfNeeded = $true
        }
    )
}
Write-Log "INFO" "Generating configuration"
DSCPullNode -PullServerUrl $pullServerUrl -RegistrationKey $registrationKey -OutputPath $configurationPath -ConfigurationData $configurationData
Write-Log "INFO" "Starting configuration"
Set-DscLocalConfigurationManager -Path $configurationPath -ComputerName localhost -Force -Verbose
Write-Log "INFO" "Finished configuring DSC Pull"

Write-Log "INFO" "Applying configuration (from pull server)"
Update-DscConfiguration -Wait -Verbose
Write-Log "INFO" "Finished applying configution"
