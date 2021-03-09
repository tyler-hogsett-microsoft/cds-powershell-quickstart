@{

# Script module or binary module file associated with this manifest.
RootModule = 'Microsoft.PowerApps.Administration.Powershell.psm1'

# Version number of this module.
ModuleVersion = '2.0.108'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '1c40b0da-ee6a-4226-9a3d-e60092e1daae'

# Author of this module
Author = 'Microsoft Common Data Service Team'

# Company or vendor of this module
CompanyName = 'Microsoft'

# Copyright statement for this module
Copyright = '© 2020 Microsoft Corporation. All rights reserved'

# Description of the functionality provided by this module
Description = 'PowerShell interface for Microsoft PowerApps and Flow Administrative features'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
PowerShellHostVersion = '1.0'

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
DotNetFrameworkVersion = '4.0.0.0'

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
#RequiredModules = @(@{ModuleName = "Microsoft.PowerApps.RestClientModule"; ModuleVersion = "1.0"; Guid = "04800678-e13e-4b41-8d46-424e707ea733"})
#RequiredModules = @(@{ModuleName = "Microsoft.PowerApps.RestClientModule"; ModuleVersion = "1.0"; Guid = "04800678-e13e-4b41-8d46-424e707ea733"})

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
#NestedModules = @('Microsoft.PowerApps.AuthModule', 'Microsoft.PowerApps.RestClientModule')

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @(
    'New-AdminPowerAppCdsDatabase', `
    'Get-AdminPowerAppCdsDatabaseLanguages', `
    'Get-AdminPowerAppCdsDatabaseCurrencies', `
    'Get-AdminPowerAppEnvironmentLocations', `
    'Get-AdminPowerAppCdsDatabaseTemplates', `
    'New-AdminPowerAppEnvironment', `
    'Set-AdminPowerAppEnvironmentDisplayName', `
    'Set-AdminPowerAppEnvironmentRuntimeState', `
    'Get-AdminPowerAppEnvironment', `
    'Get-AdminPowerAppSoftDeletedEnvironment', `
    'Get-AdminPowerAppOperationStatus', `
    'Remove-AdminPowerAppEnvironment', `
    'Recover-AdminPowerAppEnvironment', `
    'Reset-PowerAppEnvironment', `
    'Get-AdminPowerAppEnvironmentRoleAssignment', `
    'Set-AdminPowerAppEnvironmentRoleAssignment', `
    'Remove-AdminPowerAppEnvironmentRoleAssignment', `
    'Get-AdminPowerApp', `
    'Remove-AdminPowerApp', `
    'Get-AdminPowerAppRoleAssignment', `
    'Remove-AdminPowerAppRoleAssignment', `
    'Set-AdminPowerAppRoleAssignment', `
    'Set-AdminPowerAppOwner', `
    'Get-AdminFlow', `
    'Enable-AdminFlow', `
    'Disable-AdminFlow', `
    'Remove-AdminFlow', `
    'Remove-AdminFlowApprovals', `
    'Set-AdminFlowOwnerRole', `
    'Remove-AdminFlowOwnerRole', `
    'Get-AdminFlowOwnerRole', `
    'Get-AdminPowerAppConnector', `
    'Get-AdminPowerAppConnectorAction', `
    'Get-AdminPowerAppConnectorRoleAssignment', `
    'Set-AdminPowerAppConnectorRoleAssignment', `
    'Remove-AdminPowerAppConnectorRoleAssignment', `
    'Remove-AdminPowerAppConnector', `
    'Get-AdminPowerAppConnection', `
    'Remove-AdminPowerAppConnection', `
    'Get-AdminPowerAppConnectionRoleAssignment', `
    'Set-AdminPowerAppConnectionRoleAssignment', `
    'Remove-AdminPowerAppConnectionRoleAssignment', `
    'Get-AdminPowerAppsUserDetails', `
    'Get-AdminFlowUserDetails', `
    'Remove-AdminFlowUserDetails', `
    'Set-AdminPowerAppAsFeatured', `
    'Clear-AdminPowerAppAsFeatured', `
    'Set-AdminPowerAppAsHero', `
    'Clear-AdminPowerAppAsHero', `
    'Set-AdminPowerAppApisToBypassConsent', `
    'Clear-AdminPowerAppApisToBypassConsent', `
    'Get-AdminDlpPolicy', `
    'New-AdminDlpPolicy', `
    'Remove-AdminDlpPolicy', `
    'Set-AdminDlpPolicy', `
    'Add-ConnectorToBusinessDataGroup', `
    'Remove-ConnectorFromBusinessDataGroup', `
    'Get-AdminPowerAppConnectionReferences', `
    'Add-CustomConnectorToPolicy', `
    'Remove-CustomConnectorFromPolicy', `
    'Remove-LegacyCDSDatabase', `
    'Get-AdminDeletedPowerAppsList', `
    'Get-AdminRecoverDeletedPowerApp', `
    #from Rest and Auth Module Helpers
    'Select-CurrentEnvironment', `
    'Add-PowerAppsAccount', `
    'Remove-PowerAppsAccount',`
    'Test-PowerAppsAccount', `
    'Get-TenantDetailsFromGraph', `
    'Get-UsersOrGroupsFromGraph', `
    'Get-JwtToken', `
    'ReplaceMacro', `
    'Set-TenantSettings', `
    'Get-TenantSettings', `
    'Get-AdminPowerAppTenantConsumedQuota', `
    'InvokeApi', `
    'InvokeApiNoParseContent', `
    'Add-AdminPowerAppsSyncUser', `
    'Remove-AllowedConsentPlans', `
    'Add-AllowedConsentPlans', `
    'Get-AllowedConsentPlans', `
    'Get-AdminPowerAppCdsAdditionalNotificationEmails', `
    'Set-AdminPowerAppCdsAdditionalNotificationEmails', `
    'Get-AdminPowerAppLicenses', `
    # DLP policy Version 1 APIs
    'Get-DlpPolicy', `
    'New-DlpPolicy', `
    'Remove-DlpPolicy', `
    'Set-DlpPolicy', `
    # URL patterns Version 1 APIs
    'Get-PowerAppTenantUrlPatterns', `
    'New-PowerAppTenantUrlPatterns', `
    'Remove-PowerAppTenantUrlPatterns', `
    'Get-PowerAppPolicyUrlPatterns', `
    'New-PowerAppPolicyUrlPatterns', `
    'Remove-PowerAppPolicyUrlPatterns', `
    # Dlp policy connector configurations Version 1 APIs
    'Get-PowerAppDlpPolicyConnectorConfigurations', `
    'New-PowerAppDlpPolicyConnectorConfigurations', `
    'Remove-PowerAppDlpPolicyConnectorConfigurations', `
    'Set-PowerAppDlpPolicyConnectorConfigurations', `
    # Copy/Backup/Restore APIs
    'Copy-PowerAppEnvironment', `
    'Backup-PowerAppEnvironment', `
    'Get-PowerAppEnvironmentBackups', `
    'Restore-PowerAppEnvironment', `
    'Remove-PowerAppEnvironmentBackup', `
    # ManagementApp APIs
    'Get-PowerAppManagementApp', `
    'Get-PowerAppManagementApps', `
    'New-PowerAppManagementApp', `
    'Remove-PowerAppManagementApp', `
    # Environment Keywords
    'Get-AdminPowerAppSharepointFormEnvironment', `
    'Set-AdminPowerAppSharepointFormEnvironment', `
    'Reset-AdminPowerAppSharepointFormEnvironment', `
    # Protection key APIs
    'Get-PowerAppGenerateProtectionKey', `
    'Get-PowerAppRetrieveTenantProtectionKey', `
    'Get-PowerAppRetrieveAvailableTenantProtectionKeys', `
    'New-PowerAppImportProtectionKey', `
    'Set-PowerAppProtectionStatus', `
    'Set-PowerAppTenantProtectionKey', `
    'Set-PowerAppLockAllEnvironments', `
    'Set-PowerAppUnlockEnvironment', `
    # Tenant isolation APIs
    'Get-PowerAppTenantIsolationPolicy', `
    'Set-PowerAppTenantIsolationPolicy', `
    'Get-PowerAppTenantIsolationOperationStatus', `
	# Dlp Error Settings APIs
	'Get-PowerAppDlpErrorSettings', `
	'New-PowerAppDlpErrorSettings', `
	'Set-PowerAppDlpErrorSettings', `
	'Remove-PowerAppDlpErrorSettings'
)

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
# CmdletsToExport = @()

# Variables to export from this module
# VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
# AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
ModuleList = @("Microsoft.PowerApps.Administration.PowerShell" )

# List of all files packaged with this module
# Note that Microsoft.IdentityModel.Clients.ActiveDirectory.dll and Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll are not included
# When included they are automatically loaded which can pull the files by name from uncontrolled locations.
FileList = @(
    "Microsoft.PowerApps.Administration.PowerShell.psm1", `
    "Microsoft.PowerApps.Administration.PowerShell.psd1", `
    "Microsoft.PowerApps.AuthModule.psm1", `
    "Microsoft.PowerApps.RestClientModule.psm1"
)

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
         LicenseUri = 'https://aka.ms/powerappspowershellprereleaseterms'

        # A URL to the main website for this project.
         ProjectUri = 'https://docs.microsoft.com/en-us/powerapps/administrator/powerapps-powershell'

        # A URL to an icon representing this module.
         IconUri = 'https://connectoricons-prod.azureedge.net/powerplatformforadmins/icon_1.0.1056.1255.png'

        # ReleaseNotes of this module
        ReleaseNotes = '

Current Release:
2.0.108
Added new APIs for error settings DLP:
    Get-PowerAppDlpErrorSettings,
    New-PowerAppDlpErrorSettings,
    Set-PowerAppDlpErrorSettings,
    Remove-PowerAppDlpErrorSettings

2.0.101:
    Revert "Add-CustomConnectorToPolicy is limited to only work for environment-level policies"

2.0.100:
    Add-CustomConnectorToPolicy is limited to only work for environment-level policies

2.0.96:
    Add tenant isolation APIs
    Skip triggers in Get-AdminPowerAppConnectorAction

2.0.92:
    Fix polling behavior on failures for environment lifecycle operations

2.0.86:
    Add Get-AdminPowerAppConnectorAction API

2.0.81:
    Add new DLP Policy Connector Configurations APIs:
        Get-PowerAppDlpPolicyConnectorConfigurations,
        New-PowerAppDlpPolicyConnectorConfigurations,
        Remove-PowerAppDlpPolicyConnectorConfigurations,
        Set-PowerAppDlpPolicyConnectorConfigurations

2.0.77:
    Add ProtectionKey APIs:
        Get-PowerAppGenerateProtectionKey,
        Get-PowerAppRetrieveTenantProtectionKey,
        Get-PowerAppRetrieveAvailableTenantProtectionKeys,
        New-PowerAppImportProtectionKey,
        Set-PowerAppProtectionStatus,
        Set-PowerAppTenantProtectionKey,
        Set-PowerAppLockAllEnvironments,
        Set-PowerAppUnlockEnvironment

2.0.76:
    Add Get-AdminPowerAppTenantConsumedQuota API and GetProtectedEnvironment parameter for Get-AdminPowerAppEnvironment

2.0.75:
    Add ManagementApp APIs:
        Get-PowerAppManagementApp,
        Get-PowerAppManagementApps,
        New-PowerAppManagementApp,
        Remove-PowerAppManagementApp

    Add Sharepoint Environment APIs:
        Get-AdminPowerAppSharepointFormEnvironment
        Set-AdminPowerAppSharepointFormEnvironment
        Reset-AdminPowerAppSharepointFormEnvironment

2.0.72:
    Fix bugs for SPN error handling

2.0.70:
    Add test automation support
    Added new APIs:
        Get-PowerAppTenantUrlPatterns,
        New-PowerAppTenantUrlPatterns,
        Remove-PowerAppTenantUrlPatterns,
        Get-PowerAppPolicyUrlPatterns,
        New-PowerAppPolicyUrlPatterns,
        Remove-PowerAppPolicyUrlPatterns

2.0.67:
    Add Set-AdminPowerAppEnvironmentRuntimeState API

2.0.66:
    Add SubscriptionBasedTrial SKU support.

2.0.65:
    Add Get-AdminPowerAppOperationStatus API for async scenario support.

2.0.64:
    Added new APIs:
        Copy-PowerAppEnvironment,
        Backup-PowerAppEnvironment,
        Get-PowerAppEnvironmentBackups,
        Restore-PowerAppEnvironment,
        Remove-PowerAppEnvironmentBackup,
        Reset-PowerAppEnvironment

2.0.63:
    Added DoD support. Fix bug PowerShell Cmdlet "Set-AdminPowerAppRoleAssignment" is broken when setting the tenant sharing.

2.0.61:
    BREAKING CHANGE: Changed return value to environment object when New-AdminPowerAppEnvironment CDS provision completed.
    Fixed empty return error bug (error code and error message will be returned when API fails).

2.0.60:
    Add TimeoutInMinutes parameter in New-AdminPowerAppEnvironment to make timeout configurable.
    BREAKING CHANGE: The default timeout is changed to a week (waiting for server timeout).
    Fixed "Cannot bind argument to parameter ''Route'' because it is an empty string" exception for New-AdminPowerAppEnvironment.

2.0.59:
    Fixed removing connector from policy that had been added with an invalid connector ID.

2.0.57:
    Fixed pagination problem for Get-DlpPolicy, Get-AdminFlow, and Get-AdminPowerApp.

2.0.56:
    Fixed duplicate key error for ConvertFrom-Json with case-invariant comparison.

2.0.53:
    Added early Public Preview release of DLP (Data Loss Prevention) v2 PowerShell cmdlets

2.0.52:
    Introduced new cmdlets for admins to list and recover deleted Power Apps

2.0.45:
    Fixed missing Example sections for some incorrectly formatted cmdlet headers

2.0.44:
    Added a cmdlet to download a manifest of all user''s Power Apps licenses for a tenant

2.0.42:
    Fixed cmdlet deadlock issue when long-running operations reached a timeout condition

2.0.40:
    Fixed set of codes to wait for when long-running operations were checking for status
    Fixed an incorrect error message when creating a CDS database environment failed
    Fixed defective ability to associate new DLP policies with specific environments

2.0.37:
    Fixed bug when deserializing "Common Data Service for Apps" environment information
    Introduced new cmdlets for admins to get and set additional notification emails

2.0.34:
    Added logic to skip filtered flows that could not be deserialized instead of failing
    Fixed bug that prevented paging from working properly when getting all flows as admin

2.0.33:
    Enabled creation of new environments as type Sandbox [addition to Trial and Production]

2.0.31:
    Introduced new cmdlets for admins to list and recover soft-deleted environments

2.0.27:
    Revamp cmdlets to block and allow consent plans in response to breaking service change

2.0.26:
    Fixed a handful of bugs related to parameters to create new CDS database environments

2.0.19:
    Introduced new cmdlet to get all CDS database templates so all inputs are retrievable

2.0.15:
    Introduced new cmdlet to sync licensed and authorized AAD tenant user into environment
    Fixed bugs in limited Private Preview cmdlets for DLP v1 connector Blocking [obsolete]
    Added limited Private Preview cmdlets for DLP v1 connector Blocking [obsolete]

2.0.12:
    Introduced new cmdlets to block and allow consent plans in tenant

2.0.6:
    Added support for the Verbose flag to extend to internal calls'
    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = 'PowerApp'

}

# SIG # Begin signature block
# MIIjhAYJKoZIhvcNAQcCoIIjdTCCI3ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAXvK1RtMjiUIj/
# QguWAzS89ag5bByirKmrUfpEpgZx6qCCDYEwggX/MIID56ADAgECAhMzAAABh3IX
# chVZQMcJAAAAAAGHMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAwMzA0MTgzOTQ3WhcNMjEwMzAzMTgzOTQ3WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDOt8kLc7P3T7MKIhouYHewMFmnq8Ayu7FOhZCQabVwBp2VS4WyB2Qe4TQBT8aB
# znANDEPjHKNdPT8Xz5cNali6XHefS8i/WXtF0vSsP8NEv6mBHuA2p1fw2wB/F0dH
# sJ3GfZ5c0sPJjklsiYqPw59xJ54kM91IOgiO2OUzjNAljPibjCWfH7UzQ1TPHc4d
# weils8GEIrbBRb7IWwiObL12jWT4Yh71NQgvJ9Fn6+UhD9x2uk3dLj84vwt1NuFQ
# itKJxIV0fVsRNR3abQVOLqpDugbr0SzNL6o8xzOHL5OXiGGwg6ekiXA1/2XXY7yV
# Fc39tledDtZjSjNbex1zzwSXAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUhov4ZyO96axkJdMjpzu2zVXOJcsw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDU4Mzg1MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAixmy
# S6E6vprWD9KFNIB9G5zyMuIjZAOuUJ1EK/Vlg6Fb3ZHXjjUwATKIcXbFuFC6Wr4K
# NrU4DY/sBVqmab5AC/je3bpUpjtxpEyqUqtPc30wEg/rO9vmKmqKoLPT37svc2NV
# BmGNl+85qO4fV/w7Cx7J0Bbqk19KcRNdjt6eKoTnTPHBHlVHQIHZpMxacbFOAkJr
# qAVkYZdz7ikNXTxV+GRb36tC4ByMNxE2DF7vFdvaiZP0CVZ5ByJ2gAhXMdK9+usx
# zVk913qKde1OAuWdv+rndqkAIm8fUlRnr4saSCg7cIbUwCCf116wUJ7EuJDg0vHe
# yhnCeHnBbyH3RZkHEi2ofmfgnFISJZDdMAeVZGVOh20Jp50XBzqokpPzeZ6zc1/g
# yILNyiVgE+RPkjnUQshd1f1PMgn3tns2Cz7bJiVUaqEO3n9qRFgy5JuLae6UweGf
# AeOo3dgLZxikKzYs3hDMaEtJq8IP71cX7QXe6lnMmXU/Hdfz2p897Zd+kU+vZvKI
# 3cwLfuVQgK2RZ2z+Kc3K3dRPz2rXycK5XCuRZmvGab/WbrZiC7wJQapgBodltMI5
# GMdFrBg9IeF7/rP4EqVQXeKtevTlZXjpuNhhjuR+2DMt/dWufjXpiW91bo3aH6Ea
# jOALXmoxgltCp1K7hrS6gmsvj94cLRf50QQ4U8Qwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWTCCFVUCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAYdyF3IVWUDHCQAAAAABhzAN
# BglghkgBZQMEAgEFAKCBoDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgO/l36LCV
# AC4MoeQcQaJCO7yY5+aWXjGNf7IlH2EuxqUwNAYKKwYBBAGCNwIBDDEmMCSgEoAQ
# AFQAZQBzAHQAUwBpAGcAbqEOgAxodHRwOi8vdGVzdCAwDQYJKoZIhvcNAQEBBQAE
# ggEAZeTM5f5XDCWF8UC23IxIngIMd/M19AAFLFhY1atGSGcTWgA3O6Cg6wbeLi3o
# bzWuWcidOYqECKtPABeS3Sk3cxDCy5nLJUzr4IOrY5pG7UdYcbSbH1D6gYWwy5Xj
# zyWb8m3kCkBpovKGX7lICCsU/KXRTgeb2YFw+xcv6Hkltj5TenB35xmgDVD1aUel
# cvBCvmSixHibRVvA9S+g1HuwYJ2BLyI/kKBP+vL0S1HcdU7Jf1d2wKWFP3+z/e37
# X/F8PM/wzbLMB2IOR54QqvEH7Waqhu2aw6rjQGEpsvDpfH21HnO/OSEb3qM22b9w
# RsmGiiGY1ns+s5103JgpUc/HhqGCEvEwghLtBgorBgEEAYI3AwMBMYIS3TCCEtkG
# CSqGSIb3DQEHAqCCEsowghLGAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFVBgsqhkiG
# 9w0BCRABBKCCAUQEggFAMIIBPAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQC
# AQUABCCzc9zwFcyU27w6jLFJUWVsNClpBlI2hbRMszY/QbXewAIGYA9Ar2BBGBMy
# MDIxMDEyNjIxMDkxMC41MTFaMASAAgH0oIHUpIHRMIHOMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0
# aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MEE1Ni1F
# MzI5LTRENEQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# gg5EMIIE9TCCA92gAwIBAgITMwAAAScvbqPvkagZqAAAAAABJzANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0xOTEyMTkwMTE0
# NTlaFw0yMTAzMTcwMTE0NTlaMIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVydG8g
# UmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MEE1Ni1FMzI5LTRENEQxJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQD4Ad5xEZ5On0uNL71ng9xwoDPRKeMUyEIj5yVx
# PRPh5GVbU7D3pqDsoXzQMhfeRP61L1zlU1HCRS+129eo0yj1zjbAlmPAwosUgyIo
# nesWt9E4hFlXCGUcIg5XMdvQ+Ouzk2r+awNRuk8ABGOa0I4VBy6zqCYHyX2pGaui
# B43frJSNP6pcrO0CBmpBZNjgepof5Z/50vBuJDUSug6OIMQ7ZwUhSzX4bEmZUUjA
# ycBb62dhQpGqHsXe6ypVDTgAEnGONdSBKkHiNT8H0Zt2lm0vCLwHyTwtgIdi67T/
# LCp+X2mlPHqXsY3u72X3GYn/3G8YFCkrSc6m3b0wTXPd5/2fAgMBAAGjggEbMIIB
# FzAdBgNVHQ4EFgQU5fSWVYBfOTEkW2JTiV24WNNtlfIwHwYDVR0jBBgwFoAU1WM6
# XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5t
# aWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENBXzIwMTAt
# MDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAxMC0wNy0w
# MS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQsFAAOCAQEACsqNfNFVxwalZ42cEMuzZc126Nvluanx8UewDVeUQZEZHRmp
# pMFHAzS/g6RzmxTyR2tKE3mChNGW5dTL730vEbRhnYRmBgiX/gT3f4AQrOPnZGXY
# 7zszcrlbgzxpakOX+x0u4rkP3Ashh3B2CdJ11XsBdi5PiZa1spB6U5S8D15gqTUf
# oIniLT4v1DBdkWExsKI1vsiFcDcjGJ4xRlMRF+fw7SY0WZoOzwRzKxDTdg4DusAX
# paeKbch9iithLFk/vIxQrqCr/niW8tEA+eSzeX/Eq1D0ZyvOn4e2lTnwoJUKH6OQ
# AWSBogyK4OCbFeJOqdKAUiBTgHKkQIYh/tbKQjCCBnEwggRZoAMCAQICCmEJgSoA
# AAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRl
# IEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIxNDY1NVow
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3DQEBAQUA
# A4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF++18aEss
# X8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRDDNdNuDgI
# s0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSxz5NMksHE
# pl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1rL2KQk1A
# UdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16HgcsOmZzTzn
# L0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB4jAQBgkr
# BgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqFbVUwGQYJ
# KwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQF
# MAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8w
# TTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVj
# dHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBK
# BggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9N
# aWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCBkjCBjwYJ
# KwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwA
# ZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQALiAdMA0G
# CSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUxvs8F4qn+
# +ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GASinbMQEBB
# m9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1L3mBZdmp
# tWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWOM7tiX5rb
# V0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4pm3S4Zz5
# Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45V3aicaoG
# ig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x4QDf5zEH
# pJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEegPsbiSpU
# ObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKnQqLJzxlB
# TeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp3lfB0d4w
# wP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvTX4/edIhJ
# EqGCAtIwggI7AgEBMIH8oYHUpIHRMIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVy
# dG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MEE1Ni1FMzI5LTRENEQx
# JTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUr
# DgMCGgMVALOVuE5sgxzETO4s+poBqI6r1x8zoIGDMIGApH4wfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDjumfOMCIYDzIwMjEw
# MTI2MTQwNTAyWhgPMjAyMTAxMjcxNDA1MDJaMHcwPQYKKwYBBAGEWQoEATEvMC0w
# CgIFAOO6Z84CAQAwCgIBAAICJbECAf8wBwIBAAICEakwCgIFAOO7uU4CAQAwNgYK
# KwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQAC
# AwGGoDANBgkqhkiG9w0BAQUFAAOBgQCaVWTNP6WjZWDp2F058FJUFgT1mZLl7evz
# /7MmuU/3kMVdD7ZLq390Y0wLYNs0XoqRFdZ/xXPkQYvIZ2wM4CIEXTp1CdsIuzVj
# /Ma9MBrO7cMlAXkovwmjsUnUqDU2I1W//dm8DRPUTZbP4PhpOg9ZLocD8vXoyXjH
# x9PhUdGNgjGCAw0wggMJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAy
# MDEwAhMzAAABJy9uo++RqBmoAAAAAAEnMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkq
# hkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIGMdo1s+oim6
# nrCloFO4Ed2PFvRM2H8NBJipTG1oGmjZMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB
# 5DCBvQQgG5LoSxKGHWoW/wVMlbMztlQ4upAdzEmqH//vLu0jPiIwgZgwgYCkfjB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAScvbqPvkagZqAAAAAAB
# JzAiBCD09fSpmHjVAuBwtRv6coBN4qjgfQUQzR9GLUuAmktxhjANBgkqhkiG9w0B
# AQsFAASCAQCOU9lhCmBGUJwgQFMkFYZkk1zK1pOQne+aXYYB5AJz+cIbTtIU+jTK
# Issk5w8UsfONu5wcZEcZizOU3aVeuOqzZBAqa5UbwCWh/XXJtSg1yjVYq0WZ97QU
# 43SwGU9uHCDy7Y+C0yGaqi8Wnm+l+sb59i9tlY4i09mwwB2vywHj1RQLDt4b93nv
# C4KiTLuFSQxtLo6mNYFs68P+dcK338uinGyVDHnlea9OMaLdmuFSK/CNerHjGIPl
# xKuo8UoQ4dIRzRBqbNy+04AjrjpTaC+ybALOuAnmLfcTxYS8uN/OPkmRxso3AYhr
# Vqy+zz2g5zE2HM44XIPAv+OlRKzguCcN
# SIG # End signature block
