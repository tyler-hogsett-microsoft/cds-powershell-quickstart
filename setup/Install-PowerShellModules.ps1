$modulesFolder = "$PSScriptRoot\..\modules"

Remove-Item $modulesFolder -Force -Recurse -ErrorAction Ignore
md $modulesFolder

function Install-ModuleLocally {
  param(
    [string]$Name,
    [string]$Version
  )
  
  if($Version) {
    Find-Module `
      -Name $Name `
      -Repository 'PSGallery' `
      -RequiredVersion $Version `
    | Save-Module -Path $modulesFolder
  } else {
    Find-Module `
      -Name $Name `
      -Repository 'PSGallery' `
    | Save-Module -Path $modulesFolder
  }
}

Install-ModuleLocally "Microsoft.Xrm.Tooling.CrmConnector.Powershell"
Install-ModuleLocally "Microsoft.Xrm.Tooling.ConfigurationMigration"
Install-ModuleLocally "Microsoft.Xrm.Data.Powershell"
Install-ModuleLocally "Microsoft.PowerApps.Administration.PowerShell"
Install-ModuleLocally "Microsoft.PowerApps.PowerShell"
Install-ModuleLocally "AzureAD"
