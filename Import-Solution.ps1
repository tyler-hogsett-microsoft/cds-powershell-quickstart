param(
  [Parameter(Mandatory=$true)]
  [string]$ConnectionString,
  [Parameter(Mandatory=$true)]
  [string]$SolutionFilePath
)

. $PSScriptRoot\Import-Module.ps1 Microsoft.Xrm.Tooling.CrmConnector.Powershell
. $PSScriptRoot\Import-Module.ps1 Microsoft.Xrm.Data.Powershell

Import-CrmSolution `
  -conn (Get-CrmConnection -ConnectionString $ConnectionString) `
  -SolutionFilePath (Resolve-Path $SolutionFilePath) `
  -ActivatePlugIns