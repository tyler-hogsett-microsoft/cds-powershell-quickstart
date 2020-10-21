param(
  [Parameter(ParameterSetName="Dev")]
  $Context = (. $PSScriptRoot\Get-Context.ps1),
  [Parameter(ParameterSetName="Dev")]
  [string]$SolutionFolder = $Context.SolutionFolder,

  [Parameter(Mandatory=$true, ParameterSetName="NonInteractive")]
  [string]$ConnectionString,
  
  [Parameter(ParameterSetName="Dev")]
  $Connection = (. $PSScriptRoot\Get-CrmConnection.ps1),
  
  [Parameter(Mandatory=$true, ParameterSetName="NonInteractive")]
  [Parameter(ParameterSetName="Dev")]
  [string]$SolutionFilePath =
    "$(Resolve-Path $PSScriptRoot\..\temp)\packed-solutions\$($Context.SolutionUniqueName)" +
      "$( if($Managed) { "_managed" } ).zip",

  [switch]$Managed
)

. $PSScriptRoot\Import-Module.ps1 Microsoft.Xrm.Tooling.CrmConnector.Powershell
. $PSScriptRoot\Import-Module.ps1 Microsoft.Xrm.Data.Powershell

if($PSCmdlet.ParameterSetName -eq "Dev") {
  . $PSScriptRoot\Run-SolutionPackager.ps1 `
    -action Pack `
    -solutionName $SolutionUniqueName `
    -zipFilePath $SolutionFilePath `
    -solutionFolder $SolutionFolder `
    -packageType (% { if($Managed) { "Managed" } else { "Unmanaged" } })
} else {
  $Connection = Get-CrmConnection -ConnectionString $ConnectionString
}
<#
Import-CrmSolution `
  -conn $Connection `
  -SolutionFilePath $SolutionFilePath `
  -ActivatePlugIns
if(-not $Managed) {
  Publish-CrmAllCustomization `
    -conn $Connection
}
#>