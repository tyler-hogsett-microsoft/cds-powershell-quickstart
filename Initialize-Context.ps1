[CmdletBinding(DefaultParameterSetName="ClientSecretAuthentication")]

param(
  [Parameter(Mandatory=$true)]
  [string]$Url,
  [Parameter(Mandatory=$true)]
  [string]$SolutionFolder,
  [string]$SolutionUniqueName = (% {
    $solutionXmlFilePath = "$PSScriptRoot\..\$SolutionFolder\Other\solution.xml"
    if(Test-Path $solutionXmlFilePath) {
      $solutionXml = [xml](Get-Content $solutionXmlFilePath)
      $solutionXml.SelectSingleNode(
        "/ImportExportXml/SolutionManifest/UniqueName"
      ).InnerText
    } else {
      Read-Host -Prompt "UniqueName"
    }
  }),

  [Parameter(
    Mandatory=$true,
    ParameterSetName="ClientSecretAuthentication")]
  [string]$ClientId,
  [Parameter(
    Mandatory=$true,
    ParameterSetName="ClientSecretAuthentication")]
  [SecureString]$ClientSecret,

  [Parameter(
    Mandatory=$true,
    ParameterSetName="UsernamePasswordAuthentication")]
  [switch]$UseBasicAuthentication,

  [Parameter(
    Mandatory=$true,
    ParameterSetName="ActiveDirectoryAuthentication"
  )]
  [switch]$UseActiveDirectoryAuthentication,

  [Parameter(
    Mandatory=$true,
    ParameterSetName="UsernamePasswordAuthentication")]
  [Parameter(ParameterSetName="ActiveDirectoryAuthentication")]
  [string]$Username,
  [Parameter(
    Mandatory=$true,
    ParameterSetName="UsernamePasswordAuthentication")]
  [Parameter(ParameterSetName="ActiveDirectoryAuthentication")]
  [SecureString]$Password,
  [Parameter(ParameterSetName="ActiveDirectoryAuthentication")]
  [string]$Domain
)

$context = @{
  Url = $Url;
  SolutionFolder = $SolutionFolder;
  SolutionUniqueName = $SolutionUniqueName
}
if($UseBasicAuthentication)
{
  $context.AuthenticationType = "Basic"
  $context.Username = $Username
  $context.Password = (ConvertFrom-SecureString $Password)
} elseif($UseActiveDirectoryAuthentication) {
  $context.AuthenticationType = "ActiveDirectory"
  if($Username) {
    $context.Username = $Username
    $context.Password = (ConvertFrom-SecureString $Password)
    $context.Domain = $Domain
  }
} else {
  $context.AuthenticationType = "ClientSecret"
  $context.ClientId = $ClientId
  $context.ClientSecret = (ConvertFrom-SecureString $ClientSecret)
}

$context | ConvertTo-Json `
| Out-File "$PSScriptRoot\..\local.config.json"