param(
  [Parameter(Mandatory=$true)]
  [string]$Name
)

if(-Not (Get-Module -ListAvailable -Name $Name)) {
  Import-Module `
    -FullyQualifiedName "$PSScriptRoot\modules\$Name"
}
