param(
    $Connection,
    [Parameter(Mandatory=$true)]
    [string]$SourceFolderPath,
    [switch]$Managed
)

. $PSScriptRoot\..\environment-setup\Add-ModulesPath.ps1

if($Connection -eq $null)
{
    $Connection = (. $PSScriptRoot\..\cds\Get-CrmConnection.ps1)
}

$solutionFilePath = "$PSScriptRoot\..\temp\solution.zip"

& $PSScriptRoot\Compress-Solution.ps1 `
    -SourceFolderPath $SourceFolderPath `
    -SolutionZipFilePath $solutionFilePath `
    -PackageType $(if($Managed) { "Managed" } else { "Unmanaged" })

Import-CrmSolution `
    -conn $Connection `
    -SolutionFilePath $solutionFilePath `
    -AsyncOperationImportMethod

if(-not $Managed) {
    Publish-CrmAllCustomization `
        -conn $Connection
}
