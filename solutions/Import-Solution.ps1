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

$tempFolder = "$PSScriptRoot\..\temp"
md $tempFolder -ErrorAction Ignore

$solutionFileName = "solution.zip"

$solutionFilePath = "$tempFolder\$solutionFileName"
Remove-Item $solutionFilePath -ErrorAction Ignore

$preSolutionPackagerDoctoredFolderPath = "$tempFolder\pre-solution-packager-doctored-solution"
Remove-Item $preSolutionPackagerDoctoredFolderPath -Recurse -Force -ErrorAction Ignore

Copy-Item $SourceFolderPath $preSolutionPackagerDoctoredFolderPath -Recurse

& $PSScriptRoot\doctoring\Add-KeysToMissingDependencies.ps1 `
    -SolutionFolderPath $preSolutionPackagerDoctoredFolderPath

& $PSScriptRoot\Run-SolutionPackager.ps1 `
    -Action Pack `
    -ZipFile $solutionFilePath `
    -PackageType $(if($Managed) { "Managed" } else { "Unmanaged" }) `
    -Folder $preSolutionPackagerDoctoredFolderPath

$postSolutionPackagerDoctoredFolderPath = "$tempFolder\post-solution-packager-doctored-solution"
Remove-Item $postSolutionPackagerDoctoredFolderPath -Recurse -Force -ErrorAction Ignore

Import-CrmSolution `
    -conn $Connection `
    -SolutionFilePath $solutionFilePath `
    -AsyncOperationImportMethod

if(-not $Managed) {
    Publish-CrmAllCustomization `
        -conn $Connection
}
