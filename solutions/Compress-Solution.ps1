param(
    [Parameter(Mandatory)]
    [string]$SourceFolderPath,
    [Parameter(Mandatory)]
    [string]$SolutionZipFilePath,
    [Parameter(Mandatory)]
    [ValidateSet("Managed", "Unmanaged", "Both")]
    [string]$PackageType = "Both"
)

. $PSScriptRoot\..\environment-setup\Add-ModulesPath.ps1

$tempFolder = "$PSScriptRoot\..\temp"
md $tempFolder -ErrorAction Ignore

$preSolutionPackagerDoctoredFolderPath = "$tempFolder\pre-solution-packager-doctored-solution"
Remove-Item $preSolutionPackagerDoctoredFolderPath -Recurse -Force -ErrorAction Ignore

Copy-Item $SourceFolderPath $preSolutionPackagerDoctoredFolderPath -Recurse

& $PSScriptRoot\doctoring\Add-KeysToMissingDependencies.ps1 `
    -SolutionFolderPath $preSolutionPackagerDoctoredFolderPath

Remove-Item $SolutionZipFilePath -ErrorAction Ignore

& $PSScriptRoot\Run-SolutionPackager.ps1 `
    -Action Pack `
    -ZipFile $SolutionZipFilePath `
    -PackageType $PackageType `
    -Folder $preSolutionPackagerDoctoredFolderPath
