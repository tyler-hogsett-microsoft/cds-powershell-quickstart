param(
  $Context = (. $PSScriptRoot\Get-Context.ps1),
  [string]$SolutionFolder = $Context.SolutionFolder,
  [string]$SolutionUniqueName = $Context.SolutionUniqueName,
  $Connection = (. $PSScriptRoot\Get-CrmConnection.ps1),
  [string]$SolutionZipFolderPath = "$(Resolve-Path $PSScriptRoot\..\temp)\packed-solutions",
  [string]$SolutionZipFileName = "$($Context.SolutionUniqueName).zip"
)

. $PSScriptRoot\Import-Module "Microsoft.Xrm.Data.Powershell"

Remove-Item $SolutionZipFolderPath -ErrorAction Ignore -Recurse
New-Item $SolutionZipFolderPath -ItemType Directory

Export-CrmSolution `
  -conn $Connection `
  -SolutionName $SolutionUniqueName `
  -SolutionFilePath $SolutionZipFolderPath `
  -SolutionZipFileName $SolutionZipFileName

<#Export-CrmSolution `
  -conn $Connection `
  -SolutionName $SolutionUniqueName `
  -SolutionFilePath $SolutionZipFolderPath `
  -SolutionZipFileName ("$SolutionZipFileName" -Replace "\.zip`$", "_managed.zip") `
  -Managed#>

$tempUnpackedFolder = "$PSScriptRoot\..\temp\unpacked-solution"
Remove-Item $tempUnpackedFolder -ErrorAction Ignore -Recurse

. $PSScriptRoot\Run-SolutionPackager.ps1 `
  -action Extract `
  -solutionName $SolutionUniqueName `
  -zipFilePath "$SolutionZipFolderPath\$SolutionZipFileName" `
  -solutionFolderPath $tempUnpackedFolder `
  -packageType Unmanaged

$solutionXml = New-Object xml
$solutionXml.Load("$tempUnpackedFolder\Other\solution.xml")
$managedNode = $solutionXml.SelectSingleNode("/ImportExportXml/SolutionManifest/Managed")
$managedNode.InnerText = "2"
$solutionXml.Save("$tempUnpackedFolder\Other\solution.xml")

$solutionFolderPath = "$PSScriptRoot\..\$SolutionFolder"
Remove-Item $solutionFolderPath -Recurse -ErrorAction Ignore
Copy-Item `
  -Path $tempUnpackedFolder `
  -Destination $solutionFolderPath `
  -Recurse
