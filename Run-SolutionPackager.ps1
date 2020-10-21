param(
  $action,
  $solutionName = (. $PSScriptRoot\Get-SolutionName.ps1),
  $zipFilePath = (% {
    if ($solutionName) {
      "$PSScriptRoot\..\temp\packed-solutions\$($solutionName).zip"
    }
  }),
  $solutionFolderPath = (% {
    $context = . $PSScriptRoot\Get-Context.ps1
    if($context) {
      "$PSScriptRoot\..\$($context.SolutionFolder)"
    }
  }),
  $packageType = "Both"
)

Set-Alias SolutionPackager "$PSScriptRoot\..\nuget-tools\CoreTools\SolutionPackager.exe"

SolutionPackager `
  /action:$action `
  /zipfile:$zipFilePath `
  /packagetype:$packageType `
  /folder:$solutionFolderPath `
  /useUnmanagedFileForMissingManaged