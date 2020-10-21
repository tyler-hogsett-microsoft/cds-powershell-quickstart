param(
    [string]$SolutionFolder = ((. "$PSScriptRoot\Get-Context.ps1").SolutionFolder)
)

$solutionXmlFilePath = "$PSScriptRoot\..\$SolutionFolder\Other\solution.xml"
if(Test-Path $solutionXmlFilePath) {
    $solutionXml = [xml](Get-Content $solutionXmlFilePath)
    $solutionXml.SelectSingleNode(
        "/ImportExportXml/SolutionManifest/UniqueName"
    ).InnerText
} elseif(-not [Environment]::GetCommandLineArgs().Contains("-NonInteractive")) {
    Read-Host -Prompt "SolutionName"
}
