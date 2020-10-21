param(
    $connection = (. $PSScriptRoot\Get-CrmConnection.ps1),
    $solutionName = (. $PSScriptRoot\Get-SolutionName.ps1),
    $targetFolder = "$PSScriptRoot\..\temp\packed-solutions\",
    $zipFileName = "$solutionName.zip",
    $packageType = "Both"
)

. $PSScriptRoot\Import-Module "Microsoft.Xrm.Data.Powershell"

if(-not (Test-Path $targetFolder)) {
    New-Item -Path $targetFolder -ItemType Directory
}
Remove-Item "$targetFolder\$zipFileName" -ErrorAction Ignore
Remove-Item "$targetFolder\$($zipFileName -Replace "\.zip$", "_managed.zip")" -ErrorAction Ignore

if($packageType -eq "Both" -or $packageType -eq "Unmanaged") {
    Export-CrmSolution `
        -conn $connection `
        -SolutionName $solutionName `
        -SolutionFilePath $targetFolder `
        -SolutionZipFileName $zipFileName
}

if($packageType -eq "Both" -or $packageType -eq "Managed") {
    Export-CrmSolution `
        -conn $connection `
        -SolutionName $solutionName `
        -SolutionFilePath $targetFolder `
        -SolutionZipFileName (% {
            if($packageType -eq "Both") {
                $zipFileName -Replace "\.zip$", "_managed.zip"
            } else {
                $zipFileName
            }
        }) `
        -Managed
}
