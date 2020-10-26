param(
    $Connection,
    [Parameter(Mandatory=$true)]
    [string]$FolderPath
)

if($Connection -eq $null)
{
    $Connection = (. $PSScriptRoot\..\cds\Get-CrmConnection.ps1)
}

. $PSScriptRoot\..\environment-setup\Add-ModulesPath.ps1

$tempFolder = "$PSScriptRoot\..\temp"
md $tempFolder -ErrorAction Ignore

$dataFilePath = "$tempFolder\portal-data.zip"

$job = Start-Job {
    param($Source, $Destination)
    Compress-Archive $Source $Destination -Force
} -ArgumentList @(
    "$(Resolve-Path $FolderPath)/*",
    $dataFilePath)
While ($job.State -eq "Running") {}
Receive-Job $job | Out-Null

$logsPath = "$tempFolder\logs\portal-import"
New-Item $logsPath -ItemType Directory -ErrorAction Ignore

Import-CrmDataFile `
    -CrmConnection $Connection `
    -DataFile $dataFilePath `
    -LogWriteDirectory $logsPath