param(
    $Connection = (. $PSScriptRoot\Get-CrmConnection.ps1),
    [Parameter(Mandatory=$true)]
    [string]$SchemaFilePath,
    [Parameter(Mandatory=$true)]
    [string]$TargetFolderPath
)

. $PSScriptRoot\Import-Module.ps1 Microsoft.Xrm.Tooling.ConfigurationMigration

$tempFolder = "$PSScriptRoot\temp"
md $tempFolder -ErrorAction Ignore

$dataFilePath = "$tempFolder\portal-data.zip"
Remove-Item $dataFilePath -ErrorAction Ignore

$logsPath = "$tempFolder\logs\portal-export"
New-Item $logsPath -ItemType Directory -ErrorAction Ignore

Export-CrmDataFile `
    -CrmConnection $Connection `
    -SchemaFile $SchemaFilePath `
    -DataFile $dataFilePath `
    -LogWriteDirectory $logsPath

Remove-Item $TargetFolderPath -Recurse -Force -ErrorAction Ignore
$job = Start-Job {
    param($Source, $Destination)
    Expand-Archive $Source $Destination
} -ArgumentList @(
    $dataFilePath,
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        $TargetFolderPath))
While ($job.State -eq "Running") {}
Receive-Job $job | Out-Null
