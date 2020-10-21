if(-Not (Test-Path "$PSScriptRoot\..\local.config.json"))
{
  if(-not [Environment]::GetCommandLineArgs().Contains("-NonInteractive")) {
    . "$PSScriptRoot\Initialize-Context.ps1"
  }
}

if(Test-Path "$PSScriptRoot\..\local.config.json") {
  $context = Get-Content "$PSScriptRoot\..\local.config.json" `
  | ConvertFrom-Json

  if($context.Password) {
    $context.Password = (ConvertTo-SecureString $context.Password)
  }
  if($context.ClientSecret) {
    $context.ClientSecret = (ConvertTo-SecureString $context.ClientSecret)
  }

  $context
}
