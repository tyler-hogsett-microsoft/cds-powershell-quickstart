if(-not (Get-PackageProvider -Name NuGet))
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-PackageProvider -Name NuGet -RequiredVersion 2.8.5.201 -Force
}
