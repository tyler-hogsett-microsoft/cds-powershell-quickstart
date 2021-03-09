$local:ErrorActionPreference = "Stop"
function Get-AudienceForHostName
{
    [CmdletBinding()]
    Param(
        [string] $Uri
    )

    $hostMapping = @{
        "management.azure.com" = "https://management.azure.com/";
        "api.powerapps.com" = "https://service.powerapps.com/";
        "api.apps.appsplatform.us" = "https://service.apps.appsplatform.us/";
        "tip1.api.powerapps.com" = "https://service.powerapps.com/";
        "tip2.api.powerapps.com" = "https://service.powerapps.com/";
        "graph.windows.net" = "https://graph.windows.net/";
        "api.bap.microsoft.com" = "https://service.powerapps.com/";
        "tip1.api.bap.microsoft.com" = "https://service.powerapps.com/";
        "tip2.api.bap.microsoft.com" = "https://service.powerapps.com/";
        "api.flow.microsoft.com" = "https://service.flow.microsoft.com/";
        "api.flow.appsplatform.us" = "https://service.flow.appsplatform.us/";
        "tip1.api.flow.microsoft.com" = "https://service.flow.microsoft.com/";
        "tip2.api.flow.microsoft.com" = "https://service.flow.microsoft.com/";
        "gov.api.bap.microsoft.us" = "https://gov.service.powerapps.us/";
        "high.api.bap.microsoft.us" = "https://high.service.powerapps.us/";
        "api.bap.appsplatform.us" = "https://service.apps.appsplatform.us/";
        "gov.api.powerapps.us" = "https://gov.service.powerapps.us/";
        "high.api.powerapps.us" = "https://high.service.powerapps.us/";
        "gov.api.flow.microsoft.us" = "https://gov.service.flow.microsoft.us/";
        "high.api.flow.microsoft.us" = "https://high.service.flow.microsoft.us/";
    }

    $uriObject = New-Object System.Uri($Uri)
    $hostName = $uriObject.Host

    if ($null -ne $hostMapping[$hostName])
    {
        return $hostMapping[$hostName];
    }

    Write-Verbose "Unknown host $hostName. Using https://management.azure.com/ as a default";
    return "https://management.azure.com/";
}

function Invoke-Request(
    [CmdletBinding()]

    [Parameter(Mandatory=$True)]
    [string] $Uri,

    [Parameter(Mandatory=$True)]
    [string] $Method,

    [object] $Body = $null,

    [Hashtable] $Headers = @{},

    [switch] $ParseContent,

    [switch] $ThrowOnFailure
)
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $audience = Get-AudienceForHostName -Uri $Uri
    $token = Get-JwtToken -Audience $audience
    $Headers["Authorization"] = "Bearer $token";
    $Headers["User-Agent"] = "PowerShell cmdlets 1.0";

    try {
        if ($null -eq $Body -or $Body -eq "")
        {
            $response = Invoke-WebRequest -Uri $Uri -Headers $Headers -Method $Method -UseBasicParsing
        }
        else
        {
            $jsonBody = ConvertTo-Json $Body -Depth 20
            $response = Invoke-WebRequest -Uri $Uri -Headers $Headers -Method $Method -ContentType "application/json; charset=utf-8" -Body $jsonBody -UseBasicParsing
        }

        if ($ParseContent)
        {
            if ($response.Content)
            {
                return ConvertFrom-JsonWithErrorHandling -JsonString $response.Content;
            }
        }

        return $response
    } catch {
        $response = $_.Exception.Response
        if ($_.ErrorDetails)
        {
            $errorResponse = ConvertFrom-JsonWithErrorHandling -JsonString $_.ErrorDetails;
            $code = $response.StatusCode.value__
            $message = $errorResponse.Error.Message
            Write-Verbose "Status Code: '$code'. Message: '$message'"

            $response = New-Object -TypeName PSObject `
                | Add-Member -PassThru -MemberType NoteProperty -Name StatusCode -Value $response.StatusCode.value__ `
                | Add-Member -PassThru -MemberType NoteProperty -Name StatusDescription -Value $response.StatusDescription `
                | Add-Member -PassThru -MemberType NoteProperty -Name Headers -Value $response.Headers `
                | Add-Member -PassThru -MemberType NoteProperty -Name Error -Value $errorResponse.Error `
                | Add-Member -PassThru -MemberType NoteProperty -Name Message -Value $message `
                | Add-Member -PassThru -MemberType NoteProperty -Name Internal -value $response;
        }

        if ($ThrowOnFailure)
        {
            throw;
        }
        else
        {
            return $response
        }
    }
}

function InvokeApi
{
    <#
    .SYNOPSIS
    Invoke an API.
    .DESCRIPTION
    The InvokeApi cmdlet invokes an API based on input parameters.
    Use Get-Help InvokeApi -Examples for more detail.
    .PARAMETER Method
    The http request method.
    .PARAMETER Route
    The http URL.
    .PARAMETER Body
    The http request body.
    .PARAMETER ThrowOnFailure
    Throw exception on failure if it is true.
    .PARAMETER ApiVersion
    The service API version.
    .EXAMPLE
    InvokeApi -Method GET -Route $uri -Body $body -ThrowOnFailure
    Call $uri API as GET method with $body input and throw exception on failure.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Route,

        [Parameter(Mandatory = $false)]
        [object]$Body = $null,

        [Parameter(Mandatory = $false)]
        [switch]$ThrowOnFailure,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )

    Test-PowerAppsAccount;

    $uri = $Route `
        | ReplaceMacro -Macro "{apiVersion}"  -Value $ApiVersion `
        | ReplaceMacro -Macro "{flowEndpoint}" -Value $global:currentSession.flowEndpoint `
        | ReplaceMacro -Macro "{powerAppsEndpoint}" -Value $global:currentSession.powerAppsEndpoint `
        | ReplaceMacro -Macro "{bapEndpoint}" -Value $global:currentSession.bapEndpoint `
        | ReplaceMacro -Macro "{graphEndpoint}" -Value $global:currentSession.graphEndpoint `
        | ReplaceMacro -Macro "{cdsOneEndpoint}" -Value $global:currentSession.cdsOneEndpoint;

    Write-Verbose $uri

    If($ThrowOnFailure)
    {
        $result = Invoke-Request `
        -Uri $uri `
        -Method $Method `
        -Body $body `
        -ParseContent `
        -ThrowOnFailure `
        -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true);
    }
    else {
        $result = Invoke-Request `
        -Uri $uri `
        -Method $Method `
        -Body $body `
        -ParseContent `
        -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true);
    }

    if($result.nextLink)
    {
        $nextLink = $result.nextLink
        $resultValue = $result.value

        while($nextLink)
        {
            If($ThrowOnFailure)
            {
                $nextResult = Invoke-Request `
                -Uri $nextLinkuri `
                -Method $Method `
                -Body $body `
                -ParseContent `
                -ThrowOnFailure `
                -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true);
            }
            else {
                $nextResult = Invoke-Request `
                -Uri $nextLink `
                -Method $Method `
                -Body $body `
                -ParseContent `
                -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true);
            }

            $nextLink = $nextResult.nextLink
            $resultValue = $resultValue + $nextResult.value
        }

        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name value -Value $resultValue `
    }

    return $result;
}

function InvokeApiNoParseContent
{
    <#
    .SYNOPSIS
    Invoke an API without parsing return content.
    .DESCRIPTION
    The InvokeApiNoParseContent cmdlet invokes an API based on input parameters without parsing return content.
    Use Get-Help InvokeApiNoParseContent -Examples for more detail.
    .PARAMETER Method
    The http request method.
    .PARAMETER Route
    The http URL.
    .PARAMETER Body
    The http request body.
    .PARAMETER ThrowOnFailure
    Throw exception on failure if it is true.
    .PARAMETER ApiVersion
    The service API version.
    .EXAMPLE
    InvokeApiNoParseContent -Method PUT -Route $uri -Body $body -ThrowOnFailure
    Call $uri API as PUT method with $body input and throw exception on failure.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Route,

        [Parameter(Mandatory = $false)]
        [object]$Body = $null,

        [Parameter(Mandatory = $false)]
        [switch]$ThrowOnFailure,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )

    Test-PowerAppsAccount;

    $uri = $Route `
        | ReplaceMacro -Macro "{apiVersion}"  -Value $ApiVersion `
        | ReplaceMacro -Macro "{flowEndpoint}" -Value $global:currentSession.flowEndpoint `
        | ReplaceMacro -Macro "{powerAppsEndpoint}" -Value $global:currentSession.powerAppsEndpoint `
        | ReplaceMacro -Macro "{bapEndpoint}" -Value $global:currentSession.bapEndpoint `
        | ReplaceMacro -Macro "{graphEndpoint}" -Value $global:currentSession.graphEndpoint `
        | ReplaceMacro -Macro "{cdsOneEndpoint}" -Value $global:currentSession.cdsOneEndpoint;

    Write-Verbose $uri

    If($ThrowOnFailure)
    {
        $result = Invoke-Request `
        -Uri $uri `
        -Method $Method `
        -Body $body `
        -ThrowOnFailure `
        -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true);
    }
    else {
        $result = Invoke-Request `
        -Uri $uri `
        -Method $Method `
        -Body $body `
        -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true);
    }

    if($result.nextLink)
    {
        $nextLink = $result.nextLink
        $resultValue = $result.value

        while($nextLink)
        {
            If($ThrowOnFailure)
            {
                $nextResult = Invoke-Request `
                -Uri $nextLinkuri `
                -Method $Method `
                -Body $body `
                -ThrowOnFailure `
                -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true);
            }
            else {
                $nextResult = Invoke-Request `
                -Uri $nextLink `
                -Method $Method `
                -Body $body `
                -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true);
            }

            $nextLink = $nextResult.nextLink
            $resultValue = $resultValue + $nextResult.value
        }

        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name value -Value $resultValue `
    }

    return $result;
}

function ReplaceMacro
{
    <#
    .SYNOPSIS
    Replace macro to the specified value.
    .DESCRIPTION
    The ReplaceMacro cmdlet replace macro in input string with the specified value.
    Use Get-Help ReplaceMacro -Examples for more detail.
    .PARAMETER Input
    The input string.
    .PARAMETER Macro
    The macro to be replaced.
    .PARAMETER Value
    The value for the replacement.
    .EXAMPLE
    ReplaceMacro -Macro "{apiVersion}"  -Value $ApiVersion
    Replace {apiVersion} to $ApiVersion.
    #>
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Input,

        [Parameter(Mandatory = $true)]
        [string]$Macro,

        [Parameter(Mandatory = $false)]
        [string]$Value
    )

    return $Input.Replace($Macro, $Value)
}


function BuildFilterPattern
{
    param
    (
        [Parameter(Mandatory = $false)]
        [object]$Filter
    )

    if ($null -eq $Filter -or $Filter.Length -eq 0)
    {
        return New-Object System.Management.Automation.WildcardPattern "*"
    }
    else
    {
        return New-Object System.Management.Automation.WildcardPattern @($Filter,"IgnoreCase")
    }
}

function ConvertFrom-JsonWithErrorHandling
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$JsonString
    )

    try {
        return ConvertFrom-Json $JsonString
    } catch {
        Write-Verbose "Invalid JSON string: '$JsonString', falling back to .NET deserialization."

        # try to de-serialize the json string by using .Net json serializer
        [void][System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")
        return (New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer -Property @{MaxJsonLength=67108864}).DeserializeObject($JsonString)
    }
}

function ResolveEnvironment
{
    param
    (
        [Parameter(Mandatory = $false)]
        [string]$OverrideId
    )

    if (-not [string]::IsNullOrWhiteSpace($OverrideId))
    {
        return $OverrideId;
    }
    elseif ($global:currentSession.selectedEnvironment)
    {
        return $global:currentSession.selectedEnvironment;
    }

    return "~default";
}


function Select-CurrentEnvironment
{
 <#
 .SYNOPSIS
 Sets the current environment for listing powerapps, flows, and other environment resources
 .DESCRIPTION
 The Select-CurrentEnvironment cmdlet sets the current environment in which commands will
 execute when an environment is not specified. Use Get-Help Select-CurrentEnvironment -Examples
 for more detail.
 .PARAMETER EnvironmentName
 Environment identifier (not display name).
 .PARAMETER Default
 Shortcut to specify the default tenant environment
 .EXAMPLE
 Select-CurrentEnvironment -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Select environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239 as the current environment. Cmdlets invoked
 after running this command will operate against this environment.
 .EXAMPLE
 Select-CurrentEnvironment ~default
 Select the default environment. Cmdlets invoked after running this will operate against the default
 environment.
 #>
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName=$true, ParameterSetName = "Name")]
        [String]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "Default")]
        [Switch]$Default
    )

    Test-PowerAppsAccount;

    if ($Default)
    {
        $global:currentSession.selectedEnvironment = "~default";
    }
    else
    {
        $global:currentSession.selectedEnvironment = $EnvironmentName;
    }
}
# SIG # Begin signature block
# MIIjeAYJKoZIhvcNAQcCoIIjaTCCI2UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAbQPh+W+zJoKJJ
# KyQRqVihpv4ScaJ0Kod8yts9+RTD5aCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVTTCCFUkCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBoDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgsG3fE0tT
# Bx/G4exmROb3Vklz6n8K2aJPJ1rR4TJ80vowNAYKKwYBBAGCNwIBDDEmMCSgEoAQ
# AFQAZQBzAHQAUwBpAGcAbqEOgAxodHRwOi8vdGVzdCAwDQYJKoZIhvcNAQEBBQAE
# ggEANDu0pD9gzBl8E2/gWcuHwRirdFRV8ngT4vpP3wkDQhUkNtgviZdPNjp9zecs
# G82VUyz1VpBCIT4iwrjicRNvY5/nH8Qv/T+VLlZSeBEvbF3d5aUKIz90Jy/+JU8F
# Yf1bGw5BFp6gqLs3e+t1NwonBkubHqjQkh43jpKt/uQnQt4nXTJljzNiN2t+8ORa
# m6T0CVIlnv7FX4N+joCDdvoR1pu8oD1RKOh2+Sb2DoGFIkfUmpkIJI6TRKtKWNYW
# E5vwcKdz9K/6h43kRKbY2VDsDyvoXlvmdv1RQLL0Xbm4jpVgEZubTOLVRCps6kWm
# 3tGABsDv2pF18mxlyqS5DGVcHqGCEuUwghLhBgorBgEEAYI3AwMBMYIS0TCCEs0G
# CSqGSIb3DQEHAqCCEr4wghK6AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsqhkiG
# 9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQC
# AQUABCD/haaYiz7tGGu7Z2zfemGSptuCD0IpkzhnM/elZLjbpQIGYCWJPr4GGBMy
# MDIxMDIyMzAwNTI1Ni4xMDFaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmlj
# YSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpFQUNFLUUzMTYt
# QzkxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCDjww
# ggTxMIID2aADAgECAhMzAAABTMVMwdDbbz+yAAAAAAFMMA0GCSqGSIb3DQEBCwUA
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIwMTExMjE4MjYwMFoX
# DTIyMDIxMTE4MjYwMFowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAk
# BgNVBAsTHVRoYWxlcyBUU1MgRVNOOkVBQ0UtRTMxNi1DOTFEMSUwIwYDVQQDExxN
# aWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAymFgUcOsx7nvo1XsgQoP+OTfvE+JpON57bMrdc/6pQmkFUxj
# YgLFpFGHLUKfJ//m9ZGmffcGT3FsZ6CeluSgvzzRs2lJnq5ZynNKAUE52Y1StMG3
# 3pFZdo9juS1QwFkRa+JJ/fIJXYheBZgBAW5n2yxD1iCOmjWm9Su1qhTACOJozjfp
# QJT19bUP6RwQfTmbiG5xZsTwlb471vduV62K/vyf58LqgqTppJBFEUvg4mKi9L6J
# vXvkbqlJ/3ANGT1feQ7rrU60JysdkB/B7YwdcM/h5l8ZGSwD8i++ssU1xqMjsi3p
# PH6icPJHmKBGL6QImhMbRhQYLVQyMIrTla0OuwIDAQABo4IBGzCCARcwHQYDVR0O
# BBYEFAGWHqcECl7nJ5VCAYD0EEfeZvp8MB8GA1UdIwQYMBaAFNVjOlyKMZDzQ3t8
# RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNy
# bDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAtMDctMDEuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggEBAE8E5LD31kOuqIBir3frZncdiEGGhJe8x4gIb3HDuuWnyEC2aJIc8gBwzvjG
# R9hmd0F/VlDm6dTliZX788b9C7s1fxkqCRyw1bxQ8CdVtOlH682Z//+Rd2IMk/dv
# xTuczNnTml5EoxXi9Q4RgPr7DDwc1JIESNFV9oRIEtneimM+jHNrJqin5ZdTlla2
# WiaXeguue6bWyJxNWrDfSYzaNj/Akkf9srhtNHPO/u3ufXyAH/5cL9hH+Pb60i6e
# 2PTEvRBQUbRe4EAv7rMtIK0lHfqrSE//vtmyTS3Ev3mY1ytF9FAnLjFPmWQYhlds
# DIRCDnUEblqiZU7/X7Tm+u3PymswggZxMIIEWaADAgECAgphCYEqAAAAAAACMA0G
# CSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3Jp
# dHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2NTVaMHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
# CgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvtfGhLLF/Fw+Vhwna3
# PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzXTbg4CLNC3ZOs1nMw
# VyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+TTJLBxKZd0WETbijG
# GvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9ikJNQFHRD5wGPmd/
# 9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDpmc085y9Euqf03GS9
# pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIwEAYJKwYBBAGCNxUB
# BAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1VMBkGCSsGAQQBgjcU
# AgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8G
# A1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeG
# RWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jv
# b0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUH
# MAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2Vy
# QXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIwgY8GCSsGAQQBgjcu
# AzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL1BLSS9k
# b2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwA
# XwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0B
# AQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7PBeKp/vpXbRkws8LF
# Zslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2zEBAQZvcXBf/XPle
# FzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95gWXZqbVr5MfO9sp6
# AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7Yl+a21dA6fHOmWaQ
# jP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt0uGc+R38ONiU9Mal
# CpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2onGqBooPiRa6YacR
# y5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA3+cxB6STOvdlR3jo
# +KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7G4kqVDmyW9rIDVWZ
# eodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Kiyc8ZQU3ghvkqmqMR
# ZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5XwdHeMMD9zOZN+w2/
# XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P3nSISRKhggLOMIIC
# NwIBATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQG
# A1UECxMdVGhhbGVzIFRTUyBFU046RUFDRS1FMzE2LUM5MUQxJTAjBgNVBAMTHE1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAD2ZW04J
# KBNidh0YzWMoBJca4PegoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTAwDQYJKoZIhvcNAQEFBQACBQDj3oeZMCIYDzIwMjEwMjIzMDM0MjE3WhgP
# MjAyMTAyMjQwMzQyMTdaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOPeh5kCAQAw
# CgIBAAICIRwCAf8wBwIBAAICETIwCgIFAOPf2RkCAQAwNgYKKwYBBAGEWQoEAjEo
# MCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG
# 9w0BAQUFAAOBgQBMXBo5wsL7WycypKfrKq17BeQNR9gynuk8WIAJZ1iTrC75tecX
# ON6a9rXVuSmK1UhLgT08P+fSu/Qla2WFKcj6IxgfbH9H2J+HWo8iLb11Us9zjI3d
# /nRv4EcW4MZXZC0p9Oydu+23bjVP5q/CCO+959l7xQ+2EkNcKhVkro72lDGCAw0w
# ggMJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABTMVM
# wdDbbz+yAAAAAAFMMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYL
# KoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIESQsd4oB50m8U+7adrrqh78mbP+
# fUEimWzr9eKGq5soMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg28Klu79Q
# SzLREEwg4fpPCy2GU33T+3PZrxBiZ8SvTiUwgZgwgYCkfjB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAUzFTMHQ228/sgAAAAABTDAiBCBCZxhS/nEX
# tzcHpZh646WCx8yoqPimc/BhLq6dppjW4jANBgkqhkiG9w0BAQsFAASCAQDE5prx
# YTvUE1zxY+RRwe2/WD5Ua104bifv5WTz6WSI7y8UpeMvs+t6/8UWme8X0EZ3URcd
# sRsxI4ifClvVN1rIBVdd25v9YnVViqr6BmVv1ZeS1MJGesGPM0ER0oyPPCJbqL9p
# 2Qf05x0HKYnnoOSMHwc++2vofXWh41ft1GQN2lqBBAkmesugtkNbegq19hbBTGut
# zPltZ0DMifQ2UxVVFkP3S1Ac9MWC1NQDM7w3rnNhqKHVq4SWomiP4semuh5vC3kr
# dU4qx8cjIMWNqh4XfojJILYb4247BDLWZaJUk4H26GPnuHBopjw6tjb8TvlXYthK
# rDN1jDvpQipwGBx6
# SIG # End signature block
