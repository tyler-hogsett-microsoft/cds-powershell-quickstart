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
# MIIjhAYJKoZIhvcNAQcCoIIjdTCCI3ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAbQPh+W+zJoKJJ
# KyQRqVihpv4ScaJ0Kod8yts9+RTD5aCCDYEwggX/MIID56ADAgECAhMzAAABh3IX
# chVZQMcJAAAAAAGHMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAwMzA0MTgzOTQ3WhcNMjEwMzAzMTgzOTQ3WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDOt8kLc7P3T7MKIhouYHewMFmnq8Ayu7FOhZCQabVwBp2VS4WyB2Qe4TQBT8aB
# znANDEPjHKNdPT8Xz5cNali6XHefS8i/WXtF0vSsP8NEv6mBHuA2p1fw2wB/F0dH
# sJ3GfZ5c0sPJjklsiYqPw59xJ54kM91IOgiO2OUzjNAljPibjCWfH7UzQ1TPHc4d
# weils8GEIrbBRb7IWwiObL12jWT4Yh71NQgvJ9Fn6+UhD9x2uk3dLj84vwt1NuFQ
# itKJxIV0fVsRNR3abQVOLqpDugbr0SzNL6o8xzOHL5OXiGGwg6ekiXA1/2XXY7yV
# Fc39tledDtZjSjNbex1zzwSXAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUhov4ZyO96axkJdMjpzu2zVXOJcsw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDU4Mzg1MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAixmy
# S6E6vprWD9KFNIB9G5zyMuIjZAOuUJ1EK/Vlg6Fb3ZHXjjUwATKIcXbFuFC6Wr4K
# NrU4DY/sBVqmab5AC/je3bpUpjtxpEyqUqtPc30wEg/rO9vmKmqKoLPT37svc2NV
# BmGNl+85qO4fV/w7Cx7J0Bbqk19KcRNdjt6eKoTnTPHBHlVHQIHZpMxacbFOAkJr
# qAVkYZdz7ikNXTxV+GRb36tC4ByMNxE2DF7vFdvaiZP0CVZ5ByJ2gAhXMdK9+usx
# zVk913qKde1OAuWdv+rndqkAIm8fUlRnr4saSCg7cIbUwCCf116wUJ7EuJDg0vHe
# yhnCeHnBbyH3RZkHEi2ofmfgnFISJZDdMAeVZGVOh20Jp50XBzqokpPzeZ6zc1/g
# yILNyiVgE+RPkjnUQshd1f1PMgn3tns2Cz7bJiVUaqEO3n9qRFgy5JuLae6UweGf
# AeOo3dgLZxikKzYs3hDMaEtJq8IP71cX7QXe6lnMmXU/Hdfz2p897Zd+kU+vZvKI
# 3cwLfuVQgK2RZ2z+Kc3K3dRPz2rXycK5XCuRZmvGab/WbrZiC7wJQapgBodltMI5
# GMdFrBg9IeF7/rP4EqVQXeKtevTlZXjpuNhhjuR+2DMt/dWufjXpiW91bo3aH6Ea
# jOALXmoxgltCp1K7hrS6gmsvj94cLRf50QQ4U8Qwggd6MIIFYqADAgECAgphDpDS
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWTCCFVUCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAYdyF3IVWUDHCQAAAAABhzAN
# BglghkgBZQMEAgEFAKCBoDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgsG3fE0tT
# Bx/G4exmROb3Vklz6n8K2aJPJ1rR4TJ80vowNAYKKwYBBAGCNwIBDDEmMCSgEoAQ
# AFQAZQBzAHQAUwBpAGcAbqEOgAxodHRwOi8vdGVzdCAwDQYJKoZIhvcNAQEBBQAE
# ggEAYdDEcqZPh94ZenusNU86IWc7H7rzMsD1JANQCay+liToRcNKlQ3qoQHICSeG
# JP2UzWtnWxvXCbuGG1SGQrvxF6zSgQkr/87FgNkkD12FLg20+klfjoB9Y+VYtU2L
# qMZwi+IZKtlpAqP5casHPYB63BMxYyKloPrcedA+tSfrxJY4batMsfE7i8XUos3j
# Oq7why3wIYrqeRJWJHUhzx664sM6lLHSpDlWSFgGggqMZ5OhYJ76GFghZf0Cn+mm
# nSKTbfjjJW/NBncXGCimDmdubaL6MxQeJ7dfrCQ97DqvY+1cPufQRq7fQFslqDWy
# cW1+IZ5u5aGN+c0uKwb6jpyFfKGCEvEwghLtBgorBgEEAYI3AwMBMYIS3TCCEtkG
# CSqGSIb3DQEHAqCCEsowghLGAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFVBgsqhkiG
# 9w0BCRABBKCCAUQEggFAMIIBPAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQC
# AQUABCBikAasGoN4A1AsYtj2EJEXLex1nBRZtOj85VktbVGVEwIGX9uI2+93GBMy
# MDIxMDEyMjE4MzQ0Mi4yMDZaMASAAgH0oIHUpIHRMIHOMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0
# aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046NjBCQy1F
# MzgzLTI2MzUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# gg5EMIIE9TCCA92gAwIBAgITMwAAASbfuksiuYKCBwAAAAABJjANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0xOTEyMTkwMTE0
# NTlaFw0yMTAzMTcwMTE0NTlaMIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVydG8g
# UmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046NjBCQy1FMzgzLTI2MzUxJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCeML6GnE7zDZV0E7XxfwseTpd19H3I1DTL4y4E
# 5juflh2CRW6e9uT9/qrxSg0UB1hCNUs9IAduLq1QyI14wYeTVTSVTECSNrZbb+zO
# P+CG4WSW98c0Fuy6JRKGWFGWpwU1LspcvaLAoOKOY6FYk9hrZssSvhb+ZAttJdqK
# XmnqbXfxO3HgwBUTPO4YjQrCvyh8gvvPrMJ5YOIEznsus0Koc4DbBuh64ywbg7Q7
# PYswDMEtslk9E+dkAPYd0PgdQvabNnzCjHvgx6RvtHOtQ/eGIenFdlx4m+EgQp8C
# BWQHmRNlCeKjwDUmKMyPDx/hOawk90lamLx6Lvex7F7z9iNzAgMBAAGjggEbMIIB
# FzAdBgNVHQ4EFgQUSausHxewfphCjdFYpl/GozQOYUEwHwYDVR0jBBgwFoAU1WM6
# XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5t
# aWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENBXzIwMTAt
# MDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAxMC0wNy0w
# MS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQsFAAOCAQEAQJb7nWjpb/Qn87+em51+NXMxerS7RyweOpel1HIfqjTeOWZj
# kxcC6LdyY8Eq5+KMnEPakxE9UxQ2HdUDQ9C4l5is/TqgV2oukvF3cgkBGb3y/Noy
# ALPacLAEOl71fYzcmz0rUYBf7DgDPw3sn5no/U4PRXEcF2p5NqoM3WWTW/BqBM3u
# 39aK3ExdEPPSFF1iJZsBMEBWBdcI5/OzeGcS/Wf8QNpv0dc4sxcpVj/5qWpgp1X2
# WS5GnxSzVDVZnL3PvYDO73HibN+3d8nWm5OMEejm0d+LFmi6aZsj5bCNUKuS7umy
# QlqF82LlqZKCuqBHqdYDC+kkQtxylUt1LHGYbTCCBnEwggRZoAMCAQICCmEJgSoA
# AAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRl
# IEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIxNDY1NVow
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3DQEBAQUA
# A4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF++18aEss
# X8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRDDNdNuDgI
# s0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSxz5NMksHE
# pl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1rL2KQk1A
# UdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16HgcsOmZzTzn
# L0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB4jAQBgkr
# BgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqFbVUwGQYJ
# KwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQF
# MAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8w
# TTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVj
# dHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBK
# BggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9N
# aWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCBkjCBjwYJ
# KwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwA
# ZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQALiAdMA0G
# CSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUxvs8F4qn+
# +ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GASinbMQEBB
# m9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1L3mBZdmp
# tWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWOM7tiX5rb
# V0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4pm3S4Zz5
# Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45V3aicaoG
# ig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x4QDf5zEH
# pJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEegPsbiSpU
# ObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKnQqLJzxlB
# TeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp3lfB0d4w
# wP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvTX4/edIhJ
# EqGCAtIwggI7AgEBMIH8oYHUpIHRMIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVy
# dG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046NjBCQy1FMzgzLTI2MzUx
# JTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUr
# DgMCGgMVAApnMjlpmcRK6atOgfHcuqDGev/8oIGDMIGApH4wfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDjtXvRMCIYDzIwMjEw
# MTIyMjAyOTA1WhgPMjAyMTAxMjMyMDI5MDVaMHcwPQYKKwYBBAGEWQoEATEvMC0w
# CgIFAOO1e9ECAQAwCgIBAAICJkACAf8wBwIBAAICEeEwCgIFAOO2zVECAQAwNgYK
# KwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQAC
# AwGGoDANBgkqhkiG9w0BAQUFAAOBgQAUPq0srJ6VALJco7LSMSP1VNM6mQXeKZB1
# O6UIEUGQYFUWu2ehPD31g2Wx/ulqbJS63xkJSn7dbfxsDKgmGg/lKaKmrzr4xol0
# RmXO9YrVaNtRG2gOE72bVgwM0oTiJBvO79pkuCDO8m1Gyf5aTTRb59snZ+Iz5Jmw
# s22v48ugYjGCAw0wggMJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAy
# MDEwAhMzAAABJt+6SyK5goIHAAAAAAEmMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkq
# hkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIPi39B6IxXuQ
# 27CV3lX2eICZ2RqmFnLGmvhA4aJ4jlaVMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB
# 5DCBvQQgNv3P7569XnAM72qTlmdsRnwJM65H6RnK7zFtOwkJdQ8wgZgwgYCkfjB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAASbfuksiuYKCBwAAAAAB
# JjAiBCC/+CM5LaYHdiJJoVX4W/D/4aeHbsrxjLLvok31A+C3zDANBgkqhkiG9w0B
# AQsFAASCAQB9p6Xqeki/yIO1Z6D0o6VmWTiwCOLhL6uGGwd8DyJdrREOGtqbuQ++
# CkdRT/hjg7FHapD73GWLcgxT3F5rZ53M3DTDfi7o6q6QnQpgMG8He3LPXpd01YMz
# gI3ySa22u1lBq9eS7gBanK0M3C65Za+oGUHvKzq40xJI6lpCvjLQDWmxta8A3Pm2
# ldlxBZiTi1g6WOBxnWaNHiGtHXwfaPJfK5Y1StNHcI36CEyKIXSTGQUn/7bseMK4
# AFieKrW5GVzHgyXESLZEeVC09D+9+0qy4jmQBqLF+Ikp/kyq0t3nLCSBG1OaA6hb
# FTvNjh+k7E0lGXLOnDOqRIa/H4rRTFvr
# SIG # End signature block
