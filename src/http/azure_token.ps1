$ErrorActionPreference = 'Stop'
[version]$minimumVersion = '2.2.0'

$mod = Import-Module Az.Accounts -MinimumVersion $minimumVersion `
    -PassThru -ErrorAction SilentlyContinue

if (-not $mod) {
    Write-Error 'Az.Accounts module not found'
}

$params = @{
    ResourceUrl   = '{resource}'
    WarningAction = 'Ignore'
}

if ($mod.Version -ge [version]'2.17.0' -and
    $mod.Version -lt [version]'5.0.0') {
    $params['AsSecureString'] = $true
}

$tenantId = '{tenant}'
if ($tenantId.Length -gt 0) {
    $params['TenantId'] = '{tenant}'
}

$token = Get-AzAccessToken @params

$customToken = New-Object -TypeName psobject

$marshal = [System.Runtime.InteropServices.Marshal]
if ($token.Token -is [System.Security.SecureString]) {
    $ssPtr = $marshal::SecureStringToBSTR($token.Token)
    try {
        $plainToken = $marshal::PtrToStringBSTR($ssPtr)
    } finally {
        $marshal::ZeroFreeBSTR($ssPtr)
    }
    $customToken | Add-Member -MemberType NoteProperty -Name Token `
        -Value $plainToken
} else {
    $customToken | Add-Member -MemberType NoteProperty -Name Token `
        -Value $token.Token
}
$customToken | Add-Member -MemberType NoteProperty -Name ExpiresOn `
    -Value $token.ExpiresOn.ToUnixTimeSeconds()

$jsonToken = $customToken | ConvertTo-Json
return $jsonToken
