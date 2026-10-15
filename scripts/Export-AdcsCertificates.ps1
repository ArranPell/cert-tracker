<#
.SYNOPSIS
    Exports currently valid issued certificates from an AD CS certificate authority and sends
    them to Cert Tracker (or writes a CSV you can upload on the Settings page).

.DESCRIPTION
    Reads the CA database with certutil, keeps issued (not revoked), unexpired certificates,
    leaves out auto-enrolled machine/user templates by default, and either posts the result to
    Cert Tracker's /api/import/adcs endpoint or saves a CSV.

    Run it on the CA (or anywhere with read access to the CA database). For hands-off
    syncing, run it daily as a scheduled task under a service account. Importing the same
    certificates again is harmless.

.PARAMETER TrackerUrl
    Base address of Cert Tracker, e.g. https://certs.corp.example.ca

.PARAMETER ApiToken
    The API_TOKEN configured on the Cert Tracker server. Prefer -ApiTokenFile for scheduled tasks.

.PARAMETER ApiTokenFile
    Path to a file holding the API token (lock the file down with NTFS permissions).

.PARAMETER OutFile
    Write a CSV here instead of posting it.

.PARAMETER Config
    CA config string ("CAHOST\CA Name"). Defaults to the local CA.

.PARAMETER ExcludeTemplate
    Templates to leave out. Matched against the template name, the OID, or the display name,
    with -like wildcards. Defaults cover the usual auto-enrolment templates.

.PARAMETER IncludeTemplate
    If given, only these templates are exported (after exclusions).

.EXAMPLE
    .\Export-AdcsCertificates.ps1 -OutFile C:\Temp\issued.csv

.EXAMPLE
    .\Export-AdcsCertificates.ps1 -TrackerUrl https://certs.corp.example.ca -ApiTokenFile C:\CertTracker\token.txt
#>
[CmdletBinding(DefaultParameterSetName = 'Post')]
param(
    [Parameter(ParameterSetName = 'Post', Mandatory)] [string] $TrackerUrl,
    [Parameter(ParameterSetName = 'Post')] [string] $ApiToken,
    [Parameter(ParameterSetName = 'Post')] [string] $ApiTokenFile,
    [Parameter(ParameterSetName = 'File', Mandatory)] [string] $OutFile,
    [string] $Config,
    [string] $CaName,
    [string[]] $ExcludeTemplate = @(
        'Machine', 'User', 'UserSignature', 'DomainController', 'DomainControllerAuthentication',
        'KerberosAuthentication', 'DirectoryEmailReplication', 'EFS', 'EFSRecovery', 'Administrator',
        'Workstation*', 'ClientAuth', 'SmartcardLogon', 'SmartcardUser', 'CA', 'SubCA', 'CAExchange',
        'OCSPResponseSigning'
    ),
    [string[]] $IncludeTemplate
)

$ErrorActionPreference = 'Stop'

$columns = 'RequestID', 'RequesterName', 'CommonName', 'NotBefore', 'NotAfter', 'SerialNumber',
           'CertificateTemplate', 'CertificateHash'
$headers = 'RequestID', 'Requester', 'CommonName', 'NotBefore', 'NotAfter', 'Serial', 'Template', 'Thumbprint'

$certutilArgs = @('-view')
if ($Config) { $certutilArgs += @('-config', $Config) }
# Disposition 20 = issued (revoked certificates are 21 and are left out).
$certutilArgs += @('-restrict', 'Disposition=20', '-out', ($columns -join ','), 'csv')

Write-Verbose "certutil $($certutilArgs -join ' ')"
$raw = & certutil.exe @certutilArgs
if ($LASTEXITCODE -ne 0) { throw "certutil failed (exit $LASTEXITCODE): $($raw -join [Environment]::NewLine)" }

# certutil's own header row uses localised display names, so replace it with ours.
$rows = $raw | Select-Object -Skip 1 | Where-Object { $_.Trim() } | ConvertFrom-Csv -Header $headers

function Test-TemplateMatch([string] $Template, [string[]] $Patterns) {
    if (-not $Template) { return $false }
    # v2+ templates can appear as "1.3.6.1.4.1.311.21.8.x.y Display Name"; test each part.
    $candidates = @($Template)
    if ($Template -match '^(?<oid>[\d\.]+)\s+(?<name>.+)$') { $candidates += $Matches.oid, $Matches.name }
    foreach ($p in $Patterns) {
        foreach ($c in $candidates) { if ($c -like $p) { return $true } }
    }
    return $false
}

function ConvertTo-UtcIso([string] $Value) {
    if (-not $Value -or $Value -eq 'EMPTY') { return $null }
    # certutil prints local time in the current culture's format.
    $dt = [datetime]::Parse($Value, [Globalization.CultureInfo]::CurrentCulture)
    return $dt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

$now = (Get-Date).ToUniversalTime()
$records = foreach ($r in $rows) {
    $template = if ($r.Template -eq 'EMPTY') { '' } else { $r.Template }
    if (Test-TemplateMatch $template $ExcludeTemplate) { continue }
    if ($IncludeTemplate -and -not (Test-TemplateMatch $template $IncludeTemplate)) { continue }
    $notAfter = ConvertTo-UtcIso $r.NotAfter
    if (-not $notAfter -or [datetime]::Parse($notAfter).ToUniversalTime() -lt $now) { continue }
    [pscustomobject]@{
        RequestID  = $r.RequestID
        Requester  = $r.Requester
        CommonName = if ($r.CommonName -eq 'EMPTY') { '' } else { $r.CommonName }
        NotBefore  = ConvertTo-UtcIso $r.NotBefore
        NotAfter   = $notAfter
        Serial     = ($r.Serial -replace '\s', '')
        Template   = $template
        Thumbprint = ($r.Thumbprint -replace '\s', '')
    }
}
$records = @($records)
Write-Host "$($records.Count) current certificate(s) after template filtering."

if ($PSCmdlet.ParameterSetName -eq 'File') {
    $records | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    Write-Host "Wrote $OutFile. Upload it on Cert Tracker's Settings page."
    return
}

if ($ApiTokenFile) { $ApiToken = (Get-Content -Path $ApiTokenFile -Raw).Trim() }
if (-not $ApiToken) { throw 'Provide -ApiToken or -ApiTokenFile.' }
if (-not $CaName) { $CaName = if ($Config) { $Config } else { $env:COMPUTERNAME } }

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$body = @{ ca = $CaName; certificates = $records } | ConvertTo-Json -Depth 4 -Compress
$result = Invoke-RestMethod -Method Post -Uri ($TrackerUrl.TrimEnd('/') + '/api/import/adcs') `
    -Headers @{ Authorization = "Bearer $ApiToken" } -ContentType 'application/json; charset=utf-8' `
    -Body ([Text.Encoding]::UTF8.GetBytes($body))
Write-Host ("Cert Tracker: {0} new, {1} updated, {2} already known, {3} expired skipped, {4} unreadable." -f `
    $result.added, $result.updated, $result.unchanged, $result.skipped_expired, $result.invalid)
