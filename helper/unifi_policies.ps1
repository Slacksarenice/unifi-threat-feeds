<#
.SYNOPSIS
Create the UniFi firewall policies that put threat feed lists to use.

.DESCRIPTION
A UniFi block policy covers one zone pair, one list and one address family,
so blocking a few lists across every zone means clicking through dozens of
near-identical policies. This script asks the gateway for its zones and IP
lists, shows the policies it would create, and creates them once you confirm.

It talks to the official UniFi Network API on your gateway with an API key,
which you create under Settings > Control Plane > Integrations. The key is
used for this run only and is never written to disk.

Works in Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER Gateway
Gateway address, for example 192.168.1.1. Falls back to $env:UNIFI_GATEWAY,
then asks.

.PARAMETER ApiKey
UniFi API key. Falls back to $env:UNIFI_API_KEY, then asks without echoing.

.PARAMETER Site
Site name, when the gateway has more than one.

.PARAMETER Outbound
Lists to block as a destination, from your zones to External.

.PARAMETER Inbound
Lists to block as a source, from External to your zones.

.PARAMETER OutboundZones
Zones to protect outbound. Default: every zone except External and Gateway.

.PARAMETER InboundZones
Zones to protect inbound. Default: every zone except External.

.PARAMETER Remove
Delete the policies this helper created.

.PARAMETER DryRun
Show the plan and change nothing.

.PARAMETER Yes
Do not ask for confirmation.

.PARAMETER Log
Turn on logging for the new policies.

.PARAMETER NoReorder
Leave new policies where the gateway puts them instead of moving them to
the top of their zone pair.

.PARAMETER SkipCertificateCheck
Skip the TLS certificate check. Gateways use a self-signed certificate
unless you installed your own.

.EXAMPLE
.\unifi_policies.ps1
Answer a few questions, review the plan, confirm.

.EXAMPLE
.\unifi_policies.ps1 -Gateway 192.168.1.1 -SkipCertificateCheck -Outbound "Threat Core v4" -Inbound "Threat All v4" -DryRun

.EXAMPLE
.\unifi_policies.ps1 -Remove
#>
[CmdletBinding()]
param(
    [string]$Gateway = $env:UNIFI_GATEWAY,
    [string]$ApiKey = $env:UNIFI_API_KEY,
    [string]$Site,
    [string[]]$Outbound,
    [string[]]$Inbound,
    [string[]]$OutboundZones,
    [string[]]$InboundZones,
    [switch]$Remove,
    [switch]$DryRun,
    [switch]$Yes,
    [switch]$Log,
    [switch]$NoReorder,
    [Alias('Insecure')]
    [switch]$SkipCertificateCheck,
    [string]$ApiPath = '/proxy/network/integration'
)

$ErrorActionPreference = 'Stop'
$Marker = 'Created by the unifi-threat-feeds helper'
$Prefix = 'ThreatFeed'
$IpVersion = @{ IPV4_ADDRESSES = 'IPV4'; IPV6_ADDRESSES = 'IPV6' }
$FamilyLabel = @{ IPV4_ADDRESSES = 'IPv4'; IPV6_ADDRESSES = 'IPv6' }

function Stop-Helper([string]$Message) {
    Write-Host $Message
    exit 1
}

function Get-CountText([int]$Number) {
    if ($Number -eq 1) { return '1 policy' }
    return "$Number policies"
}

function Split-Names([string[]]$Values) {
    # Accept names repeated or comma-separated: -Outbound "A,B","C"
    $names = @()
    foreach ($value in $Values) {
        foreach ($part in ($value -split ',')) {
            if ($part.Trim()) { $names += $part.Trim() }
        }
    }
    return , $names
}

function Find-ByName($Items, [string[]]$Names, [string]$What) {
    $found = @()
    $missing = @()
    foreach ($name in $Names) {
        $hit = @($Items | Where-Object { $_.name -eq $name })
        if ($hit.Count) { $found += $hit[0] } else { $missing += $name }
    }
    if ($missing.Count) {
        $known = (@($Items | ForEach-Object { $_.name }) | Sort-Object) -join ', '
        if (-not $known) { $known = 'none' }
        Stop-Helper "No $What named: $($missing -join ', ')`nThe gateway has: $known"
    }
    return , $found
}

function Get-ErrorText($Failure) {
    # Pull the API's own message out of a failed request, on PowerShell 5.1 and 7.
    $status = $null
    $text = $null
    $response = $Failure.Exception.Response
    if ($response) {
        try { $status = [int]$response.StatusCode } catch { }
    }
    if ($Failure.ErrorDetails -and $Failure.ErrorDetails.Message) {
        $text = $Failure.ErrorDetails.Message
    }
    elseif ($response -and ($response | Get-Member -Name GetResponseStream -ErrorAction SilentlyContinue)) {
        try {
            $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
            $text = $reader.ReadToEnd()
        }
        catch { }
    }
    if ($text) {
        try {
            $parsed = $text | ConvertFrom-Json
            if ($parsed.message) { $text = $parsed.message }
        }
        catch { }
    }
    if (-not $text) { $text = $Failure.Exception.Message }
    return @{ Status = $status; Text = $text }
}

function Invoke-Api([string]$Method, [string]$Path, $Query, $Body) {
    $url = $script:BaseUrl + $Path
    if ($Query) {
        $pairs = foreach ($key in $Query.Keys) {
            '{0}={1}' -f $key, [uri]::EscapeDataString([string]$Query[$key])
        }
        $url += '?' + ($pairs -join '&')
    }
    $request = @{
        Uri        = $url
        Method     = $Method
        Headers    = @{ 'X-API-KEY' = $script:Key; 'Accept' = 'application/json' }
        TimeoutSec = 30
    }
    if ($null -ne $Body) {
        $json = $Body | ConvertTo-Json -Depth 10 -Compress
        $request.Body = [System.Text.Encoding]::UTF8.GetBytes($json)
        $request.ContentType = 'application/json'
    }
    if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -ge 6) {
        $request.SkipCertificateCheck = $true
    }
    try {
        return Invoke-RestMethod @request
    }
    catch {
        $failure = Get-ErrorText $_
        if ($failure.Status) {
            $text = $failure.Text
            if ($failure.Status -eq 401 -or $failure.Status -eq 403) { $text += ' (check the API key)' }
            throw "$Method $Path failed with HTTP $($failure.Status): $text"
        }
        $all = "$($failure.Text) $($_.Exception.InnerException)"
        if (-not $SkipCertificateCheck -and $all -match 'certificate|trust relationship|SSL connection') {
            throw ("The gateway's certificate is not trusted. That is normal for a " +
                "gateway using its built-in certificate.`n" +
                'Run again with -SkipCertificateCheck to skip the certificate check.')
        }
        throw "Could not reach $($script:BaseUrl): $($failure.Text)"
    }
}

function Get-Everything([string]$Path) {
    # Read every page of a list endpoint.
    $items = @()
    while ($true) {
        $page = Invoke-Api 'GET' $Path @{ offset = $items.Count; limit = 200 }
        $data = @($page.data)
        $items += $data
        if (-not $data.Count -or $items.Count -ge $page.totalCount) { break }
    }
    return , $items
}

function Confirm-Step([string]$Question) {
    if ($Yes) { return $true }
    $answer = Read-Host "$Question [y/N]"
    return ($answer -eq 'y' -or $answer -eq 'yes')
}

function Select-Lists($Lists, [string]$Question) {
    while ($true) {
        $answer = (Read-Host $Question)
        if (-not $answer -or -not $answer.Trim()) { return , @() }
        $parts = @($answer -split '[,\s]+' | Where-Object { $_ })
        $bad = @($parts | Where-Object { $_ -notmatch '^\d+$' -or [int]$_ -lt 1 -or [int]$_ -gt $Lists.Count })
        if (-not $bad.Count) {
            $chosen = @()
            foreach ($number in ($parts | Select-Object -Unique)) { $chosen += $Lists[[int]$number - 1] }
            return , $chosen
        }
        Write-Host "  Enter numbers from 1 to $($Lists.Count), separated by spaces."
    }
}

function Select-Site($Wanted) {
    $sites = Get-Everything '/v1/sites'
    if (-not $sites.Count) { Stop-Helper 'The gateway reported no sites.' }
    if ($Wanted) {
        $hit = @($sites | Where-Object { $_.name -eq $Wanted -or $_.internalReference -eq $Wanted })
        if (-not $hit.Count) {
            Stop-Helper "No site named $Wanted. Sites: $(@($sites | ForEach-Object { $_.name }) -join ', ')"
        }
        return $hit[0]
    }
    if ($sites.Count -eq 1) { return $sites[0] }
    Write-Host 'Sites:'
    for ($i = 0; $i -lt $sites.Count; $i++) { Write-Host "  $($i + 1). $($sites[$i].name)" }
    while ($true) {
        $answer = Read-Host 'Which site?'
        if ($answer -match '^\d+$' -and [int]$answer -ge 1 -and [int]$answer -le $sites.Count) {
            return $sites[[int]$answer - 1]
        }
    }
}

function New-PlanEntry($Source, $Destination, $Item, [string]$Direction) {
    $match = [ordered]@{
        type            = 'IP_ADDRESS'
        ipAddressFilter = [ordered]@{
            type                  = 'TRAFFIC_MATCHING_LIST'
            trafficMatchingListId = $Item.id
            matchOpposite         = $false
        }
    }
    $body = [ordered]@{
        enabled         = $true
        name            = "$Prefix $($Source.name) to $($Destination.name) - $($Item.name)"
        description     = $Marker
        action          = @{ type = 'BLOCK' }
        source          = [ordered]@{ zoneId = $Source.id }
        destination     = [ordered]@{ zoneId = $Destination.id }
        ipProtocolScope = @{ ipVersion = $IpVersion[$Item.type] }
        loggingEnabled  = [bool]$Log
    }
    if ($Direction -eq 'out') {
        $body.destination.trafficFilter = $match
    }
    else {
        $body.source.trafficFilter = $match
        # Only refuse connections the listed address tries to open. Replies to
        # connections started from inside still get through, so a host on an
        # inbound list is not cut off from clients that reach out to it.
        $body.connectionStateFilter = @('NEW', 'INVALID')
    }
    return @{ Body = $body; Source = $Source; Destination = $Destination; List = $Item; Direction = $Direction }
}

function Move-ToTop($Source, $Destination, [string[]]$NewIds) {
    $query = [ordered]@{ sourceFirewallZoneId = $Source.id; destinationFirewallZoneId = $Destination.id }
    $path = "/v1/sites/$($script:SiteId)/firewall/policies/ordering"
    $order = (Invoke-Api 'GET' $path $query).orderedFirewallPolicyIds
    $before = @($NewIds) + @($order.beforeSystemDefined | Where-Object { $_ -and $NewIds -notcontains $_ })
    $after = @($order.afterSystemDefined | Where-Object { $_ -and $NewIds -notcontains $_ })
    $body = @{ orderedFirewallPolicyIds = [ordered]@{ beforeSystemDefined = @($before); afterSystemDefined = @($after) } }
    $null = Invoke-Api 'PUT' $path $query $body
}

function Remove-HelperPolicies {
    $allPolicies = Get-Everything "/v1/sites/$($script:SiteId)/firewall/policies"
    $policies = @($allPolicies | Where-Object { $_.description -eq $Marker })
    if (-not $policies.Count) {
        Write-Host 'No policies created by this helper were found.'
        return 0
    }
    Write-Host "Policies created by this helper ($($policies.Count)):"
    foreach ($policy in $policies) { Write-Host "  $($policy.name)" }
    if ($DryRun) {
        Write-Host "`nDry run: nothing was deleted."
        return 0
    }
    Write-Host ''
    if (-not (Confirm-Step "Delete $(Get-CountText $policies.Count)?")) {
        Write-Host 'Nothing was deleted.'
        return 0
    }
    $failed = 0
    foreach ($policy in $policies) {
        try {
            $null = Invoke-Api 'DELETE' "/v1/sites/$($script:SiteId)/firewall/policies/$($policy.id)"
        }
        catch {
            $failed++
            Write-Host "  FAILED $($policy.name): $($_.Exception.Message)"
        }
    }
    $tail = ''
    if ($failed) { $tail = " $failed failed." }
    Write-Host "Deleted $(Get-CountText ($policies.Count - $failed)).$tail"
    if ($failed) { return 1 }
    return 0
}

function Invoke-Helper {
    if (-not $Gateway) { $script:Gateway = Read-Host 'Gateway address (for example 192.168.1.1)' }
    if (-not $ApiKey) {
        $secure = Read-Host 'API key (input is hidden)' -AsSecureString
        $script:ApiKey = (New-Object System.Net.NetworkCredential('', $secure)).Password
    }
    $gatewayText = "$($script:Gateway)".Trim().TrimEnd('/')
    $script:Key = "$($script:ApiKey)".Trim()
    if (-not $gatewayText -or -not $script:Key) {
        Stop-Helper 'A gateway address and an API key are both required.'
    }
    if ($gatewayText -notmatch '://') { $gatewayText = "https://$gatewayText" }
    $script:BaseUrl = $gatewayText + '/' + $ApiPath.Trim('/')

    if ($PSVersionTable.PSVersion.Major -lt 6) {
        # Windows PowerShell 5.1: turn on TLS 1.2, and honor -SkipCertificateCheck
        # the only way that version allows.
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        if ($SkipCertificateCheck) {
            if (-not ('UnifiHelperTrustAll' -as [type])) {
                Add-Type -TypeDefinition @'
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class UnifiHelperTrustAll : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint point, X509Certificate cert, WebRequest request, int problem) {
        return true;
    }
}
'@
            }
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object UnifiHelperTrustAll
        }
    }

    $version = (Invoke-Api 'GET' '/v1/info').applicationVersion
    if (-not $version) { $version = 'unknown' }
    $chosenSite = Select-Site $Site
    $script:SiteId = $chosenSite.id
    Write-Host "Connected to UniFi Network $version, site `"$($chosenSite.name)`".`n"

    if ($Remove) { return (Remove-HelperPolicies) }

    $zones = Get-Everything "/v1/sites/$($script:SiteId)/firewall/zones"
    $allLists = Get-Everything "/v1/sites/$($script:SiteId)/traffic-matching-lists"
    $lists = @($allLists | Where-Object { $IpVersion.ContainsKey([string]$_.type) })
    Write-Host ('Zones: ' + (@($zones | ForEach-Object { $_.name }) -join ', '))
    if (-not $lists.Count) {
        Stop-Helper "`nThe gateway reported no IP lists. Create them first under Networks > Network Lists, then run this again."
    }
    Write-Host 'IP lists:'
    for ($i = 0; $i -lt $lists.Count; $i++) {
        Write-Host "  $($i + 1). $($lists[$i].name) ($($FamilyLabel[$lists[$i].type]))"
    }
    Write-Host ''

    $outNames = Split-Names $Outbound
    $inNames = Split-Names $Inbound
    if ($outNames.Count -or $inNames.Count) {
        $outLists = Find-ByName $lists $outNames 'IP list'
        $inLists = Find-ByName $lists $inNames 'IP list'
    }
    else {
        Write-Host 'Outbound: stops your devices reaching listed addresses. Use the core lists.'
        $outLists = Select-Lists $lists 'Lists to block outbound (numbers, Enter for none)'
        Write-Host 'Inbound: stops listed addresses reaching you. Use the all or inbound lists.'
        $inLists = Select-Lists $lists 'Lists to block inbound (numbers, Enter for none)'
        Write-Host ''
    }
    if (-not $outLists.Count -and -not $inLists.Count) {
        Write-Host 'No lists chosen, so there is nothing to do.'
        return 0
    }

    $external = @($zones | Where-Object { $_.name -eq 'External' })
    if (-not $external.Count) {
        Stop-Helper 'The gateway has no zone named External, so there is nothing to plan.'
    }
    $external = $external[0]
    $outZoneNames = Split-Names $OutboundZones
    $inZoneNames = Split-Names $InboundZones
    if ($outZoneNames.Count) { $outZones = Find-ByName $zones $outZoneNames 'zone' }
    else { $outZones = @($zones | Where-Object { $_.name -ne 'External' -and $_.name -ne 'Gateway' }) }
    if ($inZoneNames.Count) { $inZones = Find-ByName $zones $inZoneNames 'zone' }
    else { $inZones = @($zones | Where-Object { $_.name -ne 'External' }) }

    $plan = @()
    foreach ($item in $outLists) { foreach ($zone in $outZones) { $plan += New-PlanEntry $zone $external $item 'out' } }
    foreach ($item in $inLists) { foreach ($zone in $inZones) { $plan += New-PlanEntry $external $zone $item 'in' } }

    $allPolicies = Get-Everything "/v1/sites/$($script:SiteId)/firewall/policies"
    $existing = @($allPolicies | ForEach-Object { $_.name })
    Write-Host "Plan ($(Get-CountText $plan.Count)):"
    $width = 0
    foreach ($entry in $plan) {
        $width = [Math]::Max($width, "$($entry.Source.name) to $($entry.Destination.name)".Length)
    }
    $todo = @()
    foreach ($entry in $plan) {
        $pair = "$($entry.Source.name) to $($entry.Destination.name)".PadRight($width)
        $side = 'source'
        if ($entry.Direction -eq 'out') { $side = 'destination' }
        $state = ''
        if ($existing -contains $entry.Body.name) { $state = '  (already exists, skipped)' }
        else { $todo += $entry }
        Write-Host "  $pair  block $side in `"$($entry.List.name)`" ($($FamilyLabel[$entry.List.type]))$state"
    }
    Write-Host ''
    if (-not $todo.Count) {
        Write-Host 'Every policy in the plan already exists.'
        return 0
    }
    if ($DryRun) {
        Write-Host "Dry run: $(Get-CountText $todo.Count) would be created. Nothing was changed."
        return 0
    }
    if (-not (Confirm-Step "Create $(Get-CountText $todo.Count)?")) {
        Write-Host 'Nothing was changed.'
        return 0
    }

    $created = [ordered]@{}
    $failed = 0
    $total = 0
    foreach ($entry in $todo) {
        try {
            $policy = Invoke-Api 'POST' "/v1/sites/$($script:SiteId)/firewall/policies" $null $entry.Body
        }
        catch {
            $failed++
            Write-Host "  FAILED $($entry.Body.name): $($_.Exception.Message)"
            continue
        }
        $pairKey = "$($entry.Source.id)/$($entry.Destination.id)"
        if (-not $created.Contains($pairKey)) {
            $created[$pairKey] = @{ Source = $entry.Source; Destination = $entry.Destination; Ids = @() }
        }
        $created[$pairKey].Ids += $policy.id
        $total++
        Write-Host "  created $($entry.Body.name)"
    }

    if (-not $NoReorder) {
        foreach ($pairKey in $created.Keys) {
            $group = $created[$pairKey]
            try {
                Move-ToTop $group.Source $group.Destination $group.Ids
            }
            catch {
                Write-Host "  Could not move the $($group.Source.name) to $($group.Destination.name) policies to the top: $($_.Exception.Message)"
                Write-Host '  They were created. Check their position in the policy table.'
            }
        }
    }

    $tail = ''
    if ($failed) { $tail = " $failed failed." }
    Write-Host "`nCreated $(Get-CountText $total).$tail"
    Write-Host 'Run again with -Remove to delete them.'
    if ($failed) { return 1 }
    return 0
}

try {
    $code = Invoke-Helper
}
catch {
    Write-Host "Error: $($_.Exception.Message)"
    exit 1
}
exit $code
