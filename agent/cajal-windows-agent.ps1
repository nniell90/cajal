param(
  [string]$Server = $env:CAJAL_AGENT_SERVER,
  [string]$Site = $env:CAJAL_AGENT_SITE,
  [string]$Password = $env:CAJAL_AGENT_PASSWORD,
  [double]$PollIntervalSec = 1.5,
  [switch]$InsecureTls
)

$ErrorActionPreference = 'Stop'
$AgentVersion = '1.0.0'
$SupportedCommands = @(
  'help',
  'status',
  'doctor',
  'capabilities',
  'speedtest',
  'publicip',
  'ping',
  'traceroute',
  'tracert',
  'dns',
  'resolve',
  'nslookup',
  'ipconfig',
  'clear',
  'cls'
)

function Write-AgentLog {
  param([string]$Message)
  Write-Host "[agent] $Message"
}

if ([string]::IsNullOrWhiteSpace($Server)) {
  throw 'CAJAL agent server is required (set -Server or CAJAL_AGENT_SERVER).'
}
if ([string]::IsNullOrWhiteSpace($Site)) {
  throw 'CAJAL site id is required (set -Site or CAJAL_AGENT_SITE).'
}
if ([string]::IsNullOrWhiteSpace($Password)) {
  throw 'CAJAL agent password is required (set -Password or CAJAL_AGENT_PASSWORD).'
}

$Server = $Server.Trim().TrimEnd('/')
$Site = $Site.Trim()
$Password = [string]$Password
$PollIntervalSec = [Math]::Max(0.5, [double]$PollIntervalSec)
$IsPs7OrLater = $PSVersionTable.PSVersion.Major -ge 7

if ($InsecureTls -and -not $IsPs7OrLater) {
  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}

function Invoke-AgentApi {
  param(
    [string]$Method,
    [string]$Path,
    $Body = $null,
    [int]$TimeoutSec = 30
  )
  $uri = "$Server$Path"
  $params = @{
    Method = $Method
    Uri = $uri
    TimeoutSec = [Math]::Max(2, $TimeoutSec)
    ErrorAction = 'Stop'
    Headers = @{
      Accept = 'application/json'
    }
  }
  if ($InsecureTls -and $IsPs7OrLater) {
    $params.SkipCertificateCheck = $true
  }
  if ($null -ne $Body) {
    $params.ContentType = 'application/json'
    $params.Body = ($Body | ConvertTo-Json -Depth 8 -Compress)
  }
  return Invoke-RestMethod @params
}

function Get-PrimaryLocalIpv4 {
  try {
    $routes = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
      Sort-Object -Property RouteMetric, ifMetric
    foreach ($route in $routes) {
      $ip = Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -and $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -notlike '127.*' } |
        Select-Object -First 1
      if ($ip) {
        return [string]$ip.IPAddress
      }
    }
  } catch {
    # fallback below
  }
  try {
    $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
      Where-Object { $_.IPAddress -and $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -notlike '127.*' } |
      Sort-Object -Property InterfaceMetric |
      Select-Object -First 1
    if ($ip) {
      return [string]$ip.IPAddress
    }
  } catch {
    # no-op
  }
  return ''
}

function Get-AgentInstallIdentity {
  $envInstallId = [string]$env:CAJAL_AGENT_INSTALL_ID
  $envInstalledAt = [string]$env:CAJAL_AGENT_INSTALLED_AT
  if (-not [string]::IsNullOrWhiteSpace($envInstallId) -and -not [string]::IsNullOrWhiteSpace($envInstalledAt)) {
    return @{
      installId = $envInstallId.Trim()
      installedAt = $envInstalledAt.Trim()
    }
  }

  $baseDir = if ([string]::IsNullOrWhiteSpace($env:ProgramData)) { $PSScriptRoot } else { Join-Path $env:ProgramData 'Cajal' }
  $identityFile = Join-Path $baseDir 'agent-install.json'
  try {
    if (Test-Path -LiteralPath $identityFile) {
      $parsed = Get-Content -LiteralPath $identityFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
      $id = [string]$parsed.installId
      $at = [string]$parsed.installedAt
      if (-not [string]::IsNullOrWhiteSpace($id) -and -not [string]::IsNullOrWhiteSpace($at)) {
        return @{
          installId = $id.Trim()
          installedAt = $at.Trim()
        }
      }
    }
  } catch {
    # ignore and regenerate below
  }

  $created = @{
    installId = [guid]::NewGuid().Guid
    installedAt = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
  }
  try {
    New-Item -ItemType Directory -Path $baseDir -Force -ErrorAction Stop | Out-Null
    ($created | ConvertTo-Json -Depth 3) | Set-Content -LiteralPath $identityFile -Encoding UTF8 -ErrorAction Stop
  } catch {
    # Continue even when persistence is blocked; the current process still sends identity.
  }
  return $created
}

function Invoke-ExternalCommand {
  param(
    [string]$Command,
    [string[]]$Arguments = @(),
    [int]$TimeoutSec = 60
  )

  $outputLines = @()
  try {
    $resolved = (Get-Command $Command -ErrorAction Stop).Source
    $line = & $resolved @Arguments 2>&1
    if ($line) {
      $outputLines = @($line | ForEach-Object { [string]$_ })
    }
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    return @{
      ok = $exitCode -eq 0
      exitCode = $exitCode
      lines = @($outputLines)
      cmdline = "$Command $($Arguments -join ' ')".Trim()
    }
  } catch {
    return @{
      ok = $false
      exitCode = 1
      lines = @([string]$_.Exception.Message)
      cmdline = "$Command $($Arguments -join ' ')".Trim()
    }
  }
}

function Parse-SpeedtestJson {
  param([string]$RawText)
  if ([string]::IsNullOrWhiteSpace($RawText)) {
    return @{ down = $null; up = $null; publicIp = '' }
  }
  try {
    $payload = $RawText | ConvertFrom-Json -ErrorAction Stop
    $downBps = 0.0
    $upBps = 0.0
    $publicIp = ''
    if ($payload.download -and $payload.upload -and $payload.download.bandwidth -and $payload.upload.bandwidth) {
      $downBps = [double]$payload.download.bandwidth * 8.0
      $upBps = [double]$payload.upload.bandwidth * 8.0
    } elseif ($payload.download -and $payload.upload) {
      $downBps = [double]$payload.download
      $upBps = [double]$payload.upload
    }
    if ($payload.interface -and $payload.interface.externalIp) {
      $publicIp = [string]$payload.interface.externalIp
    } elseif ($payload.client -and $payload.client.ip) {
      $publicIp = [string]$payload.client.ip
    }
    $down = if ($downBps -gt 0) { [Math]::Round($downBps / 1000000.0, 1) } else { $null }
    $up = if ($upBps -gt 0) { [Math]::Round($upBps / 1000000.0, 1) } else { $null }
    return @{ down = $down; up = $up; publicIp = $publicIp.Trim() }
  } catch {
    return @{ down = $null; up = $null; publicIp = '' }
  }
}

function Parse-PingAverageMs {
  param([string[]]$Lines)
  foreach ($line in @($Lines)) {
    $text = [string]$line
    if ($text -match 'Average\s*=\s*([0-9]+)ms') {
      return [double]$matches[1]
    }
  }
  return $null
}

function Test-PublicIpv4 {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
  try {
    $ip = [System.Net.IPAddress]::Parse($Value.Trim())
  } catch {
    return $false
  }
  if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
  $bytes = $ip.GetAddressBytes()
  if ($bytes.Length -ne 4) { return $false }
  if ($bytes[0] -eq 10) { return $false }
  if ($bytes[0] -eq 127) { return $false }
  if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { return $false }
  if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return $false }
  if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return $false }
  if ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) { return $false }
  if ($bytes[0] -eq 0) { return $false }
  return $true
}

function Find-PublicIpv4InText {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
  $matches = [regex]::Matches($Text, '(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)')
  for ($i = $matches.Count - 1; $i -ge 0; $i -= 1) {
    $candidate = [string]$matches[$i].Value
    if (Test-PublicIpv4 -Value $candidate) {
      return $candidate.Trim()
    }
  }
  return ''
}

function Run-SpeedtestCommand {
  param([string]$Target)
  $host = if ([string]::IsNullOrWhiteSpace($Target)) { '8.8.8.8' } else { $Target.Trim() }
  $speedCandidates = @(
    @{ cmd = 'speedtest'; args = @('--accept-license', '--accept-gdpr', '--format=json') },
    @{ cmd = 'speedtest.exe'; args = @('--accept-license', '--accept-gdpr', '--format=json') }
  )

  $down = $null
  $up = $null
  $publicIp = ''
  $backend = ''
  $notes = @()
  foreach ($candidate in $speedCandidates) {
    $result = Invoke-ExternalCommand -Command $candidate.cmd -Arguments $candidate.args -TimeoutSec 90
    $parsed = Parse-SpeedtestJson -RawText (($result.lines -join "`n"))
    if ($null -ne $parsed.down -or $null -ne $parsed.up) {
      $down = $parsed.down
      $up = $parsed.up
      $publicIp = [string]$parsed.publicIp
      $backend = "$($candidate.cmd) $($candidate.args -join ' ')".Trim()
      break
    }
    $notes += "$($candidate.cmd): $($result.lines | Select-Object -First 1)"
  }

  $ping = Invoke-ExternalCommand -Command 'ping' -Arguments @('-n', '3', $host) -TimeoutSec 15
  $latency = Parse-PingAverageMs -Lines $ping.lines

  $lines = @(
    "Speed test snapshot for target $host",
    "down=$(if ($null -ne $down) { $down } else { 'n/a' }) Mbps up=$(if ($null -ne $up) { $up } else { 'n/a' }) Mbps latency=$(if ($null -ne $latency) { $latency } else { 'n/a' }) ms"
  )
  if ($backend) {
    $lines += "speedtest backend: $backend"
  }
  if (-not [string]::IsNullOrWhiteSpace($publicIp)) {
    $lines += "public_ip=$publicIp"
  }
  if (-not $backend -and $notes.Count -gt 0) {
    $lines += "speedtest unavailable: $($notes[0])"
  }

  return @{
    ok = ($null -ne $down -or $null -ne $up -or $null -ne $latency)
    exitCode = 0
    lines = $lines
    metrics = @{
      speedtest = @{
        target = $host
        downloadMbps = $down
        uploadMbps = $up
        latencyMs = $latency
        publicIp = if ([string]::IsNullOrWhiteSpace($publicIp)) { $null } else { $publicIp }
      }
    }
  }
}

function Run-PublicIpCommand {
  $candidates = @(
    @{ cmd = 'curl.exe'; args = @('-4', '-fsSL', 'https://api.ipify.org') },
    @{ cmd = 'curl.exe'; args = @('-4', '-fsSL', 'https://ipv4.icanhazip.com') },
    @{ cmd = 'curl.exe'; args = @('-4', '-fsSL', 'https://ifconfig.me/ip') },
    @{ cmd = 'nslookup'; args = @('myip.opendns.com', 'resolver1.opendns.com') },
    @{ cmd = 'nslookup'; args = @('o-o.myaddr.l.google.com', 'ns1.google.com') }
  )
  $notes = @()
  $hits = @()
  $counts = @{}
  $firstSeen = @{}
  $sourcesByIp = @{}
  $hitIndex = 0
  foreach ($candidate in $candidates) {
    $result = Invoke-ExternalCommand -Command $candidate.cmd -Arguments $candidate.args -TimeoutSec 15
    $joined = ($result.lines -join "`n")
    $publicIp = Find-PublicIpv4InText -Text $joined
    if (-not [string]::IsNullOrWhiteSpace($publicIp)) {
      $cmdline = [string]$result.cmdline
      if ([string]::IsNullOrWhiteSpace($cmdline)) {
        $cmdline = "$($candidate.cmd) $($candidate.args -join ' ')".Trim()
      }
      $hits += $publicIp
      if (-not $firstSeen.ContainsKey($publicIp)) {
        $firstSeen[$publicIp] = $hitIndex
      }
      if ($counts.ContainsKey($publicIp)) {
        $counts[$publicIp] = [int]$counts[$publicIp] + 1
      } else {
        $counts[$publicIp] = 1
      }
      if (-not $sourcesByIp.ContainsKey($publicIp)) {
        $sourcesByIp[$publicIp] = @()
      }
      if ($cmdline -and -not ($sourcesByIp[$publicIp] -contains $cmdline)) {
        $sourcesByIp[$publicIp] += $cmdline
      }
      $hitIndex += 1
      continue
    }
    $first = [string]($result.lines | Select-Object -First 1)
    if ([string]::IsNullOrWhiteSpace($first)) { $first = 'no output' }
    $notes += "$($candidate.cmd): $first"
  }

  if ($counts.Count -gt 0) {
    $bestIp = (
      $counts.Keys |
        Sort-Object -Stable -Property @{
          Expression = { -1 * [int]$counts[$_] }
        }, @{
          Expression = { [int]$firstSeen[$_] }
        } |
        Select-Object -First 1
    )
    $bestSources = @()
    if ($sourcesByIp.ContainsKey($bestIp)) {
      $bestSources = @($sourcesByIp[$bestIp])
    }
    $confidence = [int]$counts[$bestIp]
    $lines = @(
      'Collector WAN public IP probe complete.',
      "public_ip=$bestIp",
      "confidence=$confidence/$($hits.Count)"
    )
    if ($bestSources.Count -gt 0) {
      $lines += "source=$($bestSources[0])"
    }
    return @{
      ok = $true
      exitCode = 0
      lines = $lines
      metrics = @{
        publicIp = [string]$bestIp
      }
    }
  }

  $failLines = @('Collector WAN public IP probe failed.')
  if ($notes.Count -gt 0) {
    $failLines += $notes[0]
  }
  $failLines += 'No public IPv4 detected.'
  return @{
    ok = $false
    exitCode = 1
    lines = $failLines
    metrics = @{
      publicIp = ''
    }
  }
}

function Run-AgentCommand {
  param([string]$CommandText)
  $raw = [string]$CommandText
  $trimmed = $raw.Trim()
  if ([string]::IsNullOrWhiteSpace($trimmed)) {
    return @{ ok = $false; exitCode = 1; lines = @('Empty command.') }
  }

  $parts = @($trimmed -split '\s+')
  $name = $parts[0].ToLowerInvariant()
  $args = @()
  if ($parts.Count -gt 1) {
    $args = $parts[1..($parts.Count - 1)]
  }

  switch ($name) {
    'help' {
      return @{
        ok = $true
        exitCode = 0
        lines = @(
          'Collector Windows agent commands:',
          'help, status, doctor, capabilities, speedtest [target], publicip, ping [host], traceroute|tracert [host], dns|resolve|nslookup [host], ipconfig [interface], clear, cls'
        )
      }
    }
    'status' {
      return @{
        ok = $true
        exitCode = 0
        lines = @(
          "Windows collector agent online.",
          "server=$Server",
          "site=$Site",
          "hostname=$env:COMPUTERNAME",
          "version=$AgentVersion"
        )
      }
    }
    'doctor' {
      $checks = @(
        "ping: $(if (Get-Command ping -ErrorAction SilentlyContinue) { 'ok' } else { 'missing' })",
        "tracert: $(if (Get-Command tracert -ErrorAction SilentlyContinue) { 'ok' } else { 'missing' })",
        "nslookup: $(if (Get-Command nslookup -ErrorAction SilentlyContinue) { 'ok' } else { 'missing' })",
        "speedtest: $(if ((Get-Command speedtest -ErrorAction SilentlyContinue) -or (Get-Command speedtest.exe -ErrorAction SilentlyContinue)) { 'ok' } else { 'missing' })"
      )
      return @{ ok = $true; exitCode = 0; lines = $checks }
    }
    'capabilities' {
      return @{ ok = $true; exitCode = 0; lines = @("commands=$($SupportedCommands -join ', ')") }
    }
    'speedtest' {
      $target = if ($args.Count -gt 0) { $args[0] } else { '8.8.8.8' }
      return Run-SpeedtestCommand -Target $target
    }
    'publicip' {
      return Run-PublicIpCommand
    }
    'public-ip' {
      return Run-PublicIpCommand
    }
    'wanip' {
      return Run-PublicIpCommand
    }
    'ping' {
      if ($args.Count -lt 1) {
        return @{ ok = $false; exitCode = 1; lines = @('Usage: ping [host]') }
      }
      return Invoke-ExternalCommand -Command 'ping' -Arguments @('-n', '3', $args[0]) -TimeoutSec 15
    }
    'traceroute' {
      $target = if ($args.Count -gt 0) { $args[0] } else { '8.8.8.8' }
      return Invoke-ExternalCommand -Command 'tracert' -Arguments @('-d', '-h', '8', $target) -TimeoutSec 45
    }
    'tracert' {
      $target = if ($args.Count -gt 0) { $args[0] } else { '8.8.8.8' }
      return Invoke-ExternalCommand -Command 'tracert' -Arguments @('-d', '-h', '8', $target) -TimeoutSec 45
    }
    'dns' {
      if ($args.Count -lt 1) {
        return @{ ok = $false; exitCode = 1; lines = @('Usage: dns [hostname]') }
      }
      return Invoke-ExternalCommand -Command 'nslookup' -Arguments @($args[0]) -TimeoutSec 20
    }
    'resolve' {
      if ($args.Count -lt 1) {
        return @{ ok = $false; exitCode = 1; lines = @('Usage: resolve [hostname]') }
      }
      return Invoke-ExternalCommand -Command 'nslookup' -Arguments @($args[0]) -TimeoutSec 20
    }
    'nslookup' {
      if ($args.Count -lt 1) {
        return @{ ok = $false; exitCode = 1; lines = @('Usage: nslookup [hostname]') }
      }
      return Invoke-ExternalCommand -Command 'nslookup' -Arguments @($args[0]) -TimeoutSec 20
    }
    'ipconfig' {
      return Invoke-ExternalCommand -Command 'ipconfig' -Arguments @('/all') -TimeoutSec 20
    }
    'clear' { return @{ ok = $true; exitCode = 0; lines = @('Terminal cleared.') } }
    'cls' { return @{ ok = $true; exitCode = 0; lines = @('Terminal cleared.') } }
    default {
      return @{ ok = $false; exitCode = 1; lines = @("Unsupported agent command: $name") }
    }
  }
}

$token = ''
$script:AgentInstallIdentity = Get-AgentInstallIdentity

function Register-Agent {
  $install = $script:AgentInstallIdentity
  $agent = @{
    hostname = $env:COMPUTERNAME
    version = $AgentVersion
    platform = "windows-powershell/$($PSVersionTable.PSVersion)"
    localIp = (Get-PrimaryLocalIpv4)
  }
  if ($install -and -not [string]::IsNullOrWhiteSpace([string]$install.installId)) {
    $agent.installId = [string]$install.installId
  }
  if ($install -and -not [string]::IsNullOrWhiteSpace([string]$install.installedAt)) {
    $agent.installedAt = [string]$install.installedAt
  }
  $payload = @{
    siteId = $Site
    password = $Password
    agent = $agent
  }
  $response = Invoke-AgentApi -Method 'POST' -Path '/api/agent/register' -Body $payload -TimeoutSec 30
  if (-not $response.token) {
    throw 'Missing token from register response'
  }
  $script:token = [string]$response.token
  if ($response.pollIntervalSec) {
    $script:PollIntervalSec = [Math]::Max(0.5, [double]$response.pollIntervalSec)
  }
  Write-AgentLog "registered site=$Site host=$env:COMPUTERNAME poll=$([Math]::Round($PollIntervalSec, 2))s"
}

while ($true) {
  try {
    if ([string]::IsNullOrWhiteSpace($token)) {
      Register-Agent
    }
    $poll = Invoke-AgentApi -Method 'POST' -Path '/api/agent/poll' -Body @{ token = $token } -TimeoutSec 40
    if ($poll.pollIntervalSec) {
      $PollIntervalSec = [Math]::Max(0.5, [double]$poll.pollIntervalSec)
    }

    $commandId = [string]$poll.commandId
    $commandText = [string]$poll.command
    if (-not [string]::IsNullOrWhiteSpace($commandId) -and -not [string]::IsNullOrWhiteSpace($commandText)) {
      $result = Run-AgentCommand -CommandText $commandText
      $resultPayload = @{
        token = $token
        commandId = $commandId
        ok = [bool]$result.ok
        exitCode = [int]$result.exitCode
        lines = @($result.lines)
      }
      if ($result.metrics) {
        $resultPayload.metrics = $result.metrics
      }
      Invoke-AgentApi -Method 'POST' -Path '/api/agent/result' -Body $resultPayload -TimeoutSec 30 | Out-Null
    }
    Start-Sleep -Milliseconds ([int]([Math]::Max(250, $PollIntervalSec * 1000)))
  } catch {
    $msg = [string]$_.Exception.Message
    if ($msg -match 'Invalid or expired agent session|401') {
      $token = ''
      Start-Sleep -Seconds 2
      continue
    }
    Write-AgentLog "poll error: $msg"
    Start-Sleep -Seconds 2
  }
}
