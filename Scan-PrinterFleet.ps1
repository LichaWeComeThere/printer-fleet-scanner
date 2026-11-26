<#
.SYNOPSIS
  Printer fleet scan: sweeps every address in a network over and over and logs every PRINTER that answers.

.DESCRIPTION
  Every pass sends a read-only SNMP query (the same thing a print-management agent does) to every address in -Ranges
  (default: all of 10.0.0.0/8, 16.7 million addresses). Any device that answers like a printer - a serial
  number, a page count, or a printer model string - goes into fleet_printers.csv with its serial, model,
  MAC, IP, page count, first seen, last seen and how many times it has answered. Switches, UPSes, access
  points and other SNMP devices are ignored. On the PC's own subnet (and any -Subnets) devices are also
  pinged and identified by MAC, so a printer with SNMP turned off is still logged.

  Known printers are re-checked every -RecheckMinutes and at the end of every pass: a printer that stops
  answering is marked NOT ANSWERING (with the time it was last seen) and logged as GONE; it is logged as
  BACK when it answers again, and as MOVED when the same serial turns up at a new address.

  It runs until you press Q (or -Hours / -Passes run out), saves every few minutes, and continues where it
  left off when started again. The first run seeds the list from fleet_seed.csv (an export from an earlier
  scan) if that file is next to the script, so it does not start from zero.

.PARAMETER Ranges
  Ranges to sweep each pass (CIDR). Default: 10.0.0.0/8 (everything).
.PARAMETER Exclude
  Ranges to skip, e.g. -Exclude 10.2.0.0/16
.PARAMETER Subnets
  Extra /24s to ping every pass for MAC identification (plug the laptop into that VLAN).
.PARAMETER RecheckMinutes
  How often to re-check known printers (default 60). 0 = only at the end of each pass.
.PARAMETER PacketsPerSecond
  How hard to push the network. 800 (default) = about 7-8 h per pass over 10.0.0.0/8; 1500 = about 4 h.
.PARAMETER Hours / Passes
  Stop after this many hours / complete passes. 0 (default) = run until Q is pressed.
.PARAMETER SeedFile
  A CSV from an earlier scan (fleet_seed.csv format) to start from, if it is not next to the script.
.PARAMETER Community
  SNMP read community (default public).

.EXAMPLE
  .\Scan-PrinterFleet.ps1
  .\Scan-PrinterFleet.ps1 -PacketsPerSecond 1500
  .\Scan-PrinterFleet.ps1 -Ranges 10.1.0.0/16,10.2.0.0/16 -Passes 1
  .\Scan-PrinterFleet.ps1 -Ranges 192.168.0.0/16 -Subnets 192.168.1.0

  v1.1: detects a lost network connection (no printer answers) and pauses instead of marking everything GONE;
  ignores bogus 00-00-00 MACs; one summary line when hundreds of printers come back after an outage.
  v1.2: public release - generic file names (fleet_*.csv/.txt), no customer-specific text.
#>
[CmdletBinding()]
param(
    [string[]]$Ranges = @("10.0.0.0/8"),
    [string[]]$Exclude = @(),
    [string[]]$Subnets = @(),
    [double]$RecheckMinutes = 60,
    [int]$NetworkRetrySeconds = 300,
    [int]$PacketsPerSecond = 800,
    [int]$BatchSubnets = 16,
    [double]$Hours = 0,
    [int]$Passes = 0,
    [string]$SeedFile = "",
    [string]$Community = "public",
    [int]$SnmpPort = 161,
    [int]$TimeoutMs = 1500,
    [int]$PingTimeoutMs = 1000
)

$ErrorActionPreference = "Stop"

# Windows PowerShell 5.1 leaves $PSScriptRoot empty while parameter defaults are evaluated, so resolve paths here
$scriptDir = $PSScriptRoot
if (-not $scriptDir -and $MyInvocation.MyCommand.Path) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }

# ------------------------------------------------------------------------------------------------
# Minimal SNMP v2c / v1 GET client (BER encode/decode), no external modules needed
# ------------------------------------------------------------------------------------------------
$OIDS = [ordered]@{
    sysDescr   = "1.3.6.1.2.1.1.1.0"
    sysName    = "1.3.6.1.2.1.1.5.0"
    model      = "1.3.6.1.2.1.25.3.2.1.3.1"       # hrDeviceDescr
    serial     = "1.3.6.1.2.1.43.5.1.1.17.1"      # prtGeneralSerialNumber (Printer-MIB)
    pages      = "1.3.6.1.2.1.43.10.2.1.4.1.1"    # prtMarkerLifeCount (total impressions)
    mac1       = "1.3.6.1.2.1.2.2.1.6.1"          # ifPhysAddress.1
    mac2       = "1.3.6.1.2.1.2.2.1.6.2"          # ifPhysAddress.2
    hpSerial   = "1.3.6.1.4.1.11.2.3.9.4.2.1.1.3.3.0"   # HP private serial (fallback)
}

function ConvertTo-BerLength([int]$n) {
    if ($n -lt 128) { return ,[byte]$n }
    if ($n -lt 256) { return [byte[]](0x81, $n) }
    return [byte[]](0x82, (($n -shr 8) -band 0xFF), ($n -band 0xFF))
}
function New-BerTlv([byte]$tag, [byte[]]$content) {
    if ($null -eq $content) { $content = @() }
    return [byte[]](@($tag) + (ConvertTo-BerLength $content.Length) + $content)
}
function ConvertTo-BerInteger([long]$v) {
    # minimal two's-complement big-endian
    $bytes = New-Object System.Collections.Generic.List[byte]
    $tmp = $v
    do {
        $bytes.Insert(0, [byte]($tmp -band 0xFF))
        $tmp = $tmp -shr 8
    } while (($v -ge 0 -and ($tmp -ne 0 -or ($bytes[0] -band 0x80))) -or ($v -lt 0 -and ($tmp -ne -1 -or -not ($bytes[0] -band 0x80))))
    return New-BerTlv 0x02 $bytes.ToArray()
}
function ConvertTo-BerOid([string]$oid) {
    $parts = $oid.Trim('.').Split('.') | ForEach-Object { [int]$_ }
    $bytes = New-Object System.Collections.Generic.List[byte]
    $bytes.Add([byte](40 * $parts[0] + $parts[1]))
    for ($i = 2; $i -lt $parts.Count; $i++) {
        $v = $parts[$i]
        if ($v -lt 128) { $bytes.Add([byte]$v); continue }
        $stack = @()
        do { $stack = ,([byte]($v -band 0x7F)) + $stack; $v = $v -shr 7 } while ($v -gt 0)
        for ($j = 0; $j -lt $stack.Count - 1; $j++) { $bytes.Add([byte]($stack[$j] -bor 0x80)) }
        $bytes.Add($stack[$stack.Count - 1])
    }
    return New-BerTlv 0x06 $bytes.ToArray()
}
$script:VERSION = "1.2"
function New-SnmpGetTemplate([string]$community, [string[]]$oids, [int]$version) {
    # A GET packet whose request-id is a fixed 4-byte field that the sender overwrites with the TARGET IP ADDRESS.
    # Agents echo the request-id, so every reply says which address it came from, whatever the socket reports.
    $varbinds = @()
    foreach ($o in $oids) { $varbinds += New-BerTlv 0x30 ([byte[]]((ConvertTo-BerOid $o) + (New-BerTlv 0x05 @()))) }
    $vbl = New-BerTlv 0x30 ([byte[]]($varbinds | ForEach-Object { $_ }))
    $ridTlv = [byte[]](0x02, 0x04, 0x0A, 0x00, 0x00, 0x01)
    $pdu = New-BerTlv 0xA0 ([byte[]]($ridTlv + (ConvertTo-BerInteger 0) + (ConvertTo-BerInteger 0) + $vbl))
    $comm = New-BerTlv 0x04 ([System.Text.Encoding]::ASCII.GetBytes($community))
    $verTlv = ConvertTo-BerInteger $version
    $body = [byte[]]($verTlv + $comm + $pdu)
    $msg = New-BerTlv 0x30 $body
    # locate the rid field: the 6-byte pattern right after the A0 (GetRequest) header
    $offset = -1
    for ($i = 0; $i -le $msg.Length - 6; $i++) {
        if ($msg[$i] -eq 0xA0) {
            $hdr = 2; if ($msg[$i + 1] -band 0x80) { $hdr = 2 + ($msg[$i + 1] -band 0x7F) }
            $j = $i + $hdr
            if ($msg[$j] -eq 0x02 -and $msg[$j + 1] -eq 0x04 -and $msg[$j + 2] -eq 0x0A -and $msg[$j + 3] -eq 0x00 -and $msg[$j + 4] -eq 0x00 -and $msg[$j + 5] -eq 0x01) { $offset = $j + 2; break }
        }
    }
    if ($offset -lt 0) { throw "internal error: request-id field not found in SNMP template" }
    return @{ Bytes = $msg; RidOffset = $offset }
}
function Set-SnmpTemplateTarget($tpl, [string]$ip) {
    # stamp the target address into the request-id field (in place)
    $n = ConvertTo-IpInt $ip
    $b = $tpl.Bytes; $o = $tpl.RidOffset
    $b[$o] = [byte](($n -shr 24) -band 255); $b[$o + 1] = [byte](($n -shr 16) -band 255); $b[$o + 2] = [byte](($n -shr 8) -band 255); $b[$o + 3] = [byte]($n -band 255)
}
function Get-SnmpReplySource($parsed, $endpointIp, $sentTo) {
    # the address a reply came from: the echoed request-id if it is one we sent to, else what the socket reported
    try {
        $rid = $parsed["_rid"]
        if ($null -ne $rid) {
            $n = [long]$rid; if ($n -lt 0) { $n += 4294967296 }
            if ($n -ge 0 -and $n -le 4294967295) { $ip = ConvertFrom-IpInt $n; if ($sentTo.ContainsKey($ip)) { return $ip } }
        }
    } catch { }
    return $endpointIp
}
function New-SnmpGetPacket([string]$community, [string[]]$oids, [int]$requestId, [int]$version) {
    $varbinds = @()
    foreach ($o in $oids) { $varbinds += New-BerTlv 0x30 ([byte[]]((ConvertTo-BerOid $o) + (New-BerTlv 0x05 @()))) }
    $vbl = New-BerTlv 0x30 ([byte[]]($varbinds | ForEach-Object { $_ }))
    $pdu = New-BerTlv 0xA0 ([byte[]]((ConvertTo-BerInteger $requestId) + (ConvertTo-BerInteger 0) + (ConvertTo-BerInteger 0) + $vbl))
    $comm = New-BerTlv 0x04 ([System.Text.Encoding]::ASCII.GetBytes($community))
    return New-BerTlv 0x30 ([byte[]]((ConvertTo-BerInteger $version) + $comm + $pdu))
}
function Read-BerTlv([byte[]]$buf, [int]$pos) {
    # returns @{Tag; Start; Length; Next}  (Start = first content byte)
    $tag = $buf[$pos]; $pos++
    $len = [int]$buf[$pos]; $pos++
    if ($len -band 0x80) {
        $n = $len -band 0x7F; $len = 0
        for ($i = 0; $i -lt $n; $i++) { $len = ($len -shl 8) + $buf[$pos]; $pos++ }
    }
    return @{ Tag = $tag; Start = $pos; Length = $len; Next = $pos + $len }
}
function ConvertFrom-BerOid([byte[]]$b) {
    $parts = @([math]::Floor($b[0] / 40), ($b[0] % 40))
    $v = 0
    for ($i = 1; $i -lt $b.Length; $i++) {
        $v = ($v -shl 7) + ($b[$i] -band 0x7F)
        if (-not ($b[$i] -band 0x80)) { $parts += $v; $v = 0 }
    }
    return ($parts -join '.')
}
function ConvertFrom-BerValue([byte]$tag, [byte[]]$b) {
    switch ($tag) {
        0x02 { $v = 0; $neg = ($b.Length -gt 0 -and ($b[0] -band 0x80)); foreach ($x in $b) { $v = ($v -shl 8) + $x }; if ($neg) { $v = $v - [math]::Pow(2, 8 * $b.Length) }; return [long]$v }
        { $_ -in 0x41, 0x42, 0x43, 0x46 } { $v = [uint64]0; foreach ($x in $b) { $v = ($v -shl 8) + $x }; return $v }
        0x04 {
            if ($b.Length -eq 0) { return "" }
            $printable = $true
            foreach ($x in $b) { if ($x -lt 0x20 -or $x -gt 0x7E) { if ($x -notin 0x09, 0x0A, 0x0D) { $printable = $false; break } } }
            if ($printable) { return ([System.Text.Encoding]::ASCII.GetString($b)).Trim() }
            return (($b | ForEach-Object { $_.ToString("X2") }) -join '-')
        }
        0x06 { return (ConvertFrom-BerOid $b) }
        0x40 { return (($b | ForEach-Object { [int]$_ }) -join '.') }
        0x05 { return $null }
        { $_ -in 0x80, 0x81, 0x82 } { return $null }   # noSuchObject / noSuchInstance / endOfMibView
        default { return (($b | ForEach-Object { $_.ToString("X2") }) -join '') }
    }
}
function Invoke-SnmpGet([string]$ip, [string]$community, [string[]]$oids, [int]$port, [int]$timeoutMs, [int]$version = 1) {
    # version: 1 = v2c, 0 = v1. Returns hashtable oid -> value, or $null on no reply.
    $reqId = Get-Random -Minimum 1000 -Maximum 2000000000
    $packet = New-SnmpGetPacket $community $oids $reqId $version
    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Client.ReceiveTimeout = $timeoutMs
        $udp.Connect($ip, $port)
        [void]$udp.Send($packet, $packet.Length)
        $remote = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any, 0)
        $resp = $udp.Receive([ref]$remote)
    } catch { return $null } finally { $udp.Close() }
    return (ConvertFrom-SnmpResponse $resp)
}
function ConvertFrom-SnmpResponse([byte[]]$resp) {
    if ($null -eq $resp -or $resp.Length -lt 10) { return $null }
    try {
        $msg = Read-BerTlv $resp 0
        $ver = Read-BerTlv $resp $msg.Start
        $comm = Read-BerTlv $resp $ver.Next
        $pdu = Read-BerTlv $resp $comm.Next
        if ($pdu.Tag -ne 0xA2) { return $null }
        $rid = Read-BerTlv $resp $pdu.Start
        $errStat = Read-BerTlv $resp $rid.Next
        $errIdx = Read-BerTlv $resp $errStat.Next
        $vbl = Read-BerTlv $resp $errIdx.Next
        $result = @{}
        try { if ($rid.Length -gt 0) { $result["_rid"] = ConvertFrom-BerValue 0x02 ([byte[]]$resp[$rid.Start..($rid.Next - 1)]) } } catch { }
        $p = $vbl.Start
        while ($p -lt $vbl.Next) {
            $vb = Read-BerTlv $resp $p
            $oidT = Read-BerTlv $resp $vb.Start
            $valT = Read-BerTlv $resp $oidT.Next
            $oid = ConvertFrom-BerOid ($resp[$oidT.Start..($oidT.Next - 1)])
            $valBytes = if ($valT.Length -gt 0) { $resp[$valT.Start..($valT.Next - 1)] } else { @() }
            $result[$oid] = ConvertFrom-BerValue $valT.Tag ([byte[]]$valBytes)
            $p = $vb.Next
        }
        return $result
    } catch { return $null }
}
function Invoke-SnmpProbeMany([string[]]$ips, [string[]]$oids) {
    # Fire one SNMP GET at every address from a single socket and collect whatever answers.
    # Does not depend on ping at all, and probes thousands of addresses in seconds.
    $results = @{}
    $batchSize = 300
    for ($start = 0; $start -lt $ips.Count; $start += $batchSize) {
        $batch = $ips[$start..([math]::Min($start + $batchSize, $ips.Count) - 1)]
        $udp = New-Object System.Net.Sockets.UdpClient
        try {
            $udp.Client.ReceiveTimeout = $TimeoutMs
            try { $udp.Client.ReceiveBufferSize = 4194304 } catch { }
            # Windows: stop ICMP "port unreachable" from hosts without SNMP (PCs etc.) from killing the socket (SIO_UDP_CONNRESET)
            try { [void]$udp.Client.IOControl(-1744830452, [byte[]](0, 0, 0, 0), $null) } catch { }
            $tpl = New-SnmpGetTemplate $Community $oids 1
            $sentTo = @{}
            foreach ($ip in $batch) {
                try {
                    Set-SnmpTemplateTarget $tpl $ip
                    $ep = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($ip), $SnmpPort)
                    [void]$udp.Send($tpl.Bytes, $tpl.Bytes.Length, $ep)
                    $sentTo[$ip] = 1
                } catch { }
            }
            [void](Receive-SnmpReplies $udp $results $null $TimeoutMs $sentTo)   # collect until TimeoutMs of silence
        } finally { $udp.Close() }
        Write-Progress -Activity "SNMP probe" -Status ("{0} / {1} addresses, {2} replies" -f [math]::Min($start + $batchSize, $ips.Count), $ips.Count, $results.Count) -PercentComplete (100 * [math]::Min($start + $batchSize, $ips.Count) / $ips.Count)
    }
    Write-Progress -Activity "SNMP probe" -Completed
    return $results
}
function Get-PrinterInfo([string]$ip) {
    $oidList = @($OIDS.Values)
    $r = Invoke-SnmpGet $ip $Community $oidList $SnmpPort $TimeoutMs 1
    if ($null -eq $r) {
        # some older agents only speak v1 and reject requests containing unknown OIDs: retry v1, one OID at a time
        $r = @{}
        $probe = Invoke-SnmpGet $ip $Community @($OIDS.sysDescr) $SnmpPort $TimeoutMs 0
        if ($null -eq $probe) { return $null }
        foreach ($o in $oidList) { $x = Invoke-SnmpGet $ip $Community @($o) $SnmpPort $TimeoutMs 0; if ($x) { foreach ($k in $x.Keys) { $r[$k] = $x[$k] } } }
    }
    return (ConvertTo-PrinterInfo $r)
}
function Get-PrinterInfoV1([string]$ip) {
    # v1 agents that reject a multi-OID request: ask for each OID separately
    $r = @{}
    foreach ($o in @($OIDS.Values)) { $x = Invoke-SnmpGet $ip $Community @($o) $SnmpPort $TimeoutMs 0; if ($x) { foreach ($k in $x.Keys) { $r[$k] = $x[$k] } } }
    if ($r.Count -eq 0) { return $null }
    return $r
}
function ConvertTo-PrinterInfo($r) {
    $serial = $r[$OIDS.serial]; if ([string]::IsNullOrWhiteSpace($serial)) { $serial = $r[$OIDS.hpSerial] }
    $mac = $null
    foreach ($k in $OIDS.mac1, $OIDS.mac2) { $m = $r[$k]; if ($m -is [string] -and $m -match '^([0-9A-F]{2}-){5}[0-9A-F]{2}$' -and $m -ne '00-00-00-00-00-00') { $mac = $m; break } }
    $model = $r[$OIDS.model]; if ([string]::IsNullOrWhiteSpace($model)) { $model = $r[$OIDS.sysDescr] }
    return [pscustomobject]@{
        DeviceSerial = $(if ($serial) { ([string]$serial).Trim() } else { "" })
        DeviceModel  = $(if ($model) { ([string]$model).Trim() } else { "" })
        DeviceMAC    = $(if ($mac) { $mac } else { "" })
        DeviceName   = $(if ($r[$OIDS.sysName]) { [string]$r[$OIDS.sysName] } else { "" })
        TotalPages   = $(if ($null -ne $r[$OIDS.pages]) { [string]$r[$OIDS.pages] } else { "" })
    }
}

# ------------------------------------------------------------------------------------------------
# Ping sweep (parallel, .NET Ping so it works on PowerShell 5.1 and 7)
# ------------------------------------------------------------------------------------------------
function Test-HostsAlive([string[]]$ips) {
    $alive = @{}
    $batchSize = 256
    for ($start = 0; $start -lt $ips.Count; $start += $batchSize) {
        $batch = $ips[$start..([math]::Min($start + $batchSize, $ips.Count) - 1)]
        $tasks = @{}
        foreach ($ip in $batch) {
            $p = New-Object System.Net.NetworkInformation.Ping
            $tasks[$ip] = $p.SendPingAsync($ip, $PingTimeoutMs)
        }
        try { [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($tasks.Values), $PingTimeoutMs + 3000) } catch { }
        foreach ($ip in $batch) {
            $t = $tasks[$ip]
            if ($t.Status -eq 'RanToCompletion' -and $t.Result.Status -eq 'Success') { $alive[$ip] = $t.Result.RoundtripTime }
        }
        Write-Progress -Activity "Pinging" -Status ("{0} / {1}" -f [math]::Min($start + $batchSize, $ips.Count), $ips.Count) -PercentComplete (100 * [math]::Min($start + $batchSize, $ips.Count) / $ips.Count)
    }
    Write-Progress -Activity "Pinging" -Completed
    return $alive
}
function Normalize-Mac([string]$m) { if (-not $m) { return "" }; return ($m -replace '[^0-9A-Fa-f]', '').ToUpper() }

# ------------------------------------------------------------------------------------------------
# ARP: MAC addresses of hosts on THIS PC's own subnet(s). Works even when a printer has SNMP turned off.
# (Across a router ARP only ever shows the gateway, so entries exist only for local-subnet addresses.)
# ------------------------------------------------------------------------------------------------
function Get-PrefixFromMask([string]$mask) {
    try {
        $n = ConvertTo-IpInt $mask; $bits = 0
        for ($i = 31; $i -ge 0; $i--) { if (($n -shr $i) -band 1) { $bits++ } else { break } }
        return $bits
    } catch { return 24 }
}
function Get-LocalSubnets {
    $subs = @()
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne 'Up') { continue }
            foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.AddressFamily -ne 'InterNetwork') { continue }
                $ip = $ua.Address.ToString()
                if ($ip -like '127.*' -or $ip -like '169.254.*') { continue }
                $prefix = 0
                try { $prefix = [int]$ua.PrefixLength } catch { }
                if ($prefix -lt 1 -or $prefix -gt 32) { try { $m = $ua.IPv4Mask; if ($m) { $prefix = Get-PrefixFromMask $m.ToString() } } catch { } }
                if ($prefix -lt 1 -or $prefix -gt 32) { $prefix = 24 }
                $subs += ("{0}/{1}" -f $ip, $prefix)
            }
        }
    } catch { }
    if ($subs.Count -eq 0) {
        try {
            if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue) {
                foreach ($a in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
                    if ($a.IPAddress -like '127.*' -or $a.IPAddress -like '169.254.*') { continue }
                    $subs += ("{0}/{1}" -f $a.IPAddress, $a.PrefixLength)
                }
            }
        } catch { }
    }
    return $subs
}
function Get-ArpTable {
    $map = @{}
    try {
        $out = & arp -a 2>$null
        foreach ($line in $out) {
            if ($line -match '^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s') {           # Windows
                $map[$matches[1]] = ($matches[2] -replace ':', '-').ToUpper()
            } elseif ($line -match '\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})') {   # Linux/macOS
                $map[$matches[1]] = ($matches[2] -replace ':', '-').ToUpper()
            }
        }
    } catch { }
    foreach ($k in @($map.Keys)) { if ($map[$k] -match '^(FF-FF-FF-FF-FF-FF|00-00-00-00-00-00)$') { $map.Remove($k) } }
    return $map
}
$OUI = @{ "9C934E" = "Xerox"; "E84DEC" = "Xerox"; "0000AA" = "Xerox"; "30138B" = "HP"; "0001E6" = "HP"; "3C5282" = "HP"; "A0D3C1" = "HP";
          "00074D" = "Zebra"; "001570" = "Zebra"; "002368" = "Zebra"; "AC3FA4" = "Zebra"; "00C0B7" = "APC"; "282986" = "APC" }
function Get-MacVendor([string]$mac) { $k = (Normalize-Mac $mac); if ($k.Length -ge 6 -and $OUI.ContainsKey($k.Substring(0, 6))) { return $OUI[$k.Substring(0, 6)] }; return "" }

# ------------------------------------------------------------------------------------------------
# Address / pacing / probing helpers
# ------------------------------------------------------------------------------------------------
$script:MASK32 = [long]4294967295
function ConvertTo-IpInt([string]$ip) {
    $o = $ip.Trim().Split('.')
    if ($o.Count -ne 4) { throw "Bad IP address: $ip" }
    return ([long]$o[0] * 16777216) + ([long]$o[1] * 65536) + ([long]$o[2] * 256) + [long]$o[3]
}
function ConvertFrom-IpInt([long]$n) {
    return ("{0}.{1}.{2}.{3}" -f (($n -shr 24) -band 255), (($n -shr 16) -band 255), (($n -shr 8) -band 255), ($n -band 255))
}
function Expand-CidrTo24([string]$cidr) {
    # "10.1.0.0/16" -> 10.1.0, 10.1.1 ... 10.1.255     "192.168.1.0" or "192.168.1.0/24" -> 192.168.1
    $parts = $cidr.Trim().Split('/')
    $prefix = 24
    if ($parts.Count -gt 1) { $prefix = [int]$parts[1] }
    if ($prefix -gt 24) { $prefix = 24 }
    if ($prefix -lt 8) { throw "Range '$cidr' is wider than /8 - use /8 or narrower" }
    $size = [long][math]::Pow(2, 32 - $prefix)
    $start = [long]([math]::Floor((ConvertTo-IpInt $parts[0]) / $size) * $size)
    $list = New-Object System.Collections.Generic.List[string]
    for ($n = $start; $n -lt ($start + $size); $n += 256) {
        $list.Add(("{0}.{1}.{2}" -f (($n -shr 24) -band 255), (($n -shr 16) -band 255), (($n -shr 8) -band 255)))
    }
    return $list.ToArray()
}
function Get-LocalNetworks {
    $nets = @()
    foreach ($s in @(Get-LocalSubnets)) {
        $parts = $s.Split('/')
        $prefix = [int]$parts[1]
        if ($prefix -lt 1 -or $prefix -gt 32) { $prefix = 24 }
        $mask = ($script:MASK32 -shl (32 - $prefix)) -band $script:MASK32
        $ipInt = ConvertTo-IpInt $parts[0]
        $nets += [pscustomobject]@{ Address = $parts[0]; Prefix = $prefix; Network = ($ipInt -band $mask); Mask = $mask
                                    Cidr = ((ConvertFrom-IpInt ($ipInt -band $mask)) + "/" + $prefix); Size = [long][math]::Pow(2, 32 - $prefix) }
    }
    return $nets
}
function Test-LocalSubnet([string]$prefix24, $nets) {
    $ipInt = ConvertTo-IpInt "$prefix24.1"
    foreach ($n in @($nets)) { if (($ipInt -band $n.Mask) -eq $n.Network) { return $true } }
    return $false
}

# --- rate limiter: keeps the scan at -PacketsPerSecond so it is gentle on the network ---
$script:paceSw = $null
$script:paceSent = 0
function Start-Pace { $script:paceSw = [System.Diagnostics.Stopwatch]::StartNew(); $script:paceSent = 0 }
function Wait-Pace([int]$n) {
    if ($PacketsPerSecond -le 0 -or $null -eq $script:paceSw) { return }
    $script:paceSent += $n
    $due = [long](1000.0 * $script:paceSent / $PacketsPerSecond)
    $lag = $due - $script:paceSw.ElapsedMilliseconds
    if ($lag -gt 15) { Start-Sleep -Milliseconds ([int]$lag) }
}
function Receive-SnmpReplies($udp, $results, $pending, [int]$tailWaitMs, $sentTo) {
    # Collects SNMP replies from the socket into $results (ip -> parsed varbinds).
    #   tailWaitMs = 0 : take only what has already arrived (non-blocking; used while still sending)
    #   tailWaitMs > 0 : keep collecting until that many ms pass with no reply (end of batch)
    # Returns the still-pending receive task (pass it back in on the next call) or $null.
    # Uses ReceiveAsync, which hands back the sender's address in the result: Windows PowerShell 5.1 does not
    # update a [ref] IPEndPoint passed to UdpClient.Receive, which left every reply looking like it came from 0.0.0.0.
    $faults = 0
    while ($true) {
        if ($null -eq $pending) {
            if ($tailWaitMs -le 0 -and $udp.Available -le 0) { return $null }
            $pending = $udp.ReceiveAsync()
        }
        if (-not $pending.IsCompleted) {
            $waitMs = $tailWaitMs
            if ($tailWaitMs -le 0) { if ($udp.Available -le 0) { return $pending }; $waitMs = 50 }
            $done = $false
            try { $done = $pending.Wait($waitMs) } catch { $done = $true }
            if (-not $done) { return $pending }
        }
        if ($pending.Status -eq 'RanToCompletion') {
            try {
                $r = $pending.Result
                $parsed = ConvertFrom-SnmpResponse ([byte[]]$r.Buffer)
                if ($parsed) { $results[(Get-SnmpReplySource $parsed $r.RemoteEndPoint.Address.ToString() $sentTo)] = $parsed }
            } catch { }
            $faults = 0
        } else { $faults++; if ($faults -gt 20) { return $null } }
        $pending = $null
    }
}
function Invoke-SnmpProbeBatch([string[]]$ips, $tpl) {
    # One GET to every address (paced, target address stamped into the request-id), one socket, collect whatever
    # answers. Returns ip -> parsed varbinds.
    $results = @{}
    if ($null -eq $ips -or $ips.Count -eq 0) { return $results }
    $sentTo = @{}
    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        try { $udp.Client.ReceiveBufferSize = 8388608 } catch { }
        try { [void]$udp.Client.IOControl(-1744830452, [byte[]](0, 0, 0, 0), $null) } catch { }   # SIO_UDP_CONNRESET off (Windows)
        Start-Pace
        $i = 0
        $pending = $null
        foreach ($ip in $ips) {
            try {
                Set-SnmpTemplateTarget $tpl $ip
                $ep = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($ip), $SnmpPort)
                [void]$udp.Send($tpl.Bytes, $tpl.Bytes.Length, $ep)
                $sentTo[$ip] = 1
            } catch { }
            $i++
            if (($i % 32) -eq 0) { Wait-Pace 32; $pending = Receive-SnmpReplies $udp $results $pending 0 $sentTo }
        }
        [void](Receive-SnmpReplies $udp $results $pending $TimeoutMs $sentTo)   # collect until TimeoutMs of silence
    } finally { $udp.Close() }
    return $results
}
function Test-HostsAliveFast([string[]]$ips) {
    # Paced parallel ping; returns ip -> round trip ms for the ones that answered
    $alive = @{}
    if ($null -eq $ips -or $ips.Count -eq 0) { return $alive }
    $chunk = 1024
    for ($start = 0; $start -lt $ips.Count; $start += $chunk) {
        $batch = $ips[$start..([math]::Min($start + $chunk, $ips.Count) - 1)]
        $pings = New-Object System.Collections.Generic.List[object]
        $tasks = New-Object System.Collections.Generic.List[object]
        Start-Pace
        $i = 0
        foreach ($ip in $batch) {
            try { $p = New-Object System.Net.NetworkInformation.Ping; $pings.Add($p); $tasks.Add(@{ IP = $ip; Task = $p.SendPingAsync($ip, $PingTimeoutMs) }) } catch { }
            $i++
            if (($i % 32) -eq 0) { Wait-Pace 32 }
        }
        try { [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($tasks | ForEach-Object { $_.Task }), $PingTimeoutMs + 3000) } catch { }
        foreach ($t in $tasks) { try { if ($t.Task.Status -eq 'RanToCompletion' -and $t.Task.Result.Status -eq 'Success') { $alive[$t.IP] = $t.Task.Result.RoundtripTime } } catch { } }
        foreach ($p in $pings) { try { $p.Dispose() } catch { } }
    }
    return $alive
}
function Set-KeepAwake([bool]$on) {
    # Tell Windows not to sleep while the watch runs (closing the lid still sleeps the laptop - keep it open)
    try {
        if (-not ("FleetScan.Power" -as [type])) {
            Add-Type -Namespace FleetScan -Name Power -MemberDefinition '[DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint esFlags);'
        }
        if ($on) { [void][FleetScan.Power]::SetThreadExecutionState([uint32]2147483649) } else { [void][FleetScan.Power]::SetThreadExecutionState([uint32]2147483648) }   # ES_CONTINUOUS (+ ES_SYSTEM_REQUIRED)
        return $true
    } catch { return $false }
}
function Test-StopRequested {
    try {
        while ([Console]::KeyAvailable) {
            $k = [Console]::ReadKey($true)
            if ($k.Key -eq [ConsoleKey]::Q) { return $true }
        }
    } catch { }
    return $false
}
function Get-Stamp { return (Get-Date -Format "yyyy-MM-dd HH:mm:ss") }

# ------------------------------------------------------------------------------------------------
# Fleet inventory: every address in the ranges, every pass; every PRINTER that answers is logged
# ------------------------------------------------------------------------------------------------
$script:F = $null
$script:PRINTER_WORDS = 'Xerox|HP |Hewlett|LaserJet|OfficeJet|DesignJet|PageWide|Lexmark|Zebra|Brother|Canon|Ricoh|Kyocera|Konica|Epson|Toshiba|Sharp|Dell Laser|Printer|MFP|Multifunction'

function Write-FleetLog([string]$level, [string]$msg, [string]$color = "Gray") {
    $line = "{0}  {1,-7} {2}" -f (Get-Stamp), $level, $msg
    try { Add-Content -Path $script:F.LogFile -Value $line -Encoding UTF8 } catch { }
    Write-Host $line -ForegroundColor $color
}
function Test-IsPrinter($info) {
    if ($info.DeviceSerial -or $info.TotalPages) { return $true }
    return (($info.DeviceModel + " " + $info.DeviceName) -match $script:PRINTER_WORDS)
}
function Test-RealMac([string]$mac) {
    $mk = Normalize-Mac $mac
    if ($mk.Length -ne 12) { return $false }
    if ($mk.StartsWith("000000") -or $mk -eq "FFFFFFFFFFFF") { return $false }   # some Zebra agents report 00-00-00-xx-xx-xx
    return $true
}
function Get-PrinterKey($info, [string]$ip) {
    if ($info.DeviceSerial) { return "SN:" + $info.DeviceSerial.Trim().ToUpper() }
    if (Test-RealMac $info.DeviceMAC) { return "MAC:" + (Normalize-Mac $info.DeviceMAC) }
    return "IP:" + $ip
}
function New-FleetRecord([string]$key, $info, [string]$ip, [string]$now, [string]$via) {
    return [pscustomobject][ordered]@{
        Serial = $info.DeviceSerial; Model = $info.DeviceModel; MAC = $info.DeviceMAC; IP = $ip
        Status = "ACTIVE"; TotalPages = $info.TotalPages; PagesReadAt = $(if ($info.TotalPages) { $now } else { "" })
        FirstSeen = $now; LastSeen = $now; TimesSeen = 1; MissCount = 0; PreviousIPs = ""
        DeviceName = $info.DeviceName; Subnet = (($ip -replace '\.\d+$', '') + ".0/24"); IdentifiedBy = $via; Key = $key
    }
}
function Register-FleetPrinter($info, [string]$ip, [string]$now, [string]$via) {
    $F = $script:F
    $key = Get-PrinterKey $info $ip
    $label = $(if ($info.DeviceSerial) { $info.DeviceSerial } elseif ($info.DeviceMAC) { "MAC " + $info.DeviceMAC } else { $ip })
    if ($F.Printers.ContainsKey($key)) {
        $p = $F.Printers[$key]
        $wasGone = ([int]$p.MissCount -ge 2)
        if ($p.IP -ne $ip) {
            Write-FleetLog "MOVED" ("{0,-11} {1,-40} {2} -> {3}" -f $label, $p.Model, $p.IP, $ip) "Cyan"
            $prev = @(($p.PreviousIPs -split ';') | Where-Object { $_ })
            if ($prev -notcontains $p.IP) { $prev += $p.IP }
            $p.PreviousIPs = ($prev -join ';')
            if ($F.ByIp.ContainsKey($p.IP) -and $F.ByIp[$p.IP] -eq $key) { $F.ByIp.Remove($p.IP) }
            $p.IP = $ip; $p.Subnet = (($ip -replace '\.\d+$', '') + ".0/24")
            $F.PassMoved++
        }
        if ($info.DeviceSerial) { $p.Serial = $info.DeviceSerial }
        if ($info.DeviceModel -and $via -eq "SNMP") { $p.Model = $info.DeviceModel }
        if ($info.DeviceMAC) { $p.MAC = $info.DeviceMAC }
        if ($info.DeviceName) { $p.DeviceName = $info.DeviceName }
        if ($info.TotalPages) { $p.TotalPages = $info.TotalPages; $p.PagesReadAt = $now }
        if ($via -eq "SNMP") { $p.IdentifiedBy = "SNMP" }
        $p.LastSeen = $now
        if (-not $F.SeenThisRound.ContainsKey($key)) { $p.TimesSeen = [int]$p.TimesSeen + 1 }
        $p.MissCount = 0; $p.Status = "ACTIVE"
        if ($wasGone) { $F.RoundBack++; if (-not $F.QuietBack) { Write-FleetLog "BACK" ("{0,-11} {1,-40} at {2} answering again (pages {3})" -f $label, $p.Model, $ip, $p.TotalPages) "Green" } }
    } else {
        $F.Printers[$key] = New-FleetRecord $key $info $ip $now $via
        $F.PassNew++
        Write-FleetLog "NEW" ("{0,-11} {1,-40} at {2,-15} MAC {3} pages {4}" -f $label, $info.DeviceModel, $ip, $info.DeviceMAC, $info.TotalPages) "Green"
    }
    $F.ByIp[$ip] = $key
    $F.SeenThisRound[$key] = 1
}
function Register-FleetResults($snmp, $alive, $arp) {
    $now = Get-Stamp
    foreach ($ip in @($snmp.Keys)) {
        $info = ConvertTo-PrinterInfo $snmp[$ip]
        if (Test-IsPrinter $info) { Register-FleetPrinter $info $ip $now "SNMP" }
    }
    foreach ($ip in @($alive.Keys)) {
        if ($snmp.ContainsKey($ip) -or -not $arp.ContainsKey($ip)) { continue }
        $mac = $arp[$ip]; $vendor = Get-MacVendor $mac
        if (-not $vendor -or $vendor -eq "APC") { continue }
        $info = [pscustomobject]@{ DeviceSerial = ""; DeviceModel = ("no SNMP - " + $vendor + " (MAC via ARP)"); DeviceMAC = $mac; DeviceName = ""; TotalPages = "" }
        Register-FleetPrinter $info $ip $now "ARP"
    }
}
function Invoke-FleetBatch([string[]]$subs) {
    $F = $script:F
    $ips = New-Object System.Collections.Generic.List[string]
    foreach ($s in $subs) { for ($i = 1; $i -le 254; $i++) { $ips.Add("$s.$i") } }
    $snmp = Invoke-SnmpProbeBatch $ips.ToArray() $F.Tpl
    $alive = @{}; $arp = @{}
    $pingSubs = @($subs | Where-Object { $F.PingAlways.ContainsKey($_) -or (Test-LocalSubnet $_ $F.LocalNets) })
    if ($pingSubs.Count -gt 0) {
        $pingIps = New-Object System.Collections.Generic.List[string]
        foreach ($s in $pingSubs) { for ($i = 1; $i -le 254; $i++) { $pingIps.Add("$s.$i") } }
        $alive = Test-HostsAliveFast $pingIps.ToArray()
        if ($alive.Count -gt 0) { $arp = Get-ArpTable }
    }
    $F.PassAddresses += $ips.Count; $F.PassReplies += $snmp.Count
    Register-FleetResults $snmp $alive $arp
}
function Invoke-FleetRecheck([string]$why) {
    # Ask every known printer (at its last IP) whether it still answers. GONE after 2 misses in a row, BACK when it returns.
    $F = $script:F
    $F.SeenThisRound = @{}
    $keys = @($F.Printers.Keys)
    if ($keys.Count -eq 0) { return }
    $ipList = @($keys | ForEach-Object { $F.Printers[$_].IP } | Sort-Object -Unique)
    $snmp = @{}
    for ($s = 0; $s -lt $ipList.Count; $s += 2048) {
        $chunk = [string[]]$ipList[$s..([math]::Min($s + 2048, $ipList.Count) - 1)]
        $r = Invoke-SnmpProbeBatch $chunk $F.Tpl
        foreach ($k in $r.Keys) { $snmp[$k] = $r[$k] }
    }
    $rest = @($ipList | Where-Object { -not $snmp.ContainsKey($_) })
    if ($rest.Count -gt 0) {
        $v1 = Invoke-SnmpProbeBatch ([string[]]$rest) $F.TplV1
        foreach ($ip in @($v1.Keys)) { $full = Get-PrinterInfoV1 $ip; if ($full) { $snmp[$ip] = $full } else { $snmp[$ip] = $v1[$ip] } }
    }
    $arpIps = @($keys | Where-Object { $F.Printers[$_].IdentifiedBy -eq "ARP" } | ForEach-Object { $F.Printers[$_].IP })
    $alive = @{}; $arp = @{}
    if ($arpIps.Count -gt 0) { $alive = Test-HostsAliveFast ([string[]]$arpIps); if ($alive.Count -gt 0) { $arp = Get-ArpTable } }
    if ($keys.Count -ge 20 -and $snmp.Count -eq 0 -and $alive.Count -eq 0) {
        # not one of the known printers answered: that is the laptop's network, not the printers. Keep every status as it was.
        $F.NetworkDown = $true
        Write-FleetLog "NETWORK" ("{0}: none of the {1} known printers answered - the laptop has probably lost its network connection (check the cable / ipconfig). Statuses left unchanged; the sweep is paused until replies come back." -f $why, $keys.Count) "Red"
        $F.LastRecheck = Get-Date
        return
    }
    $F.QuietBack = $false; $F.RoundBack = 0
    $goneNow = @($keys | Where-Object { [int]$F.Printers[$_].MissCount -ge 2 }).Count
    if ($F.NetworkDown -or $goneNow -gt 100) { $F.QuietBack = $true }   # after an outage hundreds come back at once: one summary line instead of hundreds
    Register-FleetResults $snmp $alive $arp
    if ($F.NetworkDown) { Write-FleetLog "NETWORK" ("replies are back ({0} printers answered) - resuming the sweep" -f $snmp.Count) "Green"; $F.NetworkDown = $false }
    if ($F.QuietBack -and $F.RoundBack -gt 0) { Write-FleetLog "BACK" ("{0} printers answering again" -f $F.RoundBack) "Green" }
    $gone = 0; $missed = 0
    foreach ($k in $keys) {
        if ($F.SeenThisRound.ContainsKey($k)) { continue }
        $p = $F.Printers[$k]
        $p.MissCount = [int]$p.MissCount + 1
        if ([int]$p.MissCount -eq 1) { $p.Status = "MISSED 1 CHECK"; $missed++ }
        elseif ([int]$p.MissCount -eq 2) {
            $p.Status = "NOT ANSWERING since " + $p.LastSeen
            $label = $(if ($p.Serial) { $p.Serial } elseif ($p.MAC) { "MAC " + $p.MAC } else { $p.IP })
            Write-FleetLog "GONE" ("{0,-11} {1,-40} at {2} stopped answering (last seen {3})" -f $label, $p.Model, $p.IP, $p.LastSeen) "Yellow"
            $gone++
        }
    }
    $active = @($keys | Where-Object { $F.Printers[$_].Status -eq "ACTIVE" }).Count
    $notAns = @($keys | Where-Object { $F.Printers[$_].Status -like "NOT ANSWERING*" }).Count
    Write-FleetLog "CHECK" ("{0}: {1} known printers re-checked - {2} active, {3} missed once, {4} not answering ({5} newly gone)" -f $why, $keys.Count, $active, $missed, $notAns, $gone) "DarkGray"
    $F.LastRecheck = Get-Date
}
function Save-FleetFiles {
    $F = $script:F
    try {
        if ($F.Printers.Count -gt 0) {
            $rows = @($F.Printers.Values | Sort-Object { ConvertTo-IpInt $_.IP })
            $tmp = $F.FleetFile + ".tmp"
            $rows | Export-Csv -Path $tmp -NoTypeInformation -Encoding UTF8
            Move-Item -Path $tmp -Destination $F.FleetFile -Force
        }
        $state = @(("pass={0}" -f $F.Pass), ("cursor={0}" -f $F.Cursor), ("ranges={0}" -f $F.RangesKey), ("lastSaved={0}" -f (Get-Stamp)))
        Set-Content -Path $F.StateFile -Value $state -Encoding UTF8
        $F.LastSave = Get-Date
    } catch {
        Write-Host ("  (could not save the result files right now: {0} - if one of them is open in Excel, close it)" -f $_.Exception.Message) -ForegroundColor Red
    }
}
function Import-FleetSeed([string]$path, [bool]$ownFormat) {
    # ownFormat: fleet_printers.csv from an earlier run; otherwise a watch-format export (printers only)
    $F = $script:F; $n = 0
    foreach ($row in @(Import-Csv $path)) {
        if (-not $row.IP) { continue }
        if ($ownFormat) {
            $key = $row.Key
            if (-not $key) { $key = Get-PrinterKey ([pscustomobject]@{ DeviceSerial = $row.Serial; DeviceMAC = $row.MAC }) $row.IP }
            $rec = [pscustomobject][ordered]@{
                Serial = $row.Serial; Model = $row.Model; MAC = $row.MAC; IP = $row.IP; Status = $row.Status
                TotalPages = $row.TotalPages; PagesReadAt = $row.PagesReadAt; FirstSeen = $row.FirstSeen; LastSeen = $row.LastSeen
                TimesSeen = $(if ($row.TimesSeen) { [int]$row.TimesSeen } else { 1 }); MissCount = $(if ($row.MissCount) { [int]$row.MissCount } else { 0 })
                PreviousIPs = $row.PreviousIPs; DeviceName = $row.DeviceName; Subnet = $row.Subnet; IdentifiedBy = $row.IdentifiedBy; Key = $key
            }
        } else {
            $isPrinter = ($row.Kind -eq "Printer") -or ($row.Kind -like "Printer-vendor*") -or $row.DeviceSerial -or $row.TotalPages
            if (-not $isPrinter) { continue }
            $via = $(if ($row.Kind -like "Printer-vendor*") { "ARP" } else { "SNMP" })
            $key = Get-PrinterKey ([pscustomobject]@{ DeviceSerial = $row.DeviceSerial; DeviceMAC = $row.DeviceMAC }) $row.IP
            $rec = [pscustomobject][ordered]@{
                Serial = $row.DeviceSerial; Model = $row.DeviceModel; MAC = $row.DeviceMAC; IP = $row.IP; Status = "ACTIVE"
                TotalPages = $row.TotalPages; PagesReadAt = $row.LastSeen; FirstSeen = $row.FirstSeen; LastSeen = $row.LastSeen
                TimesSeen = $(if ($row.TimesSeen) { [int]$row.TimesSeen } else { 1 }); MissCount = 0
                PreviousIPs = ""; DeviceName = $row.DeviceName; Subnet = (($row.IP -replace '\.\d+$', '') + ".0/24"); IdentifiedBy = $via; Key = $key
            }
        }
        if ($F.Printers.ContainsKey($key)) { continue }
        $F.Printers[$key] = $rec; $F.ByIp[$row.IP] = $key; $n++
    }
    return $n
}
function Show-FleetSummary {
    $F = $script:F
    $all = @($F.Printers.Values)
    $active = @($all | Where-Object { $_.Status -eq "ACTIVE" }).Count
    $missed = @($all | Where-Object { $_.Status -like "MISSED*" }).Count
    $notAns = @($all | Where-Object { $_.Status -like "NOT ANSWERING*" }).Count
    $bySub = @{}
    foreach ($p in $all) { $k = (($p.IP -split '\.')[0..1] -join '.') + ".x"; if (-not $bySub.ContainsKey($k)) { $bySub[$k] = 0 }; $bySub[$k]++ }
    Write-Host ("Printers known: {0}   active: {1}   missed last check: {2}   not answering: {3}" -f $all.Count, $active, $missed, $notAns) -ForegroundColor Cyan
    Write-Host ("By range: " + ((@($bySub.Keys | Sort-Object { $bySub[$_] } -Descending | Select-Object -First 12) | ForEach-Object { "{0} {1}" -f $_, $bySub[$_] }) -join ', '))
}
function Invoke-Fleet {
    $F = @{}
    $script:F = $F
    $F.Started = Get-Date
    $F.LogFile = Join-Path $scriptDir "fleet_log.txt"
    $F.FleetFile = Join-Path $scriptDir "fleet_printers.csv"
    $F.StateFile = Join-Path $scriptDir "fleet_state.txt"
    $F.Tpl = New-SnmpGetTemplate $Community @($OIDS.Values) 1
    $F.TplV1 = New-SnmpGetTemplate $Community @($OIDS.sysDescr) 0
    $F.Printers = @{}; $F.ByIp = @{}; $F.SeenThisRound = @{}
    $F.Pass = 0; $F.Cursor = 0; $F.LastSave = Get-Date; $F.LastRecheck = Get-Date
    $F.PassNew = 0; $F.PassMoved = 0; $F.PassAddresses = 0; $F.PassReplies = 0
    $F.NetworkDown = $false; $F.QuietBack = $false; $F.RoundBack = 0
    # ---- address list ----
    $F.PingAlways = @{}
    $excl = @{}
    foreach ($r in $Exclude) { foreach ($s in (Expand-CidrTo24 $r)) { $excl[$s] = 1 } }
    $subs = New-Object System.Collections.Generic.List[string]; $seenSub = @{}
    foreach ($r in $Ranges) { foreach ($s in (Expand-CidrTo24 $r)) { if (-not $seenSub.ContainsKey($s) -and -not $excl.ContainsKey($s)) { $subs.Add($s); $seenSub[$s] = 1 } } }
    foreach ($r in $Subnets) { foreach ($s in (Expand-CidrTo24 $r)) { $F.PingAlways[$s] = 1; if (-not $seenSub.ContainsKey($s)) { $subs.Add($s); $seenSub[$s] = 1 } } }
    $F.Subs = [string[]]$subs.ToArray()
    $F.RangesKey = (@($Ranges) -join ',') + "|" + (@($Exclude) -join ',') + "|" + (@($Subnets) -join ',')
    # ---- resume / seed ----
    $resumed = $false
    if (Test-Path $F.StateFile) {
        try {
            $kv = @{}
            foreach ($line in (Get-Content $F.StateFile)) { if ($line -match '^([^=]+)=(.*)$') { $kv[$matches[1]] = $matches[2] } }
            if ($kv['ranges'] -eq $F.RangesKey) { $F.Pass = [int]$kv['pass']; $F.Cursor = [int]$kv['cursor']; $resumed = $true }
        } catch { }
    }
    if ($F.Cursor -ge $F.Subs.Count) { $F.Cursor = 0 }
    $seedNote = "starting with an empty list"
    if (Test-Path $F.FleetFile) { $n = Import-FleetSeed $F.FleetFile $true; $seedNote = "continuing with the {0} printers already in {1}" -f $n, (Split-Path $F.FleetFile -Leaf) }
    else {
        $cands = @()
        if ($SeedFile) { $cands += $SeedFile }
        $cands += (Join-Path $scriptDir "fleet_seed.csv")
        foreach ($c in $cands) { if (Test-Path $c) { $n = Import-FleetSeed $c $false; $seedNote = "seeded with the {0} printers from {1}" -f $n, (Split-Path $c -Leaf); break } }
    }
    $F.LocalNets = @(Get-LocalNetworks)
    $localTxt = "unknown"
    if ($F.LocalNets.Count -gt 0) { $localTxt = (@($F.LocalNets | ForEach-Object { "{0} ({1}, {2:N0} addresses)" -f $_.Address, $_.Cidr, $_.Size }) -join ', ') }
    $addrPerPass = $F.Subs.Count * 254
    $batches = [math]::Ceiling($F.Subs.Count / $BatchSubnets)
    $estH = 0; if ($PacketsPerSecond -gt 0) { $estH = $addrPerPass / $PacketsPerSecond / 3600 }
    $estH += $batches * $TimeoutMs / 1000 / 3600

    $awake = Set-KeepAwake $true
    Write-Host ""
    Write-Host "=============== PRINTER FLEET SCAN ===============" -ForegroundColor Cyan
    Write-FleetLog "START" ("Scan-PrinterFleet v{0} {1} at {2}; {3}" -f $script:VERSION, $(if ($resumed) { "RESUMED (pass $($F.Pass), $([int](100 * $F.Cursor / [math]::Max(1, $F.Subs.Count)))% in)" } else { "started" }), (Get-Stamp), $seedNote) "Cyan"
    Write-FleetLog "LOCAL" ("this PC is on {0}. Ping + ARP (MAC) covers those addresses{1}; everywhere else a printer is identified by its SNMP reply." -f $localTxt, $(if ($F.PingAlways.Count -gt 0) { " plus -Subnets " + (@($F.PingAlways.Keys | Sort-Object | ForEach-Object { $_ + ".0/24" }) -join ', ') } else { "" })) "Cyan"
    Write-FleetLog "PLAN" ("every pass: {0:N0} subnets / {1:N0} addresses ({2}){3}; every reply that is a printer is logged; non-printers are ignored" -f $F.Subs.Count, $addrPerPass, (@($Ranges) -join ', '), $(if ($Exclude.Count -gt 0) { " excluding " + (@($Exclude) -join ', ') } else { "" })) "Cyan"
    Write-FleetLog "PLAN" ("rate {0} packets/s -> about {1:N1} h per pass; known printers re-checked every {2} min and at the end of each pass. Stop: {3}. Press Q to stop cleanly (Ctrl+C also works)." -f $PacketsPerSecond, $estH, $RecheckMinutes, $(if ($Hours -gt 0 -and $Passes -gt 0) { "after $Hours h or $Passes passes" } elseif ($Hours -gt 0) { "after $Hours h" } elseif ($Passes -gt 0) { "after $Passes passes" } else { "runs until you press Q" })) "Cyan"
    Write-FleetLog "FILES" ("{0} (one row per printer), {1} (events). Updated every few minutes - open COPIES in Excel, Excel locks the file." -f (Split-Path $F.FleetFile -Leaf), (Split-Path $F.LogFile -Leaf)) "Cyan"
    if (-not $awake) { Write-FleetLog "NOTE" "could not tell Windows to stay awake - set Power options to never sleep while this runs" "Yellow" }
    Write-Host ""

    $stop = $false; $stopReason = ""
    try {
        if ($F.Printers.Count -gt 0) { Invoke-FleetRecheck "startup check" }
        while (-not $stop) {
            if ($F.Cursor -eq 0) {
                $F.Pass++; $F.PassNew = 0; $F.PassMoved = 0; $F.PassAddresses = 0; $F.PassReplies = 0; $F.PassStart = Get-Date; $F.SeenThisRound = @{}
                Write-FleetLog "PASS" ("{0} starting ({1:N0} addresses)" -f $F.Pass, $addrPerPass) "Cyan"
            } else { $F.PassStart = Get-Date; $F.PassNew = 0; $F.PassMoved = 0; $F.PassAddresses = 0; $F.PassReplies = 0; $F.SeenThisRound = @{} }
            $F.LocalNets = @(Get-LocalNetworks)
            $activity = "Printer fleet scan - pass $($F.Pass)"
            for ($b = $F.Cursor; $b -lt $F.Subs.Count; $b += $BatchSubnets) {
                $batch = [string[]]$F.Subs[$b..([math]::Min($b + $BatchSubnets, $F.Subs.Count) - 1)]
                $pct = [math]::Min(99, [int](100 * $b / [math]::Max(1, $F.Subs.Count)))
                Write-Progress -Activity $activity -Status ("{0}.0/24 ... ({1}% of pass) | printers known: {2} | new this pass: {3} | moved: {4} | elapsed {5:N0} min" -f $batch[0], $pct, $F.Printers.Count, $F.PassNew, $F.PassMoved, ((Get-Date) - $F.PassStart).TotalMinutes) -PercentComplete $pct
                while ($F.NetworkDown -and -not $stop) {
                    # no point sweeping 16 million addresses with no network: wait, then ask the known printers again
                    Write-Progress -Activity $activity -Status ("NETWORK DOWN - waiting {0} s, then checking the known printers again (Q to stop)" -f $NetworkRetrySeconds) -PercentComplete $pct
                    $waited = 0
                    while ($waited -lt $NetworkRetrySeconds) { Start-Sleep -Seconds 1; $waited++; if (Test-StopRequested) { $stop = $true; $stopReason = "Q pressed"; break } }
                    if ($stop) { break }
                    try { Invoke-FleetRecheck "network retry" } catch { }
                    if (-not $F.NetworkDown) { Save-FleetFiles }
                }
                if ($stop) { break }
                try { Invoke-FleetBatch $batch }
                catch { Write-FleetLog "ERROR" ("batch {0} failed: {1}" -f $batch[0], $_.Exception.Message) "Red"; Start-Sleep -Seconds 5 }
                $F.Cursor = $b + $BatchSubnets
                if (((Get-Date) - $F.LastSave).TotalMinutes -ge 3) { Save-FleetFiles }
                if ($RecheckMinutes -gt 0 -and ((Get-Date) - $F.LastRecheck).TotalMinutes -ge $RecheckMinutes) {
                    Write-Progress -Activity $activity -Status "re-checking known printers..." -PercentComplete $pct
                    try { Invoke-FleetRecheck "hourly check" } catch { Write-FleetLog "ERROR" ("re-check failed: {0}" -f $_.Exception.Message) "Red" }
                    Save-FleetFiles
                }
                if (Test-StopRequested) { $stop = $true; $stopReason = "Q pressed"; break }
                if ($Hours -gt 0 -and ((Get-Date) - $F.Started).TotalHours -ge $Hours) { $stop = $true; $stopReason = "-Hours $Hours reached"; break }
            }
            Write-Progress -Activity $activity -Completed
            if (-not $stop) {
                $F.Cursor = 0
                try { Invoke-FleetRecheck "end-of-pass check" } catch { }
                Save-FleetFiles
                Write-FleetLog "PASS" ("{0} done in {1:N1} h: {2:N0} addresses probed, {3:N0} SNMP replies; printers known: {4} ({5} new this pass, {6} moved)" -f $F.Pass, ((Get-Date) - $F.PassStart).TotalHours, $F.PassAddresses, $F.PassReplies, $F.Printers.Count, $F.PassNew, $F.PassMoved) "Cyan"
                Show-FleetSummary
                Write-Host ""
                if ($Passes -gt 0 -and $F.Pass -ge $Passes) { $stop = $true; $stopReason = "-Passes $Passes reached" }
                if (-not $stop -and $Hours -gt 0 -and ((Get-Date) - $F.Started).TotalHours -ge $Hours) { $stop = $true; $stopReason = "-Hours $Hours reached" }
                if (-not $stop -and (Test-StopRequested)) { $stop = $true; $stopReason = "Q pressed" }
            }
        }
    } finally {
        Save-FleetFiles
        [void](Set-KeepAwake $false)
        Write-Progress -Activity "Printer fleet scan" -Completed
    }
    Write-Host ""
    Write-Host "================= FLEET SCAN SUMMARY =================" -ForegroundColor Cyan
    Write-FleetLog "STOP" ("stopped ({0}) after {1:N1} h this run; pass {2} is {3}% done" -f $stopReason, ((Get-Date) - $F.Started).TotalHours, $F.Pass, [int](100 * $F.Cursor / [math]::Max(1, $F.Subs.Count))) "Cyan"
    Show-FleetSummary
    Write-Host ("Files: {0}  |  {1}" -f $F.FleetFile, $F.LogFile)
    Write-Host "Run the same command again to continue where it left off." -ForegroundColor Cyan
}

Invoke-Fleet
