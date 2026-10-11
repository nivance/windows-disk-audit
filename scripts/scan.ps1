#Requires -Version 5.1
<#
  scan.ps1 - READ-ONLY disk space collector.

  Walks the filesystem once and aggregates sizes by path depth, then writes a
  JSON snapshot. It NEVER deletes, moves, or modifies anything.

  Why a hand written walker instead of du / Get-ChildItem / robocopy:
    * git-bash `du` follows directory junctions on Windows and loops forever.
    * Chinese Windows localizes the robocopy summary line, so parsing fails.
    * Get-ChildItem -Recurse creates a PowerShell object per file (slow) and
      still follows reparse points.
  This walker uses raw .NET APIs, skips reparse points, and uses the \\?\
  prefix so long node_modules paths are not silently dropped.

  Two engines:
    * mft  - parse the NTFS Master File Table directly (MftScan.cs). Reads the
             whole volume in seconds. Requires administrator rights, an NTFS
             volume, and a volume root as the -Root argument.
    * walk - the directory walker above. Always available, needs no privileges,
             works on any filesystem, roughly 50x slower.
  `auto` (the default) tries mft and silently falls back to walk per root.

  This file MUST stay pure ASCII. PowerShell 5.1 parses .ps1 files as the
  system ANSI codepage when there is no BOM, so non-ASCII literals break it.
#>
[CmdletBinding()]
param(
    [string[]]$Root = @(),
    [string]$OutFile = '',
    [int]$Depth = 3,
    [int]$MinBigFileMB = 300,
    [int]$RecentDays = 45,
    [int]$RecentMinMB = 100,
    [int]$MaxBucket = 60,
    [ValidateSet('auto', 'mft', 'walk')]
    [string]$Engine = 'auto',
    [switch]$NoProgress
)

$ErrorActionPreference = 'Continue'
$script:Prefix = '\\?\'
$script:ErrCount = 0
$script:MftReady = $false
$script:MftError = ''
$script:MftNotes = New-Object System.Collections.Generic.List[string]
$skillRoot = Split-Path -Parent $PSScriptRoot

function Get-AuditHome {
    if ($env:DISK_AUDIT_HOME -and $env:DISK_AUDIT_HOME.Trim() -ne '') {
        return $env:DISK_AUDIT_HOME.Trim()
    }
    $base = $env:USERPROFILE
    if (-not $base -or $base.Trim() -eq '') { $base = $env:HOME }
    if (-not $base -or $base.Trim() -eq '') { $base = [System.IO.Path]::GetTempPath() }
    return (Join-Path $base '.disk-audit')
}

function Add-Prefix([string]$p) {
    if ($p.StartsWith($script:Prefix)) { return $p }
    if ($p.StartsWith('\\')) { return $p }
    return $script:Prefix + $p
}

function Get-FixedRoots {
    $out = @()
    $vols = Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue
    if ($vols) {
        foreach ($v in $vols) { $out += ($v.DeviceID + '\') }
    }
    if ($out.Count -eq 0) {
        foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
            if ($d.DriveType -eq [System.IO.DriveType]::Fixed) { $out += ($d.Name) }
        }
    }
    return $out
}

function Get-VolumeInfo {
    $out = @()
    $vols = Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue
    if ($vols) {
        foreach ($v in $vols) {
            $t = 0; $f = 0
            if ($v.Size) { $t = [int64]$v.Size }
            if ($v.FreeSpace) { $f = [int64]$v.FreeSpace }
            $out += [pscustomobject]@{
                mount = [string]$v.DeviceID
                label = [string]$v.VolumeName
                fileSystem = [string]$v.FileSystem
                totalMB = [math]::Round($t / 1MB, 0)
                freeMB  = [math]::Round($f / 1MB, 0)
                usedMB  = [math]::Round(($t - $f) / 1MB, 0)
                usedPct = if ($t -gt 0) { [math]::Round((($t - $f) / $t) * 100, 1) } else { 0 }
            }
        }
    }
    return $out
}

# Walk one root, return aggregate buckets + a collection of notable files.
function Invoke-RootScan {
    param(
        [string]$RootPath,
        [int]$Depth,
        [int64]$BigThreshold,
        [int64]$NotableFloor,
        [System.Collections.Generic.List[object]]$BigFiles,
        [System.Collections.Generic.List[object]]$NotableFiles
    )

    $buckets = @{}
    for ($i = 1; $i -le $Depth; $i++) { $buckets[$i] = @{} }

    $total = [int64]0
    $fileCount = 0
    $dirCount = 0

    $rootFull = Add-Prefix $RootPath
    $rootLen = $rootFull.Length

    $stack = New-Object System.Collections.Stack
    $stack.Push($rootFull)

    while ($stack.Count -gt 0) {
        $dir = [string]$stack.Pop()
        $entries = $null
        try {
            $entries = [System.IO.Directory]::GetFileSystemEntries($dir)
        }
        catch {
            $script:ErrCount++
            continue
        }

        foreach ($e in $entries) {
            $fi = $null
            try { $fi = [System.IO.FileInfo]::new($e) } catch { $script:ErrCount++; continue }

            $attr = 0
            try { $attr = [int]$fi.Attributes } catch { $attr = 0 }

            if (($attr -band 16) -ne 0) {
                # Directory. Skip reparse points (junction / symlink) to avoid loops.
                if (($attr -band 1024) -eq 0) { $stack.Push($e); $dirCount++ }
                continue
            }

            $len = [int64]0
            $lw = [datetime]::MinValue
            try {
                $len = $fi.Length
                $lw = $fi.LastWriteTime
            }
            catch { $script:ErrCount++; continue }

            $total += $len
            $fileCount++

            $rel = $e.Substring($rootLen).TrimStart('\')
            $parts = $rel.Split('\')
            if ($parts.Length -ge 2) {
                for ($d = 1; $d -le $Depth; $d++) {
                    if ($parts.Length -ge ($d + 1)) {
                        $key = [string]::Join('\', $parts[0..($d - 1)])
                        $h = $buckets[$d]
                        if ($h.ContainsKey($key)) { $h[$key] = $h[$key] + $len } else { $h[$key] = $len }
                    }
                }
            }

            if ($len -ge $NotableFloor -and $NotableFiles.Count -lt 200000) {
                $absPath = $e
                if ($absPath.StartsWith($script:Prefix)) { $absPath = $absPath.Substring($script:Prefix.Length) }
                $NotableFiles.Add([pscustomobject]@{
                    path  = $absPath
                    mb    = [math]::Round($len / 1MB, 1)
                    mtime = $lw.ToString('yyyy-MM-dd HH:mm')
                })
                if ($len -ge $BigThreshold) {
                    $BigFiles.Add([pscustomobject]@{
                        path  = $absPath
                        mb    = [math]::Round($len / 1MB, 1)
                        mtime = $lw.ToString('yyyy-MM-dd')
                    })
                }
            }
        }
    }

    $rows = New-Object System.Collections.Generic.List[object]
    for ($d = 1; $d -le $Depth; $d++) {
        $h = $buckets[$d]
        $sorted = $h.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $MaxBucket
        foreach ($kv in $sorted) {
            $rows.Add([pscustomobject]@{
                root = $RootPath
                depth = $d
                path = [string]$kv.Key
                mb = [math]::Round($kv.Value / 1MB, 0)
            })
        }
    }

    return [pscustomobject]@{
        root = $RootPath
        engine = 'walk'
        totalMB = [math]::Round($total / 1MB, 0)
        files = $fileCount
        dirs = $dirCount
        buckets = $rows
    }
}

# ---------------- MFT engine ----------------

function Initialize-Mft {
    if ($script:MftReady) { return $true }
    if (-not ('DiskAudit.MftScanner' -as [type])) {
        $cs = Join-Path $skillRoot 'scripts\MftScan.cs'
        if (-not (Test-Path -LiteralPath $cs)) {
            $script:MftError = 'MftScan.cs not found next to scan.ps1'
            return $false
        }
        try {
            Add-Type -Path $cs -ErrorAction Stop
        }
        catch {
            $script:MftError = 'C# compiler failed: ' + $_.Exception.Message
            return $false
        }
    }
    $script:MftReady = $true
    return $true
}

function Convert-MftFileTime([long]$ticks) {
    if ($ticks -le 0) { return [datetime]::MinValue }
    $max = [datetime]::MaxValue.ToFileTime()
    if ($ticks -gt $max) { $ticks = $max }
    try { return [datetime]::FromFileTime($ticks) } catch { return [datetime]::MinValue }
}

# Direct $MFT parse. Produces exactly the same shape as Invoke-RootScan.
function Invoke-MftRootScan {
    param(
        [string]$RootPath,
        [int]$Depth,
        [int64]$BigThreshold,
        [int64]$NotableFloor,
        [int]$MaxBucket,
        [System.Collections.Generic.List[object]]$BigFiles,
        [System.Collections.Generic.List[object]]$NotableFiles
    )

    $letter = $RootPath.TrimEnd('\').TrimEnd(':')
    $r = [DiskAudit.MftScanner]::Scan($letter, $Depth, $BigThreshold, $NotableFloor, $MaxBucket, 200000)

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($b in $r.Buckets) {
        $rows.Add([pscustomobject]@{
            root  = $RootPath
            depth = [int]$b.Depth
            path  = [string]$b.Path
            mb    = [math]::Round([double]$b.Bytes / 1MB, 0)
        })
    }

    foreach ($f in $r.NotableFiles) {
        $dt = Convert-MftFileTime ([long]$f.MtimeTicks)
        $mb = [math]::Round([double]$f.Bytes / 1MB, 1)
        $NotableFiles.Add([pscustomobject]@{
            path  = [string]$f.Path
            mb    = $mb
            mtime = $dt.ToString('yyyy-MM-dd HH:mm')
        })
    }
    foreach ($f in $r.BigFiles) {
        $dt = Convert-MftFileTime ([long]$f.MtimeTicks)
        $BigFiles.Add([pscustomobject]@{
            path  = [string]$f.Path
            mb    = [math]::Round([double]$f.Bytes / 1MB, 1)
            mtime = $dt.ToString('yyyy-MM-dd')
        })
    }

    return [pscustomobject]@{
        root = $RootPath
        engine = 'mft'
        totalMB = [math]::Round([double]$r.TotalBytes / 1MB, 0)
        files = [int64]$r.Files
        dirs = [int64]$r.Dirs
        buckets = $rows
        mftRecords = [int64]$r.RecordCount
        mftHardLinkEntries = [int64]$r.HardLinkEntries
        mftOrphans = [int64]$r.Orphans
    }
}

# ---------------- main ----------------

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$auditHome = Get-AuditHome
$histDir = Join-Path $auditHome 'history'
if (-not (Test-Path -LiteralPath $histDir)) { New-Item -ItemType Directory -Force -Path $histDir | Out-Null }

if (-not $OutFile -or $OutFile.Trim() -eq '') {
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $OutFile = Join-Path $histDir ('scan-' + $stamp + '.json')
}

if ($Root.Count -eq 0) { $Root = Get-FixedRoots }
$Root = $Root | Where-Object { $_ -and $_.Trim() -ne '' }

$BigThreshold = [int64]$MinBigFileMB * 1MB
$NotableFloor = [int64]([math]::Min($RecentMinMB, $MinBigFileMB)) * 1MB
$cut = (Get-Date).AddDays(-1 * $RecentDays)

$big = New-Object 'System.Collections.Generic.List[object]'
$notable = New-Object 'System.Collections.Generic.List[object]'
$rootResults = New-Object System.Collections.Generic.List[object]

function Test-IsVolumeRoot([string]$p) {
    return ($p -match '^[A-Za-z]:\\?$')
}

foreach ($r in $Root) {
    if (-not $NoProgress) { Write-Host ("scanning " + $r + " ...") }
    $done = $false

    if ($Engine -eq 'mft' -or $Engine -eq 'auto') {
        if (-not (Test-IsVolumeRoot $r)) {
            $script:MftNotes.Add('MFT skipped for ' + $r + ': not a volume root (use walk)')
        }
        elseif (-not (Initialize-Mft)) {
            $script:MftNotes.Add('MFT unavailable: ' + $script:MftError)
        }
        else {
            try {
                $res = Invoke-MftRootScan -RootPath $r -Depth $Depth -BigThreshold $BigThreshold `
                                          -NotableFloor $NotableFloor -MaxBucket $MaxBucket `
                                          -BigFiles $big -NotableFiles $notable
                $rootResults.Add($res)
                $done = $true
            }
            catch {
                $msg = $_.Exception.Message
                $inner = $_.Exception
                while ($inner.InnerException) { $inner = $inner.InnerException }
                if ($inner -and -not [object]::ReferenceEquals($inner, $_.Exception)) {
                    $msg = $msg + ' | ' + $inner.Message
                }
                $script:MftNotes.Add('MFT failed on ' + $r + ': ' + $msg)
            }
        }
    }

    if (-not $done) {
        $res = Invoke-RootScan -RootPath $r -Depth $Depth -BigThreshold $BigThreshold `
                               -NotableFloor $NotableFloor -BigFiles $big -NotableFiles $notable
        $rootResults.Add($res)
    }
}

$recent = New-Object System.Collections.Generic.List[object]
foreach ($f in $notable) {
    if ($f.mb -ge $RecentMinMB) {
        $dt = [datetime]::MinValue
        if ([datetime]::TryParse($f.mtime, [ref]$dt)) {
            if ($dt -ge $cut) {
                $recent.Add([pscustomobject]@{
                    path  = $f.path
                    mb    = $f.mb
                    mtime = $f.mtime
                })
            }
        }
    }
}

$sw.Stop()

$engineUsed = @($rootResults | ForEach-Object { $_.engine } | Sort-Object -Unique) -join '+'

$doc = [pscustomobject]@{
    schema = 1
    scannedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    scanSeconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    engine = $engineUsed
    engineNotes = @($script:MftNotes)
    host = $env:COMPUTERNAME
    user = $env:USERNAME
    depth = $Depth
    thresholds = [pscustomobject]@{
        minBigFileMB = $MinBigFileMB
        recentDays = $RecentDays
        recentMinMB = $RecentMinMB
    }
    drives = Get-VolumeInfo
    roots = $rootResults
    bigFiles = ($big | Sort-Object mb -Descending)
    recentBig = ($recent | Sort-Object mb -Descending)
    errorCount = $script:ErrCount
}

$json = $doc | ConvertTo-Json -Depth 8
Set-Content -LiteralPath $OutFile -Value $json -Encoding UTF8

$grand = 0
foreach ($r in $rootResults) { $grand += $r.totalMB }
Write-Host ("RESULT " + $OutFile + " totalMB=" + $grand + " roots=" + $rootResults.Count + " engine=" + $engineUsed + " seconds=" + [math]::Round($sw.Elapsed.TotalSeconds, 1))
