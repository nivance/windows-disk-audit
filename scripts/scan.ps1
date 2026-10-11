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
    [switch]$NoProgress
)

$ErrorActionPreference = 'Continue'
$script:Prefix = '\\?\'
$script:ErrCount = 0

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
        totalMB = [math]::Round($total / 1MB, 0)
        files = $fileCount
        dirs = $dirCount
        buckets = $rows
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

foreach ($r in $Root) {
    if (-not $NoProgress) { Write-Host ("scanning " + $r + " ...") }
    $res = Invoke-RootScan -RootPath $r -Depth $Depth -BigThreshold $BigThreshold `
                           -NotableFloor $NotableFloor -BigFiles $big -NotableFiles $notable
    $rootResults.Add($res)
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

$doc = [pscustomobject]@{
    schema = 1
    scannedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    scanSeconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
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
Write-Host ("RESULT " + $OutFile + " totalMB=" + $grand + " roots=" + $rootResults.Count + " seconds=" + [math]::Round($sw.Elapsed.TotalSeconds, 1))
