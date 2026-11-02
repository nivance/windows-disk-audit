#Requires -Version 5.1
<#
  analyze.ps1 - match the rule library against a scan snapshot, grade findings,
  compare with the previous snapshot to show growth, and flag anomalies.

  READ-ONLY. Emits a JSON analysis; the calling agent renders the Chinese report.

  This file MUST stay pure ASCII (PowerShell 5.1 parses non-BOM .ps1 as ANSI).
#>
[CmdletBinding()]
param(
    [string]$Snapshot = '',
    [string]$RulesFile = '',
    [string]$NeverTouchFile = '',
    [string]$OutFile = '',
    [int]$TopGrowth = 25,
    [int]$MinFindingMB = 50,
    # How the sizes of the matched rule paths are measured. `mft` reads them out
    # of one $MFT pass (seconds), `walk` walks every path (about 90 seconds on a
    # normal C: drive), `auto` prefers the MFT and silently falls back to walking.
    [ValidateSet('auto', 'mft', 'walk')]
    [string]$SizeEngine = 'auto'
)

$ErrorActionPreference = 'Continue'
$script:Prefix = '\\?\'
$skillRoot = Split-Path -Parent $PSScriptRoot
$dirSizeScript = Join-Path $PSScriptRoot 'dirsizes.ps1'
$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $psExe)) { $psExe = 'powershell.exe' }

if (-not $RulesFile -or $RulesFile.Trim() -eq '') { $RulesFile = Join-Path $skillRoot 'rules\caches.json' }
if (-not $NeverTouchFile -or $NeverTouchFile.Trim() -eq '') { $NeverTouchFile = Join-Path $skillRoot 'rules\never-touch.json' }

function Get-AuditHome {
    if ($env:DISK_AUDIT_HOME -and $env:DISK_AUDIT_HOME.Trim() -ne '') { return $env:DISK_AUDIT_HOME.Trim() }
    $base = $env:USERPROFILE
    if (-not $base -or $base.Trim() -eq '') { $base = $env:HOME }
    if (-not $base -or $base.Trim() -eq '') { $base = [System.IO.Path]::GetTempPath() }
    return (Join-Path $base '.disk-audit')
}

# A snapshot is only a valid "previous state" if it was taken from the same
# root set at the same depth. Otherwise a scan of a different drive or of a
# single sub-directory would be mistaken for the previous state and skew growth.
function Get-RootSignature($doc) {
    if (-not $doc) { return '' }
    $roots = @()
    foreach ($r in @($doc.roots)) { $roots += ([string]$r.root).TrimEnd('\').ToLowerInvariant() }
    $roots = @($roots | Sort-Object)
    return (($roots -join '|') + '#d' + [string]$doc.depth)
}

function Add-Prefix([string]$p) {
    if ($p.StartsWith($script:Prefix)) { return $p }
    if ($p.StartsWith('\\')) { return $p }
    return $script:Prefix + $p
}

function Expand-Pattern([string]$p) {
    $out = $p
    foreach ($m in [regex]::Matches($p, '%([^%]+)%')) {
        $name = $m.Groups[1].Value
        $v = [System.Environment]::GetEnvironmentVariable($name)
        if ($v) { $out = $out.Replace($m.Value, $v) }
    }
    return $out
}

# Resolve a path pattern (with %ENV% and single-segment * wildcards) to real paths.
function Resolve-Pattern([string]$pattern) {
    $expanded = Expand-Pattern $pattern
    $parts = $expanded.Split('\')
    if ($parts.Length -lt 2) { return @() }

    $current = @($parts[0] + '\')
    for ($i = 1; $i -lt $parts.Length; $i++) {
        $seg = $parts[$i]
        if ($seg -eq '') { continue }
        $next = New-Object System.Collections.Generic.List[string]
        foreach ($c in $current) {
            $cFull = Add-Prefix $c
            if ($seg -eq '*') {
                try {
                    foreach ($d in [System.IO.Directory]::GetDirectories($cFull)) { $next.Add($d.Substring($script:Prefix.Length)) }
                }
                catch { }
            }
            elseif ($seg.Contains('*') -or $seg.Contains('?')) {
                $rx = '^' + ([regex]::Escape($seg).Replace('\*', '.*').Replace('\?', '.')) + '$'
                try {
                    foreach ($e in [System.IO.Directory]::GetFileSystemEntries($cFull)) {
                        $leaf = [System.IO.Path]::GetFileName($e)
                        if ($leaf -match $rx) { $next.Add($e.Substring($script:Prefix.Length)) }
                    }
                }
                catch { }
            }
            else {
                $p = ($c.TrimEnd('\') + '\' + $seg)
                if ([System.IO.Directory]::Exists((Add-Prefix $p)) -or [System.IO.File]::Exists((Add-Prefix $p))) {
                    $next.Add($p)
                }
            }
        }
        $current = $next
        if ($current.Count -eq 0) { break }
    }
    return $current
}

# Size in MB of a file or a directory tree (skips reparse points).
function Get-PathSizeMB([string]$path) {
    $full = Add-Prefix $path
    if ([System.IO.File]::Exists($full)) {
        try { return [math]::Round(([System.IO.FileInfo]::new($full)).Length / 1MB, 0) } catch { return 0 }
    }
    if (-not [System.IO.Directory]::Exists($full)) { return -1 }

    $total = [int64]0
    $stack = New-Object System.Collections.Stack
    $stack.Push($full)
    while ($stack.Count -gt 0) {
        $dir = [string]$stack.Pop()
        try { $entries = [System.IO.Directory]::GetFileSystemEntries($dir) } catch { continue }
        foreach ($e in $entries) {
            $fi = $null
            try { $fi = [System.IO.FileInfo]::new($e) } catch { continue }
            $attr = 0
            try { $attr = [int]$fi.Attributes } catch { $attr = 0 }
            if (($attr -band 16) -ne 0) {
                if (($attr -band 1024) -eq 0) { $stack.Push($e) }
                continue
            }
            try { $total += $fi.Length } catch { }
        }
    }
    return [math]::Round($total / 1MB, 0)
}

function Get-Normalized([string]$p) {
    $x = $p.TrimEnd('\')
    return $x.ToLowerInvariant()
}

function Test-InNeverTouch([string]$path, $neverPaths, $denyNames) {
    $n = Get-Normalized $path
    foreach ($np in $neverPaths) {
        $x = Get-Normalized $np
        if ($n -eq $x) { return $np }
        if ($n.StartsWith($x + '\')) { return $np }
    }
    foreach ($seg in $path.Split('\')) {
        foreach ($dn in $denyNames) {
            if ($seg -ieq $dn) { return ('segment:' + $dn) }
        }
    }
    return $null
}

# ---------------- load inputs ----------------

$auditHome = Get-AuditHome
$histDir = Join-Path $auditHome 'history'
if (-not (Test-Path -LiteralPath $histDir)) { New-Item -ItemType Directory -Force -Path $histDir | Out-Null }

$allScans = @()
try {
    $allScans = Get-ChildItem -LiteralPath $histDir -Filter 'scan-*.json' -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending
}
catch { }

if (-not $Snapshot -or $Snapshot.Trim() -eq '') {
    if ($allScans.Count -eq 0) {
        Write-Host 'ERROR no snapshot found. Run scan.ps1 first (or pass -Snapshot).'
        exit 2
    }
    $Snapshot = $allScans[0].FullName
}
if (-not (Test-Path -LiteralPath $Snapshot)) {
    Write-Host ('ERROR snapshot not found: ' + $Snapshot)
    exit 2
}

$snap = Get-Content -LiteralPath $Snapshot -Raw -Encoding UTF8 | ConvertFrom-Json
$rules = Get-Content -LiteralPath $RulesFile -Raw -Encoding UTF8 | ConvertFrom-Json
$never = Get-Content -LiteralPath $NeverTouchFile -Raw -Encoding UTF8 | ConvertFrom-Json

$neverPaths = @()
foreach ($p in $never.exactPaths) { $neverPaths += (Expand-Pattern $p) }
foreach ($p in $never.paths) { $neverPaths += (Expand-Pattern $p) }
$neverPaths = @($neverPaths | Sort-Object -Unique)
$denyNames = @()
if ($never.denyNamePatterns) { $denyNames = @($never.denyNamePatterns) }

# ---------------- evaluate directory rules ----------------

$findings = New-Object System.Collections.Generic.List[object]

# Resolve every rule pattern once, up front. The sizes are then measured in one
# go instead of one directory walk per path - walking the matched paths used to
# be by far the slowest part of analyze (about 90 seconds on a normal C: drive,
# most of it re-walking caches the scan had already measured).
$ruleList = @($rules.rules)
$resolvedByRule = New-Object System.Collections.Generic.List[object]
$wantDirs = New-Object System.Collections.Generic.List[string]
foreach ($rule in $ruleList) {
    $resolved = New-Object System.Collections.Generic.List[object]
    # Two patterns inside one rule can resolve to the very same folder: %TEMP%
    # and %LOCALAPPDATA%\Temp are the same directory on Windows. Both would land
    # in $resolved, and summing them would double the finding's size and its
    # match count - the shipped user-temp rule used to report 3,192 MB for a
    # 1,596 MB Temp folder. Keying on the normalised path counts each folder
    # once, per rule.
    $seenInRule = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($pat in $rule.paths) {
        foreach ($r in (Resolve-Pattern $pat)) {
            if (-not $seenInRule.Add(([string]$r).TrimEnd('\').ToLowerInvariant())) { continue }
            $isFile = $false
            try { $isFile = [System.IO.File]::Exists((Add-Prefix $r)) } catch { $isFile = $false }
            $resolved.Add([pscustomobject]@{ path = $r; isFile = $isFile })
            if (-not $isFile) { $wantDirs.Add($r) }
        }
    }
    $resolvedByRule.Add($resolved)
}

$script:sizeMap = @{}
$sizeSource = 'walk'
$sizeNotes = @()
if ($SizeEngine -ne 'walk' -and $wantDirs.Count -gt 0) {
    $tag = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $listFile = Join-Path ([System.IO.Path]::GetTempPath()) ('diskaudit-targets-' + $tag + '.txt')
    $dsOut = Join-Path ([System.IO.Path]::GetTempPath()) ('diskaudit-dirsizes-' + $tag + '.json')
    try {
        # WriteAllLines needs a real string[], not the Object[] that the pipeline
        # produces; PowerShell reports the mismatch as a binding error otherwise.
        [System.IO.File]::WriteAllLines($listFile, [string[]]@($wantDirs | Sort-Object -Unique), (New-Object System.Text.UTF8Encoding($false)))
        # A child process on purpose: the helper prints its own RESULT line, and
        # anything that leaked into this script's output would be mistaken for the
        # analysis result by whoever parses it. A child also keeps the helper's
        # `exit` codes and its Add-Type compilation from touching this run.
        $dsArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $dirSizeScript,
                    '-PathsFile', $listFile, '-OutFile', $dsOut, '-Engine', $SizeEngine)
        [void](& $psExe @dsArgs 2>&1 | Out-Null)
        if (Test-Path -LiteralPath $dsOut) {
            $ds = Get-Content -LiteralPath $dsOut -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($ds.engine -eq 'mft') {
                foreach ($s in $ds.sizes) {
                    $k = ([string]$s.path).TrimEnd('\').ToLowerInvariant()
                    $sizeMap[$k] = [math]::Round([double]$s.bytes / 1MB, 0)
                }
                $sizeSource = 'mft'
                if ([int]$ds.missing -gt 0) {
                    $sizeNotes += ([string]$ds.missing + ' of ' + [string]$ds.requested + ' matched directories were not in the MFT and were walked instead')
                }
            }
            else {
                $sizeNotes += ('the MFT directory sizer reported engine=' + [string]$ds.engine + ' (' + [string]$ds.reason + '); every path was walked')
            }
        }
        else {
            $sizeNotes += 'the MFT directory sizer produced no output; every path was walked'
        }
    }
    catch {
        $sizeNotes += ('the MFT directory sizer failed: ' + $_.Exception.Message)
    }
    finally {
        Remove-Item -LiteralPath $listFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $dsOut -Force -ErrorAction SilentlyContinue
    }
}
# Anything the MFT map does not cover is walked once and remembered, so a path
# named by several rules is never walked twice.
function Get-PathSizeCached([string]$path, [bool]$isFile) {
    if ($isFile) { return (Get-PathSizeMB $path) }
    $k = $path.TrimEnd('\').ToLowerInvariant()
    if ($script:sizeMap.ContainsKey($k)) { return [int]$script:sizeMap[$k] }
    $mb = Get-PathSizeMB $path
    if ($mb -ge 0) { $script:sizeMap[$k] = $mb }
    return $mb
}

for ($ri = 0; $ri -lt $ruleList.Count; $ri++) {
    $rule = $ruleList[$ri]
    $matches = New-Object System.Collections.Generic.List[object]
    $sum = 0
    foreach ($cand in $resolvedByRule[$ri]) {
        $mb = Get-PathSizeCached $cand.path $cand.isFile
        if ($mb -lt 0) { continue }
        $sum += $mb
        $matches.Add([pscustomobject]@{ path = $cand.path; mb = $mb })
    }
    $matches = @($matches | Sort-Object mb -Descending)
    if ($matches.Count -eq 0) { continue }
    if ($rule.risk -ne 'never' -and $sum -lt $MinFindingMB) { continue }

    $findings.Add([pscustomobject]@{
        id = [string]$rule.id
        label = [string]$rule.label
        category = [string]$rule.category
        risk = [string]$rule.risk
        cleanMode = [string]$rule.cleanMode
        command = [string]$rule.command
        cleanHint = [string]$rule.cleanHint
        why = [string]$rule.why
        mb = $sum
        matchCount = $matches.Count
        matches = $matches
    })
}

# ---------------- evaluate file rules ----------------

$fileList = New-Object System.Collections.Generic.List[object]
$seenPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$fileSources = @()
if ($snap.recentBig) { $fileSources += , $snap.recentBig }
if ($snap.bigFiles) { $fileSources += , $snap.bigFiles }
foreach ($src in $fileSources) {
    foreach ($f in $src) {
        if (-not $f -or -not $f.path) { continue }
        # A file above the big threshold that was also modified recently appears in
        # BOTH arrays. Without de-duplication every file rule total doubles.
        if (-not $seenPaths.Add([string]$f.path)) { continue }
        $fileList.Add([pscustomobject]@{
            path = [string]$f.path
            mb = [int][math]::Round([double]$f.mb)
            mtime = [string]$f.mtime
        })
    }
}

foreach ($fr in $rules.fileRules) {
    $matched = New-Object System.Collections.Generic.List[object]
    $sum = 0
    foreach ($f in $fileList) {
        if ($f.mb -lt [int]$fr.minMB) { continue }
        if ($f.path -match $fr.match) {
            $matched.Add($f)
            $sum += $f.mb
        }
    }
    $matched = @($matched | Sort-Object mb -Descending)
    if ($matched.Count -eq 0) { continue }

    $findings.Add([pscustomobject]@{
        id = [string]$fr.id
        label = [string]$fr.label
        category = [string]$fr.category
        risk = [string]$fr.risk
        cleanMode = 'manual'
        command = ''
        cleanHint = [string]$fr.cleanHint
        why = [string]$fr.why
        mb = $sum
        matchCount = $matched.Count
        matches = @($matched | Select-Object -First 30)
        # The report only needs the biggest 30 names, but the accounting needs
        # every one of them: a rule that matches 200 log files would otherwise
        # project only its first 30. Stripped before the JSON is written.
        allMatches = @($matched)
    })
}

# ---------------- never-touch summary (for the report) ----------------

$neverFindings = New-Object System.Collections.Generic.List[object]

# Sizes for protected paths come from the snapshot buckets instead of a fresh
# filesystem walk. Re-walking C:\Windows\WinSxS here used to add minutes to
# every analyze run for information the scan already collected.
$dirLookup = @{}
foreach ($r in $snap.roots) {
    $rootPrefix = ([string]$r.root).TrimEnd('\')
    foreach ($b in $r.buckets) {
        $full = ($rootPrefix + '\' + [string]$b.path).TrimEnd('\').ToLowerInvariant()
        $mb = [int]$b.mb
        if (-not $dirLookup.ContainsKey($full) -or $dirLookup[$full] -lt $mb) { $dirLookup[$full] = $mb }
    }
}

foreach ($p in $neverPaths) {
    # A bare drive root tells the report nothing useful.
    if ($p -match '^[A-Za-z]:\\?$') { continue }
    $n = $p.TrimEnd('\').ToLowerInvariant()
    $mb = -1
    $source = 'unavailable'
    if ($dirLookup.ContainsKey($n)) { $mb = $dirLookup[$n]; $source = 'exact' }
    else {
        foreach ($k in $dirLookup.Keys) {
            if ($k.StartsWith($n + '\')) {
                if ($dirLookup[$k] -gt $mb) { $mb = $dirLookup[$k] }
            }
        }
        if ($mb -ge 0) { $source = 'descendant' }
    }
    if ($mb -ge 100) {
        $neverFindings.Add([pscustomobject]@{ path = $p; mb = $mb; source = $source })
    }
}

# ---------------- growth vs previous snapshot ----------------

# The two engines do not count the same thing, so a walk snapshot and an MFT
# snapshot of an identical disk differ by a small constant factor:
#   - walk counts a hard-linked file once per directory that holds a name for
#     it (System32\en-US\*.mui are also named under WinSxS, so they are summed
#     twice), which inflates its total.
#   - MFT sums each file record once, but also sees directory entries walked
#     filtering hides (mounted WinSxS\FileMaps), which inflates its dir count.
# Observed on a real C: drive: total -0.6%, files -0.3%, dirs +4%. Deltas below
# 2% are therefore noise when the two snapshots used different engines, and the
# comparison is flagged so the report can say so instead of crying "growth".
$curEngine = 'walk'
if ($snap.engine -and ([string]$snap.engine).Trim() -ne '') { $curEngine = ([string]$snap.engine).Trim().ToLowerInvariant() }
$engineNotes = @()
if ($snap.engineNotes) { $engineNotes = @($snap.engineNotes) }

$prevFile = $null
$prevEngine = ''
$curResolved = (Resolve-Path -LiteralPath $Snapshot).Path
$curSig = Get-RootSignature $snap
foreach ($s in ($allScans | Select-Object -First 20)) {
    if ($s.FullName -eq $curResolved) { continue }
    try { $cand = Get-Content -LiteralPath $s.FullName -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { continue }
    if ((Get-RootSignature $cand) -eq $curSig) {
        $prevFile = $s.FullName
        # Snapshots written before the MFT engine existed carry no engine field.
        $prevEngine = 'walk'
        if ($cand.engine -and ([string]$cand.engine).Trim() -ne '') { $prevEngine = ([string]$cand.engine).Trim().ToLowerInvariant() }
        break
    }
}

$growth = New-Object System.Collections.Generic.List[object]
$prevAt = $null
$grandCur = [int64]0
foreach ($r in @($snap.roots)) { $grandCur += [int64]$r.totalMB }
$grandPrev = [int64]0
if ($prevFile) {
    $prev = Get-Content -LiteralPath $prevFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $prevAt = $prev.scannedAt
    foreach ($r in @($prev.roots)) { $grandPrev += [int64]$r.totalMB }

    $curMap = @{}
    foreach ($r in $snap.roots) {
        foreach ($b in $r.buckets) {
            if ($b.depth -gt 4) { continue }
            $curMap[$b.root + '||' + $b.path] = [int]$b.mb
        }
    }
    $prevMap = @{}
    foreach ($r in $prev.roots) {
        foreach ($b in $r.buckets) {
            if ($b.depth -gt 4) { continue }
            $prevMap[$b.root + '||' + $b.path] = [int]$b.mb
        }
    }
    $keys = @{}
    foreach ($k in $curMap.Keys) { $keys[$k] = 1 }
    foreach ($k in $prevMap.Keys) { $keys[$k] = 1 }
    foreach ($k in $keys.Keys) {
        $c = 0; $p = 0
        if ($curMap.ContainsKey($k)) { $c = $curMap[$k] }
        if ($prevMap.ContainsKey($k)) { $p = $prevMap[$k] }
        $d = $c - $p
        if ($d -ne 0) {
            $growth.Add([pscustomobject]@{ path = $k; mb = $c; prevMB = $p; deltaMB = $d })
        }
    }
    $growth = @($growth | Sort-Object deltaMB -Descending | Select-Object -First $TopGrowth)
}

# ---------------- engine accounting for the comparison ----------------

$totalDeltaMB = [int64]0
if ($prevFile) { $totalDeltaMB = $grandCur - $grandPrev }

$engineMismatch = $false
$noteCode = 'comparable'
$note = 'Both snapshots came from the same engine; per-directory deltas are directly comparable.'
if (-not $prevFile) {
    # An empty growth list here means "nothing to compare against", which is a
    # very different statement from "nothing changed". Say which one it is.
    $noteCode = 'no-previous'
    $note = ('No earlier snapshot with the same root set and depth was found, so the growth list is empty because ' +
             'this is the first scan of its kind, not because the disk stopped changing.')
}
elseif ($prevEngine -ne '' -and $prevEngine -ne $curEngine) {
    $engineMismatch = $true
    $noteCode = 'engine-mismatch'
    $note = ('Previous snapshot used engine=' + $prevEngine + ' but this one used engine=' + $curEngine +
             '. The engines count hard links differently, so absolute totals shift by roughly 1% (walk is higher) ' +
             'and directory counts shift by a few percent. Per-directory deltas still show the direction of change, ' +
             'but anything under about 2% of the directory size is within cross-engine noise and must not be reported as growth.')
}
if ($engineNotes.Count -gt 0) {
    $note = ($note + ' Scan notes: ' + (@($engineNotes) -join ' | '))
}

# ---------------- anomalies ----------------

$anomalies = New-Object System.Collections.Generic.List[object]
$anomCfg = $rules.anomaly

function Test-IsProtected([string]$path) {
    $n = $path.TrimEnd('\').ToLowerInvariant()
    foreach ($pp in $neverPaths) {
        $x = $pp.TrimEnd('\').ToLowerInvariant()
        if ($x -match '^[a-z]:\\?$') { continue }
        if ($n -eq $x -or $n.StartsWith($x + '\')) { return $true }
    }
    return $false
}

foreach ($f in $findings) {
    if ($f.risk -eq 'never') { continue }
    if ($f.mb -ge [int]$anomCfg.cacheDirMB) {
        $anomalies.Add([pscustomobject]@{
            kind = 'cache-dir-too-big'
            path = $f.matches[0].path
            mb = $f.mb
            thresholdMB = [int]$anomCfg.cacheDirMB
            findingId = $f.id
            reasonCode = 'cache-dir-exceeds-threshold'
        })
    }
}
foreach ($r in $snap.roots) {
    foreach ($b in $r.buckets) {
        if ($b.depth -gt 2) { continue }
        if ($b.mb -ge [int]$anomCfg.anyDirMB) {
            $fullPath = ($r.root.TrimEnd('\') + '\' + $b.path)
            # Protected system directories are already covered by the do-not-touch
            # list; reporting them as anomalies is pure noise.
            if (Test-IsProtected $fullPath) { continue }
            $anomalies.Add([pscustomobject]@{
                kind = 'dir-very-large'
                path = $fullPath
                mb = [int]$b.mb
                thresholdMB = [int]$anomCfg.anyDirMB
                findingId = ''
                reasonCode = 'dir-exceeds-threshold'
            })
        }
    }
}

# ---------------- findings must not nest ----------------
#
# Rules are evaluated independently, so two findings can describe the same
# bytes: `huge-log` sizes individual log files that sit inside a directory
# already sized by `ai-cli-sessions`. Both are true statements, but adding them
# together counts that space twice and the "reclaimable" total becomes a number
# no one can cash in.
#
# Fix: a match counts only if no *delete-capable* match from another finding
# contains it. The parent's clean mode is the deciding factor - a delete-dir or
# purge-contents parent really does take the whole subtree with it, so the child
# is already paid for. A manual or command parent does not promise that, so its
# children keep counting (under-reporting is worse than double-reporting: it
# makes the tool promise space it cannot deliver).
$deleteModes = @('delete-dir', 'purge-contents')

# The displayed match list can be truncated (a file rule keeps the top 30 for the
# report), while the money has to be counted on the full list. This returns
# whichever list is authoritative for arithmetic.
function Get-AccountingMatches($f) {
    if ($f.PSObject.Properties['allMatches']) { return @($f.allMatches) }
    return @($f.matches)
}

$acctMatches = New-Object System.Collections.Generic.List[object]
foreach ($f in $findings) {
    foreach ($m in (Get-AccountingMatches $f)) {
        $acctMatches.Add([pscustomobject]@{
            key  = ([string]$f.id + '||' + ([string]$m.path).TrimEnd('\').ToLowerInvariant())
            id   = [string]$f.id
            mode = [string]$f.cleanMode
            norm = ([string]$m.path).TrimEnd('\').ToLowerInvariant()
            mb   = [double]$m.mb
        })
    }
}

$coveredBy = @{}
foreach ($m in $acctMatches) {
    $bestId = ''
    $bestLen = -1
    foreach ($o in $acctMatches) {
        if ($o.key -eq $m.key) { continue }
        # Matches of the same finding were already de-duplicated when the rule
        # was resolved; comparing them here would just subtract a finding from
        # itself.
        if ($o.id -eq $m.id) { continue }
        if ($deleteModes -notcontains $o.mode) { continue }
        if (-not $m.norm.StartsWith($o.norm + '\')) { continue }
        # The tightest containing match wins, so a finding is never credited to
        # a parent that is itself contained in something else.
        if ($o.norm.Length -gt $bestLen) { $bestLen = $o.norm.Length; $bestId = $o.id }
    }
    if ($bestId -ne '') { $coveredBy[$m.key] = $bestId }
}

$overlapMB = 0
$overlapPairs = 0
$overlapEdges = New-Object System.Collections.Generic.List[object]
foreach ($f in $findings) {
    $acct = @(Get-AccountingMatches $f)
    $covMB = 0
    $covAcct = 0
    $parents = @{}
    foreach ($m in $acct) {
        $k = ([string]$f.id + '||' + ([string]$m.path).TrimEnd('\').ToLowerInvariant())
        if ($coveredBy.ContainsKey($k)) {
            $covMB += [double]$m.mb
            $covAcct++
            $pid2 = $coveredBy[$k]
            if (-not $parents.ContainsKey($pid2)) { $parents[$pid2] = 0 }
            $parents[$pid2] = $parents[$pid2] + [double]$m.mb
        }
    }
    # How many of the *displayed* matches are covered. Reporting the accounting
    # count here would print "12 of 3 matches nested" whenever the list is
    # truncated, which reads like a bug.
    $covShown = 0
    foreach ($m in @($f.matches)) {
        $k = ([string]$f.id + '||' + ([string]$m.path).TrimEnd('\').ToLowerInvariant())
        if ($coveredBy.ContainsKey($k)) { $covShown++ }
    }
    $eff = [double]$f.mb - $covMB
    if ($eff -lt 0) { $eff = 0 }
    $f | Add-Member -NotePropertyName effectiveMB -NotePropertyValue ([math]::Round($eff, 0)) -Force
    $f | Add-Member -NotePropertyName coveredMB -NotePropertyValue ([math]::Round($covMB, 0)) -Force
    $f | Add-Member -NotePropertyName coveredCount -NotePropertyValue $covShown -Force
    $f | Add-Member -NotePropertyName coveredBy -NotePropertyValue @($parents.Keys | Sort-Object) -Force
    $f | Add-Member -NotePropertyName subsumed -NotePropertyValue ($covAcct -gt 0 -and $covAcct -eq $acct.Count) -Force
    $overlapMB += $covMB
    $overlapPairs += $covAcct
    foreach ($pn in $parents.Keys) {
        $overlapEdges.Add([pscustomobject]@{
            child = [string]$f.id
            parent = [string]$pn
            mb = [math]::Round($parents[$pn], 0)
        })
    }
}

# ---------------- totals ----------------

# Effective sizes, not raw ones: see the containment pass above.
$safeMB = 0; $cautionMB = 0; $neverMB = 0
foreach ($f in $findings) {
    switch ($f.risk) {
        'safe' { $safeMB += $f.effectiveMB }
        'caution' { $cautionMB += $f.effectiveMB }
        'never' { $neverMB += $f.effectiveMB }
    }
}

# ---------------- volume reconciliation ----------------
#
# Three numbers describe the same disk and they are not supposed to be equal:
#   entry  - one file counted once per directory that holds a name for it
#            (Explorer and the walk engine do this; hard links inflate it)
#   inode  - one file counted once, however many names it has
#   used   - the volume's own counter: allocated clusters, which also include
#            the $MFT, directory index allocations, cluster rounding and
#            anything NTFS keeps outside file data streams
# Publishing only one of them is what made the old report need a footnote.
$inodeTotalMB = [int64]0
$inodeMeasured = $true
$hardLinkEntries = [int64]0
$usedMB = [int64]0
$freeMB = [int64]0
foreach ($r in @($snap.roots)) {
    if ($null -eq $r.totalMBUnique) { $inodeMeasured = $false }
    else { $inodeTotalMB += [int64]$r.totalMBUnique }
    if ($r.mftHardLinkEntries) { $hardLinkEntries += [int64]$r.mftHardLinkEntries }
    $letter = ([string]$r.root).TrimEnd('\').TrimEnd(':').ToUpperInvariant() + ':'
    foreach ($dv in @($snap.drives)) {
        if (([string]$dv.mount).ToUpperInvariant() -eq $letter) {
            $usedMB += [int64]$dv.usedMB
            $freeMB += [int64]$dv.freeMB
            break
        }
    }
}

$reconcileNote = ''
$reconcileCode = 'not-measured'
if ($inodeMeasured) {
    $entryOverInode = $grandCur - $inodeTotalMB
    $inodeOverUsed = $inodeTotalMB - $usedMB
    $reconcileCode = 'inode-measured'
    $rel = 'below'
    $gap = -$inodeOverUsed
    if ($inodeOverUsed -ge 0) { $rel = 'above'; $gap = $inodeOverUsed }
    $reconcileNote = ('entry total is ' + $entryOverInode + ' MB above the inode total: that is hard links counted once per ' +
                      'directory entry (' + $hardLinkEntries + ' extra entries on this volume). The inode total sits ' + $gap +
                      ' MB ' + $rel + ' the volume used counter, because used space also holds the $MFT, directory ' +
                      'index allocations, cluster rounding and VSS shadow storage, none of which lives in a file data stream.')
}
else {
    $reconcileNote = ('the snapshot has no inode total (engine=' + $curEngine + '), so the only file figure available is the ' +
                      'directory-entry total, which double counts hard links.')
}

# ---------------- space projection ----------------
#
# What the volume looks like once the findings are actually gone. Two things
# make a naive `freeMB + safeMB` wrong:
#   1. Attribution must be per volume. A finding on D: must never inflate the
#      projection for C:, and the two drives in one snapshot are usually very
#      different sizes.
#   2. A match that a containing delete-capable parent already takes with it is
#      not paid for twice. That is the same rule the totals use, so the
#      projection and the "reclaimable" headline cannot disagree.
# The result is deliberately labelled an estimate: sizes come from directory
# entries, and a hard-linked file that keeps another name frees nothing when
# its entry is removed. clean.ps1 measures the real number afterwards.
$volSafe = @{}
$volCaution = @{}
foreach ($f in $findings) {
    $isSafe = ($f.risk -eq 'safe')
    if (-not $isSafe -and $f.risk -ne 'caution') { continue }
    foreach ($m in (Get-AccountingMatches $f)) {
        $k = ([string]$f.id + '||' + ([string]$m.path).TrimEnd('\').ToLowerInvariant())
        if ($coveredBy.ContainsKey($k)) { continue }
        $p = [string]$m.path
        if ($p.Length -lt 2 -or $p[1] -ne ':') { continue }
        $letter = $p.Substring(0, 1).ToUpperInvariant() + ':'
        if ($isSafe) {
            if (-not $volSafe.ContainsKey($letter)) { $volSafe[$letter] = [double]0 }
            $volSafe[$letter] = $volSafe[$letter] + [double]$m.mb
        }
        else {
            if (-not $volCaution.ContainsKey($letter)) { $volCaution[$letter] = [double]0 }
            $volCaution[$letter] = $volCaution[$letter] + [double]$m.mb
        }
    }
}

$projections = New-Object System.Collections.Generic.List[object]
$projFreeTotalMB = [int64]0
$projFreeTotalAllMB = [int64]0
$projWarnings = @()
foreach ($dv in @($snap.drives)) {
    $letter = ([string]$dv.mount).ToUpperInvariant()
    $sMb = 0; $cMb = 0
    if ($volSafe.ContainsKey($letter)) { $sMb = $volSafe[$letter] }
    if ($volCaution.ContainsKey($letter)) { $cMb = $volCaution[$letter] }
    $totalD = [double]$dv.totalMB
    $freeD = [double]$dv.freeMB
    if ($totalD -le 0) { continue }

    $afterSafe = $freeD + $sMb
    $afterAll = $freeD + $sMb + $cMb
    # A projection above the volume size would be nonsense; clamp instead of
    # printing a number that cannot exist.
    if ($afterSafe -gt $totalD) { $afterSafe = $totalD }
    if ($afterAll -gt $totalD) { $afterAll = $totalD }

    $freePctNow = [math]::Round(($freeD / $totalD) * 100, 1)
    $freePctSafe = [math]::Round(($afterSafe / $totalD) * 100, 1)
    $freePctAll = [math]::Round(($afterAll / $totalD) * 100, 1)

    # Which free-space marks the safe cleanup would carry the drive back over.
    # 5% is where Windows starts refusing updates and hibernation; 10% is the
    # usual comfortable floor; 20% is where defrag and updates stop complaining.
    $crosses = @()
    foreach ($mark in @(5, 10, 20)) {
        if ($freePctNow -lt $mark -and $freePctSafe -ge $mark) { $crosses += $mark }
    }
    if ($freePctSafe -lt 5) {
        if ($cMb -gt 0) {
            $projWarnings += ($letter + ' stays under 5% free even after every safe item is removed; the caution items are the only way out.')
        }
        else {
            $projWarnings += ($letter + ' stays under 5% free after every safe item is removed and there is nothing left at caution level.')
        }
    }

    $projections.Add([pscustomobject]@{
        mount = $letter
        label = [string]$dv.label
        totalMB = [math]::Round($totalD, 0)
        freeMB = [math]::Round($freeD, 0)
        freePct = $freePctNow
        safeMB = [math]::Round($sMb, 0)
        cautionMB = [math]::Round($cMb, 0)
        # The headline: what you get by clearing everything the tool graded safe.
        afterSafeMB = [math]::Round($afterSafe, 0)
        afterSafePct = $freePctSafe
        # Upper bound only: caution items need a human decision each.
        afterAllMB = [math]::Round($afterAll, 0)
        afterAllPct = $freePctAll
        crossesPct = @($crosses)
    })
    $projFreeTotalMB += [int64]([math]::Round($afterSafe, 0))
    $projFreeTotalAllMB += [int64]([math]::Round($afterAll, 0))
}

# The full match lists existed only for the arithmetic above. Leaving them in
# would double the JSON size and confuse a reader who compares `matches` with
# `matchCount`.
foreach ($f in $findings) {
    if ($f.PSObject.Properties['allMatches']) { $f.PSObject.Properties.Remove('allMatches') }
}

$doc = [pscustomobject]@{
    schema = 1
    analyzedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    snapshot = (Resolve-Path -LiteralPath $Snapshot).Path
    snapshotAt = $snap.scannedAt
    previousSnapshot = $prevFile
    previousAt = $prevAt
    # Whether the growth numbers below may be read literally. See the
    # engine-mismatch note above; the report must honour this flag.
    comparison = [pscustomobject]@{
        engine = $curEngine
        previousEngine = $prevEngine
        engineMismatch = $engineMismatch
        currentTotalMB = $grandCur
        previousTotalMB = $(if ($prevFile) { $grandPrev } else { $null })
        totalDeltaMB = $(if ($prevFile) { $totalDeltaMB } else { $null })
        noteCode = $noteCode
        note = $note
    }
    engine = $curEngine
    engineNotes = @($engineNotes)
    auditHome = $auditHome
    host = $snap.host
    drives = $snap.drives
    rootTotals = @($snap.roots | ForEach-Object { [pscustomobject]@{ root = $_.root; totalMB = $_.totalMB; files = $_.files; totalMBUnique = $_.totalMBUnique; filesUnique = $_.filesUnique } })
    totals = [pscustomobject]@{
        # Effective sizes: a finding contained in a delete-capable parent is not
        # added again. These are the numbers a report may quote as "you can get
        # this much back".
        safeMB = $safeMB
        cautionMB = $cautionMB
        neverMB = $neverMB
        reclaimableMB = $safeMB + $cautionMB
        # How much of the raw per-finding sum was overlapping, so a reader can
        # see the correction instead of having to trust it.
        overlapMB = [math]::Round($overlapMB, 0)
        overlapCount = $overlapPairs
    }
    # "Clear the safe items and this is what free space looks like." Per volume,
    # clamped to the volume size, and never counting a nested match twice.
    projection = [pscustomobject]@{
        # .ToArray(), not @($projections): wrapping a generic List inside a
        # pscustomobject hashtable throws "Argument types do not match" on
        # PowerShell 5.1, and the error points at an unrelated line.
        drives = $projections.ToArray()
        projectedFreeMB = $projFreeTotalMB
        projectedFreeAllMB = $projFreeTotalAllMB
        warnings = @($projWarnings)
        # clean.ps1 sends files to the Recycle Bin on purpose (undo beats disk
        # space), so the bytes only turn into free space once the bin is
        # emptied. Any projection that omits this reads as "instant".
        note = ('Estimate, not a measurement. Sizes come from directory entries, so a hard-linked file that keeps ' +
                'another name frees less than its entry size suggests. Selected items are moved to the Recycle Bin, ' +
                'so the space appears only after the bin is emptied; clean.ps1 reports the measured figure separately.')
    }
    overlap = @($overlapEdges | Sort-Object mb -Descending)
    reconcile = [pscustomobject]@{
        code = $reconcileCode
        entryTotalMB = $grandCur
        inodeTotalMB = $(if ($inodeMeasured) { $inodeTotalMB } else { $null })
        entryOverInodeMB = $(if ($inodeMeasured) { $grandCur - $inodeTotalMB } else { $null })
        volumeUsedMB = $usedMB
        volumeFreeMB = $freeMB
        hardLinkEntries = $hardLinkEntries
        note = $reconcileNote
    }
    findings = @($findings | Sort-Object -Property @{Expression = 'mb'; Descending = $true})
    # `mft` means the finding sizes came out of one $MFT pass, `walk` means every
    # matched path was walked. The two count hard links differently (~1% apart),
    # so this is recorded rather than left implicit.
    sizeSource = $sizeSource
    sizeNotes = @($sizeNotes)
    neverTouch = @($neverFindings | Sort-Object mb -Descending)
    growth = $growth
    anomalies = @($anomalies | Sort-Object mb -Descending)
    topDirs = @($snap.roots | ForEach-Object {
        $r = $_
        $r.buckets | ForEach-Object {
            [pscustomobject]@{
                fullPath = ($r.root.TrimEnd('\') + '\' + $_.path)
                mb = $_.mb
                depth = $_.depth
            }
        }
    } | Sort-Object mb -Descending | Select-Object -First 30)
    bigFiles = @($snap.bigFiles | Select-Object -First 30)
    recentBig = @($snap.recentBig | Select-Object -First 30)
    errorCount = $snap.errorCount
}

if (-not $OutFile -or $OutFile.Trim() -eq '') {
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $OutFile = Join-Path $histDir ('analysis-' + $stamp + '.json')
}
$doc | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutFile -Encoding UTF8

$prevEngineTag = 'none'
if ($prevEngine -ne '') { $prevEngineTag = $prevEngine }
Write-Host ('RESULT ' + $OutFile + ' findings=' + $findings.Count + ' safeMB=' + $safeMB + ' cautionMB=' + $cautionMB + ' growth=' + $growth.Count + ' anomalies=' + $anomalies.Count + ' engine=' + $curEngine + ' prevEngine=' + $prevEngineTag + ' engineMismatch=' + $engineMismatch + ' totalDeltaMB=' + $totalDeltaMB + ' sizeSource=' + $sizeSource + ' overlapMB=' + [math]::Round($overlapMB, 0) + ' reconcile=' + $reconcileCode + ' projFreeMB=' + $projFreeTotalMB)
