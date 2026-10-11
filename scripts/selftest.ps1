#Requires -Version 5.1
<#
  selftest.ps1 - repeatable regression test for the windows-disk-audit skill.

  Runs entirely inside a throwaway temp directory with its own DISK_AUDIT_HOME,
  so it never touches real data or the real history. Each stage runs in a CHILD
  powershell process so the scripts' `exit` codes cannot terminate this session.

  Covers:
    T1 growth comparison against the bundled fixture snapshots
    T2 graceful failure when there is no snapshot at all (first run)
    T3 real read-only scan, size arithmetic checked against a known 3 MB file
    T4 never-touch rejection (System32 must be refused)
    T5 top-level directory under a drive root must be refused
    T6 batch limit (more than MaxBatch items must be refused)
    T7 dry-run deletes nothing
    T8 without -Confirmed it holds
    T9 rule pattern resolver + per-path size measurement
    T10 no script may contain non-ASCII bytes
    T11 file rules read the `path` field and are not double counted
    T12 shipped rule files are structurally valid
    T13 growth comparison only matches snapshots sharing the root set and depth
    T14 the engine a snapshot came from is reported and mismatches are flagged
    T15 MFT engine: compiles, validates its root argument, sizes directories,
        honours -Engine walk and does not change which findings exist
        and agrees with the walker (skipped when the MFT is unavailable)
    T16 a rule whose patterns overlap counts the shared folder only once

  This file MUST stay pure ASCII.
#>
[CmdletBinding()]
param([switch]$KeepTemp)

$ErrorActionPreference = 'Continue'
$skillRoot = Split-Path -Parent $PSScriptRoot
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('windiskaudit-selftest-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$savedHome = $env:DISK_AUDIT_HOME
$auditHome = Join-Path $tmp 'home'
$hist = Join-Path $auditHome 'history'
$cwd = Join-Path $tmp 'cwd'
$junkRoot = Join-Path $tmp 'junk'
$sizeRoot = Join-Path $tmp 'sizetest'
$resRoot = Join-Path $tmp 'resolvetest'
New-Item -ItemType Directory -Force -Path $hist, $cwd, $junkRoot, $sizeRoot, $resRoot | Out-Null
Copy-Item (Join-Path $skillRoot 'fixtures\sample-history\*.json') $hist -Force

$testRules = Join-Path $skillRoot 'fixtures\test-rules.json'

$pass = 0
$fail = 0
$skip = 0
function Check([string]$name, [bool]$ok, [string]$detail) {
    if ($ok) { $script:pass++; Write-Host ('PASS  ' + $name) }
    else { $script:fail++; Write-Host ('FAIL  ' + $name + '  ::  ' + (($detail -replace "\s+", ' ').Trim())) }
}
function Skip([string]$name, [string]$why) {
    $script:skip++; Write-Host ('SKIP  ' + $name + '  ::  ' + (($why -replace "\s+", ' ').Trim()))
}
function Get-Result([string]$out) {
    # analyze and scan both announce themselves with a RESULT line. Prefer the one
    # carrying `findings=`, which only analyze emits, so a helper script's own
    # RESULT line can never be mistaken for the stage result.
    $all = @($out -split "`n" | Where-Object { $_.Trim().StartsWith('RESULT ') })
    $line = $null
    foreach ($c in $all) { if ($c -like '*findings=*') { $line = $c; break } }
    if (-not $line -and $all.Count -gt 0) { $line = $all[0] }
    if ($line) { return $line.Trim() }
    return ''
}
function Invoke-Stage([string]$script, [hashtable]$stageArgs, [string]$envHome) {
    $env:DISK_AUDIT_HOME = $envHome
    $argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $skillRoot ('scripts\' + $script)))
    foreach ($k in $stageArgs.Keys) {
        $argv += ('-' + $k)
        $v = [string]$stageArgs[$k]
        if ($v -ne '') { $argv += $v }
    }
    return (& $ps @argv 2>&1 | Out-String)
}

Push-Location $cwd

# ---- T1 growth comparison (rules neutralized so the test is machine independent) ----
$snapNew = Join-Path $hist 'scan-2026-01-08-09-00-00.json'
$o = Invoke-Stage 'analyze.ps1' @{ Snapshot = $snapNew; RulesFile = $testRules } $auditHome
$r = Get-Result $o
Check 'T1a analyze emits RESULT' ($r -ne '') $o
$anPath = ''
if ($r -ne '') { $anPath = ($r -split ' ')[1] }
Check 'T1b analysis written into DISK_AUDIT_HOME' ($anPath -like ($auditHome + '*')) $anPath
if (Test-Path -LiteralPath $anPath) {
    $an = Get-Content -LiteralPath $anPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $u = $an.growth | Where-Object { $_.path -like '*||Users' } | Select-Object -First 1
    Check 'T1c growth on Users (+4000MB)' ($u -and [int]$u.deltaMB -eq 4000) ('delta=' + $u.deltaMB)
    $al = $an.growth | Where-Object { $_.path -like '*||Users\tester\AppData\Local' } | Select-Object -First 1
    Check 'T1d growth on AppData\Local (+3000MB)' ($al -and [int]$al.deltaMB -eq 3000) ('delta=' + $al.deltaMB)
    $up = $an.growth | Where-Object { [int]$_.deltaMB -gt 0 } | Select-Object -First 1
    Check 'T1e growth sorted descending' ($up -and [int]$up.deltaMB -eq 4000) ('first positive delta=' + $up.deltaMB)
    Check 'T1f previous snapshot recorded' ($an.previousAt -eq '2026-01-01 09:00:00') ('previousAt=' + $an.previousAt)
    Check 'T1g empty rules produce no findings' (@($an.findings).Count -eq 0) ('findings=' + @($an.findings).Count)
    $noisy = @($an.anomalies | Where-Object { $_.kind -eq 'dir-very-large' -and $_.path -like '*Windows' })
    Check 'T1h protected dirs are not reported as anomalies' ($noisy.Count -eq 0) ('noise=' + ($noisy.path -join ','))
}

# ---- T2 no snapshot at all (first run) ----
$emptyHome = Join-Path $tmp 'home-empty'
New-Item -ItemType Directory -Force -Path (Join-Path $emptyHome 'history') | Out-Null
$o2 = Invoke-Stage 'analyze.ps1' @{ RulesFile = $testRules } $emptyHome
Check 'T2 empty history fails gracefully' ($o2 -like '*ERROR no snapshot found*') $o2

# ---- T3 real scan, size arithmetic verified ----
$bytes = New-Object 'byte[]' (3MB)
[System.IO.File]::WriteAllBytes((Join-Path $sizeRoot 'three.bin'), $bytes)
$smallOut = Join-Path $tmp 'scan-small.json'
$o3 = Invoke-Stage 'scan.ps1' @{ Root = $sizeRoot; OutFile = $smallOut; NoProgress = '' } $auditHome
$r3 = Get-Result $o3
Check 'T3a scan emits RESULT' ($r3 -ne '') $o3
if (Test-Path -LiteralPath $smallOut) {
    $d3 = Get-Content -LiteralPath $smallOut -Raw -Encoding UTF8 | ConvertFrom-Json
    Check 'T3b size arithmetic correct (3MB file -> 3MB)' ([int]$d3.roots[0].totalMB -eq 3) ('totalMB=' + $d3.roots[0].totalMB)
    Check 'T3c scan counts the file' ([int]$d3.roots[0].files -eq 1) ('files=' + $d3.roots[0].files)
    Check 'T3d drive info captured' (@($d3.drives).Count -ge 1) 'no drives'
}

# ---- T4 never-touch rejection ----
$planT4 = Join-Path $tmp 'plan-t4.json'
$sys32 = Join-Path $env:SystemRoot 'System32'
[pscustomobject]@{ items = @([pscustomobject]@{ path = $sys32; mode = 'delete-dir'; id = 'x' }) } |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $planT4 -Encoding UTF8
$o4 = Invoke-Stage 'clean.ps1' @{ Plan = $planT4; DryRun = '' } $auditHome
Check 'T4a System32 is rejected' ($o4 -like '*REJECT*System32*') $o4
Check 'T4b nothing accepted' ($o4 -like '*0 item(s) accepted*') $o4

# ---- T5 top-level dir under a drive root is refused ----
$planT5 = Join-Path $tmp 'plan-t5.json'
$topLevel = ($env:SystemDrive + '\windiskaudit-selftest-fake')
[pscustomobject]@{ items = @([pscustomobject]@{ path = $topLevel; mode = 'delete-dir'; id = 'x' }) } |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $planT5 -Encoding UTF8
$o5 = Invoke-Stage 'clean.ps1' @{ Plan = $planT5; DryRun = '' } $auditHome
Check 'T5a drive-root child is rejected' ($o5 -like '*top-level directory*') $o5

# ---- T6 batch limit ----
$junkDirs = @()
for ($i = 1; $i -le 11; $i++) {
    $p = Join-Path $junkRoot ('j' + $i)
    New-Item -ItemType Directory -Force -Path $p | Out-Null
    Set-Content -LiteralPath (Join-Path $p 'f.txt') -Value ('x' * 500) -Encoding UTF8
    $junkDirs += $p
}
$items = @()
foreach ($p in $junkDirs) { $items += [pscustomobject]@{ path = $p; mode = 'delete-dir'; id = 'junk' } }
$planT6 = Join-Path $tmp 'plan-t6.json'
[pscustomobject]@{ items = $items } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $planT6 -Encoding UTF8
$o6 = Invoke-Stage 'clean.ps1' @{ Plan = $planT6; DryRun = '' } $auditHome
Check 'T6a batch limit enforced' ($o6 -like '*exceeds MaxBatch*') $o6
Check 'T6b junk untouched after refusal' ((Test-Path (Join-Path $junkRoot 'j1')) -and (Test-Path (Join-Path $junkRoot 'j11'))) 'a junk dir vanished'

# ---- T7 dry-run deletes nothing ----
$planT7 = Join-Path $tmp 'plan-t7.json'
$items7 = @()
foreach ($p in ($junkDirs | Select-Object -First 2)) { $items7 += [pscustomobject]@{ path = $p; mode = 'delete-dir'; id = 'junk' } }
[pscustomobject]@{ items = $items7 } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $planT7 -Encoding UTF8
$o7 = Invoke-Stage 'clean.ps1' @{ Plan = $planT7; DryRun = '' } $auditHome
Check 'T7a dry-run reports plan' ($o7 -like '*planned reclaim*') $o7
Check 'T7b dry-run deletes nothing' ((Test-Path (Join-Path $junkRoot 'j1')) -and (Test-Path (Join-Path $junkRoot 'j2'))) 'dry-run removed something'

# ---- T8 no -Confirmed means hold ----
$o8 = Invoke-Stage 'clean.ps1' @{ Plan = $planT7 } $auditHome
Check 'T8a without -Confirmed it holds' ($o8 -like '*HOLD*') $o8
Check 'T8b still nothing deleted' (Test-Path (Join-Path $junkRoot 'j1')) 'something got deleted'

# ---- T9 rule resolver + size measurement ----
$alpha = Join-Path $resRoot 'alpha'
$beta = Join-Path $resRoot 'beta'
New-Item -ItemType Directory -Force -Path $alpha, $beta | Out-Null
[System.IO.File]::WriteAllBytes((Join-Path $alpha 'a.bin'), (New-Object 'byte[]' (2MB)))
[System.IO.File]::WriteAllBytes((Join-Path $beta 'b.bin'), (New-Object 'byte[]' (1MB)))
$resRules = Join-Path $tmp 'resolver-rules.json'
$ruleDoc = [pscustomobject]@{
    schema = 1
    rules = @([pscustomobject]@{
        id = 'resolver-probe'; label = 'probe'; category = 'test'; risk = 'safe'
        cleanMode = 'delete-dir'; paths = @($resRoot + '\*'); cleanHint = 'probe'; why = 'probe'
    })
    fileRules = @()
    anomaly = [pscustomobject]@{ cacheDirMB = 5120; anyDirMB = 25600 }
}
$ruleDoc | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resRules -Encoding UTF8
$o9 = Invoke-Stage 'analyze.ps1' @{ Snapshot = $snapNew; RulesFile = $resRules; MinFindingMB = 0 } $auditHome
$r9 = Get-Result $o9
$an9Path = ''
if ($r9 -ne '') { $an9Path = ($r9 -split ' ')[1] }
Check 'T9a resolver produced a finding' ($an9Path -ne '') $o9
if (Test-Path -LiteralPath $an9Path) {
    $an9 = Get-Content -LiteralPath $an9Path -Raw -Encoding UTF8 | ConvertFrom-Json
    $f9 = @($an9.findings)[0]
    Check 'T9b wildcard matched both dirs' ($f9 -and [int]$f9.matchCount -eq 2) ('matchCount=' + $f9.matchCount)
    Check 'T9c measured size is 3MB total' ($f9 -and [int]$f9.mb -eq 3) ('mb=' + $f9.mb)
}

# ---- T11 file rules read the `path` field and must not double count ----
# The same file deliberately appears in both bigFiles and recentBig.
$snapT11 = Join-Path $tmp 'scan-t11.json'
$docT11 = [pscustomobject]@{
    schema = 1; scannedAt = '2026-02-01 10:00:00'; host = 'T'; user = 't'; depth = 1
    thresholds = [pscustomobject]@{ minBigFileMB = 100; recentDays = 45; recentMinMB = 100 }
    drives = @(); roots = @()
    bigFiles = @(
        [pscustomobject]@{ path = 'C:\fake\dir\installer.exe'; mb = 640; mtime = '2026-01-30' },
        [pscustomobject]@{ path = 'C:\fake\dir\app.asar'; mb = 200; mtime = '2026-01-10' }
    )
    recentBig = @([pscustomobject]@{ path = 'C:\fake\dir\installer.exe'; mb = 640; mtime = '2026-01-30 09:00' })
    errorCount = 0
}
$docT11 | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $snapT11 -Encoding UTF8
$rulesT11 = Join-Path $tmp 'filerules-t11.json'
$rlT11 = [pscustomobject]@{
    schema = 1
    rules = @()
    fileRules = @(
        [pscustomobject]@{ id = 'installer-leftover'; label = 'p'; category = 'installer'; risk = 'caution'; match = '\\installer\.exe$'; minMB = 100; cleanHint = 'h'; why = 'w' },
        [pscustomobject]@{ id = 'app-binary'; label = 'p'; category = 'app-runtime'; risk = 'never'; match = '\.asar$'; minMB = 100; cleanHint = 'h'; why = 'w' }
    )
    anomaly = [pscustomobject]@{ cacheDirMB = 5120; anyDirMB = 25600 }
}
$rlT11 | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $rulesT11 -Encoding UTF8
$o11 = Invoke-Stage 'analyze.ps1' @{ Snapshot = $snapT11; RulesFile = $rulesT11; MinFindingMB = 0 } $auditHome
$r11 = Get-Result $o11
Check 'T11a file-rule scan produced no errors' (-not ($o11 -like '*InvokeMethodOnNull*') -and -not ($o11 -like '*Cannot call a method*')) $o11
$an11Path = ''
if ($r11 -ne '') { $an11Path = ($r11 -split ' ')[1] }
if (Test-Path -LiteralPath $an11Path) {
    $an11 = Get-Content -LiteralPath $an11Path -Raw -Encoding UTF8 | ConvertFrom-Json
    $f11 = $an11.findings | Where-Object { $_.id -eq 'installer-leftover' } | Select-Object -First 1
    Check 'T11b fileRule total is not double counted (640, not 1280)' ($f11 -and [int]$f11.mb -eq 640) ('mb=' + $f11.mb)
    Check 'T11c matched path preserved' ($f11 -and $f11.matches[0].path -eq 'C:\fake\dir\installer.exe') ('path=' + $f11.matches[0].path)
    $f11b = $an11.findings | Where-Object { $_.id -eq 'app-binary' } | Select-Object -First 1
    Check 'T11d never-risk file rule still reported' ($f11b -and [int]$f11b.mb -eq 200) ('mb=' + $f11b.mb)
}

# ---- T12 shipped rule files are structurally valid ----
$shippedCaches = Get-Content -LiteralPath (Join-Path $skillRoot 'rules\caches.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$shippedNever = Get-Content -LiteralPath (Join-Path $skillRoot 'rules\never-touch.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$ids = @()
$badRules = @()
foreach ($r in $shippedCaches.rules) {
    $ids += [string]$r.id
    foreach ($fld in @('id', 'label', 'category', 'risk', 'cleanMode', 'why')) {
        if (-not $r.$fld) { $badRules += ($r.id + '.' + $fld) }
    }
    if (@($r.paths).Count -eq 0) { $badRules += ($r.id + '.paths') }
}
Check 'T12a shipped caches.json has rules' (@($shippedCaches.rules).Count -ge 25) ('count=' + @($shippedCaches.rules).Count)
Check 'T12b all rule ids unique' (($ids | Sort-Object -Unique).Count -eq $ids.Count) 'duplicate rule ids'
Check 'T12c every rule has required fields' ($badRules.Count -eq 0) ('missing: ' + ($badRules -join ', '))
Check 'T12d never-touch has exactPaths and paths' ((@($shippedNever.exactPaths).Count -ge 1) -and (@($shippedNever.paths).Count -ge 1)) 'missing arrays'

# ---- T13 growth comparison only accepts a snapshot with the same root set + depth ----
$homeT13 = Join-Path $tmp 'home-t13'
$histT13 = Join-Path $homeT13 'history'
New-Item -ItemType Directory -Force -Path $histT13 | Out-Null
Copy-Item (Join-Path $skillRoot 'fixtures\sample-history\*.json') $histT13 -Force
# a NEWER snapshot from a different drive must never be mistaken for the previous state
$unrelated = [pscustomobject]@{
    schema = 1; scannedAt = '2026-02-01 10:00:00'; host = 'T'; user = 't'; depth = 1
    thresholds = [pscustomobject]@{ minBigFileMB = 100; recentDays = 45; recentMinMB = 100 }
    drives = @(); errorCount = 0; bigFiles = @(); recentBig = @()
    roots = @([pscustomobject]@{ root = 'D:\'; totalMB = 999; files = 1; buckets = @() })
}
$unrelatedPath = Join-Path $histT13 'scan-2026-02-01-10-00-00.json'
$unrelated | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $unrelatedPath -Encoding UTF8
$o13 = Invoke-Stage 'analyze.ps1' @{ Snapshot = (Join-Path $histT13 'scan-2026-01-08-09-00-00.json'); RulesFile = $testRules } $homeT13
$r13 = Get-Result $o13
$an13Path = ''
if ($r13 -ne '') { $an13Path = ($r13 -split ' ')[1] }
if (Test-Path -LiteralPath $an13Path) {
    $an13 = Get-Content -LiteralPath $an13Path -Raw -Encoding UTF8 | ConvertFrom-Json
    Check 'T13a newer unrelated-root snapshot is skipped' ($an13.previousAt -eq '2026-01-01 09:00:00') ('previousAt=' + $an13.previousAt)
    $u13 = $an13.growth | Where-Object { $_.path -like '*||Users' } | Select-Object -First 1
    Check 'T13b growth still computed from the matching snapshot' ($u13 -and [int]$u13.deltaMB -eq 4000) ('delta=' + $u13.deltaMB)
}
# when no snapshot shares the root set, there must be no comparison at all
$homeT13b = Join-Path $tmp 'home-t13b'
$histT13b = Join-Path $homeT13b 'history'
New-Item -ItemType Directory -Force -Path $histT13b | Out-Null
Copy-Item $unrelatedPath $histT13b -Force
Copy-Item (Join-Path $histT13 'scan-2026-01-08-09-00-00.json') $histT13b -Force
$o13b = Invoke-Stage 'analyze.ps1' @{ Snapshot = (Join-Path $histT13b 'scan-2026-01-08-09-00-00.json'); RulesFile = $testRules } $homeT13b
$r13b = Get-Result $o13b
$an13bPath = ''
if ($r13b -ne '') { $an13bPath = ($r13b -split ' ')[1] }
if (Test-Path -LiteralPath $an13bPath) {
    $an13b = Get-Content -LiteralPath $an13bPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Check 'T13c no previous when no snapshot matches the root set' (-not $an13b.previousAt) ('previousAt=' + $an13b.previousAt)
    Check 'T13d no growth rows without a valid previous' (@($an13b.growth).Count -eq 0) ('growth=' + @($an13b.growth).Count)
}

# ---- T14 the engine a snapshot came from is reported, mismatches are flagged ----

$engHome = Join-Path $tmp 'home-engine'
$engHist = Join-Path $engHome 'history'
New-Item -ItemType Directory -Force -Path $engHist | Out-Null

# Snapshots written before the two engines existed carry no engine field at all,
# so "" stands for "legacy, made by the walker".
function New-EngineSnapshot([string]$name, [string]$engine, [string]$when, [int]$mb) {
    $root = [pscustomobject]@{
        root = 'C:\'; totalMB = $mb; files = 5; dirs = 3
        buckets = @([pscustomobject]@{ root = 'C:\'; depth = 1; path = 'Users'; mb = $mb })
    }
    $doc = [pscustomobject]@{
        schema = 1; scannedAt = $when; host = 'T'; user = 't'; depth = 1
        thresholds = [pscustomobject]@{ minBigFileMB = 100; recentDays = 45; recentMinMB = 100 }
        drives = @(); errorCount = 0; bigFiles = @(); recentBig = @()
        roots = @($root)
    }
    if ($engine -ne '') { $doc | Add-Member -NotePropertyName engine -NotePropertyValue $engine }
    $p = Join-Path $engHist $name
    $doc | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $p -Encoding UTF8
    return $p
}

function Get-Analyzed([string]$snapshot) {
    $o = Invoke-Stage 'analyze.ps1' @{ Snapshot = $snapshot; RulesFile = $testRules } $engHome
    $r = Get-Result $o
    if ($r -eq '') { return $null }
    $p = ($r -split ' ')[1]
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    return (Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json)
}

# walk snapshot, then an MFT snapshot on top of it
$null = New-EngineSnapshot 'scan-2026-03-01-10-00-00.json' '' '2026-03-01 10:00:00' 50000
$pCmp = New-EngineSnapshot 'scan-2026-03-02-10-00-00.json' 'mft' '2026-03-02 10:00:00' 50400
$aCmp = Get-Analyzed $pCmp
Check 'T14a mixed engines are flagged as not comparable' ($aCmp -and $aCmp.comparison.engineMismatch -eq $true) ('mismatch=' + $aCmp.comparison.engineMismatch)
Check 'T14b mismatch carries a reason code' ($aCmp -and $aCmp.comparison.noteCode -eq 'engine-mismatch') ('code=' + $aCmp.comparison.noteCode)
Check 'T14c both engines are reported' ($aCmp -and $aCmp.comparison.engine -eq 'mft' -and $aCmp.comparison.previousEngine -eq 'walk') ('cur=' + $aCmp.comparison.engine + ' prev=' + $aCmp.comparison.previousEngine)
Check 'T14d a legacy snapshot reads as the walker' ($aCmp -and $aCmp.comparison.previousEngine -eq 'walk') ('prev=' + $aCmp.comparison.previousEngine)
Check 'T14e the disk wide delta is still reported' ($aCmp -and [int]$aCmp.comparison.totalDeltaMB -eq 400) ('delta=' + $aCmp.comparison.totalDeltaMB)

# two MFT snapshots on top of each other must be comparable
$pSame = New-EngineSnapshot 'scan-2026-03-03-10-00-00.json' 'mft' '2026-03-03 10:00:00' 50900
$aSame = Get-Analyzed $pSame
Check 'T14f same engine stays comparable' ($aSame -and $aSame.comparison.noteCode -eq 'comparable' -and $aSame.comparison.engineMismatch -eq $false) ('code=' + $aSame.comparison.noteCode)
Check 'T14g a same engine delta is still produced' ($aSame -and [int]$aSame.comparison.totalDeltaMB -eq 500) ('delta=' + $aSame.comparison.totalDeltaMB)

# a lone snapshot has nothing to compare against, which is not the same as no change
$engHome2 = Join-Path $tmp 'home-engine2'
$engHist2 = Join-Path $engHome2 'history'
New-Item -ItemType Directory -Force -Path $engHist2 | Out-Null
$pOne = Join-Path $engHist2 'scan-2026-03-04-10-00-00.json'
Copy-Item $pCmp $pOne -Force
$oOne = Invoke-Stage 'analyze.ps1' @{ Snapshot = $pOne; RulesFile = $testRules } $engHome2
$rOne = Get-Result $oOne
if ($rOne -ne '') {
    $aOne = Get-Content -LiteralPath (($rOne -split ' ')[1]) -Raw -Encoding UTF8 | ConvertFrom-Json
    Check 'T14h a lone snapshot reports no-previous' ($aOne.comparison.noteCode -eq 'no-previous') ('code=' + $aOne.comparison.noteCode)
    Check 'T14i a lone snapshot has no growth rows' (@($aOne.growth).Count -eq 0) ('growth=' + @($aOne.growth).Count)
    Check 'T14j a lone snapshot reports no previous total' ($null -eq $aOne.comparison.previousTotalMB) ('prev=' + $aOne.comparison.previousTotalMB)
}

# ---- T15 the MFT engine: compiles, validates arguments, sizes directories ----

$mftOk = $false
$mftWhy = ''
$cs = Join-Path $skillRoot 'scripts\MftScan.cs'
try {
    if (-not ('DiskAudit.MftScanner' -as [type])) { Add-Type -Path $cs -ErrorAction Stop }
    $mftOk = $true
}
catch { $mftWhy = $_.Exception.Message }
Check 'T15a MftScan.cs compiles' $mftOk $mftWhy

if ($mftOk) {
    # a sub-directory is not a volume root
    $badRoot = ''
    try { [void][DiskAudit.MftScanner]::Scan('C:\Windows', 1, 100MB, 100MB, 5, 5) }
    catch { $badRoot = $_.Exception.Message }
    Check 'T15b a non-volume root is refused' ($badRoot -like '*volume root*') ('message=' + $badRoot)
}

# everything below needs administrator rights on an NTFS volume
$isAdmin = $false
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}
catch { }

$dsOut = Join-Path $tmp 'dirsizes.json'
$dsPaths = Join-Path $tmp 'dirsizes-input.txt'
# the 3 MB file written by T3 lives here, so its directory size is known exactly
[System.IO.File]::WriteAllLines($dsPaths, [string[]]@($sizeRoot, (Join-Path $sizeRoot 'no-such-dir-here')), (New-Object System.Text.UTF8Encoding($false)))
$oDs = Invoke-Stage 'dirsizes.ps1' @{ PathsFile = $dsPaths; OutFile = $dsOut; Engine = 'mft' } $auditHome

if (-not $isAdmin) {
    Skip 'T15c MFT dirsizes measures a known directory' 'needs administrator rights'
    Skip 'T15d MFT dirsizes reports missing directories' 'needs administrator rights'
}
elseif (-not (Test-Path -LiteralPath $dsOut)) {
    Check 'T15c MFT dirsizes measures a known directory' $false ('no output; ' + $oDs)
}
else {
    $ds = Get-Content -LiteralPath $dsOut -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($ds.engine -ne 'mft') {
        Skip 'T15c MFT dirsizes measures a known directory' ('engine=' + $ds.engine + ' ' + $ds.reason)
        Skip 'T15d MFT dirsizes reports missing directories' ('engine=' + $ds.engine)
    }
    else {
        $hit = @($ds.sizes | Where-Object { $_.path.TrimEnd('\') -ieq $sizeRoot.TrimEnd('\') })
        $mb = -1
        if ($hit.Count -gt 0) { $mb = [int][math]::Round([double]$hit[0].bytes / 1MB, 0) }
        Check 'T15c MFT dirsizes measures a known directory' ($hit.Count -eq 1 -and $mb -eq 3) ('mb=' + $mb + ' hits=' + $hit.Count)
        Check 'T15d missing directories are left out of the result' ([int]$ds.missing -ge 1 -and [int]$ds.found -eq 1) ('found=' + $ds.found + ' missing=' + $ds.missing)
    }
}

# the opt out must be respected, so the caller can always force walking
$dsOut2 = Join-Path $tmp 'dirsizes-walk.json'
[void](Invoke-Stage 'dirsizes.ps1' @{ PathsFile = $dsPaths; OutFile = $dsOut2; Engine = 'walk' } $auditHome)
if (Test-Path -LiteralPath $dsOut2) {
    $ds2 = Get-Content -LiteralPath $dsOut2 -Raw -Encoding UTF8 | ConvertFrom-Json
    Check 'T15e -Engine walk is honoured' ($ds2.engine -eq 'walk' -and @($ds2.sizes).Count -eq 0) ('engine=' + $ds2.engine)
}
else { Check 'T15e -Engine walk is honoured' $false 'no output file' }

# both size engines must agree on WHICH findings exist, even when the numbers move
$sizeHome = Join-Path $tmp 'home-size'
$sizeHist = Join-Path $sizeHome 'history'
New-Item -ItemType Directory -Force -Path $sizeHist | Out-Null
Copy-Item (Join-Path $skillRoot 'fixtures\sample-history\*.json') $sizeHist -Force
$sizesSeen = @()
foreach ($eng in @('walk', 'mft')) {
    $o = Invoke-Stage 'analyze.ps1' @{ Snapshot = $snapNew; RulesFile = $resRules; MinFindingMB = 0; SizeEngine = $eng } $sizeHome
    $r = Get-Result $o
    $p = ''
    if ($r -ne '') { $p = ($r -split ' ')[1] }
    if (Test-Path -LiteralPath $p) {
        $d = Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json
        $ids = @($d.findings | ForEach-Object { $_.id })
        $sizesSeen += [pscustomobject]@{ engine = $eng; ids = $ids; src = $d.sizeSource }
    }
}
if ($isAdmin) {
    Check 'T15f analyze records which size engine it used' ($sizesSeen.Count -eq 2 -and $sizesSeen[0].src -eq 'walk' -and $sizesSeen[1].src -eq 'mft') ('sources=' + (($sizesSeen | ForEach-Object { $_.src }) -join ','))
}
else {
    Skip 'T15f analyze records which size engine it used' 'needs administrator rights'
}
Check 'T15g the size engine does not change which findings exist' (
    $sizesSeen.Count -eq 2 -and
    (($sizesSeen[0].ids | Sort-Object) -join '|') -eq (($sizesSeen[1].ids | Sort-Object) -join '|')) (
    'walk=' + ($sizesSeen[0].ids -join ',') + ' mft=' + ($sizesSeen[1].ids -join ','))

# ---- T16 one rule must not count the same folder twice ----
# Two different patterns can resolve to the very same directory. The shipped
# user-temp rule does exactly that (%TEMP% and %LOCALAPPDATA%\Temp are the same
# folder on Windows) and used to report twice the folder's real size.
$dupRules = Join-Path $tmp 'dup-rules.json'
# Built outside the array literal on purpose: the comma operator binds tighter
# than + in PowerShell, so @($alpha, $resRoot + '\al*') would parse as three
# elements - $alpha, $resRoot and a literal '\al*' - and quietly measure the
# parent directory too.
$alphaGlob = $resRoot + '\al*'
$dupDoc = [pscustomobject]@{
    schema = 1
    rules = @([pscustomobject]@{
        id = 'dup-path-probe'; label = 'probe'; category = 'test'; risk = 'safe'
        cleanMode = 'delete-dir'
        paths = @($alpha, $alphaGlob)
        cleanHint = 'probe'; why = 'probe'
    })
    fileRules = @()
    anomaly = [pscustomobject]@{ cacheDirMB = 5120; anyDirMB = 25600 }
}
$dupDoc | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $dupRules -Encoding UTF8
$o16 = Invoke-Stage 'analyze.ps1' @{ Snapshot = $snapNew; RulesFile = $dupRules; MinFindingMB = 0 } $auditHome
$r16 = Get-Result $o16
$an16 = ''
if ($r16 -ne '') { $an16 = ($r16 -split ' ')[1] }
Check 'T16a a rule with overlapping patterns produced a finding' ($an16 -ne '') $o16
if (Test-Path -LiteralPath $an16) {
    $d16 = Get-Content -LiteralPath $an16 -Raw -Encoding UTF8 | ConvertFrom-Json
    $f16 = @($d16.findings)[0]
    Check 'T16b the shared folder is counted once (2MB, not 4MB)' ($f16 -and [int]$f16.mb -eq 2) ('mb=' + $f16.mb)
    Check 'T16c matchCount reports the folder once' ($f16 -and [int]$f16.matchCount -eq 1) ('matchCount=' + $f16.matchCount)
}

# The shipped rules must not carry the same trap. T16d runs them against the real
# filesystem and rejects any finding whose matches name one folder twice - that
# would inflate both the finding and the reclaimable total.
$o16b = Invoke-Stage 'analyze.ps1' @{ Snapshot = $snapNew; MinFindingMB = 0 } $auditHome
$r16b = Get-Result $o16b
$an16b = ''
if ($r16b -ne '') { $an16b = ($r16b -split ' ')[1] }
if (Test-Path -LiteralPath $an16b) {
    $d16b = Get-Content -LiteralPath $an16b -Raw -Encoding UTF8 | ConvertFrom-Json
    $dupes = @()
    foreach ($fx in $d16b.findings) {
        $keys = @($fx.matches | ForEach-Object { ([string]$_.path).TrimEnd('\').ToLowerInvariant() })
        if (@($keys | Sort-Object -Unique).Count -ne $keys.Count) { $dupes += $fx.id }
    }
    Check 'T16d no shipped finding counts one folder twice' ($dupes.Count -eq 0) ('duplicated in: ' + ($dupes -join ','))
    Write-Host ('      (T16d checked ' + @($d16b.findings).Count + ' findings from the shipped rules)')
}
else {
    Check 'T16d no shipped finding counts one folder twice' $false 'no analysis output'
}

# ---- T10 ASCII guard ----
$bad = @()
foreach ($name in @('scan.ps1', 'analyze.ps1', 'clean.ps1', 'selftest.ps1', 'dirsizes.ps1')) {
    $p = Join-Path $skillRoot ('scripts\' + $name)
    $b = [System.IO.File]::ReadAllBytes($p)
    foreach ($x in $b) { if ($x -gt 127) { $bad += $name; break } }
}
Check 'T10 scripts contain no non-ASCII bytes' ($bad.Count -eq 0) ('non-ascii in: ' + ($bad -join ','))

Pop-Location

# Invoke-Stage sets a process level env var; do not leak it to the caller.
$env:DISK_AUDIT_HOME = $savedHome

Write-Host ''
Write-Host ('SELFTEST pass=' + $pass + ' fail=' + $fail + ' skip=' + $skip + ' temp=' + $tmp)
if ($fail -gt 0) { Write-Host 'RESULT-FAIL' } else { Write-Host 'RESULT-PASS' }
if (-not $KeepTemp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 }
