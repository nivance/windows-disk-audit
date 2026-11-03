#Requires -Version 5.1
<#
  clean.ps1 - move user-approved items to the Recycle Bin.

  Safety model (all mandatory, cannot be relaxed by parameters):
    1. Only paths listed explicitly in a plan (or a named finding) are touched.
    2. Every path is validated against rules\never-touch.json and refused if inside.
    3. Drive roots are always refused.
    4. At most -MaxBatch (default 10) items per run.
    5. Nothing is deleted unless -Confirmed is passed. -DryRun always wins.
    6. Deletion goes through SHFileOperation with FOF_ALLOWUNDO, i.e. Recycle Bin.
       No rm / del / rmdir is ever used.

  This file MUST stay pure ASCII (PowerShell 5.1 parses non-BOM .ps1 as ANSI).
#>
[CmdletBinding()]
param(
    [string]$Plan = '',
    [string]$Analysis = '',
    [string[]]$FindingIds = @(),
    [string]$NeverTouchFile = '',
    [string]$OutFile = '',
    [int]$MaxBatch = 10,
    [switch]$DryRun,
    [switch]$Confirmed
)

$ErrorActionPreference = 'Continue'
$script:Prefix = '\\?\'
$skillRoot = Split-Path -Parent $PSScriptRoot
if (-not $NeverTouchFile -or $NeverTouchFile.Trim() -eq '') { $NeverTouchFile = Join-Path $skillRoot 'rules\never-touch.json' }

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RecycleBin {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHFILEOPSTRUCT {
        public IntPtr hwnd;
        public uint wFunc;
        public string pFrom;
        public string pTo;
        public ushort fFlags;
        public bool fAnyOperationsAborted;
        public IntPtr hNameMappings;
        public string lpszProgressTitle;
    }
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHFileOperation(ref SHFILEOPSTRUCT lpFileOp);

    public static int Delete(string path) {
        // SHFileOperation rejects the \\?\ long-path prefix with DE_INVALIDFILES
        // (rc=124). The prefix is only for the Win32 file APIs, so strip it here
        // and let the shell see the ordinary path it expects.
        if (path != null && path.StartsWith("\\\\?\\")) path = path.Substring(4);
        SHFILEOPSTRUCT fs = new SHFILEOPSTRUCT();
        fs.wFunc = 0x0003;
        fs.pFrom = path + "\0\0";
        fs.pTo = null;
        fs.fFlags = 0x0004 | 0x0010 | 0x0040 | 0x0200 | 0x0400;
        fs.hwnd = IntPtr.Zero;
        return SHFileOperation(ref fs);
    }
}
'@ -ErrorAction SilentlyContinue

function Get-AuditHome {
    if ($env:DISK_AUDIT_HOME -and $env:DISK_AUDIT_HOME.Trim() -ne '') { return $env:DISK_AUDIT_HOME.Trim() }
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

function Expand-Pattern([string]$p) {
    $out = $p
    foreach ($m in [regex]::Matches($p, '%([^%]+)%')) {
        $name = $m.Groups[1].Value
        $v = [System.Environment]::GetEnvironmentVariable($name)
        if ($v) { $out = $out.Replace($m.Value, $v) }
    }
    return $out
}

function Get-PathSizeMB([string]$path) {
    $full = Add-Prefix $path
    if ([System.IO.File]::Exists($full)) {
        try { return [math]::Round(([System.IO.FileInfo]::new($full)).Length / 1MB, 1) } catch { return 0 }
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
            if (($attr -band 16) -ne 0) { if (($attr -band 1024) -eq 0) { $stack.Push($e) }; continue }
            try { $total += $fi.Length } catch { }
        }
    }
    return [math]::Round($total / 1MB, 1)
}

# Free space of the volume that holds a path. This is the only figure that
# cannot be fooled by the filesystem: the per-item before/after measurement says
# how much left the folder, but moving a folder to the Recycle Bin frees nothing
# until the bin is emptied, and NTFS updates a record's size lazily on top of
# that. Comparing the volume counter before and after is what tells the truth.
function Get-VolumeFreeMB([string]$p) {
    if (-not $p) { return [int64]-1 }
    $m = [regex]::Match($p, '^([A-Za-z]:)')
    if (-not $m.Success) { return [int64]-1 }
    try {
        $di = New-Object System.IO.DriveInfo($m.Groups[1].Value)
        return [int64][math]::Round($di.AvailableFreeSpace / 1MB, 0)
    }
    catch { return [int64]-1 }
}

function Test-IsDriveRoot([string]$p) {
    $t = $p.TrimEnd('\')
    if ($t.Length -le 2 -and $t.EndsWith(':')) { return $true }
    if ($t -match '^[A-Za-z]:$') { return $true }
    return $false
}

function Test-InNeverTouch([string]$path, $exact, $prefix, $denyNames, $d1Allow) {
    $n = $path.TrimEnd('\').ToLowerInvariant()

    foreach ($ep in $exact) {
        if ($n -eq $ep.TrimEnd('\').ToLowerInvariant()) { return ('exactly matches protected entry: ' + $ep) }
    }
    foreach ($pp in $prefix) {
        $x = $pp.TrimEnd('\').ToLowerInvariant()
        if ($n -eq $x) { return ('is a protected directory: ' + $pp) }
        if ($n.StartsWith($x + '\')) { return ('is inside protected entry: ' + $pp) }
    }

    # Anything sitting directly under a drive root is refused unless explicitly allowlisted.
    if ($n -match '^[a-z]:\\[^\\]+$') {
        $allowed = $false
        foreach ($a in $d1Allow) {
            if ($n -eq $a.TrimEnd('\').ToLowerInvariant()) { $allowed = $true; break }
        }
        if (-not $allowed) { return 'is a top-level directory directly under a drive root' }
    }

    foreach ($seg in $path.Split('\')) {
        foreach ($dn in $denyNames) { if ($seg -ieq $dn) { return ('contains protected segment: ' + $dn) } }
    }
    return $null
}

# ---------------- build the item list ----------------

$items = New-Object System.Collections.Generic.List[object]

if ($Plan -and $Plan.Trim() -ne '') {
    if (-not (Test-Path -LiteralPath $Plan)) { Write-Host ('ERROR plan not found: ' + $Plan); exit 2 }
    $doc = Get-Content -LiteralPath $Plan -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($i in $doc.items) {
        $items.Add([pscustomobject]@{ path = [string]$i.path; mode = [string]$i.mode; id = [string]$i.id })
    }
}
elseif ($Analysis -and $Analysis.Trim() -ne '' -and $FindingIds.Count -gt 0) {
    if (-not (Test-Path -LiteralPath $Analysis)) { Write-Host ('ERROR analysis not found: ' + $Analysis); exit 2 }
    $an = Get-Content -LiteralPath $Analysis -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($id in $FindingIds) {
        $f = $an.findings | Where-Object { $_.id -eq $id }
        if (-not $f) { Write-Host ('WARN unknown finding id: ' + $id); continue }
        if ($f.risk -eq 'never') { Write-Host ('REFUSE finding marked never: ' + $id); continue }
        if ($f.cleanMode -eq 'command' -or $f.cleanMode -eq 'manual') {
            Write-Host ('SKIP ' + $id + ' requires ' + $f.cleanMode + ': ' + $f.command)
            continue
        }
        foreach ($m in $f.matches) {
            $items.Add([pscustomobject]@{ path = [string]$m.path; mode = [string]$f.cleanMode; id = [string]$id })
        }
    }
}
else {
    Write-Host 'ERROR nothing to do. Pass -Plan <file>, or -Analysis <file> -FindingIds id1,id2'
    Write-Host 'Refusing to run without an explicit item list.'
    exit 2
}

# ---------------- validate ----------------

$never = Get-Content -LiteralPath $NeverTouchFile -Raw -Encoding UTF8 | ConvertFrom-Json
$neverExact = @()
foreach ($p in $never.exactPaths) { $neverExact += (Expand-Pattern $p) }
$neverPaths = @()
foreach ($p in $never.paths) { $neverPaths += (Expand-Pattern $p) }
$neverD1Allow = @()
if ($never.depth1Allow) { foreach ($p in $never.depth1Allow) { $neverD1Allow += (Expand-Pattern $p) } }
$denyNames = @()
if ($never.denyNamePatterns) { $denyNames = @($never.denyNamePatterns) }

$rejected = New-Object System.Collections.Generic.List[object]
$accepted = New-Object System.Collections.Generic.List[object]

foreach ($it in $items) {
    $p = $it.path
    if (-not $p -or $p.Trim() -eq '') { continue }
    if (Test-IsDriveRoot $p) { $rejected.Add([pscustomobject]@{ path = $p; reason = 'drive root is never allowed' }); continue }
    if ($it.mode -ne 'delete-dir' -and $it.mode -ne 'purge-contents') {
        $rejected.Add([pscustomobject]@{ path = $p; reason = ('unsupported mode: ' + [string]$it.mode) }); continue
    }
    $why = Test-InNeverTouch $p $neverExact $neverPaths $denyNames $neverD1Allow
    if ($why) { $rejected.Add([pscustomobject]@{ path = $p; reason = $why }); continue }
    $full = Add-Prefix $p
    if (-not ([System.IO.Directory]::Exists($full) -or [System.IO.File]::Exists($full))) {
        $rejected.Add([pscustomobject]@{ path = $p; reason = 'does not exist' }); continue
    }
    if ($it.mode -eq 'purge-contents' -and -not [System.IO.Directory]::Exists($full)) {
        $rejected.Add([pscustomobject]@{ path = $p; reason = 'purge-contents requires a directory' }); continue
    }
    $accepted.Add($it)
}

if ($accepted.Count -gt $MaxBatch) {
    Write-Host ('ERROR ' + $accepted.Count + ' items exceeds MaxBatch ' + $MaxBatch + '. Split into smaller batches.')
    Write-Host 'Nothing was deleted.'
    exit 3
}

# ---------------- report plan ----------------

Write-Host ('--- plan: ' + $accepted.Count + ' item(s) accepted, ' + $rejected.Count + ' rejected ---')
foreach ($r in $rejected) { Write-Host ('REJECT ' + $r.path + '  <- ' + $r.reason) }
$planTotal = 0
foreach ($a in $accepted) {
    $mb = Get-PathSizeMB $a.path
    if ($mb -lt 0) { $mb = 0 }
    $a | Add-Member -NotePropertyName mb -NotePropertyValue $mb -Force
    $planTotal += $mb
    Write-Host ('ACCEPT [' + $a.mode + '] ' + [math]::Round($mb, 0) + ' MB  ' + $a.path)
}
Write-Host ('--- planned reclaim: ' + [math]::Round($planTotal, 0) + ' MB ---')

if ($DryRun) {
    Write-Host 'DRY-RUN: nothing was deleted.'
    exit 0
}

if (-not $Confirmed) {
    Write-Host 'HOLD: -Confirmed not supplied, so nothing was deleted.'
    Write-Host 'Show the ACCEPT list above to the user and get explicit approval, then re-run with -Confirmed.'
    exit 4
}

# ---------------- execute ----------------

$results = New-Object System.Collections.Generic.List[object]
$freed = 0
$failed = 0
$verifiedMB = 0
$verifiedCount = 0
$stillThere = 0

# Volume free space around the whole run, per drive touched.
$freeBefore = @{}
foreach ($a in $accepted) {
    $dl = ''
    $mm = [regex]::Match($a.path, '^([A-Za-z]:)')
    if ($mm.Success) { $dl = $mm.Groups[1].Value.ToUpperInvariant() }
    if ($dl -ne '' -and -not $freeBefore.ContainsKey($dl)) { $freeBefore[$dl] = Get-VolumeFreeMB $a.path }
}

foreach ($a in $accepted) {
    $before = Get-PathSizeMB $a.path
    if ($before -lt 0) { $before = 0 }
    $ok = $true
    $err = ''
    $shellBudget = 259
    if ((Add-Prefix $a.path).Length -gt $shellBudget) {
        $ok = $false
        $err = 'path exceeds MAX_PATH; the shell recycle API cannot move it (delete it by hand)'
    }
    else {
        try {
            if ($a.mode -eq 'purge-contents') {
                # A live directory (Temp especially) is being written while we
                # enumerate it, so entries can vanish between the listing and the
                # delete. rc=2 means exactly that - already gone, which is the
                # goal - so it is a skip, not a failure. Other errors are logged
                # but do not abort the run: one locked file should not keep the
                # remaining entries from moving.
                $kids = [System.IO.Directory]::GetFileSystemEntries((Add-Prefix $a.path))
                $errCount = 0
                foreach ($k in $kids) {
                    $rc = [RecycleBin]::Delete($k)
                    if ($rc -eq 2) { continue }
                    if ($rc -ne 0) {
                        $errCount++
                        if ($errCount -le 5) {
                            $err = ('SHFileOperation rc=' + $rc + ' on ' + [System.IO.Path]::GetFileName($k))
                        }
                    }
                }
                if ($errCount -gt 5) { $err = ($err + ' (+ ' + ($errCount - 5) + ' more skipped)') }
                if ($errCount -gt 0) { $ok = $false }
            }
            else {
                $rc = [RecycleBin]::Delete((Add-Prefix $a.path))
                if ($rc -ne 0) { $ok = $false; $err = ('SHFileOperation rc=' + $rc) }
            }
        }
        catch {
            $ok = $false
            $err = $_.Exception.Message
        }
    }

    $after = Get-PathSizeMB $a.path
    if ($after -lt 0) { $after = 0 }
    $gained = $before - $after
    if ($gained -lt 0) { $gained = 0 }
    if ($ok) { $freed += $gained } else { $failed++ }

    # Re-check the path instead of trusting the return code. The shell API can
    # report an error after the item has already moved (it refreshes a source
    # path that no longer exists), and it can also report success while a locked
    # file refuses to budge. What the path looks like now is the only evidence.
    $stillExists = Test-Path -LiteralPath (Add-Prefix $a.path)
    $existsAfter = $stillExists
    if ($a.mode -eq 'purge-contents' -and $stillExists) {
        $left = 0
        try { $left = @([System.IO.Directory]::GetFileSystemEntries((Add-Prefix $a.path))).Count } catch { $left = -1 }
        $existsAfter = ($left -ne 0)
    }
    $verified = ($ok -and -not $existsAfter)
    if ($verified) {
        $verifiedMB += $gained
        $verifiedCount++
    }
    elseif ($stillExists) { $stillThere++ }

    $results.Add([pscustomobject]@{
        path = $a.path
        id = $a.id
        mode = $a.mode
        beforeMB = $before
        afterMB = $after
        freedMB = $gained
        ok = $ok
        existsAfter = $existsAfter
        verified = $verified
        error = $err
    })
}

# Volume-level second opinion. Moving something to the Recycle Bin relocates it
# inside the same volume, so free space is expected NOT to move by the amount
# that left the folder. A positive delta here means the shell really did erase
# something (permanent delete, or a bin purge racing with this run).
$volumeReclaimed = [int64]0
$volumeKnown = $false
$freeAfter = @{}
foreach ($dl in $freeBefore.Keys) {
    foreach ($a in $accepted) {
        if ([string]$a.path -match ('^' + [regex]::Escape($dl))) { $freeAfter[$dl] = Get-VolumeFreeMB $a.path; break }
    }
    if ($freeAfter.ContainsKey($dl) -and $freeBefore[$dl] -ge 0 -and $freeAfter[$dl] -ge 0) {
        $volumeReclaimed += ($freeAfter[$dl] - $freeBefore[$dl])
        $volumeKnown = $true
    }
}

$binNote = ('Space is only returned to the volume once the Recycle Bin is emptied: ' +
            'the items above moved into it, they were not erased. Per-item freedMB measures ' +
            'what left each folder; volumeReclaimedMB measures what the volume actually gained, ' +
            'so the two only match after a bin purge. Run Clear-RecycleBin -Force (or right-click ' +
            'Empty Recycle Bin) and the space appears immediately. A scan started within a few ' +
            'seconds of a clean can still read pre-delete sizes, because NTFS writes record ' +
            'updates back lazily.')

$auditHome = Get-AuditHome
if (-not $OutFile -or $OutFile.Trim() -eq '') {
    $hist = Join-Path $auditHome 'history'
    if (-not (Test-Path -LiteralPath $hist)) { New-Item -ItemType Directory -Force -Path $hist | Out-Null }
    $OutFile = Join-Path $hist ('clean-' + (Get-Date).ToString('yyyyMMdd-HHmmss') + '.json')
}

$fbSum = [int64]0
$faSum = [int64]0
foreach ($dl in $freeBefore.Keys) {
    if ($freeBefore[$dl] -ge 0) { $fbSum += $freeBefore[$dl] }
    if ($freeAfter.ContainsKey($dl) -and $freeAfter[$dl] -ge 0) { $faSum += $freeAfter[$dl] }
}
$unverified = @($results | Where-Object { -not $_.verified }).Count

# Assigning this outside the object literal on purpose: Windows PowerShell 5.1
# throws a bare "parameter type mismatch" ArgumentException when an inline
# $(if ...) expression that can yield $null is used as a member value.
$volReclaim = $null
if ($volumeKnown) { $volReclaim = [int64]$volumeReclaimed }

$cleanDoc = [pscustomobject]@{
    schema = 2
    cleanedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    dryRun = $false
    # How much left the listed folders. This is NOT how much the disk gained.
    movedToBinMB = [math]::Round($freed, 0)
    freedMB = [math]::Round($freed, 0)
    # The part of the above that a re-check could confirm.
    verifiedMB = [math]::Round($verifiedMB, 0)
    verifiedCount = $verifiedCount
    unverifiedCount = $unverified
    # Volume counter around the run, and what it actually gained.
    volumeFreeBeforeMB = $fbSum
    volumeFreeAfterMB = $faSum
    volumeReclaimedMB = $volReclaim
    note = $binNote
    failedCount = $failed
    # .ToArray() rather than @($list): on Windows PowerShell 5.1 wrapping a
    # generic List in @() *inside a hashtable literal* throws a bare
    # "parameter type mismatch" ArgumentException, empty list included. This
    # silently killed the audit file for the whole first release of this script.
    rejected = $rejected.ToArray()
    results = $results.ToArray()
}
try {
    $cleanDoc | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutFile -Encoding UTF8
}
catch {
    Write-Host ('ERROR the audit file could not be written: ' + $_.Exception.Message)
    Write-Host 'The deletions above did happen. Do not re-run this plan blindly.'
    exit 6
}

Write-Host ('RESULT ' + $OutFile + ' freedMB=' + [math]::Round($freed, 0) + ' ok=' + ($results.Count - $failed) + ' failed=' + $failed + ' verified=' + $verifiedCount + '/' + $results.Count + ' volumeReclaimedMB=' + $(if ($volumeKnown) { $volumeReclaimed } else { 'unknown' }))
Write-Host 'Reminder: items were moved to the Recycle Bin, not erased. Empty it once you are satisfied - only then does the space come back.'
