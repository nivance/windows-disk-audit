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

foreach ($a in $accepted) {
    $before = Get-PathSizeMB $a.path
    if ($before -lt 0) { $before = 0 }
    $ok = $true
    $err = ''

    try {
        if ($a.mode -eq 'purge-contents') {
            $kids = [System.IO.Directory]::GetFileSystemEntries((Add-Prefix $a.path))
            foreach ($k in $kids) {
                $rc = [RecycleBin]::Delete($k)
                if ($rc -ne 0) { $ok = $false; $err = ('SHFileOperation rc=' + $rc); break }
            }
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

    $after = Get-PathSizeMB $a.path
    if ($after -lt 0) { $after = 0 }
    $gained = $before - $after
    if ($gained -lt 0) { $gained = 0 }
    if ($ok) { $freed += $gained } else { $failed++ }

    $results.Add([pscustomobject]@{
        path = $a.path
        id = $a.id
        mode = $a.mode
        beforeMB = $before
        afterMB = $after
        freedMB = $gained
        ok = $ok
        error = $err
    })
}

$auditHome = Get-AuditHome
if (-not $OutFile -or $OutFile.Trim() -eq '') {
    $hist = Join-Path $auditHome 'history'
    if (-not (Test-Path -LiteralPath $hist)) { New-Item -ItemType Directory -Force -Path $hist | Out-Null }
    $OutFile = Join-Path $hist ('clean-' + (Get-Date).ToString('yyyyMMdd-HHmmss') + '.json')
}

$doc = [pscustomobject]@{
    schema = 1
    cleanedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    dryRun = $false
    freedMB = [math]::Round($freed, 0)
    failedCount = $failed
    rejected = @($rejected)
    results = @($results)
}
$doc | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutFile -Encoding UTF8

Write-Host ('RESULT ' + $OutFile + ' freedMB=' + [math]::Round($freed, 0) + ' ok=' + ($results.Count - $failed) + ' failed=' + $failed)
Write-Host 'Reminder: items were moved to the Recycle Bin, not erased. Empty it once you are satisfied.'
