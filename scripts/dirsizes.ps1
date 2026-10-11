#Requires -Version 5.1
<#
  dirsizes.ps1 - measure a caller supplied list of directories in a single pass.

  analyze.ps1 needs the size of the rule paths it matched. Walking each of them
  separately costs about 90 seconds on an ordinary C: drive, and most of that is
  spent re-walking caches that were already measured during the scan. Parsing
  $MFT once and reading the subtree totals out of that same pass costs a couple
  of seconds instead.

  The MFT is only used when it is available (administrator rights, NTFS volume);
  otherwise this reports engine=none and the caller falls back to walking, which
  is slower but needs nothing.

  Output (UTF-8, no BOM): { engine, seconds, requested, found, missing, sizes: [ {path, bytes, files, dirs} ] }

  This file MUST stay pure ASCII. PowerShell 5.1 parses a non-BOM .ps1 as ANSI.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PathsFile,
    [string]$OutFile = '',
    [ValidateSet('auto', 'mft', 'walk')]
    [string]$Engine = 'auto'
)

$ErrorActionPreference = 'Continue'
$skillRoot = Split-Path -Parent $PSScriptRoot

function New-EmptyResult([string]$engine, [string]$reason, [int]$requested) {
    return [pscustomobject]@{
        engine = $engine
        reason = $reason
        seconds = 0
        requested = $requested
        found = 0
        missing = $requested
        sizes = @()
    }
}

function Write-Doc($doc, [string]$path) {
    [System.IO.File]::WriteAllText($path, ($doc | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
}

if (-not (Test-Path -LiteralPath $PathsFile)) {
    Write-Host ('ERROR path list not found: ' + $PathsFile)
    exit 2
}

# ---- collect the wanted directories ----

$paths = New-Object System.Collections.Generic.List[string]
foreach ($line in [System.IO.File]::ReadAllLines($PathsFile)) {
    $t = $line.Trim()
    if ($t -eq '' -or $t.StartsWith('#')) { continue }
    if ($t.StartsWith('\\?\')) { $t = $t.Substring(4) }
    if ($t.StartsWith('\\')) { continue }
    if ($t.Length -lt 3 -or $t[1] -ne ':') { continue }
    $t = $t.TrimEnd('\')
    if ($t.Length -lt 2) { continue }
    if ($t.Length -eq 2) { $t = $t + '\' }
    $paths.Add($t)
}
$paths = @($paths | Sort-Object -Unique)
$requested = $paths.Count

$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
if (-not $OutFile -or $OutFile.Trim() -eq '') {
    $OutFile = Join-Path ([System.IO.Path]::GetTempPath()) ('dirsizes-' + $stamp + '.json')
}

if ($requested -eq 0) {
    Write-Doc (New-EmptyResult 'none' 'no directories requested' 0) $OutFile
    Write-Host ('RESULT ' + $OutFile + ' engine=none requested=0 found=0')
    exit 0
}

if ($Engine -eq 'walk') {
    Write-Doc (New-EmptyResult 'walk' 'disabled by the caller' $requested) $OutFile
    Write-Host ('RESULT ' + $OutFile + ' engine=walk requested=' + $requested + ' found=0')
    exit 0
}

# ---- compile the parser ----

$cs = Join-Path $PSScriptRoot 'MftScan.cs'
if (-not (Test-Path -LiteralPath $cs)) {
    Write-Doc (New-EmptyResult 'none' 'MftScan.cs is missing' $requested) $OutFile
    Write-Host ('RESULT ' + $OutFile + ' engine=none requested=' + $requested + ' found=0 reason=no-source')
    exit 0
}
try {
    if (-not ('DiskAudit.MftScanner' -as [type])) { Add-Type -Path $cs -ErrorAction Stop }
}
catch {
    Write-Doc (New-EmptyResult 'none' ('could not compile the MFT parser: ' + $_.Exception.Message) $requested) $OutFile
    Write-Host ('RESULT ' + $OutFile + ' engine=none requested=' + $requested + ' found=0 reason=compile')
    exit 0
}

# ---- one pass per volume ----

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$sizes = New-Object System.Collections.Generic.List[object]
$reason = ''
$buckets = @{}
foreach ($p in $paths) {
    $letter = $p.Substring(0, 1).ToUpperInvariant()
    if (-not $buckets.ContainsKey($letter)) { $buckets[$letter] = New-Object System.Collections.Generic.List[string] }
    $buckets[$letter].Add($p)
}

$engineUsed = 'mft'
foreach ($letter in ($buckets.Keys | Sort-Object)) {
    $targets = $buckets[$letter].ToArray()
    try {
        $r = [DiskAudit.MftScanner]::Scan($letter, 0, [long]::MaxValue, [long]::MaxValue, 0, 0, $targets)
    }
    catch {
        $engineUsed = 'none'
        $reason = ('MFT unavailable on ' + $letter + ': ' + $_.Exception.Message)
        break
    }
    foreach ($t in $r.TargetSizes) {
        $sizes.Add([pscustomobject]@{
            path  = [string]$t.Path
            bytes = [long]$t.Bytes
            files = [long]$t.Files
            dirs  = [long]$t.Dirs
        })
    }
}
$sw.Stop()

$maxSeconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
$found = $sizes.Count
if ($engineUsed -eq 'mft' -and $found -eq 0) {
    $engineUsed = 'none'
    $reason = 'the volume was parsed but none of the requested directories exist'
}

$doc = [pscustomobject]@{
    engine = $engineUsed
    reason = $reason
    seconds = $maxSeconds
    requested = $requested
    found = $found
    missing = $requested - $found
    # .ToArray() rather than @($sizes): wrapping a generic List in @() inside a
    # hashtable literal makes the PSCustomObject conversion fail with a bare
    # "parameter type mismatch" ArgumentException on Windows PowerShell 5.1.
    sizes = $sizes.ToArray()
}
Write-Doc $doc $OutFile
Write-Host ('RESULT ' + $OutFile + ' engine=' + $engineUsed + ' requested=' + $requested + ' found=' + $found + ' seconds=' + $maxSeconds + ' reason=' + $reason)
