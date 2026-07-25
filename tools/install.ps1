[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Codex', 'Agents', 'Both')]
    [string]$Target = 'Both',
    [string]$HomePath = $HOME,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
# Fail closed on missing/empty HomePath instead of computing relative
# destination paths via Join-Path. Mirrors the explicit HOME validation in
# tools/install.sh so the Windows installer does not silently install into
# the current directory or an unexpected rooted target.
if ([string]::IsNullOrWhiteSpace($HomePath)) {
    throw 'HomePath is empty; pass -HomePath <path> or set $HOME.'
}
$HomePath = "$HomePath".Trim()
# IsPathRooted accepts rooted-relative paths like \tmp that still depend on the
# current drive. Require a fully qualified path (drive letter or UNC).
$isFullyQualified = $false
# Branch on PS version: IsPathFullyQualified exists on PS 6+ /.NET Core.
# Do not probe the static member under StrictMode on Windows PowerShell 5.1.
if ($PSVersionTable.PSVersion.Major -ge 6) {
    $isFullyQualified = [System.IO.Path]::IsPathFullyQualified($HomePath)
} else {
    $isFullyQualified = $HomePath -match '^[A-Za-z]:[\\/]' -or $HomePath -match '^\\\\[^\\]+\\'
}
if (-not $isFullyQualified) {
    throw "HomePath must be a fully qualified absolute path (drive letter or UNC): $HomePath"
}
$source = Split-Path -Parent $PSScriptRoot
$payload = @('SKILL.md', 'agents', 'assets', 'references', 'scripts')
$targets = @(switch ($Target) {
    'Codex' { Join-Path $HomePath '.codex\skills\debug' }
    'Agents' { Join-Path $HomePath '.agents\skills\debug' }
    'Both' {
        Join-Path $HomePath '.codex\skills\debug'
        Join-Path $HomePath '.agents\skills\debug'
    }
})

# Reject a symlink/junction/mount-point payload entry, or any nested entry
# that is one: Test-Path alone follows a reparse point and would pass, then
# Copy-Item -Recurse would stage the link (or its target) into the installed
# skill, letting a reviewed payload point outside the tree. Walk one
# directory level at a time with Get-ChildItem (no -Recurse) instead of
# recursing wholesale, because -Recurse itself follows a reparse point while
# traversing; checking each child's own Attributes before deciding whether to
# descend means a nested reparse point is rejected before it is ever
# followed.
function Assert-PayloadEntrySafe {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Label)
    $item = Get-Item -LiteralPath $Path -Force
    $isReparsePoint = [bool]($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
    $isFile = $item -is [System.IO.FileInfo]
    $isDirectory = $item -is [System.IO.DirectoryInfo]
    if ($isReparsePoint -or (-not $isFile -and -not $isDirectory)) {
        throw "Skill payload entry must be a regular file/directory, not a symlink, junction, or special file: $Label"
    }
    if ($isDirectory) {
        foreach ($child in Get-ChildItem -LiteralPath $Path -Force) {
            Assert-PayloadEntrySafe -Path $child.FullName -Label "$Label/$($child.Name)"
        }
    }
}

foreach ($entry in $payload) {
    $entryPath = Join-Path $source $entry
    if (-not (Test-Path -LiteralPath $entryPath)) {
        throw "Missing skill payload entry: $entry"
    }
    Assert-PayloadEntrySafe -Path $entryPath -Label $entry
}


function Test-DestinationOccupied {
    param([Parameter(Mandatory)][string]$Path)
    # Test-Path can return $false for a dangling symlink/junction (target missing)
    # even though the reparse point still occupies the name. Get-Item -Force sees
    # the directory entry itself.
    if (Test-Path -LiteralPath $Path) { return $true }
    try {
        $null = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

# Preflight all destinations before mutating any of them so multi-target
# installs cannot leave one path updated and another absent/partial.
foreach ($destination in $targets) {
    if ((Test-DestinationOccupied -Path $destination) -and -not $Force) {
        throw "Target exists: $destination. Rerun with -Force to preserve it as a backup and replace it."
    }
}

function New-UniqueBackupPath {
    param([Parameter(Mandatory)][string]$Destination)
    $stamp = [DateTime]::UtcNow.Ticks
    $backup = "$Destination.backup.$stamp`_$PID"
    $retry = 0
    while (Test-Path -LiteralPath $backup) {
        $retry++
        $backup = "$Destination.backup.$stamp`_$PID`_$retry"
    }
    return $backup
}

# Stage every payload under a sibling temp directory first. Only after every
# staged tree is complete do we commit (backup + replace) destinations.
$staged = @()
try {
    foreach ($destination in $targets) {
        if (-not $PSCmdlet.ShouldProcess($destination, 'Install evidence debug skill')) {
            continue
        }
        $parent = Split-Path -Parent $destination
        if (-not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        $stage = Join-Path $parent ('.debug-install-stage.' + [DateTime]::UtcNow.Ticks + '_' + $PID + '_' + $staged.Count)
        if (Test-Path -LiteralPath $stage) {
            Remove-Item -LiteralPath $stage -Recurse -Force
        }
        New-Item -ItemType Directory -Path $stage -Force | Out-Null
        foreach ($entry in $payload) {
            Copy-Item -LiteralPath (Join-Path $source $entry) -Destination $stage -Recurse -Force
        }
        $staged += [pscustomobject]@{
            Destination = $destination
            Stage       = $stage
            Backup      = $null
            Committed   = $false
        }
    }

    # Buffer success records until every destination commits. Emitting per
    # destination would let a streaming consumer persist an "installed" line
    # for a target that is later rolled back when a subsequent destination fails.
    $pendingResults = @()
    foreach ($item in $staged) {
        $backup = $null
        if (Test-DestinationOccupied -Path $item.Destination) {
            $backup = New-UniqueBackupPath -Destination $item.Destination
            Move-Item -LiteralPath $item.Destination -Destination $backup
            # Record backup before the stage commit so a failed stage→destination
            # move still restores this in-flight backup (not only fully committed
            # prior targets).
            $item.Backup = $backup
        }
        try {
            Move-Item -LiteralPath $item.Stage -Destination $item.Destination
        }
        catch {
            # Stage move failed: put the original destination back if we backed it up.
            # Only clear $item.Backup after a confirmed successful restore; if the
            # restore itself fails (e.g. destination locked), keep the reference so
            # the outer catch can retry and report rather than stranding the backup.
            if ($item.Backup -and (Test-Path -LiteralPath $item.Backup)) {
                if (Test-Path -LiteralPath $item.Destination) {
                    Remove-Item -LiteralPath $item.Destination -Recurse -Force -ErrorAction SilentlyContinue
                }
                try {
                    Move-Item -LiteralPath $item.Backup -Destination $item.Destination -ErrorAction Stop
                    $item.Backup = $null
                }
                catch {
                    Write-Warning "Immediate restore of $($item.Destination) from backup failed: $($_.Exception.Message)"
                }
            }
            throw
        }
        $item.Committed = $true
        $item.Stage = $null
        $pendingResults += [pscustomobject]@{
            status = 'installed'
            target = $item.Destination
            backup = $backup
        }
    }
    foreach ($record in $pendingResults) {
        Write-Output ($record | ConvertTo-Json -Compress)
    }
}
catch {
    # Roll back committed destinations and any in-flight backup (destination
    # renamed to backup, stage move never succeeded / already restored).
    for ($i = $staged.Count - 1; $i -ge 0; $i--) {
        $item = $staged[$i]
        try {
            if ($item.Committed) {
                if (Test-Path -LiteralPath $item.Destination) {
                    Remove-Item -LiteralPath $item.Destination -Recurse -Force
                }
                if ($item.Backup -and (Test-Path -LiteralPath $item.Backup)) {
                    Move-Item -LiteralPath $item.Backup -Destination $item.Destination
                }
            }
            elseif ($item.Backup -and (Test-Path -LiteralPath $item.Backup)) {
                # In-flight: destination was renamed to backup but never committed.
                if (Test-Path -LiteralPath $item.Destination) {
                    Remove-Item -LiteralPath $item.Destination -Recurse -Force
                }
                Move-Item -LiteralPath $item.Backup -Destination $item.Destination
            }
        }
        catch {
            # Best-effort rollback; surface the original install error below.
            # Record the rollback-step failure so a partially broken state is
            # not silently hidden behind the primary install error.
            Write-Warning "Rollback step failed for $($item.Destination): $($_.Exception.Message)"
        }
    }
    throw
}
finally {
    foreach ($item in $staged) {
        if ($item.Stage -and (Test-Path -LiteralPath $item.Stage)) {
            Remove-Item -LiteralPath $item.Stage -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
