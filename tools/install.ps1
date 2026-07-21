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
if (-not ([System.IO.Path]::IsPathRooted($HomePath))) {
    throw "HomePath must be an absolute path: $HomePath"
}
$source = Split-Path -Parent $PSScriptRoot
$payload = @('SKILL.md', 'agents', 'assets', 'references', 'scripts')
$targets = switch ($Target) {
    'Codex' { Join-Path $HomePath '.codex\skills\debug' }
    'Agents' { Join-Path $HomePath '.agents\skills\debug' }
    'Both' {
        Join-Path $HomePath '.codex\skills\debug'
        Join-Path $HomePath '.agents\skills\debug'
    }
}

foreach ($entry in $payload) {
    if (-not (Test-Path -LiteralPath (Join-Path $source $entry))) {
        throw "Missing skill payload entry: $entry"
    }
}

foreach ($destination in $targets) {
    $backup = $null
    if (Test-Path -LiteralPath $destination) {
        if (-not $Force) {
            throw "Target exists: $destination. Rerun with -Force to preserve it as a backup and replace it."
        }
        # Collision-proof backup name: high-resolution UTC Ticks + PID, with a
        # retrying counter so repeated forced installs cannot collide.
        $stamp = [DateTime]::UtcNow.Ticks
        $backup = "$destination.backup.$stamp`_$PID"
        $retry = 0
        while (Test-Path -LiteralPath $backup) {
            $retry++
            $backup = "$destination.backup.$stamp`_$PID`_$retry"
        }
    }

    if ($PSCmdlet.ShouldProcess($destination, 'Install evidence debug skill')) {
        if ($backup) {
            Move-Item -LiteralPath $destination -Destination $backup
        }
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        foreach ($entry in $payload) {
            Copy-Item -LiteralPath (Join-Path $source $entry) -Destination $destination -Recurse -Force
        }
        Write-Output ([pscustomobject]@{
            status = 'installed'
            target = $destination
            backup = $backup
        } | ConvertTo-Json -Compress)
    }
}
