[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Codex', 'Agents', 'Both')]
    [string]$Target = 'Both',
    [string]$HomePath = $HOME,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
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
        $backup = "$destination.backup.$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))"
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
