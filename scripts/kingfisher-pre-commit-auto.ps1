<#
.SYNOPSIS
    Kingfisher pre-commit hook with automatic binary download for Windows.

.DESCRIPTION
    Downloads and caches the Kingfisher binary, then scans staged changes.
    No manual installation required.

.PARAMETER Version
    Specific version to download (e.g., "1.76.0" or "v1.76.0").
    Defaults to "latest".

.EXAMPLE
    ./kingfisher-pre-commit-auto.ps1

.EXAMPLE
    $env:KINGFISHER_VERSION = "1.76.0"; ./kingfisher-pre-commit-auto.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repo = 'mongodb/kingfisher'
$cacheDir = if ($env:KINGFISHER_CACHE_DIR) { 
    $env:KINGFISHER_CACHE_DIR 
} else { 
    Join-Path $env:LOCALAPPDATA 'kingfisher' 
}
$kingfisherBin = Join-Path $cacheDir 'kingfisher.exe'
$versionFile = Join-Path $cacheDir '.version'
$expectedVersion = if ($env:KINGFISHER_VERSION) { $env:KINGFISHER_VERSION } else { 'latest' }

function Get-AssetName {
    # Windows only supports x64 currently
    return 'kingfisher-windows-x64.zip'
}

function Download-Kingfisher {
    param(
        [string]$Version
    )

    $assetName = Get-AssetName

    if (-not (Test-Path $cacheDir)) {
        New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
    }

    $tempDir = New-Item -ItemType Directory -Path ([System.IO.Path]::GetTempPath()) -Name ([System.Guid]::NewGuid().ToString())

    try {
        if ($Version -eq 'latest') {
            $downloadUrl = "https://github.com/$repo/releases/latest/download/$assetName"
            Write-Host "Downloading kingfisher (latest) for Windows..." -ForegroundColor Cyan
        } else {
            # Support both "v1.76.0" and "1.76.0" formats
            if (-not $Version.StartsWith('v')) {
                $Version = "v$Version"
            }
            $downloadUrl = "https://github.com/$repo/releases/download/$Version/$assetName"
            Write-Host "Downloading kingfisher ($Version) for Windows..." -ForegroundColor Cyan
        }

        $archivePath = Join-Path $tempDir.FullName $assetName

        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath -UseBasicParsing
        } catch {
            Write-Error "Failed to download $downloadUrl : $_"
            exit 1
        }

        Write-Host "Extracting archive..." -ForegroundColor Cyan
        Expand-Archive -Path $archivePath -DestinationPath $tempDir.FullName -Force

        $extractedBinary = Join-Path $tempDir.FullName 'kingfisher.exe'
        if (-not (Test-Path $extractedBinary)) {
            Write-Error "Binary not found in downloaded archive"
            exit 1
        }

        Copy-Item -Path $extractedBinary -Destination $kingfisherBin -Force

        # Store the version we downloaded
        if ($Version -eq 'latest') {
            try {
                $versionOutput = & $kingfisherBin --version 2>$null | Select-Object -First 1
                Set-Content -Path $versionFile -Value $versionOutput -NoNewline
            } catch {
                Set-Content -Path $versionFile -Value 'latest' -NoNewline
            }
        } else {
            Set-Content -Path $versionFile -Value $Version -NoNewline
        }

        Write-Host "Kingfisher installed to $kingfisherBin" -ForegroundColor Green
    }
    finally {
        if ($tempDir -and (Test-Path $tempDir.FullName)) {
            Remove-Item -Path $tempDir.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-NeedsDownload {
    # Binary doesn't exist
    if (-not (Test-Path $kingfisherBin)) {
        return $true
    }

    # No version tracking - always use existing binary for 'latest'
    if ($expectedVersion -eq 'latest') {
        return $false
    }

    # Check if version matches
    if (Test-Path $versionFile) {
        $installedVersion = Get-Content -Path $versionFile -Raw
        
        # Normalize version format for comparison
        $expectedNormalized = $expectedVersion
        if (-not $expectedNormalized.StartsWith('v')) {
            $expectedNormalized = "v$expectedNormalized"
        }
        
        if ($installedVersion -like "*$expectedNormalized*" -or $installedVersion -eq $expectedVersion) {
            return $false
        }
    }

    return $true
}

# Main execution
if (Test-NeedsDownload) {
    Download-Kingfisher -Version $expectedVersion
}

# Run kingfisher scan on staged changes
# Pass through any additional arguments
& $kingfisherBin scan . --staged --quiet --no-update-check @args
exit $LASTEXITCODE
