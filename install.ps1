# Installs the latest snad release for Windows.
#
#   irm https://raw.githubusercontent.com/grubk/snad/main/install.ps1 | iex
#
# Override the install directory with $env:SNAD_INSTALL_DIR (default: %LOCALAPPDATA%\snad).

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = 'grubk/snad'
$installDir = if ($env:SNAD_INSTALL_DIR) { $env:SNAD_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'snad' }

switch ($env:PROCESSOR_ARCHITECTURE) {
	'AMD64' { $arch = 'amd64' }
	'ARM64' { $arch = 'arm64' }
	default {
		Write-Error "snad: unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)"
		exit 1
	}
}

$release = Invoke-RestMethod -UseBasicParsing "https://api.github.com/repos/$repo/releases/latest"
$tag = $release.tag_name

if (-not $tag) {
	Write-Error 'snad: could not determine the latest release tag'
	exit 1
}

$archive = "snad_windows_${arch}.zip"
$baseUrl = "https://github.com/$repo/releases/download/$tag"

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $workDir | Out-Null

try {
	Write-Host "snad: downloading $archive ($tag)..."
	Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/$archive" -OutFile (Join-Path $workDir $archive)
	Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/checksums.txt" -OutFile (Join-Path $workDir 'checksums.txt')

	Write-Host 'snad: verifying checksum...'
	$checksums = Get-Content (Join-Path $workDir 'checksums.txt')
	$expectedLine = $checksums | Where-Object { $_ -match [regex]::Escape($archive) }
	if (-not $expectedLine) {
		Write-Error "snad: no checksum entry found for $archive"
		exit 1
	}
	$expectedHash = ($expectedLine -split '\s+')[0]
	$actualHash = (Get-FileHash -Algorithm SHA256 (Join-Path $workDir $archive)).Hash
	if ($actualHash.ToLower() -ne $expectedHash.ToLower()) {
		Write-Error "snad: checksum mismatch for $archive (expected $expectedHash, got $actualHash)"
		exit 1
	}

	Expand-Archive -Path (Join-Path $workDir $archive) -DestinationPath $workDir -Force

	New-Item -ItemType Directory -Path $installDir -Force | Out-Null
	Move-Item -Path (Join-Path $workDir 'snad.exe') -Destination (Join-Path $installDir 'snad.exe') -Force

	Write-Host "snad: installed to $(Join-Path $installDir 'snad.exe')"
} finally {
	Remove-Item -Recurse -Force $workDir -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$pathEntries = $userPath -split ';' | Where-Object { $_ }
if ($installDir -notin $pathEntries) {
	[Environment]::SetEnvironmentVariable('Path', "$userPath;$installDir", 'User')
	Write-Host ''
	Write-Host "snad: added $installDir to your user PATH."
	Write-Host 'Restart your terminal for this to take effect.'
} else {
	Write-Host "snad: $installDir is already on your PATH."
}
