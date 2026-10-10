$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$toolsDir = Join-Path $root 'tools'
New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
$opaVersion = '1.21.1'
$trivyVersion = '0.75.0'
$opaUrl = "https://github.com/open-policy-agent/opa/releases/download/v$opaVersion/opa_windows_amd64.exe"
$opaPath = Join-Path $toolsDir 'opa.exe'
Invoke-WebRequest -Uri $opaUrl -OutFile $opaPath
$opaChecksum = (Invoke-WebRequest -Uri "$opaUrl.sha256").Content
if ($opaChecksum -is [byte[]]) { $opaChecksum = [Text.Encoding]::UTF8.GetString($opaChecksum) }
$expected = ([string]$opaChecksum).Trim().Split(' ')[0]
if ((Get-FileHash -LiteralPath $opaPath -Algorithm SHA256).Hash -ne $expected) { throw 'OPA checksum mismatch' }

$archiveName = "trivy_" + $trivyVersion + "_windows-64bit.zip"
$archivePath = Join-Path $toolsDir $archiveName
$base = "https://github.com/aquasecurity/trivy/releases/download/v$trivyVersion"
Invoke-WebRequest -Uri "$base/$archiveName" -OutFile $archivePath
$checksums = (Invoke-WebRequest -Uri "$base/trivy_${trivyVersion}_checksums.txt").Content
if ($checksums -is [byte[]]) { $checksums = [Text.Encoding]::UTF8.GetString($checksums) }
$line = ([string]$checksums -split "\n" | Where-Object { $_.Trim().EndsWith($archiveName) }) | Select-Object -First 1
if (-not $line) { throw 'Trivy checksum entry not found' }
$expected = ($line.Trim() -split '\s+')[0]
if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash -ne $expected) { throw 'Trivy checksum mismatch' }
Expand-Archive -LiteralPath $archivePath -DestinationPath $toolsDir -Force
& $opaPath version
& (Join-Path $toolsDir 'trivy.exe') --version
