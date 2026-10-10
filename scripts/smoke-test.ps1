param(
 [string]$BaseUrl = 'http://127.0.0.1:8082',
 [string]$Token = $env:SCAN_TOKEN,
 [switch]$RealImageScan
)
$ErrorActionPreference = 'Stop'
if (-not $Token) { throw 'Set SCAN_TOKEN to a configured tenant token' }
$headers = @{Authorization="Bearer $Token";'Idempotency-Key'=('smoke-'+[guid]::NewGuid().ToString('N'))}
$root = Split-Path -Parent $PSScriptRoot
$body = @{
 kind='manifest'
 target='checkout-api/staging'
 manifest=(Get-Content -Raw -LiteralPath (Join-Path $root 'examples/unsafe-deployment.json') | ConvertFrom-Json)
}
if($RealImageScan){$body=@{kind='image';target='alpine:3.22'}}
$json = $body | ConvertTo-Json -Depth 30
$job = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/v1/scans" -Headers $headers -ContentType 'application/json' -Body $json
$reused = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/v1/scans" -Headers $headers -ContentType 'application/json' -Body $json
if($job.id -ne $reused.id -or -not $reused.reused){throw 'Idempotency failed'}
$deadline=(Get-Date).AddMinutes(8)
do{
 Start-Sleep -Seconds 2
 $state=Invoke-RestMethod -Uri "$BaseUrl/api/v1/scans/$($job.id)" -Headers $headers
}while($state.status -in @('queued','running') -and (Get-Date) -lt $deadline)
if($state.status -ne 'succeeded'){throw "Scan did not succeed: $($state | ConvertTo-Json -Depth 10)"}
$summary=Invoke-RestMethod -Uri "$BaseUrl/api/v1/scans/$($job.id)/summary" -Headers $headers
$findings=Invoke-RestMethod -Uri "$BaseUrl/api/v1/scans/$($job.id)/findings?limit=100" -Headers $headers
if(-not $RealImageScan -and $summary.gate -ne 'block'){throw 'Unsafe deployment was not blocked'}
@{scan=$state;summary=$summary;findings=$findings} | ConvertTo-Json -Depth 20
