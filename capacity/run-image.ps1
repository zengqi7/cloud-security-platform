param([ValidateRange(1,10)][int]$Repetitions = 3, [string]$OutputRoot = 'results/capacity-image')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$target = 'alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6'
function Get-FreeTcpPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $listener.Start()
    try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port } finally { $listener.Stop() }
}
for ($attempt = 1; $attempt -le $Repetitions; $attempt++) {
    $runId = "cloud-image-a${attempt}-$(Get-Date -Format 'yyyyMMddHHmmss')"
    $project = $runId.ToLowerInvariant()
    $result = Join-Path $root "$OutputRoot/$runId"
    New-Item -ItemType Directory -Force -Path $result | Out-Null
    $envFile = Join-Path $result 'compose.env'
    $mysqlRoot = [Guid]::NewGuid().ToString('N'); $mysqlApp = [Guid]::NewGuid().ToString('N')
    $httpPort = Get-FreeTcpPort
    @("MYSQL_ROOT_PASSWORD=$mysqlRoot", "MYSQL_PASSWORD=$mysqlApp", 'MYSQL_PORT=0', "HTTP_PORT=$httpPort") | Set-Content $envFile -Encoding ascii
    $compose = @('compose','-p',$project,'-f',(Join-Path $root 'compose.yaml'),'-f',(Join-Path $root 'capacity/compose.capacity.yaml'),'--env-file',$envFile)
    try {
        & docker @compose up -d --build --wait
        $keyOutput = & docker @compose run --rm --no-deps --entrypoint /usr/local/bin/key -e "MYSQL_DSN=root:$mysqlRoot@tcp(mysql:3306)/cloud_security?parseTime=true&charset=utf8mb4&loc=UTC" api -tenant acme -subject capacity-image -scopes scans:read,scans:submit -ttl 2h
        $token = ($keyOutput | ConvertFrom-Json).token
        $headers = @{ Authorization="Bearer $token"; 'Content-Type'='application/json' }
        $measurements = @()
        foreach ($cache in @('cold','warm')) {
            $key = "$runId-$cache"
            $body = @{ kind='image'; target=$target; asset="capacity-image/$runId"; series='cache-comparison' } | ConvertTo-Json -Compress
            $start = Get-Date
            $response = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$httpPort/api/v1/scans" -Headers ($headers + @{'Idempotency-Key'=$key}) -Body $body
            do { Start-Sleep 1; $job = Invoke-RestMethod -Uri "http://127.0.0.1:$httpPort/api/v1/scans/$($response.id)" -Headers $headers } while ($job.status -in @('queued','running'))
            $measurements += @{ cache=$cache; status=$job.status; elapsed_seconds=[Math]::Round(((Get-Date)-$start).TotalSeconds,3); scan_id=$response.id }
        }
        @{ run_id=$runId; target=$target; http_port=$httpPort; measurements=$measurements } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $result 'run.json') -Encoding utf8
    } finally {
        & docker @compose down -v --remove-orphans | Out-Null
        Remove-Item -LiteralPath $envFile -Force -ErrorAction SilentlyContinue
    }
}
