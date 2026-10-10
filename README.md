# CloudGuard Scan Platform

面向研发发布流水线的多租户云原生安全检查服务。调用方提交容器镜像或 Kubernetes workload，平台异步执行 Trivy 漏洞扫描与 OPA 基线检查，统一归一化风险、生成发布门禁结论，并保留可查询的任务状态和结果。

## 应用场景

某团队每天发布多个微服务。CI 在部署前提交镜像地址和 Kubernetes workload：

1. API 根据 Bearer token 确定租户，并用 `Idempotency-Key` 防止流水线重试重复建单。
2. Worker 使用带租约的 MySQL 队列领取任务，崩溃后可重试接管。
3. 镜像任务调用 Trivy；manifest 任务调用 OPA Rego。
4. 平台把不同工具的输出归一为统一 finding，按指纹去重。
5. `HIGH` 或 `CRITICAL` 风险返回 `block`，无高危风险返回 `pass`；扫描失败返回 `error`，绝不误放行。

## 能力

- API token 到租户的隔离映射，数据库查询强制附带 tenant。
- 幂等键与请求哈希，重复请求复用任务，键冲突返回 `409`。
- 异步任务状态 `queued -> running -> succeeded/failed`。
- 180 秒租约、最多 3 次尝试、过期接管与 fencing token。
- Trivy SchemaVersion 2 结果解析、严重级归一和 finding 指纹去重。
- OPA 1.x Rego 基线：特权容器、权限提升、非 root、只读根文件系统、hostNetwork、资源限制、可变镜像标签。
- 门禁摘要、严重级筛选、分页、健康检查与基础 Prometheus 指标。
- 请求体、工具输出、执行时间和外部进程 stderr 均有限制。

## 快速启动

要求 Docker Compose v2。先配置随机密码和至少 16 字符的 API token：

```powershell
Copy-Item .env.example .env
docker compose up --build -d
docker compose ps
```

默认 API：`http://127.0.0.1:8082`。Compose 镜像内固定包含 Trivy 0.75.0 和 OPA 1.21.1。

提交 Kubernetes 基线扫描：

```powershell
$token = 'replace-with-your-token'
$manifest = Get-Content .\examples\unsafe-deployment.json -Raw | ConvertFrom-Json
$body = @{kind='manifest'; target='checkout-api/staging'; manifest=$manifest} | ConvertTo-Json -Depth 30
$headers = @{Authorization="Bearer $token"; 'Idempotency-Key'='release-20261010-42'}
$job = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8082/api/v1/scans -Headers $headers -ContentType application/json -Body $body
Invoke-RestMethod -Uri "http://127.0.0.1:8082/api/v1/scans/$($job.id)/summary" -Headers $headers
```

执行完整 smoke test：

```powershell
$env:SCAN_TOKEN='replace-with-your-token'
.\scripts\smoke-test.ps1
```

使用 `-RealImageScan` 可扫描 `alpine:3.22`，首次运行会下载漏洞数据库并需要外网。

## API

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/scans` | 提交 image、manifest 或受信任的 Trivy report |
| `GET` | `/api/v1/scans` | 查询当前租户最近任务 |
| `GET` | `/api/v1/scans/{id}` | 查询任务状态 |
| `GET` | `/api/v1/scans/{id}/summary` | 获取门禁结论 |
| `GET` | `/api/v1/scans/{id}/findings` | 按 severity 分页查询风险 |
| `GET` | `/healthz`, `/readyz`, `/metrics` | 健康、依赖和指标 |

所有 `/api/` 请求必须携带 `Authorization: Bearer <token>`。提交接口建议携带最多 128 字节的 `Idempotency-Key`。

### 请求类型

- `image`：`target` 为镜像引用，Worker 从远端 registry 拉取元数据并由 Trivy 扫描。
- `manifest`：`manifest` 为 Kubernetes JSON 对象，支持 Pod、Deployment、StatefulSet、DaemonSet、ReplicaSet、Job 和 CronJob。
- `trivy_report`：导入 Trivy JSON，用于受信任 CI 或隔离环境。V1 不验证报告签名，不应将不可信客户端上传的报告当作供应链证明。

## 本地开发

下载安装并校验 Windows 版工具到项目 `tools` 目录：

```powershell
.\scripts\install-tools.ps1
$env:OPA_BIN=(Resolve-Path .\tools\opa.exe)
.\scripts\test.ps1
```

启动 MySQL 后，可分别运行：

```powershell
$env:MYSQL_DSN='cloud_app:password@tcp(127.0.0.1:3307)/cloud_security?parseTime=true&charset=utf8mb4&loc=UTC'
$env:SCAN_API_TOKENS='{"acme":"replace-with-at-least-16-random-characters"}'
go run ./cmd/server
go run ./cmd/worker
```

## 安全边界

- V1 token 来自环境变量，日志不会输出 token；生产环境应由 secret manager 注入。
- API 默认仅绑定本机，公开部署必须置于 TLS 反向代理之后。
- Trivy 只启用漏洞扫描并限制为 remote image source；不把客户端输入交给 shell。
- OPA 仅加载部署时固定的策略路径。
- `pass` 只说明当前 V1 策略下没有 HIGH/CRITICAL finding，不等价于镜像或集群绝对安全。
- 漏洞数据库具有时效性，生产环境需监控更新时间并定期重扫。

## 测试与 CI

- 单元测试覆盖 Trivy 解析、去重、门禁、manifest 解析、认证、租户隔离和 Worker 失败语义。
- OPA 集成测试使用真实 OPA 二进制验证危险/安全 workload。
- MySQL 集成测试覆盖任务幂等、冲突、租户隔离、领取、完成和过期 lease 拒绝。
- GitHub Actions 执行 `go test -race`、`go vet`、真实 OPA 测试、MySQL 集成测试和容器构建。
