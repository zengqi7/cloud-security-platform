# CloudGuard Scan Platform

[![CI](https://github.com/zengqi7/cloud-security-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/zengqi7/cloud-security-platform/actions/workflows/ci.yml)

面向研发流水线的多租户发布门禁与风险治理平台。CI 在部署前提交固定镜像摘要和 Kubernetes workload，平台执行真实扫描并保留证据；发布者读取当前有效门禁评估，安全负责人可进行有期限的双人豁免。

## 工程证据

| 资料 | 内容 |
|---|---|
| [最新 Release](https://github.com/zengqi7/cloud-security-platform/releases/latest) | 发行包、checksum、provenance 和版本说明 |
| [支持矩阵](docs/support-matrix.md) | Go、数据库、Docker、工具版本及平台验证边界 |
| [容量报告](docs/capacity/v0.1.0.md) | 历史固定负载的吞吐、P95、恢复和资源数据 |
| [可审计测试输入](capacity/evidence/v0.1.0) | 脱敏样本、汇总、元数据和 SHA-256；可机器复算 |
| [发行验证](docs/release-verification.md) | 严格验证流程；每次完成结果见 Release notes |

## 已实现能力

- MySQL 队列、幂等请求、租约/fencing、三次尝试、关系化 finding 分页和 SQL 迁移。
- API Key tenant/subject/scopes、到期/吊销与审计；不信任客户端 tenant。
- Trivy 0.75.0 镜像漏洞扫描及 CycloneDX SBOM；OPA 1.21.1 受限能力策略执行。
- 不可变策略 bundle/version/digest、扫描策略快照；未知风险、工具失败、缺失或过期证据均 fail-closed。
- 独立 immutable assessment，最长 15 分钟且受 DB/waiver 到期限制；特定 scan/fingerprint 的 TTL waiver，申请者不能自批，finding 不变。
- asset/scan series、严格可比差异；不同镜像摘要的缺失风险只能称 possibly_fixed。SBOM 取出时校验摘要。
- 可选 Cosign 3.1.3 精确身份/公钥验签和 SLSA v1 builder/subject 检查；默认 disabled，不宣称真实性。
- Trivy DB UpdatedAt 48 小时新鲜度检查；持久重扫固定 artifact，创建凭证吊销或到期后关闭调度。
- CLI、SARIF 2.1.0、GitHub composite Action；退出码 0/pass、2/block、3/error。

## 快速启动

需要 Docker Compose v2。复制模板后设置随机数据库密码：

```powershell
Copy-Item .env.example .env
docker compose up --build -d
$key = docker compose run --rm --no-deps --entrypoint key api -tenant acme -subject local-ci -scopes scans:read,scans:submit,assessments:write -ttl 24h | ConvertFrom-Json
$env:SCAN_TOKEN = $key.token
.\scripts\smoke-test.ps1
```

API：http://127.0.0.1:8082。smoke 验证危险 Deployment 被 block；`-RealImageScan` 扫描固定 Alpine 摘要，首次下载 DB 需网络。默认 Compose 不要求签名；启用 keyless/只读公钥见 [supply-chain](docs/supply-chain.md)。

## CI 和开发

生产客户端使用 HTTPS，令牌通过 CI Secret 环境变量注入：

```sh
export CLOUDGUARD_API_URL=https://scanner.example
# CLOUDGUARD_TOKEN is injected by the CI secret store.
cloudguard -kind image -target registry.example/app@sha256:REPLACE_WITH_DIGEST -asset checkout -series production -assess -sarif cloudguard.sarif
```

镜像必须固定摘要才能产生可信门禁证据。CI 不能以 continue-on-error 绕过门禁。完整路径和权限见 [OpenAPI](docs/openapi.json)。

Go 版本以 go.mod 为准，使用 database/sql。容器附带工具；本地需设置 OPA_BIN、TRIVY_BIN、COSIGN_BIN 为匹配 OS 的可信程序。Windows scripts/install-tools.ps1 安装校验后的 OPA/Trivy，Cosign 需另行核对官方校验和。先 cmd/migrate，后 cmd/server 与 cmd/worker。测试：`go test ./...`、`go vet ./...`；真实 OPA 设置 OPA_BIN；独立 MySQL 设置 INTEGRATION_MYSQL_DSN 后运行 `go test -race -tags=integration ./...`。

## 边界与运维

pass 仅代表策略与证据范围内通过，不证明没有漏洞。无集群自动发现、自动部署、管理 UI、SSO、自动 retention；重扫不追踪可变标签。签名成功输出只存摘要，未归档完整证书，不宣称 SLSA 等级。业务 assessment 与本仓库构建 provenance 是不同证据。上线需要 TLS、出口网络控制、Secret、告警、备份恢复和容量验证。

- [架构](docs/architecture.md) / [认证](docs/authentication.md) / [CI 集成](docs/ci-integration.md)
- [策略](docs/policy-bundles.md) / [评估与豁免](docs/gate-assessments.md) / [风险生命周期](docs/risk-lifecycle.md)
- [供应链与重扫](docs/supply-chain.md) / [存储升级](docs/storage-upgrades.md)
- [发布、升级、恢复与兼容政策](docs/release-and-operations.md)
