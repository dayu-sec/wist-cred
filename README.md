# wist-cred

Wist **凭据服务**（设计文档里的 **C**）。

为**程序**（CI、运维脚本、break-glass）签发凭据、撤销凭据、把摘要推给各验证方（X）。
它**不验任何业务请求**，也不持有业务数据。

> 设计口径：`wist-design/doc/design/foundation/auth-token-verification.md`
> （三种凭据来源、`register` / `revoke` 推送、S1–S7 硬约束、P0–P3 落地顺序）。

## 三件套

| 仓库 | 角色 |
|---|---|
| **wist-cred**（本仓） | 签发 / 撤销 / 推送，只存 `sha256` 摘要 |
| `wist-cred-web` | 管理页面：为程序创建 / 撤销凭据，明文仅一次性展示 |
| `wist-cred-stack` | gops 部署栈：编排、配置渲染、CA-I 证书与密钥注入 |

## 端点

| 端点 | 语义 |
|---|---|
| `POST /api/v1/credentials` | 为程序创建凭据；**明文只在响应里出现一次** |
| `GET /api/v1/credentials` | 列出已发放凭据（**永不含摘要与明文**） |
| `GET /api/v1/credentials/{id}` | 单条 |
| `POST /api/v1/credentials/{id}/revoke` | 撤销（幂等：重放不重复升 revision） |
| `GET /healthz` / `GET /version` | 探针 |

### 创建

```sh
curl -s -X POST https://cred.internal/api/v1/credentials \
  -H 'x-wist-operator: alice' \
  -H 'content-type: application/json' \
  -d '{
    "subject": "ci-nightly",
    "purpose": "nightly disk inspection",
    "roles": ["investigation:run"],
    "resources": { "agents": ["agent-7f3"] },
    "audience": "wist-center"
  }'
```

- `x-wist-operator` 由**内网入口**注入，客户端不自己填（外部同名头会被入口剥离）。
- 响应里的 `token`（`wcr_...`）**只此一次**；磁盘只留 `sha256` 摘要 ——
  实测在 `state/credentials.db` 里搜不到 `wcr_`。
- `owner` 取自注入头，**不接受请求体覆盖**；`purpose` 必填（进审计）。

### 约束

| 约束 | 行为 |
|---|---|
| `mode = "ingress"` 不得绑 `0.0.0.0` / `[::]`（S1） | 加载期拒绝启动 |
| `mode = "ingress"` 时 `trusted_peers` 为空（S3 的前提） | 加载期拒绝启动 |
| 对端不在 `trusted_peers` | `401 untrusted_ingress_peer` + 告警 |
| 缺操作者头 | `401 missing_operator` |
| `mode = "oidc"` | 加载期拒绝启动（本期不做） |
| `ttl_seconds` 超上限 | 静默压到上限（脚本 30d / break-glass 90d） |
| 配了 `[[issue.targets]]` 但 `audience` 不在其中 | `400 audience_not_configured` |

## 运行

```sh
cp config.example.toml cred.toml      # 按现场改 listen_addr / trusted_peers
export WIST_CRED_CONFIG=$PWD/cred.toml
export WIST_CRED_SEC_FILE=$PWD/sec-value.yml   # 可选：提供 ${SEC_...}

gx run build -e debug                 # 版本同步 + 构建 + 测试 + 产物落到 ~/bin
```

也可以直接给配置路径：`wist-cred /path/to/cred.toml`。

## 开发

构建 / 检查 / 测试统一走 `gx`（不要直接 `cargo build`）：

```sh
gx run            # 列出可用 flow / env
gx run build -e debug
gx run lint       # fmt + fix + clippy -D warnings
gx run test
```

版本以 `version.txt` 为权威，用 `gx adm v_patch` / `v_feat` 升级；`Cargo.toml` 里的
`version = "x.y.z" #@gxl:set(version)` marker 不要删。
