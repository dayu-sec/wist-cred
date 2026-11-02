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
| `wist-cred-stack` | gops 部署栈：编排、配置渲染、PKI 与验证方接入包 |

## 端点

| 端点 | 语义 |
|---|---|
| `GET /` | 自述（服务名 / 版本 / 端点列表）；**本服务只有 API，没有页面** |
| `POST /api/v1/credentials` | 为程序创建凭据；**明文只在响应里出现一次** |
| `GET /api/v1/credentials` | 列出已发放凭据（**永不含摘要与明文**） |
| `GET /api/v1/credentials/{id}` | 单条 |
| `POST /api/v1/credentials/{id}/revoke` | 撤销（幂等：重放不重复升 revision） |
| `GET /api/v1/policy` | 签发策略：`max_ttl_seconds` / `break_glass_max_ttl_seconds`（页面用它把超限选项标出来） |
| `GET /api/v1/onboarding/peers` | 列出认证系统（含**心跳状态**：`unknown` / `up`+延迟 / `down`+原因） |
| `POST /api/v1/onboarding/peers` | 新建认证系统（名称 / 主机名 / 收数地址）；落 `state/peers.json`，**不需重启** |
| `POST /api/v1/onboarding/peers/{name}/endpoint` | 改收数地址（`null` = 退回手工分发），下一轮心跳即生效 |
| `POST /api/v1/onboarding/peers/{name}/script` | 签一张**一次性**接入券（默认 900s） |
| `GET /onboarding/script/{token}` | 取出接入脚本（**只有公开材料 + 券，无任何私钥**） |
| `POST /onboarding/enroll/{token}` | X 交 CSR 换自己的服务器证书（**兑现券**，一次性） |
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
| `onboarding.script_ttl_seconds` > 3600 | 加载期拒绝启动 |
| `onboarding.ca_cert` 与 `[[issue.targets]].ca` 不是同一把 | 加载期拒启（会签出自己认不了的证书） |
| 有 peer 但没配 `onboarding.ca_cert` / `ca_key` | `503 enrollment_disabled`（建系统/接入被拒） |
| `[push].ca` 与 `onboarding.ca_cert` 不是同一把 | 加载期拒绝启动 |
| 认证系统名冲突 / 受众重复 | `409 peer_conflict` |
| 请求里的角色不在该认证系统上报的列表里 | `400 role_not_supported`（错误信息会列出它支持什么） |
| `endpoint` 不是 `https://` | `400 invalid_peer`（推送走 mTLS，不收明文） |
| 认证系统有 `endpoint` 但推送失败 | `500 credential_delivery_pending`，**不给明文** |
| 接入券重复兑现 / 过期 | `401 enrollment_rejected`（不区分原因） |
| 坏 CSR | `400 invalid_csr`，**不消耗券** |

## 运行

```sh
cp config.example.toml cred.toml      # 按现场改 listen_addr / trusted_peers
export WIST_CRED_CONFIG=$PWD/cred.toml
export WIST_CRED_SEC_FILE=$PWD/sec-value.yml   # 可选：提供 ${SEC_...}

gx run build -e debug                 # 版本同步 + 构建 + 测试 + 产物落到 ~/bin
```

也可以直接给配置路径：`wist-cred /path/to/cred.toml`。

## 闭环测试

```sh
cargo run --example closed_loop
```

单进程跑完 **签发 → 登记到 `wist_auth::CredentialStore` → 验证 → 撤销 → 再验证**，
不需要端口、不需要数据库。用本地 `path` 依赖 sibling 的 `../wist-auth`（多 crate 联调口径）。

```text
① cred 签发   credential_id=cred_...
② X 登记完成   条目 1 条
③ 验证通过     subject=ci-nightly roles=["investigation:run"] ...
   跨服务重放被拒  code=audience_mismatch
④ cred 撤销   revision=2
⑤ 再验证失败    code=token_revoked status=401
```

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
