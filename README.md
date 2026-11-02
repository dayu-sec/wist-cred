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

## 当前状态（骨架）

| 端点 | 状态 |
|---|---|
| `GET /healthz` | ✅ |
| `GET /version` | ✅ |
| `POST /api/v1/credentials` | ⏳ `501 not_implemented` |
| `GET /api/v1/credentials` | ⏳ `501 not_implemented` |
| `POST /api/v1/credentials/{id}/revoke` | ⏳ `501 not_implemented` |

配置校验已生效，两条约束会在**加载期拒绝启动**：

1. `mode = "ingress"` 时 `listen_addr` 不得绑 `0.0.0.0` / `[::]`（S1）；
2. `mode = "ingress"` 时 `trusted_peers` 不得为空（S2 的前提）。

`mode = "oidc"` 是留给用户中心 / 钉钉的位置，**本期写出来会直接拒绝启动**，不会静默退化成不校验。

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
