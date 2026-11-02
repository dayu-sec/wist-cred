# Changelog

## [Unreleased]

### Added

- **P2 签发闭环（cred 侧）**：`POST /api/v1/credentials` 为程序创建凭据，
  明文只在响应里出现一次，磁盘只留 `sha256` 摘要。
- `GET /api/v1/credentials`、`GET /api/v1/credentials/{id}`、幂等 `revoke`。
- 人机面授权：操作者头（`x-wist-operator`）+ `trusted_peers` CIDR 校验（S3）。
- `owner`（申请人，取自注入头，不接受请求体覆盖）与 `purpose`（必填，进审计）；
  `last_used_at` 预留列，等 X 侧回传。
- `examples/closed_loop.rs`：**签发 → 登记 → 验证 → 撤销 → 再验证** 的闭环示例，
  dev-dependency 走本地 `../wist-auth`（多 crate 联调）。

### Security

- `mode = "ingress"` 时拒绝绑定 `0.0.0.0` / `[::]`，`trusted_peers` 为空也拒绝启动（S1 / S3 前提）。
- `mode = "oidc"` 本期 fail-closed：写出来直接拒绝启动，不会静默退化成不校验。
- 凭据文件 `0600`，写入走临时文件 + rename。
