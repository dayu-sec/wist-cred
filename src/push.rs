//! 推送到认证系统（X）与心跳探测：**双向 TLS**。
//!
//! | 方向 | 谁证明谁 | 手段 |
//! |---|---|---|
//! | 本服务 → X | 客户端证书（CA-I 签） | `reqwest::Identity` |
//! | X → 本服务 | 服务器证书（CA-S 签） | `tls_certs_only`（CA-S 是**唯一**信任锚） |
//!
//! 与 center ↔ gwlinkd 同一形态：**先认证对方，再交凭据**。
//! 客户端证书缺失或服务端证书不在信任锚里，握手就失败 —— 不会把摘要交给错的人。
//!
//! 所有认证系统共用**一套客户端**：身份（cred-client）和信任锚（CA-S）是同一份，
//! 只有 URL 不同。所以这里不再按 target 预建客户端，而是"给地址就发"。

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use reqwest::{Certificate, Client, Identity};
use serde_json::json;

use crate::store::CredentialRecord;

pub struct Pusher {
    client: Client,
    timeout: Duration,
}

impl Pusher {
    /// `client_cert` / `client_key` 由 CA-I 签，`ca` 是 CA-S 信任锚。
    pub fn new(
        client_cert: &Path,
        client_key: &Path,
        ca: &Path,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let anchor =
            std::fs::read(ca).with_context(|| format!("read trust anchor {}", ca.display()))?;
        let certificate = Certificate::from_pem(&anchor)
            .with_context(|| format!("parse trust anchor {}", ca.display()))?;

        let mut pem = std::fs::read(client_cert)
            .with_context(|| format!("read client cert {}", client_cert.display()))?;
        pem.push(b'\n');
        pem.extend(
            std::fs::read(client_key)
                .with_context(|| format!("read client key {}", client_key.display()))?,
        );
        let identity = Identity::from_pem(&pem).context("parse client identity")?;

        let client = Client::builder()
            .timeout(timeout)
            .https_only(true)
            // **只认 CA-S**：`add_root_certificate` 是与系统/平台根证书**合并**的，
            // 那意味着任何公信 CA 签的站点证书都能接过 cred 的客户端证书与摘要。
            // `tls_certs_only` 把内置根整个换掉，对端只能出示 CA-S 签的证书。
            .tls_certs_only([certificate])
            .identity(identity)
            .build()
            .context("build push HTTP client")?;

        Ok(Self { client, timeout })
    }

    /// 登记一条凭据。失败意味着"对方没认"，调用方据此决定要不要交付明文。
    pub async fn register(
        &self,
        peer: &str,
        endpoint: &str,
        record: &CredentialRecord,
    ) -> anyhow::Result<()> {
        let body = json!({
            "credential_id": record.credential_id,
            "digest": format!("sha256:{}", record.digest),
            "subject": record.subject,
            "roles": record.roles,
            "resources": record.resources,
            "audience": record.audience,
            "issued_at": record.issued_at,
            "expires_at": record.expires_at,
            "revision": record.revision,
            "revoked_at": record.revoked_at,
        });

        let response = self
            .client
            .post(endpoint)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("push register to {peer} ({endpoint})"))?;

        if response.status() == reqwest::StatusCode::CONFLICT {
            // 对端已经有同一条（或更新的）记录：X 只在 `revision` 前进时才接受。
            // 对“重新投递”而言这就是目标状态，不算失败。
            log::debug!("push register to {peer} was already present (409)");
            return Ok(());
        }
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            bail!("push register to {peer} rejected: {status} {text}");
        }
        Ok(())
    }

    /// 撤销：对端不认识这条凭据（404）视为已完成（可能已清理）。
    pub async fn revoke(
        &self,
        peer: &str,
        endpoint: &str,
        credential_id: &str,
        revision: u64,
    ) -> anyhow::Result<()> {
        let url = format!("{}/{credential_id}/revoke", endpoint.trim_end_matches('/'));
        let body = json!({ "revision": revision });
        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("push revoke to {peer} ({url})"))?;
        if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        bail!("push revoke to {peer} rejected: HTTP {}", response.status());
    }

    /// 心跳：探一次可达性，返回耗时（毫秒）。2xx 才算在线。
    ///
    /// 探测本身走同一套 mTLS —— 「能握手」比「能 ping 通」有意义得多：
    /// 证书过期、链不对、时间偏了，都会在这里暴露，而不是等到推送失败。
    pub async fn probe(&self, url: &str) -> anyhow::Result<u64> {
        let started = Instant::now();
        let response = self
            .client
            .get(url)
            .timeout(self.timeout)
            .send()
            .await
            .with_context(|| format!("probe {url}"))?;
        let status = response.status();
        if !status.is_success() {
            bail!("probe {url} returned HTTP {status}");
        }
        Ok(started.elapsed().as_millis() as u64)
    }
}
