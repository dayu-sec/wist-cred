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
use wist_auth::credential::CredentialEntry;

use crate::config::SigningKey;
use crate::store::CredentialRecord;

pub struct Pusher {
    client: Client,
    timeout: Duration,
    /// 授权记录的签发钥：有它就签名，`None` 则下游开了 `require_signature` 会拒收。
    signing: Option<SigningKey>,
}

impl Pusher {
    /// `client_cert` / `client_key` 由 CA-I 签，`ca` 是 CA-S 信任锚。
    pub fn new(
        client_cert: &Path,
        client_key: &Path,
        ca: &Path,
        timeout: Duration,
        signing: Option<SigningKey>,
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

        Ok(Self {
            client,
            timeout,
            signing,
        })
    }

    /// 把本地记录折成可签名的形状（与验证方 `CredentialEntry` 同构）。
    fn entry_of(record: &CredentialRecord) -> CredentialEntry {
        CredentialEntry {
            credential_id: record.credential_id.clone(),
            digest: record.digest.clone(),
            subject: record.subject.clone(),
            roles: record.roles.clone(),
            resources: record.resources.clone(),
            audience: record.audience.clone(),
            issued_at: record.issued_at,
            expires_at: record.expires_at,
            revision: record.revision,
            revoked_at: record.revoked_at,
            signature: None,
        }
    }

    fn signature_for(&self, record: &CredentialRecord) -> anyhow::Result<Option<String>> {
        match &self.signing {
            Some(signing) => Ok(Some(signing.sign(&Self::entry_of(record))?)),
            None => Ok(None),
        }
    }

    /// 登记一条凭据。失败意味着"对方没认"，调用方据此决定要不要交付明文。
    pub async fn register(
        &self,
        peer: &str,
        endpoint: &str,
        record: &CredentialRecord,
    ) -> anyhow::Result<()> {
        let mut body = json!({
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
        if let Some(signature) = self.signature_for(record)? {
            body["signature"] = json!(signature);
        }

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
            bail!(
                "{}",
                Self::reject_reason("register", peer, endpoint, status, &text)
            );
        }
        Ok(())
    }

    /// 撤销：对端不认识这条凭据（404）视为已完成（可能已清理）。
    pub async fn revoke(
        &self,
        peer: &str,
        endpoint: &str,
        record: &CredentialRecord,
    ) -> anyhow::Result<()> {
        let url = format!(
            "{}/{}/revoke",
            endpoint.trim_end_matches('/'),
            record.credential_id
        );
        let mut body = json!({
            "revision": record.revision,
            "revoked_at": record.revoked_at,
        });
        // 签名覆盖“已撤销的那条记录”：验证方会用它替换旧签名。
        if let Some(signature) = self.signature_for(record)? {
            body["signature"] = json!(signature);
        }
        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("push revoke to {peer} ({url})"))?;
        if response.status().is_success() {
            return Ok(());
        }
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            // 对端不认识这条凭据 = 已经是目标状态（可能已清理）。
            // 但**收数地址写错也是 404**，协议上不可区分 —— 那意味着 token 在对方那边仍然有效。
            // 不改返回值（撤销必须幂等），只留一条 warn 让现场有机会发现。
            log::warn!(
                "push revoke to {peer} ({url}) returned 404; treating as already revoked \
                 (a wrong endpoint path also looks like this — the token would still be valid there)"
            );
            return Ok(());
        }
        bail!(
            "push revoke to {peer} rejected: HTTP {} ({url})",
            response.status()
        );
    }

    /// 推送失败时给现场看的话。
    ///
    /// 404 几乎总是收数地址没带路径：`probe_url` 会把路径剔掉（`origin + /healthz`），
    /// 所以那种地址**探活是绿的**，只有推送会 404。不点名的话，现场只能看到一句
    /// `404 Not Found`（本地联调就是这么被坑了一次）。
    fn reject_reason(
        action: &str,
        peer: &str,
        endpoint: &str,
        status: reqwest::StatusCode,
        body: &str,
    ) -> String {
        if status == reqwest::StatusCode::NOT_FOUND {
            format!(
                "push {action} to {peer} rejected: {status} {body}; \
                 endpoint {endpoint:?} did not match the verifier's push route — \
                 it must include the push path (e.g. {})",
                crate::peers::DEFAULT_PUSH_PATH
            )
        } else {
            format!("push {action} to {peer} rejected: {status} {body}")
        }
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;

    use super::*;

    fn record() -> CredentialRecord {
        CredentialRecord {
            credential_id: "cred_1".to_string(),
            digest: "aa".repeat(32),
            subject: "ci-nightly".to_string(),
            owner: "alice".to_string(),
            purpose: "test".to_string(),
            roles: vec!["read".to_string()],
            resources: BTreeMap::new(),
            audience: "wist-center".to_string(),
            break_glass: false,
            issued_at: 1_700_000_000,
            expires_at: 1_700_003_600,
            revision: 1,
            revoked_at: None,
            last_used_at: None,
        }
    }

    #[test]
    fn pushed_record_signature_covers_authorization_content() {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("keypair");
        let key = SigningKey::from_pkcs8(pkcs8.as_ref().to_vec()).expect("signing key");
        let public = wist_auth::signing::decode_hex(&key.public_hex()).expect("public hex");

        let entry = Pusher::entry_of(&record());
        let signature = key.sign(&entry).expect("sign");
        assert!(
            wist_auth::signing::verify(&entry, &signature, std::slice::from_ref(&public)),
            "the pushed signature must verify"
        );

        // 改角色 / 延长有效期 → 同一个签名不再成立。
        let mut escalated = entry.clone();
        escalated.roles.push("admin".to_string());
        assert!(!wist_auth::signing::verify(
            &escalated,
            &signature,
            std::slice::from_ref(&public)
        ));
        let mut extended = entry;
        extended.expires_at += 86_400;
        assert!(!wist_auth::signing::verify(
            &extended,
            &signature,
            std::slice::from_ref(&public)
        ));
    }

    #[test]
    fn a_404_points_at_the_missing_push_path() {
        // 「探活绿、推送 404」那个坑：报错必须自己说出原因，
        // 否则现场只能看到一句 `404 Not Found`。
        let message = Pusher::reject_reason(
            "register",
            "wist-center",
            "https://h:3103",
            reqwest::StatusCode::NOT_FOUND,
            "",
        );
        assert!(
            message.contains("did not match the verifier's push route"),
            "{message}"
        );
        assert!(
            message.contains(crate::peers::DEFAULT_PUSH_PATH),
            "the hint must name the path: {message}"
        );
        assert!(message.contains("https://h:3103"), "{message}");
    }

    #[test]
    fn other_failures_keep_the_plain_message() {
        let message = Pusher::reject_reason(
            "register",
            "wist-center",
            "https://h:3103/api/v1/internal/credentials",
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            "boom",
        );
        assert!(message.contains("500"), "{message}");
        assert!(message.contains("boom"), "{message}");
        assert!(
            !message.contains("push route"),
            "no path hint when the path is not the problem: {message}"
        );
    }
}
