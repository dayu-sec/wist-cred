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
//!
//! # 失败必须分类
//!
//! 以前所有失败都是一句 `anyhow` 字符串，API 层只能统回「稍后重试」—— 可「对方说不认识这个
//! 受众」是**改配置才好**的永久错误，重试一辈子也不会成功。现在分成三类（见 [`PushError`]），
//! 并把稳定码与生态分类交给 `orion-error` 的 `ErrorIdentityProvider`：API 层只从这一处取
//! `code`，不自己拼字符串。
//!
//! # 日志只在一处
//!
//! 这里**只记成功**（单行、info）：失败会以 API 错误形态返回页面，由 `ApiError` 记那一行
//! 带 `request_id` 的日志。两处都记会让同一次故障出现两行，而且推送那行没有对账 id；
//! 撤销广播这类没有 API 返回的路径由调用方自己记（见 `api::revoke_credential`）。

use std::fmt;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context;
use orion_error::reason::{ErrorCategory, ErrorIdentityProvider};
use reqwest::{Certificate, Client, Identity};
use serde_json::{Value, json};
use wist_auth::credential::CredentialEntry;

use crate::config::SigningKey;
use crate::store::CredentialRecord;

/// 推送失败的两类原因。
///
/// 它们的处置**完全不同**（这是 `retryable` 的来源）：
///
/// - [`PushError::Rejected`]：对端收到了、但**拒绝**（4xx 带业务码，如 `audience_mismatch`）。
///   永久错误：重试无用，要人改配置。
/// - [`PushError::Unreachable`]：根本没连上（DNS / TCP / TLS / 超时 / 对端重启）。
///   瞬时错误：稍后重试有意义。
/// - [`PushError::Internal`]：本地把请求造出来就失败了（签名、序列化）。属于我们的 bug/环境问题。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushError {
    Rejected {
        /// `register` / `revoke`。
        action: &'static str,
        peer: String,
        endpoint: String,
        /// 上游的 HTTP 状态（4xx / 5xx）。
        status: u16,
        /// 上游错误体里的业务码（能解析出来才有）。
        code: Option<String>,
        /// 上游错误体里的可暴露短文本。
        message: String,
    },
    Unreachable {
        action: &'static str,
        peer: String,
        endpoint: String,
        detail: String,
    },
    Internal {
        action: &'static str,
        detail: String,
    },
}

impl PushError {
    pub fn action(&self) -> &'static str {
        match self {
            Self::Rejected { action, .. }
            | Self::Unreachable { action, .. }
            | Self::Internal { action, .. } => action,
        }
    }

    /// 对端明确拒绝（而不是没连上）。
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }

    /// 上游拒绝是否属于「客户端侧错误」（4xx）：重试无用。
    pub fn is_client_side_rejection(&self) -> bool {
        matches!(self, Self::Rejected { status, .. } if (400..500).contains(status))
    }

    pub fn peer(&self) -> Option<&str> {
        match self {
            Self::Rejected { peer, .. } | Self::Unreachable { peer, .. } => Some(peer),
            Self::Internal { .. } => None,
        }
    }
}

impl fmt::Display for PushError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected {
                action,
                peer,
                endpoint,
                status,
                code,
                message,
            } => {
                write!(f, "push {action} to {peer} rejected: HTTP {status}")?;
                if let Some(code) = code {
                    write!(f, " ({code})")?;
                }
                if !message.is_empty() {
                    write!(f, " {message}")?;
                }
                if *status == 404 {
                    // 404 几乎总是收数地址没带路径：`probe_url` 会把路径剔掉（`origin + /healthz`），
                    // 所以那种地址**探活是绿的**，只有推送会 404。不点名的话现场只能看到一句
                    // `404 Not Found`（本地联调就是这么被坑了一次）。
                    write!(
                        f,
                        "; endpoint {endpoint:?} did not match the verifier's push route — \
                         it must include the push path (e.g. {})",
                        crate::peers::DEFAULT_PUSH_PATH
                    )?;
                }
                Ok(())
            }
            Self::Unreachable {
                action,
                peer,
                endpoint,
                detail,
            } => write!(f, "push {action} to {peer} ({endpoint}) failed: {detail}"),
            Self::Internal { action, detail } => write!(f, "push {action} failed: {detail}"),
        }
    }
}

impl std::error::Error for PushError {}

/// 交给 `orion-error` 的稳定码分类：日志、指标、API 投影共用同一套叫法。
impl ErrorIdentityProvider for PushError {
    fn stable_code(&self) -> &'static str {
        match self {
            Self::Rejected { .. } => "verifier_rejected",
            Self::Unreachable { .. } => "verifier_unreachable",
            Self::Internal { .. } => "push_internal",
        }
    }

    fn error_category(&self) -> ErrorCategory {
        match self {
            // 4xx 是对端在契约/配置上拒收（业务问题）；5xx 是对端自己坏了（系统问题）。
            Self::Rejected { status, .. } if (400..500).contains(status) => ErrorCategory::Biz,
            Self::Rejected { .. } => ErrorCategory::Sys,
            // 连不上是系统问题；造请求失败是本地逻辑问题。
            Self::Unreachable { .. } => ErrorCategory::Sys,
            Self::Internal { .. } => ErrorCategory::Logic,
        }
    }
}

/// 一次推送的**单行**生命周期日志（只记成功）。
///
/// 失败不在这里记：它最终会以 API 错误形态返回（`ApiError` 记一行带 `request_id` 的日志，
/// 并带上 `category` / `peer` / `upstream_code`），两处都记会让同一次故障出现两行。
fn logged_push<T>(
    action: &'static str,
    peer: &str,
    endpoint: &str,
    result: Result<T, PushError>,
) -> Result<T, PushError> {
    if result.is_ok() {
        log::info!("push {action} ok: peer={peer} endpoint={endpoint}");
    }
    result
}

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

    fn signature_for(&self, record: &CredentialRecord) -> Result<Option<String>, PushError> {
        match &self.signing {
            Some(signing) => signing
                .sign(&Self::entry_of(record))
                .map(Some)
                .map_err(|error| PushError::Internal {
                    action: "sign",
                    detail: format!("{error:#}"),
                }),
            None => Ok(None),
        }
    }

    /// 登记一条凭据。失败意味着"对方没认"，调用方据此决定要不要交付明文。
    pub async fn register(
        &self,
        peer: &str,
        endpoint: &str,
        record: &CredentialRecord,
    ) -> Result<(), PushError> {
        let result = self.register_inner(peer, endpoint, record).await;
        logged_push("register", peer, endpoint, result)
    }

    async fn register_inner(
        &self,
        peer: &str,
        endpoint: &str,
        record: &CredentialRecord,
    ) -> Result<(), PushError> {
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
            .map_err(|error| unreachable("register", peer, endpoint, &error))?;

        if response.status() == reqwest::StatusCode::CONFLICT {
            // 对端已经有同一条（或更新的）记录：X 只在 `revision` 前进时才接受。
            // 对“重新投递”而言这就是目标状态，不算失败。
            log::debug!("push register to {peer} was already present (409)");
            return Ok(());
        }
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(rejected("register", peer, endpoint, status, &text));
        }
        Ok(())
    }

    /// 撤销：对端不认识这条凭据（404）视为已完成（可能已清理）。
    pub async fn revoke(
        &self,
        peer: &str,
        endpoint: &str,
        record: &CredentialRecord,
    ) -> Result<(), PushError> {
        let url = format!(
            "{}/{}/revoke",
            endpoint.trim_end_matches('/'),
            record.credential_id
        );
        let result = self.revoke_inner(peer, &url, record).await;
        logged_push("revoke", peer, &url, result)
    }

    async fn revoke_inner(
        &self,
        peer: &str,
        url: &str,
        record: &CredentialRecord,
    ) -> Result<(), PushError> {
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
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|error| unreachable("revoke", peer, url, &error))?;
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
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        Err(rejected("revoke", peer, url, status, &text))
    }

    /// 心跳：探一次可达性，返回耗时（毫秒）。2xx 才算在线。
    ///
    /// 探测本身走同一套 mTLS —— 「能握手」比「能 ping 通」有意义得多：
    /// 证书过期、链不对、时间偏了，都会在这里暴露，而不是等到推送失败。
    pub async fn probe(&self, url: &str) -> Result<u64, PushError> {
        let started = Instant::now();
        let response = self
            .client
            .get(url)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|error| PushError::Unreachable {
                action: "probe",
                peer: String::new(),
                endpoint: url.to_string(),
                detail: format!("{error:#}"),
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(PushError::Rejected {
                action: "probe",
                peer: String::new(),
                endpoint: url.to_string(),
                status: status.as_u16(),
                code: None,
                message: String::new(),
            });
        }
        Ok(started.elapsed().as_millis() as u64)
    }
}

/// 请求根本没发出去（DNS / TCP / TLS / 超时）。
fn unreachable(
    action: &'static str,
    peer: &str,
    endpoint: &str,
    error: &reqwest::Error,
) -> PushError {
    PushError::Unreachable {
        action,
        peer: peer.to_string(),
        endpoint: endpoint.to_string(),
        detail: format!("{error:#}"),
    }
}

/// 对端回了非 2xx：把它的业务码与短文案拆出来（拆不出就截断原文）。
fn rejected(
    action: &'static str,
    peer: &str,
    endpoint: &str,
    status: reqwest::StatusCode,
    body: &str,
) -> PushError {
    let (code, message) = parse_rejection(body);
    PushError::Rejected {
        action,
        peer: peer.to_string(),
        endpoint: endpoint.to_string(),
        status: status.as_u16(),
        code,
        message,
    }
}

/// 从验证方的错误体里取 `{"error":{"code","message"}}`；拿不到就把原文截断。
fn parse_rejection(body: &str) -> (Option<String>, String) {
    let trimmed = body.trim();
    if let Ok(value) = serde_json::from_str::<Value>(trimmed)
        && let Some(error) = value.get("error")
    {
        let code = error
            .get("code")
            .and_then(Value::as_str)
            .map(str::to_string);
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if code.is_some() || !message.is_empty() {
            return (code, message);
        }
    }
    (None, truncate(trimmed, 300))
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let head: String = text.chars().take(max).collect();
    format!("{head}…")
}

impl PushError {
    /// 上游业务码（日志与 API 的 `fields.upstream_code` 共用）。
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Rejected { code, .. } => code.as_deref(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_parses_the_upstream_business_code() {
        let body = r#"{"error":{"code":"audience_mismatch","message":"this service is \"wist-field-api\""}}"#;
        let (code, message) = parse_rejection(body);
        assert_eq!(code.as_deref(), Some("audience_mismatch"));
        assert!(message.contains("wist-field-api"));
    }

    #[test]
    fn rejection_falls_back_to_truncated_text() {
        let body = "x".repeat(400);
        let (code, message) = parse_rejection(&body);
        assert!(code.is_none());
        assert_eq!(message.chars().count(), 301); // 300 + 省略号
    }

    #[test]
    fn client_side_rejections_are_not_retryable_but_server_side_are() {
        let client = PushError::Rejected {
            action: "register",
            peer: "p".into(),
            endpoint: "e".into(),
            status: 400,
            code: Some("audience_mismatch".into()),
            message: String::new(),
        };
        assert!(client.is_client_side_rejection());

        let server = PushError::Rejected {
            action: "register",
            peer: "p".into(),
            endpoint: "e".into(),
            status: 503,
            code: None,
            message: String::new(),
        };
        assert!(!server.is_client_side_rejection());
    }

    #[test]
    fn stable_codes_match_the_api_projection() {
        let rejected = PushError::Rejected {
            action: "register",
            peer: "p".into(),
            endpoint: "e".into(),
            status: 409,
            code: None,
            message: String::new(),
        };
        assert_eq!(rejected.stable_code(), "verifier_rejected");

        let unreachable = PushError::Unreachable {
            action: "register",
            peer: "p".into(),
            endpoint: "e".into(),
            detail: "tls".into(),
        };
        assert_eq!(unreachable.stable_code(), "verifier_unreachable");
        assert_eq!(unreachable.error_category(), ErrorCategory::Sys);

        // 4xx 拒收是业务/契约问题；5xx 拒收是对端自己坏了 —— 两者处置不同，分类也得不同。
        assert_eq!(
            PushError::Rejected {
                action: "register",
                peer: "p".into(),
                endpoint: "e".into(),
                status: 400,
                code: None,
                message: String::new(),
            }
            .error_category(),
            ErrorCategory::Biz
        );
        assert_eq!(
            PushError::Rejected {
                action: "register",
                peer: "p".into(),
                endpoint: "e".into(),
                status: 503,
                code: None,
                message: String::new(),
            }
            .error_category(),
            ErrorCategory::Sys
        );
    }

    #[test]
    fn a_404_points_at_the_push_path() {
        let error = PushError::Rejected {
            action: "register",
            peer: "p".into(),
            endpoint: "https://x/api".into(),
            status: 404,
            code: None,
            message: "not found".into(),
        };
        let text = error.to_string();
        assert!(text.contains("push path"), "got: {text}");
    }
}
