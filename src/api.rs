//! HTTP 面。
//!
//! 三个端点 + 两个探针：
//!
//! | 端点 | 语义 |
//! |---|---|
//! | `POST /api/v1/credentials` | 为程序创建凭据；**明文只在响应里出现一次** |
//! | `GET  /api/v1/credentials` | 列出已发放凭据（**永不含摘要与明文**） |
//! | `GET  /api/v1/credentials/{id}` | 单条 |
//! | `POST /api/v1/credentials/{id}/revoke` | 撤销（幂等） |
//! | `GET  /healthz` / `GET /version` | 探针 |
//!
//! 人身份来自内网入口注入的操作者头（D17）；对端不在 `trusted_peers` 内直接拒绝（S3）。

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::config::{AuthMode, Config};
use crate::store::{CredentialRecord, Store};

const TOKEN_PREFIX: &str = "wcr_";

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<Store>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(landing))
        .route("/healthz", get(healthz))
        .route("/version", get(version))
        .route(
            "/api/v1/credentials",
            get(list_credentials).post(create_credential),
        )
        .route("/api/v1/credentials/{id}", get(get_credential))
        .route("/api/v1/credentials/{id}/revoke", post(revoke_credential))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    /// 程序名（凭据归属的程序，不是人）。
    subject: String,
    /// 为什么要这把钥匙；会进审计。
    purpose: String,
    roles: Vec<String>,
    #[serde(default)]
    resources: BTreeMap<String, Vec<String>>,
    /// 这条凭据只对哪个 X 有效。
    audience: String,
    /// 应急凭据：上限按 `break_glass_max_ttl_seconds` 算。
    #[serde(default)]
    break_glass: bool,
    #[serde(default)]
    ttl_seconds: Option<u64>,
}

async fn healthz() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// 根路径自述：本服务只有 API，没有页面（避免“浏览器打开一片空白”被当成挂了）。
async fn landing() -> impl IntoResponse {
    Json(json!({
        "service": "wist-cred",
        "version": env!("CARGO_PKG_VERSION"),
        "note": "API only; the management page is served by wist-cred-web",
        "endpoints": [
            "GET  /healthz",
            "GET  /version",
            "GET  /api/v1/credentials",
            "POST /api/v1/credentials",
            "GET  /api/v1/credentials/{id}",
            "POST /api/v1/credentials/{id}/revoke",
        ],
        "auth": "requests under /api/v1 need the operator header injected by the ingress",
    }))
}

async fn version(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "name": "wist-cred",
        "version": env!("CARGO_PKG_VERSION"),
        "mode": mode_name(state.config.server.mode),
        "targets": state.config.issue.targets.len(),
    }))
}

async fn create_credential(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CreateRequest>,
) -> Response {
    let owner = match authorize(&state.config, peer, &headers) {
        Ok(operator) => operator,
        Err(denied) => return denied.into_response(),
    };

    let subject = body.subject.trim().to_string();
    if subject.is_empty() || !subject.chars().all(is_subject_char) {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_subject",
            "subject must be non-empty and use [A-Za-z0-9._-] only",
        );
    }

    let purpose = body.purpose.trim().to_string();
    if purpose.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "purpose_required",
            "purpose must not be empty (it goes into the audit trail)",
        );
    }

    if body.roles.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "roles_required",
            "roles must list at least one role",
        );
    }

    let audience = body.audience.trim().to_string();
    if audience.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "audience_required",
            "audience must name the target service",
        );
    }
    if !state.config.issue.targets.is_empty()
        && !state
            .config
            .issue
            .targets
            .iter()
            .any(|target| target.audience == audience)
    {
        return err(
            StatusCode::BAD_REQUEST,
            "audience_not_configured",
            format!("audience {audience:?} is not a configured push target"),
        );
    }

    let cap = if body.break_glass {
        state.config.issue.break_glass_max_ttl_seconds
    } else {
        state.config.issue.max_ttl_seconds
    };
    let ttl = body.ttl_seconds.unwrap_or(cap).min(cap);
    if ttl == 0 {
        return err(
            StatusCode::BAD_REQUEST,
            "ttl_out_of_range",
            "ttl_seconds must be > 0",
        );
    }

    let token = generate_token();
    let now = now_secs();
    let record = CredentialRecord {
        credential_id: format!("cred_{}", random_hex(8)),
        digest: sha256_hex(&token),
        subject,
        owner,
        purpose,
        roles: body.roles,
        resources: body.resources,
        audience,
        break_glass: body.break_glass,
        issued_at: now,
        expires_at: now + ttl as i64,
        revision: 1,
        revoked_at: None,
        last_used_at: None,
    };

    if let Err(error) = state.store.insert(record.clone()) {
        log::error!("insert credential failed: {error:#}");
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "store_unavailable",
            "failed to persist credential",
        );
    }

    log::info!(
        "credential issued: id={} subject={} owner={} audience={} ttl={}s break_glass={}",
        record.credential_id,
        record.subject,
        record.owner,
        record.audience,
        ttl,
        record.break_glass
    );

    let mut body = summary(&record);
    body["token"] = json!(token);
    (StatusCode::CREATED, Json(body)).into_response()
}

async fn list_credentials(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Err(denied) = authorize(&state.config, peer, &headers) {
        return denied.into_response();
    }
    match state.store.list() {
        Ok(items) => {
            let items: Vec<Value> = items.iter().map(summary).collect();
            Json(json!({ "credentials": items })).into_response()
        }
        Err(error) => {
            log::error!("list credentials failed: {error:#}");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_unavailable",
                "failed to read credential store",
            )
        }
    }
}

async fn get_credential(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AxumPath(credential_id): AxumPath<String>,
) -> Response {
    if let Err(denied) = authorize(&state.config, peer, &headers) {
        return denied.into_response();
    }
    match state.store.get(&credential_id) {
        Ok(Some(record)) => Json(summary(&record)).into_response(),
        Ok(None) => err(
            StatusCode::NOT_FOUND,
            "credential_not_found",
            "credential not found",
        ),
        Err(error) => {
            log::error!("get credential failed: {error:#}");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_unavailable",
                "failed to read credential store",
            )
        }
    }
}

async fn revoke_credential(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AxumPath(credential_id): AxumPath<String>,
) -> Response {
    let operator = match authorize(&state.config, peer, &headers) {
        Ok(operator) => operator,
        Err(denied) => return denied.into_response(),
    };
    match state.store.revoke(&credential_id, now_secs()) {
        Ok(Some(record)) => {
            log::info!(
                "credential revoked: id={} by={} revision={}",
                record.credential_id,
                operator,
                record.revision
            );
            Json(summary(&record)).into_response()
        }
        Ok(None) => err(
            StatusCode::NOT_FOUND,
            "credential_not_found",
            "credential not found",
        ),
        Err(error) => {
            log::error!("revoke credential failed: {error:#}");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_unavailable",
                "failed to persist revocation",
            )
        }
    }
}

/// 人机面的授权失败：小结构，避免 `Result<_, Response>` 触发 `result_large_err`。
struct Denied {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl Denied {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    fn into_response(self) -> Response {
        err(self.status, self.code, self.message)
    }
}

/// 人机面的授权：peer 必须在 `trusted_peers` 内（S3），且必须带操作者头（D17）。
fn authorize(config: &Config, peer: SocketAddr, headers: &HeaderMap) -> Result<String, Denied> {
    if !peer_allowed(config, peer.ip()) {
        log::warn!("untrusted ingress peer rejected: {peer}");
        return Err(Denied::new(
            StatusCode::UNAUTHORIZED,
            "untrusted_ingress_peer",
            "peer is not in server.trusted_peers",
        ));
    }
    if config.server.mode != AuthMode::Ingress {
        return Err(Denied::new(
            StatusCode::UNAUTHORIZED,
            "unsupported_auth_mode",
            "only ingress mode is implemented",
        ));
    }
    let operator = headers
        .get(config.server.ingress_header.as_str())
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match operator {
        Some(operator) => Ok(operator.to_string()),
        None => Err(Denied::new(
            StatusCode::UNAUTHORIZED,
            "missing_operator",
            format!(
                "missing {} header (injected by the internal ingress)",
                config.server.ingress_header
            ),
        )),
    }
}

/// `trusted_peers`：CIDR / 单个 IP。`unix:` 条目对 TCP 对端不适用，跳过。
fn peer_allowed(config: &Config, ip: IpAddr) -> bool {
    config.server.trusted_peers.iter().any(|rule| {
        let rule = rule.trim();
        if rule.is_empty() || rule.starts_with("unix:") {
            return false;
        }
        match parse_rule(rule) {
            Some(parsed) => parsed.matches(ip),
            None => {
                log::warn!("ignoring unparseable trusted_peers entry: {rule}");
                false
            }
        }
    })
}

enum PeerRule {
    Exact(IpAddr),
    V4([u8; 4], u8),
    V6([u8; 16], u8),
}

impl PeerRule {
    fn matches(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (PeerRule::Exact(expected), actual) => *expected == actual,
            (PeerRule::V4(network, prefix), IpAddr::V4(actual)) => {
                prefix_eq(&network[..], &actual.octets()[..], *prefix as usize)
            }
            (PeerRule::V6(network, prefix), IpAddr::V6(actual)) => {
                prefix_eq(&network[..], &actual.octets()[..], *prefix as usize)
            }
            _ => false,
        }
    }
}

fn prefix_eq(network: &[u8], actual: &[u8], prefix: usize) -> bool {
    let full = prefix / 8;
    let rest = prefix % 8;
    if network[..full] != actual[..full] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    network[full] & mask == actual[full] & mask
}

fn parse_rule(rule: &str) -> Option<PeerRule> {
    match rule.split_once('/') {
        None => rule.parse::<IpAddr>().ok().map(PeerRule::Exact),
        Some((addr, prefix)) => {
            let prefix: u8 = prefix.parse().ok()?;
            match addr.parse::<IpAddr>().ok()? {
                IpAddr::V4(ip) if prefix <= 32 => Some(PeerRule::V4(ip.octets(), prefix)),
                IpAddr::V6(ip) if prefix <= 128 => Some(PeerRule::V6(ip.octets(), prefix)),
                _ => None,
            }
        }
    }
}

fn is_subject_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
}

fn summary(record: &CredentialRecord) -> Value {
    json!({
        "credential_id": record.credential_id,
        "subject": record.subject,
        "owner": record.owner,
        "purpose": record.purpose,
        "roles": record.roles,
        "resources": record.resources,
        "audience": record.audience,
        "break_glass": record.break_glass,
        "issued_at": record.issued_at,
        "expires_at": record.expires_at,
        "revision": record.revision,
        "revoked_at": record.revoked_at,
        "last_used_at": record.last_used_at,
    })
}

fn err(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message.into() } })),
    )
        .into_response()
}

fn mode_name(mode: AuthMode) -> &'static str {
    match mode {
        AuthMode::Ingress => "ingress",
        AuthMode::Oidc => "oidc",
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

fn generate_token() -> String {
    format!("{TOKEN_PREFIX}{}", random_hex(32))
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer).expect("OS entropy");
    buffer.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{IssueConfig, ServerConfig, StorageConfig};

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const OPERATOR_HEADER: &str = "x-wist-operator";

    struct Harness {
        _dir: TempDir,
        state: AppState,
    }

    impl Harness {
        fn new() -> Self {
            let dir = TempDir::new();
            let config = Config {
                server: ServerConfig {
                    listen_addr: "127.0.0.1:8443".to_string(),
                    mode: AuthMode::Ingress,
                    ingress_header: OPERATOR_HEADER.to_string(),
                    trusted_peers: vec!["127.0.0.1/32".to_string()],
                },
                storage: StorageConfig {
                    path: dir.path.join("credentials.db"),
                },
                issue: IssueConfig {
                    digest: "sha256".to_string(),
                    max_ttl_seconds: 2_592_000,
                    break_glass_max_ttl_seconds: 7_776_000,
                    overlap_seconds: 300,
                    targets: Vec::new(),
                },
            };
            let store = Store::open(config.storage.path.clone()).expect("open store");
            Self {
                _dir: dir,
                state: AppState {
                    config: Arc::new(config),
                    store: Arc::new(store),
                },
            }
        }

        fn with_targets(mut self) -> Self {
            let mut config = (*self.state.config).clone();
            config.issue.targets = vec![crate::config::TargetConfig {
                name: "wist-center".to_string(),
                endpoint: "https://center:3103/api/v1/internal/credentials".to_string(),
                audience: "wist-center".to_string(),
                client_cert: None,
                client_key: None,
                ca: None,
            }];
            self.state.config = Arc::new(config);
            self
        }

        async fn call(
            &self,
            method: &str,
            uri: &str,
            operator: Option<&str>,
            peer: &str,
            body: Option<Value>,
        ) -> (StatusCode, Value) {
            let mut builder = Request::builder().method(method).uri(uri);
            if let Some(operator) = operator {
                builder = builder.header(OPERATOR_HEADER, operator);
            }
            let request = match body {
                Some(body) => builder
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
                None => builder.body(Body::empty()).unwrap(),
            };
            let peer: SocketAddr = format!("{peer}:40000").parse().unwrap();
            let mut request = request;
            request.extensions_mut().insert(ConnectInfo(peer));

            let response = router(self.state.clone()).oneshot(request).await.unwrap();
            let status = response.status();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let value = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            (status, value)
        }

        fn store_text(&self) -> String {
            std::fs::read_to_string(&self.state.config.storage.path).unwrap_or_default()
        }
    }

    fn create_body() -> Value {
        json!({
            "subject": "ci-nightly",
            "purpose": "nightly disk inspection",
            "roles": ["investigation:run"],
            "resources": { "agents": ["agent-7f3"] },
            "audience": "wist-center"
        })
    }

    #[tokio::test]
    async fn landing_and_healthz_are_reachable_without_auth() {
        let harness = Harness::new();

        let (status, body) = harness.call("GET", "/", None, "127.0.0.1", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["service"], "wist-cred");
        assert!(
            body["endpoints"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
        );

        let (status, body) = harness
            .call("GET", "/healthz", None, "127.0.0.1", None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
    }

    #[tokio::test]
    async fn create_returns_token_once_and_stores_only_the_digest() {
        let harness = Harness::new();
        let (status, body) = harness
            .call(
                "POST",
                "/api/v1/credentials",
                Some("alice"),
                "127.0.0.1",
                Some(create_body()),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");

        let token = body["token"].as_str().expect("token").to_string();
        assert!(token.starts_with(TOKEN_PREFIX));
        assert_eq!(body["owner"], "alice");
        assert_eq!(body["revision"], 1);

        let stored = harness.store_text();
        assert!(
            !stored.contains(&token),
            "plaintext token must never hit disk"
        );
        assert!(
            stored.contains(&sha256_hex(&token)),
            "digest must be stored"
        );

        // 列表永远不返回明文或摘要
        let (status, listed) = harness
            .call(
                "GET",
                "/api/v1/credentials",
                Some("alice"),
                "127.0.0.1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let text = listed.to_string();
        assert!(!text.contains(&token));
        assert!(!text.contains(&sha256_hex(&token)));
    }

    #[tokio::test]
    async fn missing_operator_is_rejected() {
        let harness = Harness::new();
        let (status, body) = harness
            .call(
                "POST",
                "/api/v1/credentials",
                None,
                "127.0.0.1",
                Some(create_body()),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "missing_operator");
    }

    #[tokio::test]
    async fn untrusted_peer_is_rejected() {
        let harness = Harness::new();
        let (status, body) = harness
            .call(
                "POST",
                "/api/v1/credentials",
                Some("alice"),
                "10.9.9.9",
                Some(create_body()),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "untrusted_ingress_peer");
    }

    #[tokio::test]
    async fn ttl_is_clamped_to_the_cap() {
        let harness = Harness::new();
        let mut body = create_body();
        body["ttl_seconds"] = json!(99_999_999_999u64);
        let (status, created) = harness
            .call(
                "POST",
                "/api/v1/credentials",
                Some("alice"),
                "127.0.0.1",
                Some(body),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);

        let issued = created["issued_at"].as_i64().unwrap();
        let expires = created["expires_at"].as_i64().unwrap();
        assert_eq!(expires - issued, 2_592_000);
    }

    #[tokio::test]
    async fn break_glass_uses_the_longer_cap() {
        let harness = Harness::new();
        let mut body = create_body();
        body["break_glass"] = json!(true);
        body["ttl_seconds"] = json!(99_999_999_999u64);
        let (status, created) = harness
            .call(
                "POST",
                "/api/v1/credentials",
                Some("alice"),
                "127.0.0.1",
                Some(body),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
        let issued = created["issued_at"].as_i64().unwrap();
        let expires = created["expires_at"].as_i64().unwrap();
        assert_eq!(expires - issued, 7_776_000);
    }

    #[tokio::test]
    async fn purpose_is_required() {
        let harness = Harness::new();
        let mut body = create_body();
        body["purpose"] = json!("   ");
        let (status, created) = harness
            .call(
                "POST",
                "/api/v1/credentials",
                Some("alice"),
                "127.0.0.1",
                Some(body),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(created["error"]["code"], "purpose_required");
    }

    #[tokio::test]
    async fn audience_must_be_a_configured_target() {
        let harness = Harness::new().with_targets();
        let mut body = create_body();
        body["audience"] = json!("wist-elsewhere");
        let (status, created) = harness
            .call(
                "POST",
                "/api/v1/credentials",
                Some("alice"),
                "127.0.0.1",
                Some(body),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(created["error"]["code"], "audience_not_configured");
    }

    #[tokio::test]
    async fn revoke_is_idempotent() {
        let harness = Harness::new();
        let (_, created) = harness
            .call(
                "POST",
                "/api/v1/credentials",
                Some("alice"),
                "127.0.0.1",
                Some(create_body()),
            )
            .await;
        let id = created["credential_id"].as_str().unwrap().to_string();
        let uri = format!("/api/v1/credentials/{id}/revoke");

        let (status, first) = harness
            .call("POST", &uri, Some("alice"), "127.0.0.1", None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["revision"], 2);
        assert!(!first["revoked_at"].is_null());

        let (status, second) = harness
            .call("POST", &uri, Some("bob"), "127.0.0.1", None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second["revision"], 2, "second revoke must not bump again");
        assert_eq!(second["revoked_at"], first["revoked_at"]);
    }

    #[tokio::test]
    async fn unknown_credential_is_404() {
        let harness = Harness::new();
        let (status, body) = harness
            .call(
                "GET",
                "/api/v1/credentials/cred_nope",
                Some("alice"),
                "127.0.0.1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "credential_not_found");
    }

    #[test]
    fn peer_rules_match_cidr() {
        let rule = parse_rule("10.0.20.0/24").expect("rule");
        assert!(rule.matches("10.0.20.11".parse().unwrap()));
        assert!(!rule.matches("10.0.21.11".parse().unwrap()));
        let rule = parse_rule("127.0.0.1").expect("rule");
        assert!(rule.matches("127.0.0.1".parse().unwrap()));
        assert!(!rule.matches("127.0.0.2".parse().unwrap()));
    }

    /// 临时目录：不引第三方 crate。
    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let mut bytes = [0u8; 8];
            getrandom::fill(&mut bytes).expect("entropy");
            let name: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = std::env::temp_dir().join(format!("wist-cred-api-{name}"));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
