//! 闭环测试：**签发 → 登记 → 验证 → 撤销 → 再验证**。
//!
//! ```sh
//! cargo run --example closed_loop
//! ```
//!
//! 全程无网络、无数据库：
//!
//! 1. 用 `wist-cred` 的 HTTP 面（tower `oneshot`，不占端口）创建一条凭据；
//! 2. 把 cred 落盘的登记表喂给 `wist_auth::CredentialStore`（模拟 X 收到的 `register`）；
//! 3. 验证明文 → 拿到 `VerifiedCredential`；
//! 4. 调 cred 的 `revoke`；
//! 5. 重新登记 → 验证应报 `Revoked`。
//!
//! 这一步能跑通，说明两侧对 `register` 载荷的理解是一致的。

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::{Value, json};
use tower::ServiceExt;

use wist_auth::credential::{CredentialEntry, CredentialError, CredentialStore, StoreParams};
use wist_cred::api::{self, AppState};
use wist_cred::config::{
    AuthMode, Config, IssueConfig, OnboardingConfig, ServerConfig, StorageConfig,
};
use wist_cred::onboarding::TicketStore;
use wist_cred::peers::{NewPeer, PeerRegistry};
use wist_cred::store::Store;

const OPERATOR_HEADER: &str = "x-wist-operator";

#[derive(Deserialize)]
struct CredFile {
    #[serde(default)]
    credentials: Vec<CredentialEntry>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join(format!("wist-cred-closed-loop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let cred_store_path = dir.join("credentials.db");

    let config = Config {
        server: ServerConfig {
            listen_addr: "127.0.0.1:18443".to_string(),
            mode: AuthMode::Ingress,
            ingress_header: OPERATOR_HEADER.to_string(),
            admin_password_hash: String::new(),
            trusted_peers: vec!["127.0.0.1/32".to_string()],
            public_base_url: None,
        },
        storage: StorageConfig {
            path: cred_store_path.clone(),
        },
        issue: IssueConfig {
            digest: "sha256".to_string(),
            max_ttl_seconds: 2_592_000,
            break_glass_max_ttl_seconds: 7_776_000,
            overlap_seconds: 300,
            // 本示例模拟“手工分发”（不走 push），所以不需要签发钥；
            // 真实推送会在这里配 Ed25519 私钥，X 侧开 require_signature 验签。
            signing_key: None,
        },
        push: None,
        onboarding: OnboardingConfig {
            dir: None,
            store_path: dir.join("peers.json"),
            script_ttl_seconds: 900,
            ca_cert: None,
            ca_key: None,
            client_ca: None,
            peer_cert_ttl_seconds: 7_776_000,
            heartbeat_seconds: 0,
        },
    };

    // 一个认证系统（有受众才有意义；没有 endpoint = 人工分发模式）。
    let peers = Arc::new(PeerRegistry::open(config.onboarding.store_path.clone())?);
    peers
        .create(
            NewPeer {
                name: "wist-center".to_string(),
                host: Some("center.internal".to_string()),
                endpoint: None,
                healthz: None,
                roles: vec!["investigation:run".to_string()],
                install_dir: None,
                config_path: None,
                restart_cmd: None,
            },
            "closed-loop",
        )
        .map_err(|err| anyhow::anyhow!("create peer: {err:?}"))?;

    let state = AppState {
        config: Arc::new(config.clone()),
        store: Arc::new(Store::open(cred_store_path.clone())?),
        push: None,
        boarding: Arc::new(TicketStore::new(config.onboarding.script_ttl_seconds)),
        signer: None,
        peers,
    };

    // ── ① 签发 ──────────────────────────────────────────────
    let created = call(
        &state,
        "POST",
        "/api/v1/credentials",
        Some(json!({
            "subject": "ci-nightly",
            "purpose": "closed-loop demo",
            "roles": ["investigation:run"],
            "resources": { "agents": ["agent-7f3"] },
            "audience": "wist-center"
        })),
    )
    .await?;
    let token = created["token"].as_str().expect("token").to_string();
    let credential_id = created["credential_id"].as_str().expect("id").to_string();
    println!("① cred 签发   credential_id={credential_id}");
    println!("   token={}…（只此一次）", &token[..12]);

    // ── ② 登记到 X ─────────────────────────────────────────
    let x = build_verifier(&cred_store_path)?;
    println!("② X 登记完成   条目 {} 条", x.entries().len());

    // ── ③ 验证 ─────────────────────────────────────────────
    let verified = x
        .verify(&token, "wist-center")
        .map_err(|error| anyhow::anyhow!("verify failed: {error}"))?;
    println!(
        "③ 验证通过     subject={} roles={:?} resources={:?}",
        verified.subject, verified.roles, verified.resources
    );

    // 负例：拿同一条 token 去打另一个服务
    let error = x.verify(&token, "wist-ingest").unwrap_err();
    println!("   跨服务重放被拒  code={}", error.code());

    // ── ④ 撤销 ─────────────────────────────────────────────
    let revoked = call(
        &state,
        "POST",
        &format!("/api/v1/credentials/{credential_id}/revoke"),
        None,
    )
    .await?;
    println!("④ cred 撤销   revision={}", revoked["revision"]);

    // ── ⑤ 再验证 ───────────────────────────────────────────
    let x = build_verifier(&cred_store_path)?;
    let error = x.verify(&token, "wist-center").unwrap_err();
    assert_eq!(error, CredentialError::Revoked, "撤销后必须验不过");
    println!(
        "⑤ 再验证失败    code={} status={}",
        error.code(),
        error.status()
    );

    let _ = std::fs::remove_dir_all(&dir);
    println!("\n闭环成立：cred 签发的一次性明文，X 侧本地可验、可撤销、不可跨服务重放。");
    Ok(())
}

/// 读 cred 落盘的登记表，逐条 `register` 进 X 侧的真实实现。
fn build_verifier(path: &std::path::Path) -> anyhow::Result<CredentialStore> {
    let text = std::fs::read_to_string(path)?;
    let file: CredFile = serde_json::from_str(&text)?;

    let mut roles: Vec<String> = file
        .credentials
        .iter()
        .flat_map(|entry| entry.roles.clone())
        .collect();
    roles.sort_unstable();
    roles.dedup();

    let mut caps: BTreeMap<String, i64> = BTreeMap::new();
    caps.insert("investigation:run".to_string(), 86_400);
    caps.insert("read".to_string(), 3_600);

    let store = CredentialStore::in_memory(StoreParams {
        known_roles: roles,
        max_ttl_by_role: caps,
        visible_resources: None,
        clock_skew_seconds: 60,
        require_signature: false,
        issuer_public_keys: Vec::new(),
    });
    for entry in file.credentials {
        store.register(entry)?;
    }
    Ok(store)
}

async fn call(
    state: &AppState,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> anyhow::Result<Value> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(OPERATOR_HEADER, "alice");
    let request = match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))?,
        None => builder.body(Body::empty())?,
    };
    let mut request = request;
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:40000".parse::<std::net::SocketAddr>()?,
    ));

    let response = api::router(state.clone()).oneshot(request).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    let value: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    anyhow::ensure!(status.is_success(), "{method} {uri} → {status}: {value}");
    Ok(value)
}
