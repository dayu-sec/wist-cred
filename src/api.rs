//! HTTP 面（骨架）。
//!
//! 本期只保证三件事：健康检查、版本、以及凭据端点的**稳定错误信封**。
//! 真正的签发 / 撤销 / 推送按设计文档的 P2 / P3 补齐。

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/version", get(version))
        .route(
            "/api/v1/credentials",
            get(list_credentials).post(create_credential),
        )
        .route("/api/v1/credentials/{id}/revoke", post(revoke_credential))
        .with_state(state)
}

async fn healthz() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

async fn version(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "name": "wist-cred",
        "version": env!("CARGO_PKG_VERSION"),
        "mode": mode_name(state.config.server.mode),
        "targets": state.config.issue.targets.len(),
    }))
}

async fn create_credential() -> impl IntoResponse {
    not_implemented("credential issuance is not implemented yet (design doc P2)")
}

async fn list_credentials() -> impl IntoResponse {
    not_implemented("credential listing is not implemented yet (design doc P2)")
}

async fn revoke_credential() -> impl IntoResponse {
    not_implemented("credential revocation is not implemented yet (design doc P2)")
}

/// 与 center 同口径：`{ "error": { "code": "...", "message": "..." } }`。
fn not_implemented(message: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({ "error": { "code": "not_implemented", "message": message } })),
    )
}

fn mode_name(mode: crate::config::AuthMode) -> &'static str {
    match mode {
        crate::config::AuthMode::Ingress => "ingress",
        crate::config::AuthMode::Oidc => "oidc",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthMode, IssueConfig, ServerConfig, StorageConfig};

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn state() -> AppState {
        AppState {
            config: Arc::new(Config {
                server: ServerConfig {
                    listen_addr: "127.0.0.1:8443".to_string(),
                    mode: AuthMode::Ingress,
                    ingress_header: "x-wist-operator".to_string(),
                    trusted_peers: vec!["127.0.0.1/32".to_string()],
                },
                storage: StorageConfig {
                    path: "state/credentials.db".into(),
                },
                issue: IssueConfig {
                    digest: "sha256".to_string(),
                    max_ttl_seconds: 60,
                    break_glass_max_ttl_seconds: 120,
                    overlap_seconds: 1,
                    targets: Vec::new(),
                },
            }),
        }
    }

    async fn body_json(response: axum::response::Response) -> Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn healthz_is_ok() {
        let response = router(state())
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn version_reports_mode() {
        let response = router(state())
            .oneshot(
                Request::builder()
                    .uri("/version")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["name"], "wist-cred");
        assert_eq!(body["mode"], "ingress");
    }

    #[tokio::test]
    async fn create_credential_is_not_implemented_yet() {
        let response = router(state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/credentials")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "not_implemented");
    }
}
