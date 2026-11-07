//! HTTP 错误投影（设计 `foundation/error-handling-system.md` §6）。
//!
//! 对外形状与 gateway / center **完全一致**（共用 `wist_shared::protocol::ProtocolError`）：
//!
//! ```json
//! { "error": { "code": "…", "message": "…", "retryable": false,
//!              "severity": "warning", "correlation_id": "…",
//!              "fields": { "peer": "wist-field", "upstream_code": "audience_mismatch" } } }
//! ```
//!
//! 两条硬口径：
//!
//! - **内部原因不进响应体**：source / detail / backtrace 只写本地日志（单行、带同一个
//!   `correlation_id`），响应里只留可暴露的 `message` 与结构化 `fields`；
//! - **`retryable` 必须说实话**：默认值与 gateway / center 是同一条规则 ——
//!   `429/502/503/504` 判可重试，其余 4xx 判不可重试，**其它 5xx（500 等）不臆断**
//!   （字段不出）。需要时显式覆盖：「上游 4xx 拒绝」是 409 / 不可重试（改配置才好），
//!   「连不上」是 502 / 可重试，「本部署没配 CA」是 503 / **不可重试**。
//!   这一项直接决定页面是给「重试」按钮，还是给「去修什么」的指引。
//!
//! 日志级别也跟着「瞬时上游故障」走：`502/503/504` 记 `warn`（对端没起来是日常），
//! 其余 5xx 才记 `error`。

use std::fmt::Display;

use axum::Json;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value};
use wist_shared::protocol::{ProtocolError, ProtocolErrorEnvelope, Severity};

/// 响应头 + 错误体都带同一个 id：页面报错能直接对上容器日志。
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// 人机面的错误。`IntoResponse` 一次做完三件事：投影 wire 形状、记一行日志、带 request id。
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    body: ProtocolError,
    /// 额外顶层字段（例如“已签发但未送达”时附带的 `credential`）。
    extra: Map<String, Value>,
    /// 额外响应头（例如带明文 token 时必须 `no-store`）。
    headers: Vec<(HeaderName, HeaderValue)>,
    /// 内部原因：只进日志，不进响应。
    cause: Option<String>,
    /// 内部原因的生态分类（`biz` / `sys` / `logic` / `conf`）：跟 cause 一起只进日志。
    cause_category: Option<&'static str>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        let mut body = ProtocolError::new(code, message);
        body.severity = Some(default_severity(status));
        body.retryable = default_retryable(status);
        Self {
            status,
            body,
            extra: Map::new(),
            headers: Vec::new(),
            cause: None,
            cause_category: None,
        }
    }

    /// 覆盖默认严重度（默认只由 status 推）。
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.body.severity = Some(severity);
        self
    }

    /// 覆盖默认可重试语义（例如上游 4xx 拒绝：409 但**不可重试**）。
    pub fn with_retryable(mut self, retryable: bool) -> Self {
        self.body.retryable = Some(retryable);
        self
    }

    /// 结构化字段（机器可分支，页面可据此给指引）。
    pub fn with_field(mut self, key: &str, value: impl Into<String>) -> Self {
        self.body
            .fields
            .get_or_insert_with(Default::default)
            .insert(key.to_string(), value.into());
        self
    }

    /// 可选字段：`None` 就不写。
    pub fn with_optional_field(self, key: &str, value: Option<impl Into<String>>) -> Self {
        match value {
            Some(value) => self.with_field(key, value),
            None => self,
        }
    }

    /// 顶层附加字段（与 `error` 平级），例如 `credential`。
    pub fn with_extra(mut self, key: &str, value: Value) -> Self {
        self.extra.insert(key.to_string(), value);
        self
    }

    /// 内部原因：只进日志。
    pub fn with_cause(mut self, cause: impl Display) -> Self {
        self.cause = Some(one_line(&cause.to_string()));
        self
    }

    /// 内部原因的生态分类（`ErrorCategory::as_str`）：只进日志，便于按类聚合。
    pub fn with_cause_category(mut self, category: &'static str) -> Self {
        self.cause_category = Some(category);
        self
    }

    /// 不让中间层/浏览器缓存这个响应。
    ///
    /// 带明文令牌的响应（签发成功、以及“已签发但没送达”的错误体）**必须**带它：
    /// 令牌只出现这一次，落进任何缓存都等于多一份副本。
    pub fn with_no_store(mut self) -> Self {
        self.headers
            .push((header::CACHE_CONTROL, HeaderValue::from_static("no-store")));
        self
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn code(&self) -> &str {
        &self.body.code
    }

    /// 页面据此决定“给重试按钮”还是“去修配置”。
    ///
    /// `None` = 服务端不表态（500 这类“重试性未知”），页面不该擅自当可重试。
    pub fn retryable(&self) -> Option<bool> {
        self.body.retryable
    }

    pub fn field(&self, key: &str) -> Option<&str> {
        self.body
            .fields
            .as_ref()
            .and_then(|fields| fields.get(key))
            .map(String::as_str)
    }
}

impl IntoResponse for ApiError {
    fn into_response(mut self) -> Response {
        // 每个错误一个 id：同一请求只回一个错误，所以它就是这次失败的对账锚点。
        let request_id = random_hex(8);
        self.body.correlation_id = Some(request_id.clone());

        // 单行日志：多行会破坏按行 grep（source chain 常带换行）。
        // 一次失败只记这一行 —— 上层（如推送层）**不再**重复记，否则同一故障两行、
        // 且其中一行没有对账用的 request_id。
        match (self.cause.as_deref(), self.cause_category) {
            (Some(cause), Some(category)) => log::log!(
                level_for(self.status),
                "api error: status={} code={} message={:?} request_id={} category={} cause={}",
                self.status.as_u16(),
                self.body.code,
                self.body.message,
                request_id,
                category,
                cause,
            ),
            (Some(cause), None) => log::log!(
                level_for(self.status),
                "api error: status={} code={} message={:?} request_id={} cause={}",
                self.status.as_u16(),
                self.body.code,
                self.body.message,
                request_id,
                cause,
            ),
            (None, _) => log::log!(
                level_for(self.status),
                "api error: status={} code={} message={:?} request_id={}",
                self.status.as_u16(),
                self.body.code,
                self.body.message,
                request_id,
            ),
        }

        let mut payload = match serde_json::to_value(ProtocolErrorEnvelope::new(self.body)) {
            Ok(value) => value,
            // 理论上不可能：都是 String/Option。兜底也保持同一形状。
            Err(_) => Value::Null,
        };
        if !self.extra.is_empty()
            && let Some(object) = payload.as_object_mut()
        {
            for (key, value) in self.extra {
                object.insert(key, value);
            }
        }

        let mut response = (
            self.status,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                ),
                (
                    HeaderName::from_static(REQUEST_ID_HEADER),
                    HeaderValue::from_str(&request_id).unwrap_or(HeaderValue::from_static("")),
                ),
            ],
            Json(payload),
        )
            .into_response();
        for (name, value) in self.headers {
            response.headers_mut().insert(name, value);
        }
        response
    }
}

/// 默认可重试性 —— 与 `wist-gateway` / `wist-center` 的 `default_retryable` 逐条一致：
///
/// - `429 / 502 / 503 / 504`：**瞬时**故障 → `Some(true)`；
/// - 其余 `4xx`：改请求才有用 → `Some(false)`；
/// - 其余 `5xx`（`500` 等）：重试性**未知**，不臆断 → `None`（字段不出）。
fn default_retryable(status: StatusCode) -> Option<bool> {
    match status.as_u16() {
        429 | 502 | 503 | 504 => Some(true),
        400..=499 => Some(false),
        _ => None,
    }
}

/// 「上游/依赖瞬时不可用」：这类 5xx 不是本服务的故障，记 `warn` 就够。
fn is_transient_upstream(status: StatusCode) -> bool {
    matches!(status.as_u16(), 502..=504)
}

fn default_severity(status: StatusCode) -> Severity {
    if status.is_server_error() {
        Severity::Error
    } else {
        Severity::Warning
    }
}

fn level_for(status: StatusCode) -> log::Level {
    if status.is_server_error() && !is_transient_upstream(status) {
        log::Level::Error
    } else {
        log::Level::Warn
    }
}

/// 折成单行（日志口径）。
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    // 拿不到熵也不该让错误投影失败：退化成时间戳。
    if getrandom::fill(&mut buffer).is_err() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        return format!("{now:x}");
    }
    buffer.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_defaults_match_the_gateway_and_center() {
        assert_eq!(default_retryable(StatusCode::BAD_GATEWAY), Some(true));
        assert_eq!(default_retryable(StatusCode::TOO_MANY_REQUESTS), Some(true));
        assert_eq!(
            default_retryable(StatusCode::SERVICE_UNAVAILABLE),
            Some(true)
        );
        assert_eq!(default_retryable(StatusCode::CONFLICT), Some(false));
        assert_eq!(default_retryable(StatusCode::BAD_REQUEST), Some(false));
        // 500 这类「重试性未知」不臆断：字段不出，页面就不会擅自给重试按钮。
        assert_eq!(default_retryable(StatusCode::INTERNAL_SERVER_ERROR), None);
    }

    #[test]
    fn transient_upstream_failures_are_logged_below_error() {
        assert_eq!(level_for(StatusCode::BAD_GATEWAY), log::Level::Warn);
        assert_eq!(level_for(StatusCode::SERVICE_UNAVAILABLE), log::Level::Warn);
        assert_eq!(
            level_for(StatusCode::INTERNAL_SERVER_ERROR),
            log::Level::Error
        );
        assert_eq!(level_for(StatusCode::CONFLICT), log::Level::Warn);
    }

    #[test]
    fn retryable_can_be_overridden_for_upstream_rejections() {
        let error =
            ApiError::new(StatusCode::CONFLICT, "verifier_rejected", "nope").with_retryable(false);
        assert_eq!(error.body.retryable, Some(false));
    }

    #[test]
    fn fields_are_merged_without_clobbering_each_other() {
        let error = ApiError::new(StatusCode::BAD_GATEWAY, "verifier_unreachable", "x")
            .with_field("peer", "wist-field")
            .with_optional_field("upstream_status", Some("502".to_string()))
            .with_optional_field("upstream_code", None::<String>);
        let fields = error.body.fields.expect("fields");
        assert_eq!(fields.get("peer").map(String::as_str), Some("wist-field"));
        assert_eq!(
            fields.get("upstream_status").map(String::as_str),
            Some("502")
        );
        assert!(!fields.contains_key("upstream_code"));
    }

    #[test]
    fn one_line_collapses_the_cause_chain() {
        assert_eq!(one_line("a\n  b\tc"), "a b c");
    }

    #[tokio::test]
    async fn the_wire_body_carries_a_correlation_id_and_a_header() {
        use http_body_util::BodyExt;

        let response =
            ApiError::new(StatusCode::BAD_GATEWAY, "verifier_unreachable", "nope").into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let header = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .expect("x-request-id header");

        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(body["error"]["code"], "verifier_unreachable");
        assert_eq!(body["error"]["retryable"], true);
        assert_eq!(body["error"]["correlation_id"], header.as_str());
        assert_eq!(body["error"]["severity"], "error");
    }

    #[tokio::test]
    async fn no_store_is_emitted_when_asked() {
        let response = ApiError::new(StatusCode::CONFLICT, "verifier_rejected", "no")
            .with_no_store()
            .into_response();
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
    }

    #[tokio::test]
    async fn an_unknown_retryability_omits_the_field() {
        use http_body_util::BodyExt;

        let response = ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "store_unavailable", "x")
            .into_response();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert!(body["error"].get("retryable").is_none(), "got {body}");
        assert_eq!(body["error"]["severity"], "error");
    }

    #[tokio::test]
    async fn extra_fields_sit_beside_the_error_envelope() {
        use http_body_util::BodyExt;

        let response = ApiError::new(StatusCode::CONFLICT, "verifier_rejected", "no")
            .with_extra("credential", serde_json::json!({ "token": "wcr_x" }))
            .into_response();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(body["credential"]["token"], "wcr_x");
        assert_eq!(body["error"]["retryable"], false);
    }
}
