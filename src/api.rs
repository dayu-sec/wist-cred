//! HTTP 面。
//!
//! 端点：
//!
//! | 端点 | 语义 |
//! |---|---|
//! | `POST /api/v1/credentials` | 为程序创建凭据；**明文只在响应里出现一次** |
//! | `GET  /api/v1/credentials` | 列出已发放凭据（**永不含摘要与明文**） |
//! | `GET  /api/v1/credentials/{id}` | 单条 |
//! | `POST /api/v1/credentials/{id}/revoke` | 撤销（幂等） |
//! | `GET  /api/v1/policy` | 签发上限（页面拿它标出超限选项） |
//! | `GET  /api/v1/peers` | 列出认证系统 + **心跳状态** |
//! | `POST /api/v1/peers` | 新建认证系统（名称 / 主机名 / 收数地址） |
//! | `POST /api/v1/peers/{name}/enrollment-tickets` | 签一张**一次性**接入券 |
//! | `GET  /enroll/{token}/join.sh` | 取出接入脚本（只有公开材料 + 券） |
//! | `POST /enroll/{token}/certificate` | X 交 CSR 换自己的服务器证书（**兑现券**） |
//! | `GET  /healthz` / `GET /version` | 探针 |
//!
//! 人身份由**本服务自己验**（`server.mode`）：
//!
//!   - `token`（发布态）：页面输口令 → `Authorization: Bearer <口令>`，配置里只存口令的 sha256；
//!   - `ingress`（开发态 / 已经有入口认证的场合）：由内网反代注入 `x-wist-operator`。
//!
//! 两种模式下都可以再用 `trusted_peers` 收窄对端（空 = 不限）。
//! **两条不走人机认证**：取脚本、交 CSR。取它们的是 X（机器），它没有操作者；
//! 授权依据是 URL 里那张一次性券，且在兑现（`certificate`）时作废。
//!
//! 名字的划法：`/api/v1/peers*` 是**人在管理面**对资源做的事；`/enroll/{token}/*` 是
//! **机器拿着券**兑换的具体产物（`join.sh` / `certificate`）。两套鉴权不同，路径上也分得开。
//!
//! 私钥永远不上送：X 在本机生成密钥对，只交 CSR（只含公钥），本服务按 CSR 签。

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, Path as AxumPath, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::config::{AuthMode, Config};
use crate::peers::{Health, NewPeer, Peer, PeerError, PeerRegistry};
use crate::store::{CredentialRecord, Store};

const TOKEN_PREFIX: &str = "wcr_";

/// 请求里没给 `subject` 时用它（`wist-auth` 侧要求非空，而页面上不问）。
const DEFAULT_SUBJECT: &str = "default";

// 长度上限：都是人填的短文本，卡住它们只是不让一次请求往表/日志/推送体里塞兆级内容。
const MAX_PURPOSE_CHARS: usize = 200;
const MAX_SUBJECT_CHARS: usize = 128;
/// 与认证系统名（DNS label，≤ 63）对齐。
const MAX_AUDIENCE_CHARS: usize = 63;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<Store>,
    /// 推送（X）；未配置 `[push]` 时为 `None`（P2 人工分发）。
    pub push: Option<Arc<crate::push::Pusher>>,
    /// 一次性接入券（只活在内存里）。
    pub boarding: Arc<crate::onboarding::TicketStore>,
    /// 签 X 服务器证书的 CA（CA-S）；未配置接入时为 `None`。
    pub signer: Option<Arc<wist_pki::CertificateAuthority>>,
    /// 认证系统注册表（`state/peers.json`，运行期可变）。
    pub peers: Arc<PeerRegistry>,
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
        // 重新投递：签发那一步推送失败（或 X 落盘丢了）时，人重新推一次。
        // 不是“续期”、也不改任何字段：同一摘要、同一 revision。
        .route(
            "/api/v1/credentials/{id}/redeliver",
            post(redeliver_credential),
        )
        // 签发上限：页面要用它把“1 年”这类超出上限的选项标出来，
        // 而不是选完被服务端静默压到 30 天。
        .route("/api/v1/policy", get(issue_policy))
        // 认证系统（peer）是资源；旧前缀 `/api/v1/onboarding/peers` 把资源藏在了过程词后面，
        // v0.4.1 起统一到 `/api/v1/peers`。旧路径保留**一版别名**：cred 与 cred-web 是两个
        // 镜像，灰度期页面可能还在调旧的；下个版本删。
        .route("/api/v1/peers", get(list_peers).post(create_peer))
        .route("/api/v1/peers/{name}/enrollment-tickets", post(mint_script))
        .route("/api/v1/peers/{name}/endpoint", post(set_peer_endpoint))
        // 接入落点（配置文件 + 重启命令）：挂在系统上，签发时烘进脚本。
        .route("/api/v1/peers/{name}/setup", post(set_peer_setup))
        .route(
            "/api/v1/onboarding/peers",
            get(list_peers).post(create_peer),
        )
        .route("/api/v1/onboarding/peers/{name}/script", post(mint_script))
        .route(
            "/api/v1/onboarding/peers/{name}/endpoint",
            post(set_peer_endpoint),
        )
        // 机器面：券自证。`join.sh` 可重复取（只有公开材料），真正的一次性在 `certificate`。
        // 注意：**不在 /api 下**，入口 nginx 对这一层关掉 basic auth（取它们的是机器）。
        // 券寿命 ≤ 1h 且一次即废，所以换名字不需要兼容别名。
        .route("/enroll/{token}/join.sh", get(fetch_script))
        .route("/enroll/{token}/certificate", post(enroll_peer))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    /// 调用方身份（X 验完之后记录的就是它）。
    ///
    /// **可选**：页面上不问；不给时用 `audience` 填 —— `wist-auth` 侧要求非空。
    #[serde(default)]
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
            "POST /api/v1/credentials/{id}/redeliver",
            "GET  /api/v1/policy",
            "GET  /api/v1/peers",
            "POST /api/v1/peers",
            "POST /api/v1/peers/{name}/endpoint",
            "POST /api/v1/peers/{name}/enrollment-tickets",
            "GET  /enroll/{token}/join.sh",
            "POST /enroll/{token}/certificate",
        ],
        "auth": "requests under /api/v1 need `Authorization: Bearer <password>` in token mode \
                 (the page asks for it), or the operator header injected by the ingress in ingress mode; \
                 /enroll/{token}/{join.sh,certificate} are authorised by the one-time ticket itself \
                 (join.sh: re-fetchable, certificate: single use)",
    }))
}

async fn version(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "name": "wist-cred",
        "version": env!("CARGO_PKG_VERSION"),
        "mode": mode_name(state.config.server.mode),
        "push": state.push.is_some(),
        "peers": state.peers.list().len(),
        "onboarding_signing": state.signer.is_some(),
        "heartbeat_enabled": state.config.onboarding.heartbeat_seconds > 0,
    }))
}

// ── 认证系统（onboarding）────────────────────────────────────────────────

/// 列出认证系统。**只有元数据与心跳状态**，材料一概不出。
async fn list_peers(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Err(denied) = authorize(&state.config, peer, &headers) {
        return denied.into_response();
    }
    let peers: Vec<Value> = state
        .peers
        .list()
        .iter()
        .map(|item| peer_view(item, &state.peers.health(&item.name)))
        .collect();
    Json(json!({
        "peers": peers,
        "script_ttl_seconds": state.config.onboarding.script_ttl_seconds,
        "heartbeat_seconds": state.config.onboarding.heartbeat_seconds,
        // 能不能接入，看前面两件事备齐了没有。
        "enabled": state.signer.is_some() && state.config.onboarding.client_ca.is_some(),
        "push_enabled": state.push.is_some(),
    }))
    .into_response()
}

fn peer_view(peer: &Peer, health: &Health) -> Value {
    let (state, last_seen_at, latency_ms, last_error) = match health {
        Health::Unknown => ("unknown", None, None, None),
        Health::Up { at, latency_ms } => ("up", Some(*at), Some(*latency_ms), None),
        Health::Down { at, error } => ("down", Some(*at), None, Some(error.clone())),
    };
    json!({
        "name": peer.name,
        "host": peer.host,
        "endpoint": peer.endpoint,
        "probe_url": peer.probe_url(),
        "roles": peer.roles,
        "config_path": peer.config_path,
        "restart_cmd": peer.restart_cmd,
        "created_at": peer.created_at,
        "created_by": peer.created_by,
        "health": state,
        "last_seen_at": last_seen_at,
        "latency_ms": latency_ms,
        "last_error": last_error,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatePeerRequest {
    /// 名称：页面显示、凭证的 audience、推数时的对端标识。**只要求这一个**。
    name: String,
    /// 可选：主机名（证书 SAN）。平常由对方登记时上报，这里只给脚本 / 迁移用。
    #[serde(default)]
    host: Option<String>,
    /// 可选：收数地址（`https://…`）。平常也由对方上报。
    #[serde(default)]
    endpoint: Option<String>,
    /// 可选：心跳探测地址；缺省由 endpoint 推到同源 `/healthz`。
    #[serde(default)]
    healthz: Option<String>,
    /// 可选：这个系统能验的角色。平常由它登记时上报。
    #[serde(default)]
    roles: Vec<String>,
}

/// 新建一个认证系统。落 `state/peers.json`，**不需要改配置、不需要重启**。
async fn create_peer(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CreatePeerRequest>,
) -> Response {
    let operator = match authorize(&state.config, peer, &headers) {
        Ok(operator) => operator,
        Err(denied) => return denied.into_response(),
    };

    // 没有签发 CA 就没有接入能力：建一个永远登记不了的系统只会误导人。
    if state.signer.is_none() || state.config.onboarding.client_ca.is_none() {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "enrollment_disabled",
            "this deployment has no signing CA / client CA configured",
        );
    }

    let input = NewPeer {
        name: body.name,
        host: body.host,
        endpoint: body.endpoint,
        healthz: body.healthz,
        roles: body.roles,
        // 建的时候不填：接入落点是后续在页面上改的（与“只填名称”同一取向）。
        config_path: None,
        restart_cmd: None,
    };
    match state.peers.create(input, &operator) {
        Ok(created) => {
            log::info!(
                "peer created: name={} host={:?} endpoint={:?} by={operator}",
                created.name,
                created.host,
                created.endpoint
            );
            (
                StatusCode::CREATED,
                Json(peer_view(&created, &Health::Unknown)),
            )
                .into_response()
        }
        Err(PeerError::BadRequest(message)) => {
            err(StatusCode::BAD_REQUEST, "invalid_peer", message)
        }
        // `create` 不会返回 NotFound（它正在建），保持穷举。
        Err(PeerError::NotFound(_)) => err(
            StatusCode::NOT_FOUND,
            "unknown_peer",
            "no auth system named by this request",
        ),
        Err(PeerError::Conflict(message)) => err(StatusCode::CONFLICT, "peer_conflict", message),
        Err(PeerError::Store(message)) => {
            log::error!("peer store failed: {message}");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_unavailable",
                "failed to persist the peer",
            )
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetEndpointRequest {
    /// `null` / 空串 = 退回手工分发。
    #[serde(default)]
    endpoint: Option<String>,
}

/// 改收数地址（或清空退回手工分发）。改完下一轮心跳就会去探新地址。
async fn set_peer_endpoint(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
    Json(body): Json<SetEndpointRequest>,
) -> Response {
    let operator = match authorize(&state.config, peer, &headers) {
        Ok(operator) => operator,
        Err(denied) => return denied.into_response(),
    };
    match state.peers.set_endpoint(&name, body.endpoint.as_deref()) {
        Ok(updated) => {
            log::info!(
                "peer endpoint updated: name={} endpoint={:?} by={operator}",
                updated.name,
                updated.endpoint
            );
            Json(peer_view(&updated, &state.peers.health(&updated.name))).into_response()
        }
        Err(PeerError::BadRequest(message)) => {
            err(StatusCode::BAD_REQUEST, "invalid_peer", message)
        }
        Err(PeerError::NotFound(_)) => err(
            StatusCode::NOT_FOUND,
            "unknown_peer",
            format!("no auth system named {name:?}"),
        ),
        Err(PeerError::Conflict(message)) => err(StatusCode::CONFLICT, "peer_conflict", message),
        Err(PeerError::Store(message)) => {
            log::error!("peer store failed: {message}");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_unavailable",
                "failed to persist the peer",
            )
        }
    }
}

/// 改“接入落点”：接入脚本要不要顺手写配置、写完要不要重启。
///
/// 挂在**认证系统**上而不是每条券上：这是该系统的事实（与 host / roles 同类），
/// 下一次点「接入命令」就自带 —— 不用为了补 `--config` 再开一张券。
///
/// 注意：栈部署的系统（center / ingest）**不要填** `config_path` —— 它们的配置由
/// localize 渲染、只读挂载，脚本写进去会被下一次渲染覆盖。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetSetupRequest {
    /// X 上那份配置文件的路径；`null` / 空串 = 不写文件（只打印片段）。
    #[serde(default)]
    config_path: Option<String>,
    /// 写完后让配置生效的命令；`null` / 空串 = 只提示。
    #[serde(default)]
    restart_cmd: Option<String>,
}

async fn set_peer_setup(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
    Json(body): Json<SetSetupRequest>,
) -> Response {
    let operator = match authorize(&state.config, peer, &headers) {
        Ok(operator) => operator,
        Err(denied) => return denied.into_response(),
    };
    match state.peers.set_setup(
        &name,
        body.config_path.as_deref(),
        body.restart_cmd.as_deref(),
    ) {
        Ok(updated) => {
            log::info!(
                "peer setup updated: name={} config_path={:?} restart={} by={operator}",
                updated.name,
                updated.config_path,
                if updated.restart_cmd.is_some() {
                    "yes"
                } else {
                    "no"
                }
            );
            Json(peer_view(&updated, &state.peers.health(&updated.name))).into_response()
        }
        Err(PeerError::BadRequest(message)) => {
            err(StatusCode::BAD_REQUEST, "invalid_peer", message)
        }
        Err(PeerError::NotFound(_)) => err(
            StatusCode::NOT_FOUND,
            "unknown_peer",
            format!("no auth system named {name:?}"),
        ),
        Err(PeerError::Conflict(message)) => err(StatusCode::CONFLICT, "peer_conflict", message),
        Err(PeerError::Store(message)) => {
            log::error!("peer store failed: {message}");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_unavailable",
                "failed to persist the peer",
            )
        }
    }
}

/// 签一张一次性接入券。返回的是**相对路径**，绝对地址由页面按自己的 origin 拼。
async fn mint_script(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> Response {
    let operator = match authorize(&state.config, peer, &headers) {
        Ok(operator) => operator,
        Err(denied) => return denied.into_response(),
    };

    let Some(target) = state.peers.get(&name) else {
        return err(
            StatusCode::NOT_FOUND,
            "unknown_peer",
            format!("no auth system named {name:?}"),
        );
    };

    // 未配置签发 CA / 客户端 CA 时直接拒：否则发出去的券在 enroll 那一步必然失败。
    if state.signer.is_none() || state.config.onboarding.client_ca.is_none() {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "enrollment_disabled",
            "this deployment has no signing CA / client CA configured",
        );
    }

    let (token, expires_in) = state.boarding.mint(&target.name);
    log::info!(
        "onboarding ticket minted: peer={} host={:?} operator={operator} ttl={expires_in}s",
        target.name,
        target.host
    );
    Json(json!({
        "peer": target.name,
        "host": target.host,
        "path": format!("/enroll/{token}/join.sh"),
        "expires_in": expires_in,
    }))
    .into_response()
}

/// 取出接入脚本。
///
/// 这条**不做操作者认证**：取脚本的是机器（X），它没有操作者身份。
/// 授权依据是 URL 里的券，且仍然要求请求来自 `trusted_peers`。
///
/// **券在这里不消费**：脚本里只有公开材料（客户端 CA）+ 自己的券，重取无害；
/// 真正的一次性发生在 `enroll`。兑现后这条自然失效（券状态已不是 pending）。
async fn fetch_script(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AxumPath(token): AxumPath<String>,
) -> Response {
    if peer_denied(&state.config, peer.ip()) {
        log::warn!("untrusted peer tried to fetch an onboarding script: {peer}");
        return err(
            StatusCode::UNAUTHORIZED,
            "untrusted_ingress_peer",
            "peer is not in server.trusted_peers",
        );
    }

    let Some(ticket) = state.boarding.peek(&token) else {
        return err(
            StatusCode::GONE,
            "script_link_expired",
            "this onboarding link is unknown, expired, or already used; mint a new one",
        );
    };

    let Some(target) = state.peers.get(&ticket.peer) else {
        return err(
            StatusCode::GONE,
            "script_link_expired",
            "this onboarding link is no longer usable",
        );
    };

    let Some(client_ca) = client_ca_pem(&state.config) else {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "enrollment_disabled",
            "this deployment has no client CA configured",
        );
    };

    let enroll_url = format!(
        "{}/enroll/{token}/certificate",
        public_base(&state.config.server, &headers).unwrap_or_default()
    );
    let issuer_public = state
        .config
        .issue
        .signing_key
        .as_ref()
        .map(|key| key.public_hex());
    match crate::onboarding::render_script(
        &target,
        &client_ca,
        &enroll_url,
        issuer_public.as_deref(),
        target.config_path.as_deref(),
        target.restart_cmd.as_deref(),
    ) {
        Ok(script) => {
            log::info!(
                "onboarding script served: peer={} peer_addr={peer}",
                target.name
            );
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8"),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                script,
            )
                .into_response()
        }
        Err(error) => {
            log::error!(
                "onboarding script for {:?} is unusable: {error:#}",
                target.name
            );
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "onboarding_material_unreadable",
                error.to_string(),
            )
        }
    }
}

fn client_ca_pem(config: &Config) -> Option<String> {
    let path = config.onboarding.client_ca.as_ref()?;
    match std::fs::read_to_string(path) {
        Ok(pem) => Some(pem),
        Err(error) => {
            log::error!(
                "onboarding.client_ca {} is unreadable: {error}",
                path.display()
            );
            None
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollRequest {
    /// X 本机生成的 CSR（PEM）。**只含公钥**，私钥永不上送。
    certificate_signing_request: String,
    /// X 上报的证书 SAN（通常就是它的主机名）。不给则由 endpoint 推导。
    #[serde(default)]
    host: Option<String>,
    /// X 上报的收摘要地址。`None` / 空 = 只做手工分发。
    #[serde(default)]
    endpoint: Option<String>,
    /// X 上报的**自己能验的角色**。上报非空就覆盖（重跑接入命令 = 改角色）；
    /// 上报空值只是“这次没说”，不会清空已登记的集合。
    #[serde(default)]
    roles: Vec<String>,
}

/// X 凭券登记：交 CSR，换自己的服务器证书。
///
/// 顺序是刻意的，与 center 的 `register_gateway` 同口径：
///
/// 1. 对端白名单（S3）；
/// 2. **先验 CSR（无状态）** —— 坏 CSR 不白白烧掉一张一次性券；
/// 3. **先 peek 看券与上报值**（主机名与已登记的不一致也属于坏输入，不烧券）；
/// 4. **原子兑现券** —— 两个并发请求不会都拿到证书；
/// 5. peer 从**券里**取，不信任请求方声称的任何**身份**（主机名只是它的地址，不是权限）；
/// 6. 按 CSR 签，主体（CN / DNS SAN）由本服务填 —— 用**对方上报、且与地址一致**的那个。
///
/// 券不存在 / 过期 / 已兑现 / peer 消失，对外**同一个响应**：
/// 公开端点不该变成券的枚举接口。
async fn enroll_peer(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AxumPath(token): AxumPath<String>,
    Json(body): Json<EnrollRequest>,
) -> Response {
    if peer_denied(&state.config, peer.ip()) {
        log::warn!("untrusted peer tried to enroll: {peer}");
        return err(
            StatusCode::UNAUTHORIZED,
            "untrusted_ingress_peer",
            "peer is not in server.trusted_peers",
        );
    }

    // ② 先验 CSR：无状态、便宜，而且坏输入不应该消耗一次性券。
    if let Err(reason) = wist_pki::ca::validate_csr(&body.certificate_signing_request) {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_csr",
            format!("invalid certificate signing request: {reason}"),
        );
    }

    let Some(signer) = state.signer.as_ref() else {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "enrollment_disabled",
            "this deployment has no signing CA configured",
        );
    };

    // ③ peek（不消费）：先算清“要签给谁”，有问题就当场拒，别烧券。
    let Some(peeked) = state.boarding.peek(&token) else {
        return err(
            StatusCode::UNAUTHORIZED,
            "enrollment_rejected",
            "this onboarding ticket is unknown, expired, or already used",
        );
    };
    let Some(target) = state.peers.get(&peeked.peer) else {
        return err(
            StatusCode::UNAUTHORIZED,
            "enrollment_rejected",
            "this onboarding ticket is unknown, expired, or already used",
        );
    };

    let reported_host = body
        .host
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let reported_endpoint = body
        .endpoint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    // 证书 SAN：上报的 > 已登记的 > 从地址推。三者都没有就签不了。
    let san = reported_host
        .map(str::to_string)
        .or_else(|| target.host.clone())
        .or_else(|| reported_endpoint.and_then(crate::peers::host_of));
    let Some(san) = san else {
        return err(
            StatusCode::BAD_REQUEST,
            "host_required",
            "enrollment needs the host the certificate is for; \
             pass --host or --advertise, or set the host on the auth system",
        );
    };

    // 已登记的主机名与上报的不一致：拒绝（不烧券），因为签出来的证书必然对不上。
    if let Some(known) = target.host.as_deref()
        && known != san
    {
        return err(
            StatusCode::BAD_REQUEST,
            "host_mismatch",
            format!("this auth system is registered for {known:?}, but {san:?} was reported"),
        );
    }

    // ③′ 上报值本身是否合法（主机名 / 地址 / 角色）：**在兑现券之前**查，
    // 否则一个拼错的主机名就把一整张一次性券烧掉了。
    if let Err(reason) =
        crate::peers::validate_report(reported_host, reported_endpoint, &body.roles)
    {
        return err(StatusCode::BAD_REQUEST, "invalid_enrollment", reason);
    }

    // ④ 兑现券（原子）。失败原因对外不可区分。
    let Some(ticket) = state.boarding.consume(&token) else {
        return err(
            StatusCode::UNAUTHORIZED,
            "enrollment_rejected",
            "this onboarding ticket is unknown, expired, or already used",
        );
    };
    // ⑤ peer 来自券本身（peek 与 consume 之间可能被并发改过，重新取一次）。
    let target = state.peers.get(&ticket.peer).unwrap_or(target);

    // ⑥ 按 CSR 签：主体由我们填（CSR 里的 subject / 扩展一律忽略）。
    let ttl = state.config.onboarding.peer_cert_ttl_seconds as i64;
    let issued = match signer.issue_server_certificate(
        &body.certificate_signing_request,
        std::slice::from_ref(&san),
        ttl,
    ) {
        Ok(issued) => issued,
        Err(reason) => {
            log::error!(
                "signing a peer certificate for {:?} failed: {reason}",
                target.name
            );
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "signing_failed",
                "failed to sign the certificate",
            );
        }
    };

    // ⑦ 落对方上报的身份（只补空）。失败不影响签发 —— 证书已经给出去了。
    if let Err(error) = state
        .peers
        .report(&target.name, Some(&san), reported_endpoint, &body.roles)
    {
        log::warn!(
            "peer {:?} reported values were not persisted: {error:#}",
            target.name
        );
    }

    log::info!(
        "onboarding enrolled: peer={} host={} endpoint={:?} serial={} fingerprint={} not_after={} source={peer}",
        target.name,
        san,
        reported_endpoint,
        issued.serial_hex,
        issued.fingerprint_sha256_hex,
        issued.not_after
    );

    // `Accept: application/x-pem-file` → 直接回 PEM 正文（接入脚本用）。
    // 否则回 JSON（程序用）。两者元数据一致。
    let mut out = HeaderMap::new();
    out.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(&target.name) {
        out.insert(axum::http::HeaderName::from_static("x-wist-peer"), value);
    }
    if let Ok(value) = HeaderValue::from_str(&issued.serial_hex) {
        out.insert(axum::http::HeaderName::from_static("x-wist-serial"), value);
    }
    if let Ok(value) = HeaderValue::from_str(&issued.fingerprint_sha256_hex) {
        out.insert(
            axum::http::HeaderName::from_static("x-wist-fingerprint-sha256"),
            value,
        );
    }
    if let Ok(value) = HeaderValue::from_str(&issued.not_after) {
        out.insert(
            axum::http::HeaderName::from_static("x-wist-not-after"),
            value,
        );
    }

    let wants_pem = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("application/x-pem-file"));
    if wants_pem {
        out.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-pem-file"),
        );
        return (StatusCode::OK, out, issued.certificate_pem).into_response();
    }

    (
        StatusCode::OK,
        out,
        Json(json!({
            "peer": target.name,
            "certificate": issued.certificate_pem,
            "serial": issued.serial_hex,
            "fingerprint_sha256": issued.fingerprint_sha256_hex,
            "not_before": issued.not_before,
            "not_after": issued.not_after,
        })),
    )
        .into_response()
}

/// 从请求头还原对外基址（脚本里的 `ENROLL_URL` 要用）。
///
/// 取不到或格式不对时返回 `None`，脚本自己会用 `--endpoint` 补。
/// **不对它做任何信任假设**：它只决定「往哪里回连」，而回连的目标由执行命令的人确认。
fn public_base(server: &crate::config::ServerConfig, headers: &HeaderMap) -> Option<String> {
    // 配了就以配置为准：反代默认的 `$host` 不带端口，靠请求头会把 `:4444` 弄丢。
    if let Some(base) = &server.public_base_url {
        return Some(base.clone());
    }
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|host| {
            !host.is_empty()
                && host.chars().all(|character| {
                    character.is_ascii_alphanumeric()
                        || matches!(character, '.' | '-' | ':' | '[' | ']')
                })
        })?;
    let scheme = match headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    {
        Some("http") => "http",
        Some("https") => "https",
        _ if host.starts_with("127.0.0.1") || host.starts_with("localhost") => "http",
        _ => "https",
    };
    Some(format!("{scheme}://{host}"))
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

    let purpose = body.purpose.trim().to_string();
    if purpose.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "purpose_required",
            "purpose must not be empty (it goes into the audit trail)",
        );
    }
    if purpose.chars().count() > MAX_PURPOSE_CHARS {
        return err(
            StatusCode::BAD_REQUEST,
            "purpose_too_long",
            format!("purpose must be at most {MAX_PURPOSE_CHARS} characters"),
        );
    }

    // 角色：先归一化（去空白 / 去空项 / 去重 / 限字符集），再用归一化后的值做
    // “对方认不认识”的判断。顺序不能反：`" read "` 能过白名单、到了 X 那边却会被
    // `known_roles` 裁掉 —— 那等于发了一把静默少权限的钥匙。
    let roles = match crate::peers::normalize_roles(body.roles) {
        Ok(roles) => roles,
        Err(reason) => return err(StatusCode::BAD_REQUEST, "invalid_roles", reason),
    };
    if roles.is_empty() {
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
    if audience.chars().count() > MAX_AUDIENCE_CHARS {
        return err(
            StatusCode::BAD_REQUEST,
            "audience_too_long",
            format!("audience must be at most {MAX_AUDIENCE_CHARS} characters"),
        );
    }
    // 有登记过认证系统时，受众（= 系统名）必须是其中之一 —— 否则这把钥匙没人能验。
    if !state.peers.is_empty() && !state.peers.contains(&audience) {
        return err(
            StatusCode::BAD_REQUEST,
            "audience_not_configured",
            format!("audience {audience:?} is not a registered auth system"),
        );
    }

    // 调用方身份：页面上不问。不给就用 `default` —— `wist-auth` 侧要求非空。
    let subject = match body.subject.trim() {
        "" => DEFAULT_SUBJECT.to_string(),
        given => given.to_string(),
    };
    if !subject.chars().all(is_subject_char) {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_subject",
            "subject must use [A-Za-z0-9._-] only",
        );
    }
    if subject.chars().count() > MAX_SUBJECT_CHARS {
        return err(
            StatusCode::BAD_REQUEST,
            "subject_too_long",
            format!("subject must be at most {MAX_SUBJECT_CHARS} characters"),
        );
    }

    // 角色只认注册表：X 接入时用 `--roles` 登记了它能验什么，这里就只能从那张表里挑。
    // 一个都没登记 = 它没说自己认什么，签出去也永远验不过，直接拒。
    if let Some(peer) = state.peers.get(&audience) {
        if peer.roles.is_empty() {
            return err(
                StatusCode::BAD_REQUEST,
                "roles_not_registered",
                format!(
                    "{audience} has not registered which roles it can verify; \
                     enroll it with `--roles a,b,c` before issuing credentials"
                ),
            );
        }

        let unknown: Vec<&str> = roles
            .iter()
            .filter(|role| !peer.roles.iter().any(|known| known == *role))
            .map(String::as_str)
            .collect();
        if !unknown.is_empty() {
            return err(
                StatusCode::BAD_REQUEST,
                "role_not_supported",
                format!(
                    "{} does not accept role(s) {}; it registered: {}",
                    audience,
                    unknown.join(", "),
                    peer.roles.join(", ")
                ),
            );
        }
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
        roles,
        resources: body.resources,
        audience,
        break_glass: body.break_glass,
        issued_at: now,
        expires_at: now + ttl as i64,
        revision: 1,
        revoked_at: None,
        last_used_at: None,
    };

    // **先登记、后交付**（D7）：对端不认，就不把明文交出去。
    //
    // 没有 endpoint 的认证系统 = 人工分发模式（P2）：不推，但凭据照常签发。
    // 有 endpoint 就必须推成功 —— 而本部署没配 `[push]` 时根本推不了，
    // 这种情况**在落库之前**就拒：否则会存一条“看起来发了”的凭据。
    let delivery = state.peers.get(&record.audience).and_then(|target| {
        target
            .endpoint
            .clone()
            .map(|endpoint| (target.name, endpoint))
    });
    if delivery.is_some() && state.push.is_none() {
        return err(
            StatusCode::CONFLICT,
            "push_disabled",
            format!(
                "{} has a push endpoint, but this deployment has no [push] client; \
                 nothing was issued",
                record.audience
            ),
        );
    }

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

    if let (Some((name, endpoint)), Some(push)) = (delivery, &state.push)
        && let Err(error) = push.register(&name, &endpoint, &record).await
    {
        log::error!(
            "credential {} stored but not delivered: {error:#}",
            record.credential_id
        );
        return err(
            StatusCode::BAD_GATEWAY,
            "credential_delivery_pending",
            "credential was created but the verifier did not accept it; it was not delivered \
             (POST /api/v1/credentials/{id}/redeliver to retry)",
        );
    }

    let mut body = summary(&record);
    body["token"] = json!(token);
    (StatusCode::CREATED, Json(body)).into_response()
}

/// 签发策略：页面拿它渲染有效期选项（超出上限的要标出来，而不是静默被压）。
async fn issue_policy(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Err(denied) = authorize(&state.config, peer, &headers) {
        return denied.into_response();
    }
    Json(json!({
        "max_ttl_seconds": state.config.issue.max_ttl_seconds,
        "break_glass_max_ttl_seconds": state.config.issue.break_glass_max_ttl_seconds,
        "overlap_seconds": state.config.issue.overlap_seconds,
        "digest": state.config.issue.digest,
    }))
    .into_response()
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
            // 推送失败不回滚本地状态：本地已撤销，对端最迟在 TTL 到期时失效（D12）。
            // **广播给所有有地址的认证系统**，并发发：一个慢系统不该把整次撤销
            // 拖成 N 倍的握手超时。
            if let Some(push) = &state.push {
                let mut tasks = tokio::task::JoinSet::new();
                for (name, endpoint) in state.peers.by_endpoint() {
                    let push = push.clone();
                    // 推送的签名必须覆盖“已撤销”的完整记录，所以整条记录一起带进任务。
                    let record = record.clone();
                    tasks.spawn(async move {
                        let outcome = push.revoke(&name, &endpoint, &record).await;
                        (name, outcome)
                    });
                }
                while let Some(joined) = tasks.join_next().await {
                    match joined {
                        Ok((name, Err(error))) => log::warn!(
                            "credential {} revoked locally, but push to {name} failed: {error:#}",
                            record.credential_id
                        ),
                        Ok((_, Ok(()))) => {}
                        Err(error) => log::warn!("revoke broadcast task failed: {error}"),
                    }
                }
            }
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

/// 重新把**已存在**的凭据摘要推给它的受众。
///
/// 用途：签发时推送失败（`credential_delivery_pending`），或对端落盘丢了、重启后表空了。
/// 语义刻意做窄：
///
/// - **不改任何字段**（改范围 = 换新凭据，D10）；
/// - 已撤销的不推（墓碑由 `revoke` 的广播负责，重推没有意义）；
/// - 只推给 `audience` 那**一个**系统，不广播。
async fn redeliver_credential(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AxumPath(credential_id): AxumPath<String>,
) -> Response {
    let operator = match authorize(&state.config, peer, &headers) {
        Ok(operator) => operator,
        Err(denied) => return denied.into_response(),
    };

    let record = match state.store.get(&credential_id) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return err(
                StatusCode::NOT_FOUND,
                "credential_not_found",
                "credential not found",
            );
        }
        Err(error) => {
            log::error!("redeliver: read credential failed: {error:#}");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_unavailable",
                "failed to read credential store",
            );
        }
    };

    if record.is_revoked() {
        return err(
            StatusCode::BAD_REQUEST,
            "credential_revoked",
            "this credential is revoked; there is nothing to deliver \
             (revocation is already broadcast to every verifier)",
        );
    }

    let target = state.peers.get(&record.audience);
    let endpoint = target.as_ref().and_then(|item| item.endpoint.clone());
    // 没有地址 = 手工分发：先回答“往哪儿推”，再回答“能不能推”。
    let (Some(target), Some(endpoint)) = (target, endpoint) else {
        return err(
            StatusCode::CONFLICT,
            "no_delivery_target",
            format!(
                "{} has no push endpoint; this credential is distributed by hand",
                record.audience
            ),
        );
    };

    let Some(push) = &state.push else {
        return err(
            StatusCode::CONFLICT,
            "push_disabled",
            "this deployment has no [push] client; credentials are distributed by hand",
        );
    };

    match push.register(&target.name, &endpoint, &record).await {
        Ok(()) => {
            log::info!(
                "credential redelivered: id={} audience={} operator={operator} revision={}",
                record.credential_id,
                record.audience,
                record.revision
            );
            Json(json!({
                "credential_id": record.credential_id,
                "audience": record.audience,
                "delivered_to": endpoint,
                "revision": record.revision,
            }))
            .into_response()
        }
        Err(error) => {
            log::error!(
                "redeliver {} to {} failed: {error:#}",
                record.credential_id,
                record.audience
            );
            err(
                StatusCode::BAD_GATEWAY,
                "credential_delivery_pending",
                "the verifier did not accept the credential; nothing changed, retry later",
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

/// 人机面的授权。两条路（见 `mode`）：
///
/// - `token`：验 `Authorization: Bearer <口令>`（sha256 常量时间），返回 `admin:<指纹>`；
/// - `ingress`：要求 `x-wist-operator` 头（由内网反代注入），返回操作者名。
///
/// `trusted_peers` 非空时先过这一道（S3）。
fn authorize(config: &Config, peer: SocketAddr, headers: &HeaderMap) -> Result<String, Denied> {
    if peer_denied(config, peer.ip()) {
        log::warn!("untrusted ingress peer rejected: {peer}");
        return Err(Denied::new(
            StatusCode::UNAUTHORIZED,
            "untrusted_ingress_peer",
            "peer is not in server.trusted_peers",
        ));
    }
    match config.server.mode {
        AuthMode::Token => authorize_password(config, peer, headers),
        AuthMode::Ingress => authorize_ingress(config, headers),
        AuthMode::Oidc => Err(Denied::new(
            StatusCode::UNAUTHORIZED,
            "unsupported_auth_mode",
            "oidc mode is not implemented",
        )),
    }
}

/// `mode = token`：页面口令的 Bearer。
///
/// 错误码与 gateway 的管理面逐字一致（`missing_admin_bearer_token` /
/// `invalid_admin_bearer_token`），这样页面一套 401 处理能用两处：
/// 收到 `invalid_*` 就把本地口令清掉，而不是拿错的密码每 10s 轮询一次。
///
/// 为什么这里**没有**像 gateway 那样做失败限流：那把口令是部署方设置的 24 hex（≥ 96 bit），
/// 在线猜测不可行；而 401 风暴的来源（页面拿错口令轮询）已经在协议上麦掉
/// （页面收到 `invalid_*` 就地清掉）。将来若接人工设置的弱口令，再补 `FailureLimiter`。
fn authorize_password(
    config: &Config,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<String, Denied> {
    let Some(password) = wist_auth::bearer_token(headers) else {
        return Err(Denied::new(
            StatusCode::UNAUTHORIZED,
            "missing_admin_bearer_token",
            "missing admin bearer token",
        ));
    };
    if !wist_auth::token_matches(password, &config.server.admin_password_hash) {
        // 只记对端，不记口令（也不能记）：口令多落一处就是多一个泄露面。
        log::warn!("invalid admin password presented: peer={peer}");
        return Err(Denied::new(
            StatusCode::UNAUTHORIZED,
            "invalid_admin_bearer_token",
            "invalid admin bearer token",
        ));
    }
    Ok(admin_actor(&config.server.admin_password_hash))
}

/// `mode = ingress`：操作者头由内网反代注入。
fn authorize_ingress(config: &Config, headers: &HeaderMap) -> Result<String, Denied> {
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

/// 令牌模式下，审计里的“发起人”。
///
/// 为什么不写口令、也不写 `admin` 一个词：
///
///   - 写口令就是让凭据又多落一处（日志）；
///   - 只写 `admin` 就分不出“换过口令前后”的操作。
///
/// 取 `sha256(口令)` 的前 12 个 hex 当**指纹**：能区分、不能反推。字段形状与 gateway 的
/// `admin_actor()` 一致（那边将来有用户体系就换成 `user:<id>`，这里同）。
fn admin_actor(password_hash: &str) -> String {
    let fingerprint: String = password_hash.chars().take(12).collect();
    if fingerprint.is_empty() {
        "admin:unknown".to_string()
    } else {
        format!("admin:{fingerprint}")
    }
}

/// `trusted_peers`：CIDR / 单个 IP。`unix:` 条目对 TCP 对端不适用，跳过。
///
/// **空列表 = 不做来源限制**（只写一处，两种模式、人机面与接入面共用同一个口径）：
/// 以前这里是“空 = 谁都不行”，而 `ingress` 模式又强制非空，所以看不出差别；
/// `token` 模式下 `trusted_peers` 是可选的，若接入面仍按“空 = 全拒”处理，
/// 就会变成“人机面能用、取接入脚本全 401”的隐形故障。
fn peer_denied(config: &Config, ip: IpAddr) -> bool {
    !config.server.trusted_peers.is_empty() && !peer_allowed(config, ip)
}

/// 逐条判断（不处理“空列表”的语义，那在 `peer_denied` 里）。
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

/// 配置加载期用：这条 `trusted_peers` 规则能不能用。
///
/// `unix:` 条目在 TCP 监听器上用不上，但允许写（同一份配置给多种入口），不在这里报错。
pub(crate) fn trusted_peer_rule_is_valid(rule: &str) -> bool {
    rule.starts_with("unix:") || parse_rule(rule).is_some()
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
        AuthMode::Token => "token",
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
    use crate::config::{IssueConfig, OnboardingConfig, ServerConfig, StorageConfig};
    use crate::onboarding::TicketStore;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const OPERATOR_HEADER: &str = "x-wist-operator";
    const CLIENT_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n";

    struct Harness {
        _dir: TempDir,
        state: AppState,
    }

    impl Harness {
        fn new() -> Self {
            Self::with_server(ServerConfig {
                listen_addr: "127.0.0.1:8443".to_string(),
                mode: AuthMode::Ingress,
                ingress_header: OPERATOR_HEADER.to_string(),
                admin_password_hash: String::new(),
                trusted_peers: vec!["127.0.0.1/32".to_string()],
                public_base_url: None,
            })
        }

        /// 发布态的形态：页面口令（`mode = token`），配置里只有 sha256。
        fn new_token(password: &str) -> Self {
            Self::with_server(ServerConfig {
                listen_addr: "127.0.0.1:8443".to_string(),
                mode: AuthMode::Token,
                ingress_header: OPERATOR_HEADER.to_string(),
                admin_password_hash: wist_auth::sha256_hex(password),
                trusted_peers: Vec::new(),
                public_base_url: None,
            })
        }

        /// 现场形态：外面还有一层反代，对外基址只能由配置给（`$host` 不带端口）。
        fn with_public_base(base: &str) -> Self {
            Self::with_server(ServerConfig {
                listen_addr: "127.0.0.1:8443".to_string(),
                mode: AuthMode::Ingress,
                ingress_header: OPERATOR_HEADER.to_string(),
                admin_password_hash: String::new(),
                trusted_peers: vec!["127.0.0.1/32".to_string()],
                public_base_url: Some(base.to_string()),
            })
        }

        fn with_server(server: ServerConfig) -> Self {
            let dir = TempDir::new();
            let peers =
                Arc::new(PeerRegistry::open(dir.path.join("peers.json")).expect("open registry"));
            let config = Config {
                server,
                storage: StorageConfig {
                    path: dir.path.join("credentials.db"),
                },
                issue: IssueConfig {
                    digest: "sha256".to_string(),
                    max_ttl_seconds: 2_592_000,
                    break_glass_max_ttl_seconds: 7_776_000,
                    overlap_seconds: 300,
                    signing_key: None,
                },
                push: None,
                onboarding: OnboardingConfig {
                    dir: None,
                    store_path: dir.path.join("peers.json"),
                    script_ttl_seconds: 900,
                    ca_cert: None,
                    ca_key: None,
                    client_ca: None,
                    peer_cert_ttl_seconds: 7_776_000,
                    heartbeat_seconds: 30,
                },
            };
            let store = Store::open(config.storage.path.clone()).expect("open store");
            Self {
                _dir: dir,
                state: AppState {
                    config: Arc::new(config),
                    store: Arc::new(store),
                    push: None,
                    boarding: Arc::new(TicketStore::new(900)),
                    signer: None,
                    peers,
                },
            }
        }

        /// 注册一个认证系统（走注册表，与页面同一个入口）。
        fn with_peer(self, name: &str, host: &str) -> Self {
            self.with_peer_roles(name, host, &["investigation:run", "read"])
        }

        /// 注册一个**没登记角色**的认证系统（接入时没带 `--roles`）。
        fn with_peer_without_roles(self, name: &str, host: &str) -> Self {
            self.with_peer_roles(name, host, &[])
        }

        fn with_peer_roles(self, name: &str, host: &str, roles: &[&str]) -> Self {
            self.state
                .peers
                .create(
                    NewPeer {
                        name: name.to_string(),
                        host: Some(host.to_string()),
                        endpoint: Some(format!("https://{host}:19443/api/v1/internal/credentials")),
                        healthz: None,
                        roles: roles.iter().map(|role| (*role).to_string()).collect(),
                        config_path: None,
                        restart_cmd: None,
                    },
                    "test",
                )
                .expect("create peer");
            self
        }

        /// 手工分发的认证系统：**没有收数地址**，所以签发不会去推。
        fn with_peer_manual(self, name: &str, host: &str, roles: &[&str]) -> Self {
            self.state
                .peers
                .create(
                    NewPeer {
                        name: name.to_string(),
                        host: Some(host.to_string()),
                        endpoint: None,
                        healthz: None,
                        roles: roles.iter().map(|role| (*role).to_string()).collect(),
                        config_path: None,
                        restart_cmd: None,
                    },
                    "test",
                )
                .expect("create peer");
            self
        }

        /// 备齐接入能力：真的签发 CA + 客户端信任锚，让 `mint`/`enroll` 走得通。
        fn with_signer(mut self) -> Self {
            let (signer, cert_pem, key_pem) =
                wist_pki::CertificateAuthority::generate("wist test CA").expect("generate CA");
            let cert_path = self._dir.path.join("ca.crt");
            let key_path = self._dir.path.join("ca.key");
            let client_ca_path = self._dir.path.join("client-ca.pem");
            std::fs::write(&cert_path, cert_pem).unwrap();
            std::fs::write(&key_path, key_pem).unwrap();
            std::fs::write(&client_ca_path, CLIENT_CA_PEM).unwrap();

            let mut config = (*self.state.config).clone();
            config.onboarding.ca_cert = Some(cert_path);
            config.onboarding.ca_key = Some(key_path);
            config.onboarding.client_ca = Some(client_ca_path);
            self.state.config = Arc::new(config);
            self.state.signer = Some(Arc::new(signer));
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
            // 测试的调用点早就把“人”作为第 3 个参数传进来了：ingress 模式当操作者头，
            // token 模式当页面口令 —— 两边都是“谁在动这个页面”。
            if let Some(credential) = operator {
                builder = match self.state.config.server.mode {
                    AuthMode::Token => {
                        builder.header("authorization", format!("Bearer {credential}"))
                    }
                    _ => builder.header(OPERATOR_HEADER, credential),
                };
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

        /// 接入脚本是纯文本，不能走 JSON 解码那条路。
        async fn call_text(
            &self,
            method: &str,
            uri: &str,
            operator: Option<&str>,
            peer: &str,
        ) -> (StatusCode, String) {
            let mut builder = Request::builder().method(method).uri(uri);
            if let Some(credential) = operator {
                builder = match self.state.config.server.mode {
                    AuthMode::Token => {
                        builder.header("authorization", format!("Bearer {credential}"))
                    }
                    _ => builder.header(OPERATOR_HEADER, credential),
                };
            }
            let mut request = builder.body(Body::empty()).unwrap();
            let peer: SocketAddr = format!("{peer}:40000").parse().unwrap();
            request.extensions_mut().insert(ConnectInfo(peer));

            let response = router(self.state.clone()).oneshot(request).await.unwrap();
            let status = response.status();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            (status, String::from_utf8_lossy(&bytes).to_string())
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
        let endpoints: Vec<&str> = body["endpoints"]
            .as_array()
            .expect("endpoints")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(!endpoints.is_empty());
        // 自述清单得与实际路由同源：漏一条就在自助排障时多一次“真的没这个接口吗”。
        for route in [
            "GET  /api/v1/credentials",
            "POST /api/v1/credentials",
            "POST /api/v1/credentials/{id}/revoke",
            "POST /api/v1/credentials/{id}/redeliver",
            "GET  /api/v1/peers",
            "POST /api/v1/peers",
            "POST /api/v1/peers/{name}/endpoint",
            "POST /api/v1/peers/{name}/enrollment-tickets",
            "GET  /enroll/{token}/join.sh",
            "POST /enroll/{token}/certificate",
        ] {
            assert!(endpoints.contains(&route), "landing is missing {route}");
        }

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
    async fn token_mode_rejects_missing_and_wrong_passwords() {
        const PASSWORD: &str = "0123456789abcdef01234567";
        let harness = Harness::new_token(PASSWORD);

        // 没带凭据（页面还没输口令）
        let (status, body) = harness
            .call("GET", "/api/v1/credentials", None, "127.0.0.1", None)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "missing_admin_bearer_token");

        // 口令不对：必须是 `invalid_*` —— 页面靠这个码把错的本地口令清掉。
        let (status, body) = harness
            .call(
                "GET",
                "/api/v1/credentials",
                Some("wrong-password"),
                "127.0.0.1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "invalid_admin_bearer_token");
    }

    #[tokio::test]
    async fn token_mode_accepts_the_page_password() {
        const PASSWORD: &str = "0123456789abcdef01234567";
        let harness = Harness::new_token(PASSWORD);

        let (status, body) = harness
            .call(
                "POST",
                "/api/v1/credentials",
                Some(PASSWORD),
                "127.0.0.1",
                Some(create_body()),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");

        // 审计里的“发起人”是指纹，既不是口令，也不是笼统的 admin。
        let owner = body["owner"].as_str().expect("owner");
        let fingerprint: String = wist_auth::sha256_hex(PASSWORD).chars().take(12).collect();
        assert_eq!(owner, format!("admin:{fingerprint}"));
        assert!(!owner.contains(PASSWORD));
    }

    #[tokio::test]
    async fn token_mode_keeps_the_peer_allowlist() {
        // `trusted_peers` 在 token 模式也是真的一道锁（不是只给 ingress 用的）。
        let mut harness = Harness::new_token("0123456789abcdef01234567");
        let mut config = (*harness.state.config).clone();
        config.server.trusted_peers = vec!["127.0.0.1/32".to_string()];
        harness.state.config = Arc::new(config);

        let (status, body) = harness
            .call(
                "GET",
                "/api/v1/credentials",
                Some("0123456789abcdef01234567"),
                "10.9.9.9",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "untrusted_ingress_peer");
    }

    #[tokio::test]
    async fn token_mode_leaves_the_onboarding_face_open_to_the_ticket() {
        // 取接入脚本的是 X（机器），它没有口令 —— 这条路只能靠 URL 里那张一次性券。
        let harness = Harness::new_token("0123456789abcdef01234567")
            .with_peer("wist-ingest", "ingest.internal")
            .with_signer();
        let (status, minted) = harness
            .call(
                "POST",
                "/api/v1/peers/wist-ingest/enrollment-tickets",
                Some("0123456789abcdef01234567"),
                "127.0.0.1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{minted}");
        let path = minted["path"].as_str().expect("path").to_string();

        // 不带任何口令：靠券本身。
        let (status, body) = harness.call_text("GET", &path, None, "127.0.0.1").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("curl") || body.contains("#!/"), "{body}");
    }

    #[tokio::test]
    async fn token_mode_still_serves_the_health_probe_without_a_password() {
        // 探针/落地页不该要口令：容器健康检查、反代保活都靠它们。
        let harness = Harness::new_token("0123456789abcdef01234567");
        let (status, _) = harness
            .call("GET", "/healthz", None, "127.0.0.1", None)
            .await;
        assert_eq!(status, StatusCode::OK);
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
    async fn audience_must_be_a_registered_auth_system() {
        let harness = Harness::new().with_peer("wist-center", "center.internal");
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
    async fn an_empty_registry_still_allows_manual_distribution() {
        // P2 行为：还没登记任何认证系统时，凭证照发（靠人工分发），不因为没目标而失败。
        let harness = Harness::new();
        let (status, _) = harness
            .call(
                "POST",
                "/api/v1/credentials",
                Some("alice"),
                "127.0.0.1",
                Some(create_body()),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn policy_reports_the_ttl_caps_to_the_page() {
        let harness = Harness::new();
        let (status, _) = harness
            .call("GET", "/api/v1/policy", None, "127.0.0.1", None)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, body) = harness
            .call("GET", "/api/v1/policy", Some("alice"), "127.0.0.1", None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["max_ttl_seconds"], 2_592_000);
        assert_eq!(body["break_glass_max_ttl_seconds"], 7_776_000);
        assert_eq!(body["digest"], "sha256");
    }

    #[test]
    fn subject_falls_back_to_the_audience() {
        let body: CreateRequest = serde_json::from_value(json!({
            "purpose": "nightly",
            "roles": ["read"],
            "audience": "wist-ingest"
        }))
        .expect("subject is optional in the request");
        assert_eq!(body.subject, "", "absent subject must not fail to parse");

        let explicit: CreateRequest = serde_json::from_value(json!({
            "subject": "ci-nightly",
            "purpose": "nightly",
            "roles": ["read"],
            "audience": "wist-ingest"
        }))
        .expect("explicit subject still works");
        assert_eq!(explicit.subject, "ci-nightly");
    }

    #[tokio::test]
    async fn a_credential_can_be_created_without_a_subject() {
        let harness = Harness::new().with_peer_manual(
            "wist-ingest",
            "ingest.internal",
            &["investigation:run", "read"],
        );
        let (status, created) = harness
            .call(
                "POST",
                "/api/v1/credentials",
                Some("alice"),
                "127.0.0.1",
                Some(json!({
                    "purpose": "页面不发程序名",
                    "roles": ["read"],
                    "audience": "wist-ingest"
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "body: {created}");
        // 身份不能为空（wist-auth 侧会拒），所以回落到固定值。
        assert_eq!(created["subject"], "default");
        assert_eq!(created["audience"], "wist-ingest");
    }

    #[tokio::test]
    async fn a_role_the_peer_did_not_register_is_rejected() {
        let harness = Harness::new().with_peer("wist-ingest", "ingest.internal");
        let mut body = create_body();
        body["audience"] = json!("wist-ingest");
        body["roles"] = json!(["pipeline:write"]);
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
        assert_eq!(created["error"]["code"], "role_not_supported");
        // 错误信息里要写出对方到底支持什么，不然没法自助。
        assert!(
            created["error"]["message"]
                .as_str()
                .unwrap()
                .contains("investigation:run"),
            "unexpected: {created}"
        );
    }

    #[tokio::test]
    async fn a_peer_that_registered_no_roles_cannot_be_issued_for() {
        // 角色只认注册表：对方没登记自己能验什么，就没有可选项，签出去也永远验不过。
        let harness = Harness::new().with_peer_without_roles("wist-ingest", "ingest.internal");
        let mut body = create_body();
        body["audience"] = json!("wist-ingest");
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
        assert_eq!(created["error"]["code"], "roles_not_registered");
        // 错误信息要告诉人往哪里补。
        assert!(
            created["error"]["message"]
                .as_str()
                .unwrap()
                .contains("--roles"),
            "unexpected: {created}"
        );
    }

    #[tokio::test]
    async fn credential_roles_are_normalized_before_they_are_checked() {
        // `" read "` 能过白名单，但到了 X 那边会被 `known_roles` 裁掉 ——
        // 那等于发了一把静默少权限的钥匙。所以先归一化，再判对方认不认识。
        let harness = Harness::new().with_peer_manual(
            "wist-ingest",
            "ingest.internal",
            &["investigation:run", "read"],
        );
        let mut body = create_body();
        body["audience"] = json!("wist-ingest");
        body["roles"] = json!([" read ", "read", ""]);
        let (status, created) = harness
            .call(
                "POST",
                "/api/v1/credentials",
                Some("alice"),
                "127.0.0.1",
                Some(body),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["roles"], json!(["read"]));

        // 字符集仍然是边界（与认证系统的角色表同一套规则）。
        let mut bad = create_body();
        bad["audience"] = json!("wist-ingest");
        bad["roles"] = json!(["bad'role"]);
        let (status, rejected) = harness
            .call(
                "POST",
                "/api/v1/credentials",
                Some("alice"),
                "127.0.0.1",
                Some(bad),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
        assert_eq!(rejected["error"]["code"], "invalid_roles");
    }

    #[tokio::test]
    async fn oversized_free_text_is_rejected() {
        let harness = Harness::new().with_peer_manual("wist-ingest", "ingest.internal", &["read"]);
        for (field, value, code) in [
            ("purpose", "x".repeat(201), "purpose_too_long"),
            ("subject", "s".repeat(129), "subject_too_long"),
            ("audience", "a".repeat(64), "audience_too_long"),
        ] {
            let mut body = create_body();
            body["audience"] = json!("wist-ingest");
            body["roles"] = json!(["read"]);
            body[field] = json!(value);
            let (status, rejected) = harness
                .call(
                    "POST",
                    "/api/v1/credentials",
                    Some("alice"),
                    "127.0.0.1",
                    Some(body),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{field}: {rejected}");
            assert_eq!(rejected["error"]["code"], code, "{field}: {rejected}");
        }
    }

    #[tokio::test]
    async fn create_refuses_to_issue_when_push_is_missing_for_an_endpoint_peer() {
        // 有地址但本部署没配 `[push]`：拒，而且**不落库** —— 否则会存一条“看起来发了”的记录。
        let harness = Harness::new().with_peer("wist-center", "center.internal");
        let (status, body) = harness
            .call(
                "POST",
                "/api/v1/credentials",
                Some("alice"),
                "127.0.0.1",
                Some(create_body()),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"]["code"], "push_disabled");

        let (_, listed) = harness
            .call(
                "GET",
                "/api/v1/credentials",
                Some("alice"),
                "127.0.0.1",
                None,
            )
            .await;
        assert!(
            listed["credentials"]
                .as_array()
                .is_some_and(|items| items.is_empty()),
            "nothing may be stored: {listed}"
        );
    }

    #[tokio::test]
    async fn redeliver_rejects_an_unknown_credential() {
        let harness = Harness::new();
        let (status, body) = harness
            .call(
                "POST",
                "/api/v1/credentials/cred_nope/redeliver",
                Some("alice"),
                "127.0.0.1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["error"]["code"], "credential_not_found");
    }

    #[tokio::test]
    async fn redeliver_refuses_a_revoked_credential() {
        // 墓碑不需要重推：撤销本来就是广播出去的，重推一条已撤销的记录只会造成误会。
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
        harness
            .call(
                "POST",
                &format!("/api/v1/credentials/{id}/revoke"),
                Some("alice"),
                "127.0.0.1",
                None,
            )
            .await;

        let (status, body) = harness
            .call(
                "POST",
                &format!("/api/v1/credentials/{id}/redeliver"),
                Some("alice"),
                "127.0.0.1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], "credential_revoked");
    }

    #[tokio::test]
    async fn redeliver_names_the_missing_delivery_target_first() {
        // 受众没有收数地址 = 手工分发：先说“往哪儿推”，不要先说“没有推送客户端”。
        let harness = Harness::new().with_signer();
        harness
            .call(
                "POST",
                "/api/v1/peers",
                Some("alice"),
                "127.0.0.1",
                Some(json!({ "name": "wist-center", "host": "center.internal", "roles": ["investigation:run"] })),
            )
            .await;
        let (_, created) = harness
            .call(
                "POST",
                "/api/v1/credentials",
                Some("alice"),
                "127.0.0.1",
                Some(create_body()),
            )
            .await;
        assert_eq!(created["audience"], "wist-center");
        let id = created["credential_id"].as_str().unwrap().to_string();

        let (status, body) = harness
            .call(
                "POST",
                &format!("/api/v1/credentials/{id}/redeliver"),
                Some("alice"),
                "127.0.0.1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"]["code"], "no_delivery_target");
    }

    #[tokio::test]
    async fn redeliver_needs_a_push_client() {
        // 先在“手工分发”状态签发，再把地址补上：这样 create 不会提前被 push_disabled 拦住。
        let harness = Harness::new().with_peer_manual(
            "wist-center",
            "center.internal",
            &["investigation:run", "read"],
        );
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
        harness
            .call(
                "POST",
                "/api/v1/peers/wist-center/endpoint",
                Some("alice"),
                "127.0.0.1",
                Some(json!({ "endpoint": "https://center.internal:19443/api/v1/internal/credentials" })),
            )
            .await;

        let (status, body) = harness
            .call(
                "POST",
                &format!("/api/v1/credentials/{id}/redeliver"),
                Some("alice"),
                "127.0.0.1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"]["code"], "push_disabled");
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

    #[tokio::test]
    async fn enroll_url_comes_from_the_configured_public_base() {
        // 反代的 `$host` 不带端口：靠请求头推会把 `:4444` 弄丢，登记会打到别的端口上（现场踩过）。
        let harness = Harness::with_public_base("https://cred.example.com:4444")
            .with_peer("wist-center", "center.internal")
            .with_signer();

        let (status, minted) = harness
            .call(
                "POST",
                "/api/v1/peers/wist-center/enrollment-tickets",
                Some("alice"),
                "127.0.0.1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let path = minted["path"].as_str().expect("path");

        let (status, script) = harness.call_text("GET", path, None, "127.0.0.1").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            script.contains("ENROLL_URL='https://cred.example.com:4444/enroll/"),
            "配置的基址必须原样带上端口，got: {script}"
        );
        assert!(
            script.contains("/certificate'"),
            "登记地址应指向 certificate，got: {script}"
        );
    }

    // ── public_base：配了就信配置，没配才看请求头（2026-11-03 的 404 就是后者丢端口）──

    fn server_with_base(base: Option<&str>) -> ServerConfig {
        ServerConfig {
            listen_addr: "127.0.0.1:8443".to_string(),
            mode: AuthMode::Ingress,
            ingress_header: OPERATOR_HEADER.to_string(),
            admin_password_hash: String::new(),
            trusted_peers: Vec::new(),
            public_base_url: base.map(str::to_string),
        }
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn public_base_prefers_the_configured_value_over_the_host_header() {
        let server = server_with_base(Some("https://cred.example.com:4444"));
        let headers = headers(&[(header::HOST.as_str(), "other.example.com")]);
        assert_eq!(
            public_base(&server, &headers).as_deref(),
            Some("https://cred.example.com:4444"),
            "反代写什么 Host 都不能盖过显式配置"
        );
    }

    #[test]
    fn public_base_keeps_the_port_when_derived_from_the_host_header() {
        let server = server_with_base(None);
        let headers = headers(&[
            (header::HOST.as_str(), "cred.example.com:4444"),
            ("x-forwarded-proto", "https"),
        ]);
        assert_eq!(
            public_base(&server, &headers).as_deref(),
            Some("https://cred.example.com:4444"),
            "端口是登记能不能到得了 cred 的关键，不能丢"
        );
    }

    #[test]
    fn public_base_defaults_to_https_except_for_loopback() {
        let server = server_with_base(None);
        for (host, want) in [
            ("cred.example.com", "https://cred.example.com"),
            ("127.0.0.1:18443", "http://127.0.0.1:18443"),
            ("localhost:5174", "http://localhost:5174"),
        ] {
            let headers = headers(&[(header::HOST.as_str(), host)]);
            assert_eq!(public_base(&server, &headers).as_deref(), Some(want));
        }
    }

    #[test]
    fn public_base_honours_x_forwarded_proto() {
        let server = server_with_base(None);
        let headers = headers(&[
            (header::HOST.as_str(), "cred.example.com:4444"),
            ("x-forwarded-proto", "http"),
        ]);
        assert_eq!(
            public_base(&server, &headers).as_deref(),
            Some("http://cred.example.com:4444")
        );
    }

    #[test]
    fn public_base_refuses_to_build_from_a_bogus_host() {
        let server = server_with_base(None);
        for bogus in ["", "evil/host", "a b", "host;rm"] {
            let headers = headers(&[(header::HOST.as_str(), bogus)]);
            assert_eq!(public_base(&server, &headers), None, "host={bogus:?}");
        }
        // 没有 Host 宁可返回 None（调用方再用空串），也不要拼出一个半残地址。
        assert_eq!(public_base(&server, &HeaderMap::new()), None);
    }

    #[tokio::test]
    async fn setup_endpoint_is_remembered_and_reaches_the_script() {
        // “命令自带 --config”的端到端：存一次，之后每次签发的脚本都带着它。
        let harness = Harness::new()
            .with_peer("wist-ingest", "ingest.internal")
            .with_signer();

        let (status, body) = harness
            .call(
                "POST",
                "/api/v1/peers/wist-ingest/setup",
                Some("alice"),
                "127.0.0.1",
                Some(json!({
                    "config_path": "/etc/x/ctrl.toml",
                    "restart_cmd": "systemctl restart x"
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["config_path"], "/etc/x/ctrl.toml");
        assert_eq!(body["restart_cmd"], "systemctl restart x");

        let (status, minted) = harness
            .call(
                "POST",
                "/api/v1/peers/wist-ingest/enrollment-tickets",
                Some("alice"),
                "127.0.0.1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let path = minted["path"].as_str().expect("path");
        let (status, script) = harness.call_text("GET", path, None, "127.0.0.1").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            script.contains("WIST_CRED_CONFIG_FILE:-/etc/x/ctrl.toml"),
            "脚本里应当自带配置文件\ngot: {script}"
        );
        assert!(
            script.contains("WIST_CRED_RESTART_CMD:-systemctl restart x"),
            "脚本里应当自带重启命令\ngot: {script}"
        );

        // 换行要在入口就拦住：它是单行 shell 赋值。
        let (status, body) = harness
            .call(
                "POST",
                "/api/v1/peers/wist-ingest/setup",
                Some("alice"),
                "127.0.0.1",
                Some(json!({"config_path": "/etc/x\nrm -rf /"})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_peer");
    }

    #[tokio::test]
    async fn onboarding_peers_need_an_operator() {
        let harness = Harness::new()
            .with_peer("wist-ingest", "ingest.internal")
            .with_signer();

        let (status, body) = harness
            .call("GET", "/api/v1/peers", None, "127.0.0.1", None)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "missing_operator");

        let (status, body) = harness
            .call("GET", "/api/v1/peers", Some("alice"), "127.0.0.1", None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["peers"][0]["name"], "wist-ingest");
        assert_eq!(body["peers"][0]["host"], "ingest.internal");
        // 列表绝不带材料。
        assert!(body["peers"][0].get("server_cert").is_none());
    }

    #[tokio::test]
    async fn legacy_admin_paths_keep_working_for_one_release() {
        // cred 与 cred-web 是两个镜像：灰度期页面可能还在调旧前缀。
        let harness = Harness::new()
            .with_peer("wist-ingest", "ingest.internal")
            .with_signer();

        let (status, body) = harness
            .call(
                "GET",
                "/api/v1/onboarding/peers",
                Some("alice"),
                "127.0.0.1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["peers"][0]["name"], "wist-ingest");

        let (status, minted) = harness
            .call(
                "POST",
                "/api/v1/onboarding/peers/wist-ingest/script",
                Some("alice"),
                "127.0.0.1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        // 旧入口发的券也指向**新**路径，页面不需要感知改名。
        assert!(
            minted["path"]
                .as_str()
                .unwrap_or_default()
                .starts_with("/enroll/"),
            "got {minted}"
        );
    }

    #[tokio::test]
    async fn old_machine_paths_are_gone() {
        // 券寿命 ≤ 1h 且一次即废，所以机器面不留别名。
        let harness = Harness::new()
            .with_peer("wist-ingest", "ingest.internal")
            .with_signer();
        for (method, uri) in [
            ("GET", "/onboarding/script/wot_deadbeef"),
            ("POST", "/onboarding/enroll/wot_deadbeef"),
        ] {
            let (status, _) = harness.call(method, uri, None, "127.0.0.1", None).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
        }
    }

    #[tokio::test]
    async fn onboarding_script_link_is_single_use() {
        let harness = Harness::new()
            .with_peer("wist-ingest", "ingest.internal")
            .with_signer();

        let (status, minted) = harness
            .call(
                "POST",
                "/api/v1/peers/wist-ingest/enrollment-tickets",
                Some("alice"),
                "127.0.0.1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let path = minted["path"].as_str().expect("path").to_string();
        assert!(path.starts_with("/enroll/wot_"), "got {path}");
        assert!(path.ends_with("/join.sh"), "got {path}");

        // X 取脚本：没有操作者头，靠券本身授权。
        let (status, script) = harness.call_text("GET", &path, None, "127.0.0.1").await;
        assert_eq!(status, StatusCode::OK);
        assert!(script.contains("PEER_NAME='wist-ingest'"));
        assert!(script.contains("subjectAltName") || script.contains("SAN"));
        // 关键：链接里**绝不能有私钥**。
        assert!(
            !script.contains("PRIVATE KEY"),
            "the link must not carry a private key"
        );

        // 脚本可以重取（只有公开材料 + 自己的券）。
        let (status, _) = harness.call_text("GET", &path, None, "127.0.0.1").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn onboarding_script_from_an_untrusted_peer_is_rejected() {
        let harness = Harness::new()
            .with_peer("wist-ingest", "ingest.internal")
            .with_signer();
        let (_, minted) = harness
            .call(
                "POST",
                "/api/v1/peers/wist-ingest/enrollment-tickets",
                Some("alice"),
                "127.0.0.1",
                None,
            )
            .await;
        let path = minted["path"].as_str().unwrap().to_string();

        let (status, _) = harness.call_text("GET", &path, None, "10.9.9.9").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn minting_is_refused_when_no_signing_ca_is_configured() {
        let harness = Harness::new().with_peer("wist-ingest", "ingest.internal");
        let (status, body) = harness
            .call(
                "POST",
                "/api/v1/peers/wist-ingest/enrollment-tickets",
                Some("alice"),
                "127.0.0.1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "enrollment_disabled");
    }

    #[tokio::test]
    async fn unknown_onboarding_peer_is_404() {
        let harness = Harness::new().with_signer();
        let (status, body) = harness
            .call(
                "POST",
                "/api/v1/peers/nope/enrollment-tickets",
                Some("alice"),
                "127.0.0.1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "unknown_peer");
    }

    #[tokio::test]
    async fn creating_a_peer_needs_an_operator() {
        let harness = Harness::new().with_signer();
        let body = json!({
            "name": "wist-ingest",
            "host": "ingest.internal"
        });
        let (status, _) = harness
            .call(
                "POST",
                "/api/v1/peers",
                None,
                "127.0.0.1",
                Some(body.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, created) = harness
            .call(
                "POST",
                "/api/v1/peers",
                Some("alice"),
                "127.0.0.1",
                Some(body),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "body: {created}");
        assert_eq!(created["name"], "wist-ingest");
        // 受众就是系统名，不再单独返回一个永远相同的字段。
        assert!(created.get("audience").is_none());
        assert_eq!(created["health"], "unknown");
        assert_eq!(created["created_by"], "alice");
    }

    #[tokio::test]
    async fn creating_a_duplicate_peer_is_a_conflict() {
        let harness = Harness::new().with_signer();
        let body = json!({ "name": "wist-ingest", "host": "ingest.internal" });
        let (first, _) = harness
            .call(
                "POST",
                "/api/v1/peers",
                Some("alice"),
                "127.0.0.1",
                Some(body.clone()),
            )
            .await;
        assert_eq!(first, StatusCode::CREATED);
        let (second, error) = harness
            .call(
                "POST",
                "/api/v1/peers",
                Some("bob"),
                "127.0.0.1",
                Some(body),
            )
            .await;
        assert_eq!(second, StatusCode::CONFLICT);
        assert_eq!(error["error"]["code"], "peer_conflict");
    }

    #[tokio::test]
    async fn creating_a_peer_without_a_signing_ca_is_refused() {
        let harness = Harness::new();
        let (status, body) = harness
            .call(
                "POST",
                "/api/v1/peers",
                Some("alice"),
                "127.0.0.1",
                Some(json!({ "name": "x", "host": "x.internal" })),
            )
            .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "enrollment_disabled");
    }

    #[tokio::test]
    async fn a_peer_created_through_the_api_can_enrol() {
        let harness = Harness::new().with_signer();
        let (status, created) = harness
            .call(
                "POST",
                "/api/v1/peers",
                Some("alice"),
                "127.0.0.1",
                Some(json!({ "name": "wist-ingest", "host": "ingest.internal" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);

        let uri = mint_enroll_uri(&harness, "wist-ingest").await;
        let (status, issued) = harness
            .call(
                "POST",
                &uri,
                None,
                "127.0.0.1",
                Some(json!({ "certificate_signing_request": csr() })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "body: {issued}");
        let info = wist_pki::inspect::inspect_pem(issued["certificate"].as_str().unwrap())
            .expect("inspect");
        assert!(info.subject.contains("ingest.internal"), "{}", info.subject);
        assert_eq!(created["name"], "wist-ingest");
    }

    #[tokio::test]
    async fn a_bad_role_or_endpoint_does_not_burn_the_ticket() {
        // 上报值不合法是“输入错”：不能把一张一次性券变成代价。
        let harness = Harness::new()
            .with_signer()
            .with_peer("wist-ingest", "ingest.internal");
        let uri = mint_enroll_uri(&harness, "wist-ingest").await;

        for (label, body) in [
            (
                "role",
                json!({ "certificate_signing_request": csr(), "roles": ["bad'role"] }),
            ),
            (
                "endpoint",
                json!({ "certificate_signing_request": csr(), "endpoint": "https://x`id`/y" }),
            ),
        ] {
            let (status, rejected) = harness
                .call("POST", &uri, None, "127.0.0.1", Some(body))
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {rejected}");
            assert_eq!(
                rejected["error"]["code"], "invalid_enrollment",
                "{label}: {rejected}"
            );
        }

        // 券仍然可用：同一张券还能换到证书。
        let (status, issued) = harness
            .call(
                "POST",
                &uri,
                None,
                "127.0.0.1",
                Some(json!({ "certificate_signing_request": csr() })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "ticket was burnt: {issued}");
    }

    #[tokio::test]
    async fn an_invalid_reported_host_does_not_burn_the_ticket() {
        // 没登记 host 的系统：上报值直接决定 SAN，字符集必须在烧券前就查。
        let harness = Harness::new().with_signer();
        let (status, _) = harness
            .call(
                "POST",
                "/api/v1/peers",
                Some("alice"),
                "127.0.0.1",
                Some(json!({ "name": "wist-ingest", "roles": ["read"] })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
        let uri = mint_enroll_uri(&harness, "wist-ingest").await;

        let (status, rejected) = harness
            .call(
                "POST",
                &uri,
                None,
                "127.0.0.1",
                Some(json!({ "certificate_signing_request": csr(), "host": "not a host" })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
        assert_eq!(rejected["error"]["code"], "invalid_enrollment");

        let (status, issued) = harness
            .call(
                "POST",
                &uri,
                None,
                "127.0.0.1",
                Some(json!({ "certificate_signing_request": csr(), "host": "ingest.internal" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "ticket was burnt: {issued}");
    }

    #[tokio::test]
    async fn a_peer_endpoint_with_shell_metacharacters_is_rejected() {
        // endpoint 会原样嵌进入接脚本的单引号字面量：这里就是注入面的入口。
        let harness = Harness::new().with_signer();
        let (status, rejected) = harness
            .call(
                "POST",
                "/api/v1/peers",
                Some("alice"),
                "127.0.0.1",
                Some(json!({
                    "name": "wist-ingest",
                    "host": "ingest.internal",
                    "endpoint": "https://x';id;'/api",
                    "roles": ["read"]
                })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
        assert_eq!(rejected["error"]["code"], "invalid_peer");

        // 改地址这条路也要拦（它以前只查 `https://` 前缀）。
        harness
            .call(
                "POST",
                "/api/v1/peers",
                Some("alice"),
                "127.0.0.1",
                Some(
                    json!({ "name": "wist-ingest", "host": "ingest.internal", "roles": ["read"] }),
                ),
            )
            .await;
        let (status, rejected) = harness
            .call(
                "POST",
                "/api/v1/peers/wist-ingest/endpoint",
                Some("alice"),
                "127.0.0.1",
                Some(json!({ "endpoint": "https://$(id)/api" })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
        assert_eq!(rejected["error"]["code"], "invalid_peer");
    }

    #[tokio::test]
    async fn enroll_reports_an_endpoint_and_only_fills_the_empty_slot() {
        let harness = Harness::new()
            .with_signer()
            .with_peer("wist-ingest", "ingest.internal");
        // with_peer 已经给了地址 → 上报的值不应覆盖。
        let uri = mint_enroll_uri(&harness, "wist-ingest").await;
        let (status, _) = harness
            .call(
                "POST",
                &uri,
                None,
                "127.0.0.1",
                Some(json!({
                    "certificate_signing_request": csr(),
                    "endpoint": "https://attacker.example/x"
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let (_, listed) = harness
            .call("GET", "/api/v1/peers", Some("alice"), "127.0.0.1", None)
            .await;
        assert_eq!(
            listed["peers"][0]["endpoint"],
            "https://ingest.internal:19443/api/v1/internal/credentials"
        );
    }

    #[tokio::test]
    async fn an_endpoint_can_be_set_and_cleared_through_the_api() {
        let harness = Harness::new().with_peer("wist-ingest", "ingest.internal");
        let uri = "/api/v1/peers/wist-ingest/endpoint";

        let (status, body) = harness
            .call(
                "POST",
                uri,
                Some("alice"),
                "127.0.0.1",
                Some(json!({ "endpoint": "https://other:19443/api/v1/internal/credentials" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(
            body["probe_url"], "https://other:19443/healthz",
            "probe url must follow the new endpoint"
        );

        let (status, body) = harness
            .call(
                "POST",
                uri,
                Some("alice"),
                "127.0.0.1",
                Some(json!({ "endpoint": null })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["endpoint"].is_null());
        assert!(
            body["probe_url"].is_null(),
            "manual mode has nothing to probe"
        );

        let (status, body) = harness
            .call(
                "POST",
                uri,
                Some("alice"),
                "127.0.0.1",
                Some(json!({ "endpoint": "http://plain/x" })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_peer");
    }

    #[tokio::test]
    async fn an_endpoint_posted_without_a_path_comes_back_normalized() {
        // 页面上最容易出现的填法：只给 origin。存进去的必须是能推送的完整地址，
        // 否则它会「探活绿、推送 404」—— 之前就是这样把人坑住的。
        let harness = Harness::new().with_peer("wist-center", "center.internal");
        let (status, body) = harness
            .call(
                "POST",
                "/api/v1/peers/wist-center/endpoint",
                Some("alice"),
                "127.0.0.1",
                Some(json!({ "endpoint": "https://center.internal:3103" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(
            body["endpoint"],
            "https://center.internal:3103/api/v1/internal/credentials"
        );
        assert_eq!(body["probe_url"], "https://center.internal:3103/healthz");
    }

    #[tokio::test]
    async fn setting_an_endpoint_on_an_unknown_peer_is_404() {
        let harness = Harness::new();
        let (status, _) = harness
            .call(
                "POST",
                "/api/v1/peers/nope/endpoint",
                Some("alice"),
                "127.0.0.1",
                Some(json!({ "endpoint": null })),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn enroll_accepts_the_host_and_endpoint_the_peer_reports() {
        // 建的时候只给名字（页面上就是这样），身份靠登记时上报。
        let harness = Harness::new().with_signer();
        let (status, created) = harness
            .call(
                "POST",
                "/api/v1/peers",
                Some("alice"),
                "127.0.0.1",
                Some(json!({ "name": "wist-ingest" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "body: {created}");
        assert!(
            created["host"].is_null(),
            "host must be unknown before enrol"
        );

        let uri = mint_enroll_uri(&harness, "wist-ingest").await;
        let (status, issued) = harness
            .call(
                "POST",
                &uri,
                None,
                "127.0.0.1",
                Some(json!({
                    "certificate_signing_request": csr(),
                    "host": "ingest.internal",
                    "endpoint": "https://ingest.internal:19443/api/v1/internal/credentials"
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "body: {issued}");
        let info = wist_pki::inspect::inspect_pem(issued["certificate"].as_str().unwrap())
            .expect("inspect");
        assert!(info.subject.contains("ingest.internal"), "{}", info.subject);

        let (_, listed) = harness
            .call("GET", "/api/v1/peers", Some("alice"), "127.0.0.1", None)
            .await;
        assert_eq!(listed["peers"][0]["host"], "ingest.internal");
        assert_eq!(
            listed["peers"][0]["probe_url"],
            "https://ingest.internal:19443/healthz"
        );
    }

    #[tokio::test]
    async fn enrol_without_any_host_is_rejected_and_does_not_burn_the_ticket() {
        let harness = Harness::new().with_signer();
        let (_, _) = harness
            .call(
                "POST",
                "/api/v1/peers",
                Some("alice"),
                "127.0.0.1",
                Some(json!({ "name": "wist-ingest" })),
            )
            .await;
        let uri = mint_enroll_uri(&harness, "wist-ingest").await;

        let (status, body) = harness
            .call(
                "POST",
                &uri,
                None,
                "127.0.0.1",
                Some(json!({ "certificate_signing_request": csr() })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "host_required");

        // 券还在：补上 host 就能登记。
        let (status, _) = harness
            .call(
                "POST",
                &uri,
                None,
                "127.0.0.1",
                Some(json!({ "certificate_signing_request": csr(), "host": "ingest.internal" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_reported_host_that_disagrees_with_the_registered_one_is_rejected() {
        let harness = Harness::new()
            .with_peer("wist-ingest", "ingest.internal")
            .with_signer();
        let uri = mint_enroll_uri(&harness, "wist-ingest").await;
        let (status, body) = harness
            .call(
                "POST",
                &uri,
                None,
                "127.0.0.1",
                Some(json!({
                    "certificate_signing_request": csr(),
                    "host": "impostor.internal"
                })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "host_mismatch");
    }

    #[tokio::test]
    async fn listing_peers_reports_health_and_probe_url() {
        let harness = Harness::new().with_peer("wist-ingest", "ingest.internal");
        let (status, body) = harness
            .call("GET", "/api/v1/peers", Some("alice"), "127.0.0.1", None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["peers"][0]["health"], "unknown");
        assert_eq!(
            body["peers"][0]["probe_url"],
            "https://ingest.internal:19443/healthz"
        );
        assert_eq!(body["heartbeat_seconds"], 30);
        assert!(body["peers"][0].get("server_cert").is_none());
    }

    /// 造一张真的 CSR（只含公钥）。`common_name` 故意用垃圾值：
    /// 它必须被签发方忽略，证书主体按配置填。
    fn csr() -> String {
        let key = rcgen::KeyPair::generate().expect("key");
        rcgen::CertificateParams::default()
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("csr pem")
    }

    async fn mint_enroll_uri(harness: &Harness, peer: &str) -> String {
        let (status, minted) = harness
            .call(
                "POST",
                &format!("/api/v1/peers/{peer}/enrollment-tickets"),
                Some("alice"),
                "127.0.0.1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let path = minted["path"].as_str().expect("path");
        let token = path
            .trim_start_matches("/enroll/")
            .trim_end_matches("/join.sh");
        format!("/enroll/{token}/certificate")
    }

    #[tokio::test]
    async fn enroll_signs_the_csr_with_our_subject_and_burns_the_ticket() {
        let harness = Harness::new()
            .with_peer("wist-ingest", "ingest.internal")
            .with_signer();
        let uri = mint_enroll_uri(&harness, "wist-ingest").await;

        let (status, body) = harness
            .call(
                "POST",
                &uri,
                None,
                "127.0.0.1",
                Some(json!({ "certificate_signing_request": csr() })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let pem = body["certificate"].as_str().expect("certificate");
        let info = wist_pki::inspect::inspect_pem(pem).expect("inspect issued cert");
        // 主体由我们填，不是 CSR 里声明的。
        assert!(info.subject.contains("ingest.internal"), "{}", info.subject);
        assert!(!info.is_ca);
        assert_eq!(info.sha256, body["fingerprint_sha256"].as_str().unwrap());

        // 券用掉了：再交一次同一张券 → 统一拒绝码。
        let (status, body) = harness
            .call(
                "POST",
                &uri,
                None,
                "127.0.0.1",
                Some(json!({ "certificate_signing_request": csr() })),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "enrollment_rejected");
    }

    #[tokio::test]
    async fn a_bad_csr_does_not_burn_the_ticket() {
        let harness = Harness::new()
            .with_peer("wist-ingest", "ingest.internal")
            .with_signer();
        let uri = mint_enroll_uri(&harness, "wist-ingest").await;

        let (status, body) = harness
            .call(
                "POST",
                &uri,
                None,
                "127.0.0.1",
                Some(json!({ "certificate_signing_request": "not a csr" })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_csr");

        // 同一张券 + 合法 CSR 仍然可用。
        let (status, _) = harness
            .call(
                "POST",
                &uri,
                None,
                "127.0.0.1",
                Some(json!({ "certificate_signing_request": csr() })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn enrolling_from_an_untrusted_peer_is_rejected() {
        let harness = Harness::new()
            .with_peer("wist-ingest", "ingest.internal")
            .with_signer();
        let uri = mint_enroll_uri(&harness, "wist-ingest").await;
        let (status, _) = harness
            .call(
                "POST",
                &uri,
                None,
                "10.9.9.9",
                Some(json!({ "certificate_signing_request": csr() })),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
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
