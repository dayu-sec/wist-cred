//! `wist-cred` 进程入口。

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use wist_cred::api::{self, AppState};
use wist_cred::config::Config;
use wist_cred::peers::{Health, PeerRegistry};
use wist_cred::push::Pusher;
use wist_cred::store::Store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config_path = std::env::args().nth(1);
    let config = Config::load(config_path.as_deref().map(Path::new))?;
    let store = Store::open(config.storage.path.clone())
        .with_context(|| format!("open store {}", config.storage.path.display()))?;

    // 认证系统注册表：先读自己的表，再导入部署态种子（已有的不覆盖）。
    let peers = Arc::new(
        PeerRegistry::open(config.onboarding.store_path.clone()).with_context(|| {
            format!(
                "open peer registry {}",
                config.onboarding.store_path.display()
            )
        })?,
    );
    if let Some(dir) = &config.onboarding.dir {
        match peers.import_dir(dir) {
            Ok(imported) if !imported.is_empty() => {
                log::info!("imported {} peer(s) from {}", imported.len(), dir.display());
            }
            Ok(_) => {}
            Err(error) => log::warn!("peer import from {} failed: {error:#}", dir.display()),
        }
    }

    let boarding = wist_cred::onboarding::TicketStore::new(config.onboarding.script_ttl_seconds);

    // 推送客户端：一套身份（cred-client）+ 一个信任锚（CA-S），所有认证系统共用。
    let push = match &config.push {
        Some(push) => Some(Arc::new(
            Pusher::new(
                &push.client_cert,
                &push.client_key,
                &push.ca,
                Duration::from_secs(push.timeout_seconds),
            )
            .context("build push client (mutual TLS)")?,
        )),
        None => None,
    };

    // 签发 CA：按 CSR 签认证系统的服务器证书。私钥只在这里用，且**不接收对方的私钥**。
    let signer = match (&config.onboarding.ca_cert, &config.onboarding.ca_key) {
        (Some(cert), Some(key)) => Some(
            wist_pki::CertificateAuthority::load(cert, key)
                .map_err(|err| anyhow::anyhow!("load onboarding signing CA: {err}"))?,
        ),
        _ => None,
    };

    let peer_count = peers.list().len();
    log::info!(
        "wist-cred starting: listen={} mode={:?} storage={} peers={} push={} signing={} heartbeat={}s",
        config.server.listen_addr,
        config.server.mode,
        config.storage.path.display(),
        peer_count,
        push.is_some(),
        signer.is_some(),
        config.onboarding.heartbeat_seconds
    );
    for peer in peers.list() {
        log::info!(
            "auth system: name={} host={:?} endpoint={:?}",
            peer.name,
            peer.host,
            peer.endpoint
        );
    }

    // 心跳：只有配了推送客户端（有 mTLS 身份）才有意义 ——
    // 「能握手」比「能 ping 通」有意义得多，证书过期/链不对/时间偏都会在这里暴露。
    if let (Some(pusher), 1..) = (push.clone(), config.onboarding.heartbeat_seconds) {
        let peers = peers.clone();
        let interval = config.onboarding.heartbeat_seconds;
        tokio::spawn(async move {
            heartbeat_loop(pusher, peers, interval).await;
        });
    } else if config.onboarding.heartbeat_seconds > 0 {
        log::warn!("heartbeat is enabled but [push] is not configured; skipping probes");
    }

    let state = AppState {
        config: Arc::new(config.clone()),
        store: Arc::new(store),
        push,
        boarding: Arc::new(boarding),
        signer: signer.map(Arc::new),
        peers,
    };
    let app = api::router(state);

    let listener = tokio::net::TcpListener::bind(&config.server.listen_addr)
        .await
        .with_context(|| format!("bind {}", config.server.listen_addr))?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

/// 周期性探测每个认证系统。状态只留在内存里：重启后先显示"未知"，等第一次探测。
async fn heartbeat_loop(pusher: Arc<Pusher>, peers: Arc<PeerRegistry>, seconds: u64) {
    let mut ticker = tokio::time::interval(Duration::from_secs(seconds));
    loop {
        ticker.tick().await;
        for peer in peers.list() {
            let Some(url) = peer.probe_url() else {
                continue; // 没配地址 = 手工分发模式，不探。
            };
            let previous = peers.health(&peer.name);
            // 探一次可能要等到超时；这期间地址可能被人改过。结论只对“探的那个地址”有效，
            // 所以写回前再确认一次，否则会把旧地址的结论盖到新地址头上。
            let still_current = |peers: &PeerRegistry| {
                peers.get(&peer.name).and_then(|item| item.probe_url()) == Some(url.clone())
            };
            match pusher.probe(&url).await {
                Ok(latency_ms) => {
                    if !still_current(&peers) {
                        log::debug!("skip stale heartbeat for {} ({url} changed)", peer.name);
                        continue;
                    }
                    let now = now_secs();
                    if !previous.is_up() {
                        log::info!(
                            "auth system {} is reachable again ({url}, {latency_ms}ms)",
                            peer.name
                        );
                    }
                    peers.set_health(
                        &peer.name,
                        Health::Up {
                            at: now,
                            latency_ms,
                        },
                    );
                }
                Err(error) => {
                    if !still_current(&peers) {
                        log::debug!("skip stale heartbeat for {} ({url} changed)", peer.name);
                        continue;
                    }
                    let detail = format!("{error:#}");
                    if previous.is_up() || matches!(previous, Health::Unknown) {
                        log::warn!("auth system {} is unreachable: {detail}", peer.name);
                    }
                    peers.set_health(
                        &peer.name,
                        Health::Down {
                            at: now_secs(),
                            error: detail,
                        },
                    );
                }
            }
        }
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
