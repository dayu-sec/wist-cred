//! `wist-cred` 进程入口。

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use wist_cred::api::{self, AppState};
use wist_cred::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config_path = std::env::args().nth(1);
    let config = Config::load(config_path.as_deref().map(Path::new))?;

    log::info!(
        "wist-cred starting: listen={} mode={:?} storage={} targets={}",
        config.server.listen_addr,
        config.server.mode,
        config.storage.path.display(),
        config.issue.targets.len()
    );

    let state = AppState {
        config: Arc::new(config.clone()),
    };
    let app = api::router(state);

    let listener = tokio::net::TcpListener::bind(&config.server.listen_addr)
        .await
        .with_context(|| format!("bind {}", config.server.listen_addr))?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
