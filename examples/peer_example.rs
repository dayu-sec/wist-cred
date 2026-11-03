//! 示例验证方（X）：用 `wist-cred-peer` 起一个**真的**双向认证 HTTPS 服务。
//!
//! 这是"下游怎么接"的样板 —— 依赖走 crates.io 上的 `wist-cred-peer`，不引本地 path：
//!
//! - 收 `register` / `revoke`（cred 推来的授权数据）；
//! - 自己的摘要表（只存 sha256，撤销后重启不复活）；
//! - `/healthz` 供 cred 心跳；
//! - `--verify-endpoint` 时多挂 `POST /verify`，联调时能直接拿 token 试（生产别开）。
//!
//! 为什么养在 `wist-cred` 仓里（而不是部署栈里）：它是**本服务的用法示例**，
//! 跟着本服务的版本走、由本仓的 release 流水线编译成镜像（`wist-cred-example`）——
//! 部署栈只负责拉镜像，不在现场装一套 Rust 工具链。
//!
//! 跑法：
//!   cargo run --example peer_example -- --listen 127.0.0.1:19455 --dir ./identity/demo-peer ...
//!   或者在 `wist-cred-stack` 里：`./dev/svc.sh start peer` / `COMPOSE_PROFILES=demo`

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use wist_cred_peer::{Config, DEFAULT_BASE_PATH, Error, Peer, TlsFiles};

struct Args {
    listen: String,
    dir: PathBuf,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    client_ca: Option<PathBuf>,
    store: PathBuf,
    audience: String,
    issuers: Vec<String>,
    roles: Vec<String>,
    max_ttl: BTreeMap<String, i64>,
    base_path: String,
    verify_endpoint: bool,
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}\n\n{}", usage());
            return ExitCode::from(2);
        }
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("failed to start tokio runtime: {err}");
            return ExitCode::from(1);
        }
    };

    runtime.block_on(run(args))
}

async fn run(args: Args) -> ExitCode {
    let dir = &args.dir;
    let files = TlsFiles {
        cert: args.cert.clone().unwrap_or_else(|| dir.join("server.crt")),
        key: args.key.clone().unwrap_or_else(|| dir.join("server.key")),
        client_ca: args
            .client_ca
            .clone()
            .unwrap_or_else(|| dir.join("client-ca.pem")),
    };

    let mut config = Config::new(&args.audience, &args.store)
        .known_roles(args.roles.clone())
        .base_path(&args.base_path);
    for issuer in &args.issuers {
        config = config.allow_issuer(issuer);
    }
    for (role, seconds) in &args.max_ttl {
        config = config.max_ttl(role, *seconds);
    }

    let peer = match Peer::open(config) {
        Ok(peer) => peer,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };

    let listen: std::net::SocketAddr = match args.listen.parse() {
        Ok(addr) => addr,
        Err(err) => {
            eprintln!("invalid --listen {:?}: {err}", args.listen);
            return ExitCode::from(2);
        }
    };

    println!("验证方已就绪：{}", args.audience);
    println!("  register   POST https://{listen}{}", args.base_path);
    println!(
        "  revoke     POST https://{listen}{}/{{credential_id}}/revoke",
        args.base_path
    );
    println!("  health     GET  https://{listen}/healthz");
    if args.verify_endpoint {
        println!("  verify     POST https://{listen}/verify        （仅联调）");
    }
    println!("  签发方白名单  {:?}", args.issuers);
    println!("  可验角色      {:?}", args.roles);
    println!("  摘要表        {}", args.store.display());
    println!();
    println!(
        "把它填回 cred：收数地址 = https://{listen}{}",
        args.base_path
    );

    let result = if args.verify_endpoint {
        serve_with_verify(peer, listen, files).await
    } else {
        wist_cred_peer::serve(peer, listen, files).await
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

/// 联调模式：与 `serve` 同一套握手，只是多挂了一个 `/verify`。
async fn serve_with_verify(
    peer: Arc<Peer>,
    listen: std::net::SocketAddr,
    files: TlsFiles,
) -> wist_cred_peer::Result<()> {
    let client_ca = std::fs::read_to_string(&files.client_ca)
        .map_err(|err| Error::Serve(format!("read client CA: {err}")))?;
    let config = wist_pki::tls::server_config_mtls(&files.cert, &files.key, &client_ca, false)
        .map_err(Error::Serve)?;
    wist_cred_peer::serve_router(peer.router_with_verify(), listen, config).await
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut parsed = Args {
        listen: "127.0.0.1:19443".to_string(),
        dir: PathBuf::from("/etc/wist/wist-ingest"),
        cert: None,
        key: None,
        client_ca: None,
        store: PathBuf::from("state/credentials.json"),
        audience: "wist-ingest".to_string(),
        issuers: vec!["wist-cred".to_string()],
        roles: Vec::new(),
        max_ttl: BTreeMap::new(),
        base_path: DEFAULT_BASE_PATH.to_string(),
        verify_endpoint: false,
    };

    let mut args = args.peekable();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--listen" => parsed.listen = value(&mut args, "--listen")?,
            "--dir" => parsed.dir = PathBuf::from(value(&mut args, "--dir")?),
            "--cert" => parsed.cert = Some(PathBuf::from(value(&mut args, "--cert")?)),
            "--key" => parsed.key = Some(PathBuf::from(value(&mut args, "--key")?)),
            "--client-ca" => {
                parsed.client_ca = Some(PathBuf::from(value(&mut args, "--client-ca")?))
            }
            "--store" => parsed.store = PathBuf::from(value(&mut args, "--store")?),
            "--audience" => parsed.audience = value(&mut args, "--audience")?,
            "--issuer" => {
                let issuer = value(&mut args, "--issuer")?;
                if !parsed.issuers.contains(&issuer) {
                    parsed.issuers.push(issuer);
                }
            }
            "--known-roles" => {
                parsed.roles = value(&mut args, "--known-roles")?
                    .split(',')
                    .map(|role| role.trim().to_string())
                    .filter(|role| !role.is_empty())
                    .collect();
            }
            "--max-ttl" => {
                let item = value(&mut args, "--max-ttl")?;
                let (role, seconds) = item
                    .split_once('=')
                    .ok_or_else(|| format!("--max-ttl expects role=seconds, got {item:?}"))?;
                let seconds: i64 = seconds
                    .parse()
                    .map_err(|err| format!("invalid seconds in {item:?}: {err}"))?;
                parsed.max_ttl.insert(role.trim().to_string(), seconds);
            }
            "--base-path" => parsed.base_path = value(&mut args, "--base-path")?,
            "--verify-endpoint" => parsed.verify_endpoint = true,
            "-h" | "--help" => return Err("help".to_string()),
            other => return Err(format!("unknown flag {other:?}")),
        }
    }

    if parsed.issuers.is_empty() {
        return Err(
            "at least one --issuer is required (otherwise nothing can be pushed in)".into(),
        );
    }
    Ok(parsed)
}

fn value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{flag} needs a value"))
}

fn usage() -> &'static str {
    "usage: peer-example [options]

  --listen <addr>        监听地址（默认 127.0.0.1:19443）
  --dir <dir>            证书目录（默认 /etc/wist/wist-ingest，接入命令落材料的默认位置）
  --cert / --key         覆盖 dir 下的 server.crt / server.key
  --client-ca            覆盖 dir 下的 client-ca.pem
  --store <file>         摘要表落盘位置（默认 state/credentials.json）
  --audience <name>      本服务的名字，也是凭据的 audience（默认 wist-ingest）
  --issuer <id>          允许的签发方身份，可重复（默认 wist-cred）
  --known-roles <a,b>    本服务能验的角色
  --max-ttl <role=secs>  角色有效期上限，可重复
  --base-path <path>     接收路径前缀（默认 /api/v1/internal/credentials）
  --verify-endpoint      额外挂 POST /verify（仅联调）"
}
