//! 分层配置：主配置 + `${VAR}` 展开（与 center / console 同口径，fail-closed）。
//!
//! 两条硬约束在**加载期**就拒绝启动（设计文档 §3.4 的 S1）：
//!
//! - `mode = "ingress"` 时 listener 不得绑 `0.0.0.0` / `[::]`——同一份代码绑到公网就是后门；
//! - `mode = "ingress"` 时 `trusted_peers` 不能为空，否则等于谁都能注入操作者头。
//!
//! `mode = "oidc"` 是留给用户中心 / 钉钉的位置，**本期不实现**：显式写出来会直接拒绝启动，
//! 而不是静默退化成不校验。

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use orion_sec::sec::NoSecConv;
use orion_sec::{SecFileFmt, load_sec_dict, load_secfile_by};
use orion_variate::vars::{EnvChecker, EnvDict, EnvEvaluable, ValueType};
use serde::Deserialize;

const SEC_FILE_ENV: &str = "WIST_CRED_SEC_FILE";
const CONFIG_ENV: &str = "WIST_CRED_CONFIG";

const SUPPORTED_DIGEST: &str = "sha256";

#[derive(Debug, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub issue: IssueConfig,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub mode: AuthMode,
    pub ingress_header: String,
    /// 允许到达人机面的对端（unix socket 路径 / CIDR / 回环）。空 = 拒绝启动。
    pub trusted_peers: Vec<String>,
}

/// `ingress`：人身份由内网入口（反代 / 跳板）注入；`oidc`：将来接用户中心 / 钉钉。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Ingress,
    Oidc,
}

#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// 自己的小表；**不复用 center 的 PG**（那个库在接入区）。
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct IssueConfig {
    pub digest: String,
    pub max_ttl_seconds: u64,
    pub break_glass_max_ttl_seconds: u64,
    pub overlap_seconds: u64,
    pub targets: Vec<TargetConfig>,
}

/// 一个验证方（X）。缺省 `client_cert` / `client_key` 时表示推送走同栈内网、不再另带证书。
#[derive(Debug, Clone)]
pub struct TargetConfig {
    pub name: String,
    pub endpoint: String,
    pub audience: String,
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    pub ca: Option<PathBuf>,
}

impl Config {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let path = match path {
            Some(path) => path.to_path_buf(),
            None => match std::env::var_os(CONFIG_ENV).filter(|value| !value.is_empty()) {
                Some(value) => PathBuf::from(value),
                None => PathBuf::from("cred.toml"),
            },
        };
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("read config {}", path.display()))?;
        let raw: RawConfig =
            toml::from_str(&raw).with_context(|| format!("parse config {}", path.display()))?;
        let env = secret_dict()?;
        raw.resolve(&env)
    }
}

fn expand(env: &EnvDict, value: &str) -> anyhow::Result<String> {
    let expanded: String = value.to_string().env_eval(env);
    if expanded.needs_env_eval() {
        bail!(
            "unresolved environment variable(s) in {value:?}: {}",
            expanded.list_env_vars().join(", ")
        );
    }
    Ok(expanded)
}

fn secret_dict() -> anyhow::Result<EnvDict> {
    let mut dict = match std::env::var_os(SEC_FILE_ENV).filter(|path| !path.is_empty()) {
        Some(path) => load_sec_file(Path::new(&path))?,
        None => load_sec_dict().map_err(|err| anyhow::anyhow!("failed to load secrets: {err}"))?,
    };
    for (key, value) in std::env::vars() {
        dict.insert(key, ValueType::from(value.as_str()));
    }
    Ok(dict)
}

fn load_sec_file(path: &Path) -> anyhow::Result<EnvDict> {
    if !path.exists() {
        bail!(
            "secrets file not found: {} ({SEC_FILE_ENV})",
            path.display()
        );
    }
    let space = load_secfile_by(path.to_path_buf(), SecFileFmt::Yaml)
        .map_err(|err| anyhow::anyhow!("failed to load secrets {}: {err}", path.display()))?;
    let mut dict = EnvDict::new();
    for (key, value) in space.no_sec() {
        dict.insert(key, value);
    }
    Ok(dict)
}

/// listener 的 host 部分（去掉端口）。
fn listener_host(addr: &str) -> &str {
    match addr.rfind(':') {
        Some(idx) => &addr[..idx],
        None => addr,
    }
}

/// `0.0.0.0` / `::` / `*` —— 表示"任何对端都能来"。
fn is_unspecified_host(host: &str) -> bool {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    matches!(host, "0.0.0.0" | "::" | "*")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    server: RawServer,
    #[serde(default)]
    storage: RawStorage,
    #[serde(default)]
    issue: RawIssue,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    #[serde(default = "default_listen")]
    listen_addr: String,
    #[serde(default = "default_mode")]
    mode: String,
    #[serde(default = "default_ingress_header")]
    ingress_header: String,
    #[serde(default)]
    trusted_peers: Vec<String>,
}

impl Default for RawServer {
    fn default() -> Self {
        Self {
            listen_addr: default_listen(),
            mode: default_mode(),
            ingress_header: default_ingress_header(),
            trusted_peers: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStorage {
    #[serde(default = "default_storage_path")]
    path: PathBuf,
}

impl Default for RawStorage {
    fn default() -> Self {
        Self {
            path: default_storage_path(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIssue {
    #[serde(default = "default_digest")]
    digest: String,
    #[serde(default = "default_max_ttl")]
    max_ttl_seconds: u64,
    #[serde(default = "default_break_glass_ttl")]
    break_glass_max_ttl_seconds: u64,
    #[serde(default = "default_overlap")]
    overlap_seconds: u64,
    #[serde(default)]
    targets: Vec<RawTarget>,
}

impl Default for RawIssue {
    fn default() -> Self {
        Self {
            digest: default_digest(),
            max_ttl_seconds: default_max_ttl(),
            break_glass_max_ttl_seconds: default_break_glass_ttl(),
            overlap_seconds: default_overlap(),
            targets: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTarget {
    name: String,
    endpoint: String,
    audience: String,
    #[serde(default)]
    client_cert: Option<PathBuf>,
    #[serde(default)]
    client_key: Option<PathBuf>,
    #[serde(default)]
    ca: Option<PathBuf>,
}

fn default_listen() -> String {
    "127.0.0.1:8443".to_string()
}

fn default_mode() -> String {
    "ingress".to_string()
}

fn default_ingress_header() -> String {
    "x-wist-operator".to_string()
}

fn default_storage_path() -> PathBuf {
    PathBuf::from("state/credentials.db")
}

fn default_digest() -> String {
    SUPPORTED_DIGEST.to_string()
}

fn default_max_ttl() -> u64 {
    30 * 24 * 60 * 60
}

fn default_break_glass_ttl() -> u64 {
    90 * 24 * 60 * 60
}

fn default_overlap() -> u64 {
    300
}

impl RawConfig {
    fn resolve(self, env: &EnvDict) -> anyhow::Result<Config> {
        let mode = match self.server.mode.trim() {
            "ingress" => AuthMode::Ingress,
            // 位置留在这里，但本期不做：写出来就拒绝启动，避免静默退化成"不校验"。
            "oidc" => bail!("server.mode = \"oidc\" is not implemented yet"),
            other => bail!("server.mode must be ingress|oidc, got {other:?}"),
        };

        let listen_addr = expand(env, &self.server.listen_addr)?;
        if listen_addr.trim().is_empty() {
            bail!("server.listen_addr must not be empty");
        }

        let ingress_header = expand(env, &self.server.ingress_header)?;
        if mode == AuthMode::Ingress {
            if ingress_header.trim().is_empty() {
                bail!("server.ingress_header must not be empty when mode = ingress");
            }
            if is_unspecified_host(listener_host(&listen_addr)) {
                bail!(
                    "S1: mode = ingress must not bind an unspecified address ({listen_addr}); \
                     bind the private address of the internal proxy instead"
                );
            }
            if self.server.trusted_peers.is_empty() {
                bail!("server.trusted_peers must list at least one peer when mode = ingress");
            }
        }

        let storage_path = expand(env, &self.storage.path.to_string_lossy())?;
        if storage_path.trim().is_empty() {
            bail!("storage.path must not be empty");
        }

        let digest = expand(env, &self.issue.digest)?;
        if digest != SUPPORTED_DIGEST {
            bail!("issue.digest must be {SUPPORTED_DIGEST}, got {digest:?}");
        }
        if self.issue.max_ttl_seconds == 0 {
            bail!("issue.max_ttl_seconds must be > 0");
        }
        if self.issue.break_glass_max_ttl_seconds < self.issue.max_ttl_seconds {
            bail!("issue.break_glass_max_ttl_seconds must be >= issue.max_ttl_seconds");
        }

        let mut targets = Vec::with_capacity(self.issue.targets.len());
        for raw in self.issue.targets {
            let name = expand(env, &raw.name)?;
            let endpoint = expand(env, &raw.endpoint)?;
            let audience = expand(env, &raw.audience)?;
            if name.trim().is_empty() || endpoint.trim().is_empty() || audience.trim().is_empty() {
                bail!("issue.targets entries need non-empty name / endpoint / audience");
            }
            match (&raw.client_cert, &raw.client_key) {
                (Some(_), None) | (None, Some(_)) => {
                    bail!("issue.targets[{name}]: client_cert and client_key must be set together")
                }
                _ => {}
            }
            let expand_path = |value: Option<&PathBuf>| -> anyhow::Result<Option<PathBuf>> {
                match value {
                    Some(path) => Ok(Some(PathBuf::from(expand(env, &path.to_string_lossy())?))),
                    None => Ok(None),
                }
            };
            targets.push(TargetConfig {
                name,
                endpoint,
                audience,
                client_cert: expand_path(raw.client_cert.as_ref())?,
                client_key: expand_path(raw.client_key.as_ref())?,
                ca: expand_path(raw.ca.as_ref())?,
            });
        }

        Ok(Config {
            server: ServerConfig {
                listen_addr,
                mode,
                ingress_header,
                trusted_peers: self.server.trusted_peers,
            },
            storage: StorageConfig {
                path: PathBuf::from(storage_path),
            },
            issue: IssueConfig {
                digest,
                max_ttl_seconds: self.issue.max_ttl_seconds,
                break_glass_max_ttl_seconds: self.issue.break_glass_max_ttl_seconds,
                overlap_seconds: self.issue.overlap_seconds,
                targets,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> anyhow::Result<Config> {
        let raw: RawConfig = toml::from_str(text).expect("raw config");
        raw.resolve(&EnvDict::new())
    }

    const MINIMAL: &str = r#"
        [server]
        listen_addr = "10.0.20.11:8443"
        mode = "ingress"
        trusted_peers = ["10.0.20.10/32"]
    "#;

    #[test]
    fn accepts_private_listener() {
        let config = parse(MINIMAL).expect("valid config");
        assert_eq!(config.server.mode, AuthMode::Ingress);
        assert_eq!(config.server.ingress_header, "x-wist-operator");
        assert_eq!(config.issue.digest, "sha256");
        assert_eq!(config.issue.max_ttl_seconds, 30 * 24 * 60 * 60);
        assert!(config.issue.targets.is_empty());
    }

    #[test]
    fn rejects_unspecified_listener_in_ingress_mode() {
        for addr in ["0.0.0.0:8443", "[::]:8443", "*:8443"] {
            let text = format!(
                "[server]\nlisten_addr = \"{addr}\"\nmode = \"ingress\"\ntrusted_peers = [\"10.0.0.1/32\"]\n"
            );
            let err = parse(&text).expect_err("S1 must reject");
            assert!(err.to_string().contains("S1"), "unexpected error: {err}");
        }
    }

    #[test]
    fn rejects_empty_trusted_peers_in_ingress_mode() {
        let text = "[server]\nlisten_addr = \"10.0.20.11:8443\"\nmode = \"ingress\"\n";
        let err = parse(text).expect_err("empty peers must be rejected");
        assert!(
            err.to_string().contains("trusted_peers"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_oidc_until_implemented() {
        let text = "[server]\nlisten_addr = \"10.0.20.11:8443\"\nmode = \"oidc\"\n";
        let err = parse(text).expect_err("oidc must fail closed");
        assert!(
            err.to_string().contains("not implemented"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_target_with_half_a_client_identity() {
        let text = r#"
            [server]
            listen_addr = "10.0.20.11:8443"
            mode = "ingress"
            trusted_peers = ["10.0.20.10/32"]

            [[issue.targets]]
            name = "wist-center"
            endpoint = "https://center:3103/api/v1/internal/credentials"
            audience = "wist-center"
            client_cert = "/etc/wist/cred/push.pem"
        "#;
        let err = parse(text).expect_err("half identity must be rejected");
        assert!(
            err.to_string().contains("client_key"),
            "unexpected error: {err}"
        );
    }
}
