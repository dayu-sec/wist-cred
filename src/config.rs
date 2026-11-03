//! 分层配置：主配置 + `${VAR}` 展开（与 center / console 同口径，fail-closed）。
//!
//! 人机面（页面）的认证有两种模式，**由服务自己验**，不靠反代注入：
//!
//! - `mode = "token"`（发布态默认）：页面输口令，请求带 `Authorization: Bearer <口令>`；
//!   配置里只放口令的 **sha256**（`server.admin_password = "${SEC_CRED_WEB_PASSWORD}"`，
//!   加载时算完就把明文丢掉），与 gateway / center 的管理面同一个形状。
//! - `mode = "ingress"`（开发态 / 已经有入口认证的场合）：人身份由内网反代注入 `x-wist-operator`。
//!
//! 几条**加载期就拒绝启动**的约束（设计文档 §3.4 的 S1）：
//!
//! - listener 不得绑 `0.0.0.0` / `[::]`——同一份代码绑到公网就是后门；
//! - `mode = "ingress"` 时 `trusted_peers` 不能为空，否则等于谁都能注入操作者头；
//! - `mode = "token"` 时 `admin_password` 不能为空，否则等于谁都能进页面签发凭据；
//! - `mode = "oidc"` 是留给用户中心 / 钉钉的位置，**本期不实现**：显式写出来会直接拒绝启动；
//! - 签发 CA 与推送信任锚必须是同一把 CA，否则会签出自己认不了的证书。
//!
//! 认证系统（验证方 X）**不在配置里**：它落在 `state/peers.json`，运行期可增删（见 `peers`）。

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
    /// `None` = 不推送（P2 人工分发）。
    pub push: Option<PushConfig>,
    pub onboarding: OnboardingConfig,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub mode: AuthMode,
    pub ingress_header: String,
    /// `mode = token` 时页面口令的 **sha256**（十六进制）。明文只在密钥文件里，加载后就丢。
    pub admin_password_hash: String,
    /// 允许到达人机面的对端（unix socket 路径 / CIDR / 回环）。
    /// `ingress` 必填；`token` 可选（可用的第二道锁）。
    pub trusted_peers: Vec<String>,
}

/// `token`：页面输口令，服务自己验（发布态）；
/// `ingress`：人身份由内网入口（反代 / 跳板）注入（开发态）；
/// `oidc`：将来接用户中心 / 钉钉。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Token,
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
}

/// 推送：每个认证系统共用这一套身份与信任锚，只有 URL 不同。
#[derive(Debug, Clone)]
pub struct PushConfig {
    /// CA-I 签的客户端证书（证明"我是 cred"）。
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
    /// CA-S 信任锚（校 X 的服务器证书）。
    pub ca: PathBuf,
    pub timeout_seconds: u64,
}

/// 接入：签发验证方服务器证书 + 一次性券。
#[derive(Debug, Clone)]
pub struct OnboardingConfig {
    /// 部署态种子目录（`scripts/gen-pki.sh` 的产物），首次启动导入一次。
    pub dir: Option<PathBuf>,
    /// 注册表落点（`state/peers.json`）。运行期可写。
    pub store_path: PathBuf,
    /// 一次性接入券的有效期。
    pub script_ttl_seconds: u64,
    /// 签 X 服务器证书的 CA（CA-S）。
    pub ca_cert: Option<PathBuf>,
    pub ca_key: Option<PathBuf>,
    /// 交给 X 的信任锚（CA-I 的**公开证书**），签 CSR 时一起下发。
    pub client_ca: Option<PathBuf>,
    /// 签给 X 的服务器证书有效期。
    pub peer_cert_ttl_seconds: u64,
    /// 心跳间隔；`0` = 关闭心跳（页面会一直显示"未知"）。
    pub heartbeat_seconds: u64,
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
    if host == "*" {
        return true;
    }
    // 按 IP 解析而不是字面比对：`0:0:0:0:0:0:0:0` 也是“任何地址”。
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_unspecified())
        .unwrap_or(false)
}

/// 比 PEM 内容时忽略行尾空白与末尾空行：同一张证书经常被不同工具写出不同的尾部。
fn normalize_pem(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
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
    #[serde(default)]
    push: Option<RawPush>,
    #[serde(default)]
    onboarding: RawOnboarding,
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
    /// `mode = token` 时的人人面口令。写 `${SEC_CRED_WEB_PASSWORD}`，真值只在密钥文件里。
    #[serde(default)]
    admin_password: Option<String>,
    #[serde(default)]
    trusted_peers: Vec<String>,
}

impl Default for RawServer {
    fn default() -> Self {
        Self {
            listen_addr: default_listen(),
            mode: default_mode(),
            ingress_header: default_ingress_header(),
            admin_password: None,
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
}

impl Default for RawIssue {
    fn default() -> Self {
        Self {
            digest: default_digest(),
            max_ttl_seconds: default_max_ttl(),
            break_glass_max_ttl_seconds: default_break_glass_ttl(),
            overlap_seconds: default_overlap(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPush {
    client_cert: PathBuf,
    client_key: PathBuf,
    ca: PathBuf,
    #[serde(default = "default_push_timeout")]
    timeout_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOnboarding {
    #[serde(default)]
    dir: Option<PathBuf>,
    #[serde(default = "default_peers_path")]
    store_path: PathBuf,
    #[serde(default = "default_script_ttl")]
    script_ttl_seconds: u64,
    #[serde(default)]
    ca_cert: Option<PathBuf>,
    #[serde(default)]
    ca_key: Option<PathBuf>,
    #[serde(default)]
    client_ca: Option<PathBuf>,
    #[serde(default = "default_peer_cert_ttl")]
    peer_cert_ttl_seconds: u64,
    #[serde(default = "default_heartbeat")]
    heartbeat_seconds: u64,
}

impl Default for RawOnboarding {
    fn default() -> Self {
        Self {
            dir: None,
            store_path: default_peers_path(),
            script_ttl_seconds: default_script_ttl(),
            ca_cert: None,
            ca_key: None,
            client_ca: None,
            peer_cert_ttl_seconds: default_peer_cert_ttl(),
            heartbeat_seconds: default_heartbeat(),
        }
    }
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

fn default_peers_path() -> PathBuf {
    PathBuf::from("state/peers.json")
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

fn default_script_ttl() -> u64 {
    15 * 60
}

fn default_peer_cert_ttl() -> u64 {
    90 * 24 * 60 * 60
}

fn default_heartbeat() -> u64 {
    30
}

fn default_push_timeout() -> u64 {
    10
}

impl RawConfig {
    fn resolve(self, env: &EnvDict) -> anyhow::Result<Config> {
        let mode = match self.server.mode.trim() {
            "token" => AuthMode::Token,
            "ingress" => AuthMode::Ingress,
            // 位置留在这里，但本期不做：写出来就拒绝启动，避免静默退化成"不校验"。
            "oidc" => bail!("server.mode = \"oidc\" is not implemented yet"),
            other => bail!("server.mode must be token|ingress|oidc, got {other:?}"),
        };

        let listen_addr = expand(env, &self.server.listen_addr)?;
        if listen_addr.trim().is_empty() {
            bail!("server.listen_addr must not be empty");
        }

        // S1 对两种模式都成立：绑 unspecified 地址的 listener 就是一个“谁都能来”的后门。
        if is_unspecified_host(listener_host(&listen_addr)) {
            bail!(
                "S1: server.listen_addr must not bind an unspecified address ({listen_addr}); \
                 bind the private address of the ingress/proxy instead"
            );
        }

        let ingress_header = expand(env, &self.server.ingress_header)?;
        if mode == AuthMode::Ingress && ingress_header.trim().is_empty() {
            bail!("server.ingress_header must not be empty when mode = ingress");
        }

        // 页面口令：配置里只有 sha256（跟 gateway / center 的管理面同一个形状）。
        // 明文从 `${SEC_CRED_WEB_PASSWORD}` 来（密钥文件），算完就丢。
        if mode != AuthMode::Token && self.server.admin_password.is_some() {
            // 写了但不生效 —— 与“写错了键”一样危险：现场会以为它已经生效。
            bail!("server.admin_password only applies to mode = token (current mode: {mode:?})");
        }
        let admin_password_hash = if mode == AuthMode::Token {
            let raw = self.server.admin_password.as_deref().unwrap_or("").trim();
            if raw.is_empty() {
                bail!(
                    "server.admin_password must be set when mode = token \
                     (write `${{SEC_CRED_WEB_PASSWORD}}` here, never the literal)"
                );
            }
            let password = expand(env, raw)?;
            if password.trim().is_empty() {
                bail!("server.admin_password resolved to an empty value");
            }
            // 两端空白会被裁掉（`wist_auth::bearer_token` 与页面输入都 trim）。
            // 接受它等于接受一个“看着多一个空格、实际不生效”的口令 —— 直接拒掉。
            if password != password.trim() {
                bail!(
                    "server.admin_password has leading/trailing whitespace; \
                     it is trimmed on both ends, so a password with spaces can never match"
                );
            }
            wist_auth::sha256_hex(&password)
        } else {
            String::new()
        };

        if mode == AuthMode::Ingress && self.server.trusted_peers.is_empty() {
            bail!("server.trusted_peers must list at least one peer when mode = ingress");
        }
        // 两条路都要把写错的规则打回去：否则错一个 CIDR 就是“所有人 401”，
        // 而且每个请求都会刷一条 warn。（token 模式下 trusted_peers 可为空 = 不做第二道锁。）
        if !self.server.trusted_peers.is_empty() {
            for rule in &self.server.trusted_peers {
                let rule = rule.trim();
                if rule.is_empty() {
                    bail!("server.trusted_peers must not contain empty entries");
                }
                if !crate::api::trusted_peer_rule_is_valid(rule) {
                    bail!(
                        "server.trusted_peers entry {rule:?} is not an IP, a CIDR, or unix:<path>"
                    );
                }
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

        let path_of = |value: &PathBuf| -> anyhow::Result<PathBuf> {
            Ok(PathBuf::from(expand(env, &value.to_string_lossy())?))
        };

        let push = match self.push {
            Some(raw) => {
                if raw.timeout_seconds == 0 {
                    bail!("push.timeout_seconds must be > 0");
                }
                Some(PushConfig {
                    client_cert: path_of(&raw.client_cert)?,
                    client_key: path_of(&raw.client_key)?,
                    ca: path_of(&raw.ca)?,
                    timeout_seconds: raw.timeout_seconds,
                })
            }
            None => None,
        };

        if self.onboarding.script_ttl_seconds == 0 {
            bail!("onboarding.script_ttl_seconds must be > 0");
        }
        // 上限压到 1 小时：一次性凭据不该有长窗口。
        if self.onboarding.script_ttl_seconds > 3600 {
            bail!("onboarding.script_ttl_seconds must be <= 3600");
        }
        if self.onboarding.peer_cert_ttl_seconds == 0 {
            bail!("onboarding.peer_cert_ttl_seconds must be > 0");
        }
        let onboard_ca = match (&self.onboarding.ca_cert, &self.onboarding.ca_key) {
            (Some(cert), Some(key)) => Some((path_of(cert)?, path_of(key)?)),
            (None, None) => None,
            _ => bail!("onboarding.ca_cert and onboarding.ca_key must be set together"),
        };

        let store_path = expand(env, &self.onboarding.store_path.to_string_lossy())?;
        if store_path.trim().is_empty() {
            bail!("onboarding.store_path must not be empty");
        }
        let onboarding_dir = match &self.onboarding.dir {
            Some(path) => Some(path_of(path)?),
            None => None,
        };
        let client_ca = match &self.onboarding.client_ca {
            Some(path) => Some(path_of(path)?),
            None => None,
        };

        // 签证书用的 CA 必须就是推数时验证对方的那把 —— 否则会签出自己认不了的证书。
        if let (Some((cert_path, _)), Some(push)) = (&onboard_ca, &push) {
            let signing = std::fs::read_to_string(cert_path)
                .with_context(|| format!("read onboarding.ca_cert {}", cert_path.display()))?;
            let anchoring = std::fs::read_to_string(&push.ca)
                .with_context(|| format!("read push.ca {}", push.ca.display()))?;
            if normalize_pem(&signing) != normalize_pem(&anchoring) {
                bail!(
                    "onboarding.ca_cert and push.ca are different CAs; \
                     certificates signed by one cannot be verified with the other"
                );
            }
        }

        Ok(Config {
            server: ServerConfig {
                listen_addr,
                mode,
                ingress_header,
                admin_password_hash,
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
            },
            push,
            onboarding: OnboardingConfig {
                dir: onboarding_dir,
                store_path: PathBuf::from(store_path),
                script_ttl_seconds: self.onboarding.script_ttl_seconds,
                ca_cert: onboard_ca.as_ref().map(|(cert, _)| cert.clone()),
                ca_key: onboard_ca.map(|(_, key)| key),
                client_ca,
                peer_cert_ttl_seconds: self.onboarding.peer_cert_ttl_seconds,
                heartbeat_seconds: self.onboarding.heartbeat_seconds,
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

    /// 带环境（密钥文件 / env）的解析：`mode = token` 的口令就是从这里来的。
    fn parse_with_env(text: &str, env: &[(&str, &str)]) -> anyhow::Result<Config> {
        let raw: RawConfig = toml::from_str(text).expect("raw config");
        let mut dict = EnvDict::new();
        for (key, value) in env {
            dict.insert((*key).to_string(), ValueType::from(*value));
        }
        raw.resolve(&dict)
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
        assert!(config.push.is_none());
        assert_eq!(config.onboarding.heartbeat_seconds, 30);
        assert_eq!(config.onboarding.script_ttl_seconds, 900);
    }

    #[test]
    fn accepts_a_loopback_listener_because_it_is_not_unspecified() {
        let text = "[server]\nlisten_addr = \"[::1]:8443\"\nmode = \"ingress\"\ntrusted_peers = [\"127.0.0.1/32\"]\n";
        assert!(parse(text).is_ok(), "loopback must be allowed");
    }

    #[test]
    fn rejects_trusted_peers_entries_that_would_never_match() {
        // 写错一个 CIDR 的结果是“所有人 401”，且每个请求刷一条 warn —— 加载期就拦。
        for rule in ["10.0.0.0/33", "not-an-ip", "", "10.0.0.0/"] {
            let text = format!(
                "[server]\nlisten_addr = \"10.0.20.11:8443\"\nmode = \"ingress\"\ntrusted_peers = [\"{rule}\"]\n"
            );
            let err = parse(&text).expect_err("must reject {rule:?}");
            assert!(
                err.to_string().contains("trusted_peers"),
                "unexpected error for {rule:?}: {err}"
            );
        }
    }

    const TOKEN_MINIMAL: &str = r#"
        [server]
        listen_addr = "10.0.20.11:8443"
        mode = "token"
        admin_password = "${SEC_CRED_WEB_PASSWORD}"
    "#;

    #[test]
    fn token_mode_loads_the_password_from_the_secret_file() {
        let password = "0123456789abcdef01234567";
        let config = parse_with_env(TOKEN_MINIMAL, &[("SEC_CRED_WEB_PASSWORD", password)])
            .expect("valid token config");
        assert_eq!(config.server.mode, AuthMode::Token);
        // 配置里只留 sha256：明文算完就丢（结构体里根本没有存明文的字段）。
        assert_eq!(
            config.server.admin_password_hash,
            wist_auth::sha256_hex(password)
        );
        assert_ne!(config.server.admin_password_hash, password);
        // token 模式下 trusted_peers 可为空（要第二道锁时再写）。
        assert!(config.server.trusted_peers.is_empty());
    }

    #[test]
    fn token_mode_without_a_usable_password_fails_closed() {
        for text in [
            "[server]\nlisten_addr = \"10.0.20.11:8443\"\nmode = \"token\"\n",
            "[server]\nlisten_addr = \"10.0.20.11:8443\"\nmode = \"token\"\nadmin_password = \"\"\n",
        ] {
            let err = parse(text).expect_err("token mode needs a password");
            assert!(
                err.to_string().contains("admin_password"),
                "unexpected error: {err}"
            );
        }

        // 密钥文件里没这个键（展开失败）：必须当场报错，不能静默成空口令。
        let err = parse("[server]\nlisten_addr = \"10.0.20.11:8443\"\nmode = \"token\"\nadmin_password = \"${SEC_MISSING}\"\n")
            .expect_err("unresolved secret must fail");
        assert!(
            err.to_string().contains("SEC_MISSING"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn token_mode_still_refuses_to_bind_an_unspecified_address() {
        let text =
            "[server]\nlisten_addr = \"0.0.0.0:8443\"\nmode = \"token\"\nadmin_password = \"x\"\n";
        let err = parse(text).expect_err("S1 must reject");
        assert!(err.to_string().contains("S1"), "unexpected error: {err}");
    }

    #[test]
    fn token_mode_rejects_a_password_with_padding() {
        // 两端空白在 `bearer_token` 与页面输入里都会被裁掉：接受它 = 接受一个
        // “看着多一个空格、实际永远对不上”的口令。这里走密钥文件那条路（真实现场就是这么写的）——
        // 写在配置里的字面值本身就会被 trim，真正带空白的是密钥值。
        let text = "[server]\nlisten_addr = \"10.0.20.11:8443\"\nmode = \"token\"\nadmin_password = \"${PW}\"\n";
        let err =
            parse_with_env(text, &[("PW", " abc ")]).expect_err("padded secret must be rejected");
        assert!(
            err.to_string().contains("whitespace"),
            "unexpected error: {err}"
        );

        // 不带空白的密钥值照常可用（对照组，避免上面是因为别的原因才失败）。
        assert!(parse_with_env(text, &[("PW", "abc")]).is_ok());
    }

    #[test]
    fn admin_password_is_rejected_outside_token_mode() {
        // 写了但不生效，比写错键更危险：现场会以为它已经生效。
        let text = "[server]\nlisten_addr = \"10.0.20.11:8443\"\nmode = \"ingress\"\ntrusted_peers = [\"10.0.20.10/32\"]\nadmin_password = \"x\"\n";
        let err = parse(text).expect_err("admin_password only applies to token mode");
        assert!(
            err.to_string().contains("only applies to mode = token"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn token_mode_still_validates_trusted_peers() {
        let text = "[server]\nlisten_addr = \"10.0.20.11:8443\"\nmode = \"token\"\nadmin_password = \"x\"\ntrusted_peers = [\"not-an-ip\"]\n";
        let err = parse(text).expect_err("bogus CIDR must be rejected in token mode too");
        assert!(
            err.to_string().contains("trusted_peers"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn allows_unix_entries_beside_ip_entries() {
        let text = "[server]\nlisten_addr = \"10.0.20.11:8443\"\nmode = \"ingress\"\ntrusted_peers = [\"10.0.20.10/32\", \"unix:/run/wist/cred.sock\"]\n";
        let config = parse(text).expect("unix entries are allowed in the list");
        assert_eq!(config.server.trusted_peers.len(), 2);
    }

    #[test]
    fn rejects_unspecified_listener_in_ingress_mode() {
        for addr in [
            "0.0.0.0:8443",
            "[::]:8443",
            "*:8443",
            // IPv6 的长写：字面比对会漏掉它，按 IP 解析才拦得住。
            "[0:0:0:0:0:0:0:0]:8443",
            "[::0]:8443",
        ] {
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
    fn rejects_onboarding_ttl_above_one_hour() {
        let text = format!("{MINIMAL}\n[onboarding]\nscript_ttl_seconds = 7200\n");
        let err = parse(&text).expect_err("long-lived ticket must be rejected");
        assert!(err.to_string().contains("3600"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_half_a_signing_ca() {
        let text = format!("{MINIMAL}\n[onboarding]\nca_cert = \"/x/ca.crt\"\n");
        let err = parse(&text).expect_err("half CA must be rejected");
        assert!(
            err.to_string().contains("ca_key"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_a_signing_ca_that_differs_from_the_push_anchor() {
        let dir = tempdir::TempDirGuard::new();
        let signing = dir.path.join("signing.crt");
        let anchoring = dir.path.join("anchor.crt");
        std::fs::write(
            &signing,
            "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        std::fs::write(
            &anchoring,
            "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let key = dir.path.join("ca.key");
        std::fs::write(&key, "KEY").unwrap();

        let text = format!(
            "{MINIMAL}\n[push]\nclient_cert = \"/x/c.crt\"\nclient_key = \"/x/c.key\"\nca = {:?}\n\n[onboarding]\nca_cert = {:?}\nca_key = {:?}\n",
            anchoring.display().to_string(),
            signing.display().to_string(),
            key.display().to_string()
        );
        let err = parse(&text).expect_err("different CAs must be rejected");
        assert!(
            err.to_string().contains("different CAs"),
            "unexpected error: {err}"
        );
    }

    mod tempdir {
        use std::path::PathBuf;

        pub struct TempDirGuard {
            pub path: PathBuf,
        }

        impl TempDirGuard {
            pub fn new() -> Self {
                let mut bytes = [0u8; 8];
                getrandom::fill(&mut bytes).expect("entropy");
                let name: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
                let path = std::env::temp_dir().join(format!("wist-cred-config-{name}"));
                std::fs::create_dir_all(&path).expect("create temp dir");
                Self { path }
            }
        }

        impl Drop for TempDirGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }
}
