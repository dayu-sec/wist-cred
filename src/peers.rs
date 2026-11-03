//! 认证系统注册表：**运行期可变**，落 `state/peers.json`。
//!
//! 为什么要可变：接入一个验证方（X）是运维日常动作，不该每次改 `vars.yml` 再 localize。
//! 但也不能只活在内存里 —— 它是「往哪儿推摘要」的唯一来源，重启丢了就等于全部推送中断。
//!
//! 三个来源，优先级从低到高：
//!
//! 1. **PKI 种子**（`onboarding.dir/*/peer.json`）：部署阶段由 `scripts/gen-pki.sh` 写，
//!    首次启动导入一次；已在注册表里的不覆盖。
//! 2. **API 创建**（`POST /api/v1/onboarding/peers`）：人在页面上建。
//! 3. **登记回填**（`POST /enroll/{券}/certificate`）：X 交 CSR 时可以带上自己的收数地址，
//!    只补空字段，不改已有值。
//!
//! 心跳状态**不落盘**：它十分钟就过时了，重启后应该老老实实显示"未知"，等第一次探测。

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

/// 一个认证系统（验证方 X）。
///
/// `name` 同时是三个东西：页面显示名、凭证的 `audience`、推数时的对端标识。
/// 不另设 `audience` 字段 —— 它们永远是同一个值，分开存只会多一个对不齐的地方。
///
/// **`host` 与 `endpoint` 都是对方自己上报的**（登记时），不是操作者填的：
/// X 比任何人都清楚自己叫什么、在哪里听。操作者在页面上只给一个名字。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Peer {
    pub name: String,
    /// 证书 SAN / CN。`None` = 还没登记。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// 收摘要的地址（`POST`）。`None` = 手工分发。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// 心跳探测地址；缺省由 `endpoint` 推导（同源 + `/healthz`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub healthz: Option<String>,
    /// 这个系统自己能验的**角色**，登记时由它上报。
    ///
    /// 空 = 还没登记（此时**发不出凭据**：`400 roles_not_registered`）。
    /// 非空 = 发放凭证时只能从这里选；X 重跑接入命令时上报的新集合会**覆盖**它。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    pub created_at: i64,
    /// `pki` = 部署种子；否则是操作者名。
    pub created_by: String,
}

impl Peer {
    /// 证书主体：登记过就用上报的，否则空。
    pub fn host(&self) -> &str {
        self.host.as_deref().unwrap_or_default()
    }

    /// 心跳探测地址：显式配了就用；否则从 endpoint 推到同源 `/healthz`。
    pub fn probe_url(&self) -> Option<String> {
        if let Some(url) = &self.healthz {
            return Some(url.clone());
        }
        let endpoint = self.endpoint.as_deref()?;
        let authority = origin_of(endpoint)?;
        Some(format!("{authority}/healthz"))
    }
}

/// 取 `https://host:port`（去掉 path/query），解析不出来就返回 `None`。
pub fn origin_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let authority: String = rest
        .chars()
        .take_while(|character| *character != '/' && *character != '?' && *character != '#')
        .collect();
    if authority.is_empty() {
        None
    } else {
        Some(format!("https://{authority}"))
    }
}

/// 心跳状态。**只活在内存里**。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    Unknown,
    Up { at: i64, latency_ms: u64 },
    Down { at: i64, error: String },
}

impl Health {
    pub fn is_up(&self) -> bool {
        matches!(self, Health::Up { .. })
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct FileData {
    #[serde(default)]
    revision: u64,
    #[serde(default)]
    peers: Vec<Peer>,
}

/// 注册表。读多写少；探测每 N 秒刷一次健康状态。
pub struct PeerRegistry {
    path: PathBuf,
    state: Mutex<State>,
}

struct State {
    peers: BTreeMap<String, Peer>,
    health: BTreeMap<String, Health>,
    revision: u64,
}

impl PeerRegistry {
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .with_context(|| format!("create peer store dir {}", parent.display()))?;
        }
        let data = read(&path)?;
        let peers = data
            .peers
            .into_iter()
            .map(|peer| (peer.name.clone(), peer))
            .collect();
        Ok(Self {
            path,
            state: Mutex::new(State {
                peers,
                health: BTreeMap::new(),
                revision: data.revision,
            }),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 导入部署态种子（`onboarding.dir/*/peer.json`）。已有的不覆盖。
    ///
    /// 返回新导入的名称。目录不存在只告警（首次部署还没 localize）。
    pub fn import_dir(&self, dir: &Path) -> anyhow::Result<Vec<String>> {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                log::warn!(
                    "onboarding.dir {} does not exist; no peers to import",
                    dir.display()
                );
                return Ok(Vec::new());
            }
            Err(err) => {
                return Err(err).with_context(|| format!("read onboarding dir {}", dir.display()));
            }
        };

        let mut imported = Vec::new();
        let mut to_write = Vec::new();
        for entry in entries {
            let entry = entry.with_context(|| format!("read entry in {}", dir.display()))?;
            let peer_dir = entry.path();
            if !peer_dir.is_dir() {
                continue;
            }
            let meta_path = peer_dir.join("peer.json");
            if !meta_path.is_file() {
                continue;
            }
            let text = fs::read_to_string(&meta_path)
                .with_context(|| format!("read {}", meta_path.display()))?;
            let seed: RawPeerSeed = serde_json::from_str(&text)
                .with_context(|| format!("parse {}", meta_path.display()))?;
            let peer = seed.into_peer()?;
            let dir_name = peer_dir
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_string();
            if dir_name != peer.name {
                bail!(
                    "{}: name {:?} does not match its directory {:?}",
                    meta_path.display(),
                    peer.name,
                    dir_name
                );
            }
            to_write.push(peer);
        }

        if to_write.is_empty() {
            return Ok(imported);
        }

        let mut state = self.lock();
        let mut changed = false;
        for peer in to_write {
            if state.peers.contains_key(&peer.name) {
                continue; // 运行期以注册表为准
            }
            imported.push(peer.name.clone());
            state.peers.insert(peer.name.clone(), peer);
            changed = true;
        }
        if changed {
            let before = (state.revision, state.peers.clone());
            state.revision += 1;
            let snapshot = snapshot(&state);
            drop(state);
            if let Err(error) = write(&self.path, &snapshot) {
                // 落盘失败就把内存退回：否则重启后这批种子会再次被"新导入"，
                // 而调用方已经收到失败。
                let mut state = self.lock();
                state.revision = before.0;
                state.peers = before.1;
                return Err(error);
            }
        }
        Ok(imported)
    }

    pub fn list(&self) -> Vec<Peer> {
        self.lock().peers.values().cloned().collect()
    }

    pub fn get(&self, name: &str) -> Option<Peer> {
        self.lock().peers.get(name).cloned()
    }

    pub fn by_endpoint(&self) -> BTreeMap<String, String> {
        self.lock()
            .peers
            .values()
            .filter_map(|peer| peer.endpoint.clone().map(|url| (peer.name.clone(), url)))
            .collect()
    }

    /// 这个系统是否已登记（用于创建凭证时的受众校验）。
    pub fn contains(&self, name: &str) -> bool {
        self.lock().peers.contains_key(name)
    }

    pub fn is_empty(&self) -> bool {
        self.lock().peers.is_empty()
    }

    pub fn health(&self, name: &str) -> Health {
        self.lock()
            .health
            .get(name)
            .cloned()
            .unwrap_or(Health::Unknown)
    }

    pub fn set_health(&self, name: &str, health: Health) {
        self.lock().health.insert(name.to_string(), health);
    }

    /// 新建一个认证系统。
    ///
    /// **只要求一个名称**：`host` / `endpoint` 是对方登记时自己上报的，操作者不需要知道。
    /// 它们仍可以在这里给（部署种子 / 脚本），但都是可选的。
    pub fn create(&self, input: NewPeer, by: &str) -> Result<Peer, PeerError> {
        let name = input.name.trim().to_string();
        validate_name(&name)?;

        let host = input
            .host
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        if let Some(host) = &host {
            validate_host(host)?;
        }
        let endpoint = input
            .endpoint
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        if let Some(url) = &endpoint {
            validate_endpoint(url)?;
        }

        // 只给了地址没给主机名：从地址里取 —— 证书 SAN 必须与推数时连的地址一致。
        let host = host.or_else(|| endpoint.as_deref().and_then(host_of));

        let peer = Peer {
            name: name.clone(),
            host,
            endpoint,
            healthz: input
                .healthz
                .map(|value| value.trim().to_string())
                .filter(|v| !v.is_empty()),
            roles: normalize_roles(input.roles).map_err(PeerError::BadRequest)?,
            created_at: now_secs(),
            created_by: by.to_string(),
        };

        let mut state = self.lock();
        if state.peers.contains_key(&name) {
            return Err(PeerError::Conflict(format!("peer {name:?} already exists")));
        }
        let before = state.peers.clone();
        let revision = state.revision;
        state.peers.insert(name.clone(), peer.clone());
        state.revision += 1;
        let snapshot = snapshot(&state);
        if let Err(error) = write(&self.path, &snapshot) {
            // 落盘失败不能把内存留在前面：否则重试会撞 409，而磁盘上其实没有这条。
            state.peers = before;
            state.revision = revision;
            return Err(PeerError::Store(format!("{error:#}")));
        }
        Ok(peer)
    }

    /// 登记时接收对方上报的身份：`host`（证书 SAN）、`endpoint`（收数地址）、`roles`。
    ///
    /// 规则：
    /// - `host` / `endpoint` **只补空**，不覆盖已有的值（操作者在页面上改过的优先）；
    /// - `roles` **上报非空就覆盖**：它是 X 自己的词汇表，重跑接入命令就是改它；
    ///   上报空值只是“这次没说”，不当成清空；
    /// - `host` 与 `endpoint` 同时上报时，`host` 必须等于地址里的主机 —— 证书 SAN 与
    ///   推数时连的地址必须一致，否则握手必然失败；不给 `host` 时由地址推导。
    ///
    /// 返回实际生效的值（给调用方写日志 / 回执用）。
    pub fn report(
        &self,
        name: &str,
        host: Option<&str>,
        endpoint: Option<&str>,
        roles: &[String],
    ) -> anyhow::Result<()> {
        let host = host.map(str::trim).filter(|value| !value.is_empty());
        let endpoint = endpoint.map(str::trim).filter(|value| !value.is_empty());
        validate_report(host, endpoint, roles).map_err(anyhow::Error::msg)?;
        let derived_host = host
            .map(str::to_string)
            .or_else(|| endpoint.and_then(host_of));

        let mut state = self.lock();
        let Some(peer) = state.peers.get_mut(name) else {
            return Ok(());
        };
        let mut changed = false;
        if peer.host.is_none() {
            peer.host = derived_host;
            changed = true;
        }
        if peer.endpoint.is_none() {
            peer.endpoint = endpoint.map(str::to_string);
            changed |= peer.endpoint.is_some();
        }
        if !roles.is_empty() {
            // 角色是 X 的词汇表：上报**非空就以它为准**（重跑接入命令 = 改角色）。
            // 空 = 这次没说（脚本可能没带 `--roles`），不能当成“清空”。
            let reported = normalize_roles(roles.to_vec())
                .map_err(|err| anyhow::anyhow!("reported roles are invalid: {err}"))?;
            if peer.roles != reported {
                peer.roles = reported;
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }
        let before = (state.revision, state.peers.clone());
        state.revision += 1;
        let snapshot = snapshot(&state);
        if let Err(error) = write(&self.path, &snapshot) {
            state.revision = before.0;
            state.peers = before.1;
            return Err(error);
        }
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|err| err.into_inner())
    }
}

impl PeerRegistry {
    /// 操作者改收数地址（`None` / 空串 = 退回手工分发）。
    ///
    /// 与 `fill_endpoint` 相反：这里**覆盖**，因为是人明确要求的。
    pub fn set_endpoint(&self, name: &str, endpoint: Option<&str>) -> Result<Peer, PeerError> {
        let endpoint = endpoint.map(str::trim).filter(|value| !value.is_empty());
        if let Some(url) = endpoint {
            validate_endpoint(url)?;
        }

        let mut state = self.lock();
        let Some(peer) = state.peers.get_mut(name) else {
            return Err(PeerError::NotFound(name.to_string()));
        };
        let previous = peer.endpoint.clone();
        peer.endpoint = endpoint.map(str::to_string);
        let updated = peer.clone();
        let revision = state.revision;
        state.revision += 1;
        let snapshot = snapshot(&state);
        if let Err(error) = write(&self.path, &snapshot) {
            if let Some(peer) = state.peers.get_mut(name) {
                peer.endpoint = previous;
            }
            state.revision = revision;
            return Err(PeerError::Store(format!("{error:#}")));
        }
        // 地址变了，之前的健康结论就作废了（落盘成功之后再清）。
        state.health.remove(name);
        Ok(updated)
    }
}

/// 页面/API 传来的新建请求。
#[derive(Debug, Clone)]
pub struct NewPeer {
    pub name: String,
    /// 可选：登记时一般由对方上报，这里只给部署种子 / 脚本用。
    pub host: Option<String>,
    pub endpoint: Option<String>,
    pub healthz: Option<String>,
    /// 可选：对方能验的角色。同上。
    pub roles: Vec<String>,
}

#[derive(Debug)]
pub enum PeerError {
    BadRequest(String),
    Conflict(String),
    NotFound(String),
    Store(String),
}

impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerError::BadRequest(message)
            | PeerError::Conflict(message)
            | PeerError::NotFound(message)
            | PeerError::Store(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for PeerError {}

/// 角色名：去空白、去空项、去重，保留顺序。
///
/// **字符集也是安全边界**：角色会进推送体、进 `peers.json`，还会被原样嵌进
/// 接入脚本的 shell 字面量；允许引号/反引号/`$` 等于在签发方这边开一个注入面。
///
/// 发放凭据时也走这一条：`" read "` 如果能过白名单，到了 X 那边会被
/// `known_roles` 裁掉 —— 变成一把静默少权限的钥匙。
pub(crate) fn normalize_roles(roles: Vec<String>) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::with_capacity(roles.len());
    for role in roles {
        let role = role.trim().to_string();
        if role.is_empty() {
            continue;
        }
        if role.len() > 128 {
            return Err(format!("role name is too long: {role:?}"));
        }
        if !role.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-' | '/' | '@' | '*')
        }) {
            return Err(format!(
                "role name may only use [A-Za-z0-9:._-/@*], got {role:?}"
            ));
        }
        if !out.contains(&role) {
            out.push(role);
        }
    }
    Ok(out)
}

fn validate_host(host: &str) -> Result<(), PeerError> {
    if host.is_empty() || host.len() > 253 {
        return Err(PeerError::BadRequest(
            "host must be a non-empty DNS name".to_string(),
        ));
    }
    let ok = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        && !host.starts_with('.')
        && !host.ends_with('.');
    if !ok {
        return Err(PeerError::BadRequest(
            "host may only contain letters, digits, dots and hyphens".to_string(),
        ));
    }
    Ok(())
}

fn validate_endpoint(url: &str) -> Result<(), PeerError> {
    let Some(origin) = origin_of(url) else {
        return Err(PeerError::BadRequest(
            "endpoint must be an https:// URL (push is mutual TLS only)".to_string(),
        ));
    };
    // authority 会被原样嵌进入接脚本的单引号字面量：只放行 URL 合法、shell 也安全的字符。
    let authority = origin.trim_start_matches("https://");
    let ok = !authority.is_empty()
        && authority
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']' | '_'));
    if !ok {
        return Err(PeerError::BadRequest(
            "endpoint host may only contain letters, digits, dots, hyphens and an optional port"
                .to_string(),
        ));
    }
    Ok(())
}

/// 从 `https://host:port/path` 取 `host`。
pub fn host_of(url: &str) -> Option<String> {
    let origin = origin_of(url)?;
    let authority = origin.strip_prefix("https://")?;
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (!host.is_empty()).then(|| host.to_string())
}

/// 登记上报值的**无状态校验**。
///
/// `enroll` 在**烧掉一次性券之前**先调它：主机名/地址/角色不合法是“输入错”，
/// 不该把券变成一次性的代价。`report` 也调它，保持两边一套规则。
pub(crate) fn validate_report(
    host: Option<&str>,
    endpoint: Option<&str>,
    roles: &[String],
) -> Result<(), String> {
    if let Some(url) = endpoint {
        validate_endpoint(url).map_err(|err| err.to_string())?;
    }
    if let Some(host) = host {
        validate_host(host).map_err(|err| err.to_string())?;
        if let Some(url) = endpoint
            && let Some(url_host) = host_of(url)
            && url_host != host
        {
            return Err(format!(
                "reported host {host:?} does not match the endpoint host {url_host:?}; \
                 the certificate SAN must match where cred connects"
            ));
        }
    }
    normalize_roles(roles.to_vec())?;
    Ok(())
}

fn validate_name(name: &str) -> Result<(), PeerError> {
    if name.is_empty() {
        return Err(PeerError::BadRequest("name must not be empty".to_string()));
    }
    if name.len() > 63 {
        return Err(PeerError::BadRequest(
            "name must be at most 63 characters".to_string(),
        ));
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    if !ok {
        return Err(PeerError::BadRequest(
            "name must be lowercase [a-z0-9-] and may not start or end with '-'".to_string(),
        ));
    }
    Ok(())
}

fn snapshot(state: &State) -> FileData {
    FileData {
        revision: state.revision,
        peers: state.peers.values().cloned().collect(),
    }
}

fn read(path: &Path) -> anyhow::Result<FileData> {
    match fs::read_to_string(path) {
        Ok(text) => {
            serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(FileData::default()),
        Err(err) => Err(err).with_context(|| format!("read {}", path.display())),
    }
}

/// 先写临时文件再 rename：崩在中间不会留下半个 JSON。
fn write(path: &Path, data: &FileData) -> anyhow::Result<()> {
    let text = serde_json::to_string_pretty(data)?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, text).with_context(|| format!("write {}", tmp.display()))?;
    set_perms(&tmp)?;
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn set_perms(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o640))
        .with_context(|| format!("chmod 0640 {}", path.display()))
}

#[cfg(not(unix))]
fn set_perms(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// `peer.json` 的形状：`gen-pki.sh` 写出来的种子。
///
/// `audience` 只为了兼容旧种子而保留（早期版本把它单存了一份），**读入即丢弃**。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPeerSeed {
    name: String,
    host: String,
    #[serde(default)]
    #[allow(dead_code)]
    audience: Option<String>,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
}

impl RawPeerSeed {
    fn into_peer(self) -> anyhow::Result<Peer> {
        validate_name(&self.name).map_err(|err| anyhow::anyhow!("{}: {err}", self.name))?;
        if self.host.trim().is_empty() {
            bail!("{}: host must not be empty", self.name);
        }
        let host = self.host.trim().to_string();
        let endpoint = self
            .endpoint
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        // 种子也是「上报值」的一种：和 enroll 走同一套校验（host 会进脚本、角色会进推送）。
        validate_report(Some(&host), endpoint.as_deref(), &self.roles)
            .map_err(|err| anyhow::anyhow!("{}: {err}", self.name))?;
        let roles =
            normalize_roles(self.roles).map_err(|err| anyhow::anyhow!("{}: {err}", self.name))?;
        Ok(Peer {
            name: self.name,
            host: Some(host),
            endpoint,
            healthz: None,
            roles,
            created_at: now_secs(),
            created_by: "pki".to_string(),
        })
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let mut bytes = [0u8; 8];
            getrandom::fill(&mut bytes).expect("entropy");
            let name: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = std::env::temp_dir().join(format!("wist-cred-peers-{name}"));
            fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn registry(dir: &TempDir) -> PeerRegistry {
        PeerRegistry::open(dir.0.join("peers.json")).expect("open registry")
    }

    fn new_peer(name: &str) -> NewPeer {
        NewPeer {
            name: name.to_string(),
            roles: vec!["investigation:run".to_string()],
            host: Some(format!("{name}.internal")),
            endpoint: Some(format!(
                "https://{name}.internal:19443/api/v1/internal/credentials"
            )),
            healthz: None,
        }
    }

    #[test]
    fn create_persists_across_reopen() {
        let dir = TempDir::new();
        {
            let registry = registry(&dir);
            registry
                .create(new_peer("wist-ingest"), "alice")
                .expect("create");
        }
        let registry = registry(&dir);
        let peers = registry.list();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "wist-ingest");
        assert_eq!(peers[0].created_by, "alice");
        assert!(registry.contains("wist-ingest"));
    }

    #[test]
    fn creating_a_duplicate_name_is_a_conflict() {
        let dir = TempDir::new();
        let registry = registry(&dir);
        registry
            .create(new_peer("wist-ingest"), "alice")
            .expect("create");
        let err = registry
            .create(new_peer("wist-ingest"), "bob")
            .expect_err("conflict");
        assert!(matches!(err, PeerError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn name_must_be_a_dns_label() {
        let dir = TempDir::new();
        let registry = registry(&dir);
        for bad in ["", "Wist", "-x", "x-", "a_b", "有中文"] {
            let mut input = new_peer("ok");
            input.name = bad.to_string();
            let err = registry.create(input, "alice").expect_err(bad);
            assert!(matches!(err, PeerError::BadRequest(_)), "{bad}: {err:?}");
        }
    }

    #[test]
    fn endpoint_must_be_https() {
        let dir = TempDir::new();
        let registry = registry(&dir);
        let mut input = new_peer("wist-ingest");
        input.endpoint = Some("http://ingest.internal/credentials".to_string());
        let err = registry.create(input, "alice").expect_err("plaintext push");
        assert!(matches!(err, PeerError::BadRequest(_)), "got {err:?}");
    }

    #[test]
    fn probe_url_derives_healthz_from_the_endpoint_origin() {
        let peer = Peer {
            name: "a".into(),
            roles: vec![],
            host: Some("h".into()),
            endpoint: Some("https://h:19443/api/v1/internal/credentials".into()),
            healthz: None,
            created_at: 0,
            created_by: "x".into(),
        };
        assert_eq!(peer.probe_url().as_deref(), Some("https://h:19443/healthz"));

        let explicit = Peer {
            healthz: Some("https://h:19443/api/v1/internal/credentials/health".into()),
            ..peer.clone()
        };
        assert_eq!(
            explicit.probe_url().as_deref(),
            Some("https://h:19443/api/v1/internal/credentials/health")
        );

        let no_endpoint = Peer {
            endpoint: None,
            ..peer
        };
        assert!(no_endpoint.probe_url().is_none());
    }

    #[test]
    fn import_seeds_from_pki_without_overwriting_runtime_peers() {
        let dir = TempDir::new();
        let seeds = dir.0.join("onboarding");
        for (name, host) in [
            ("wist-ingest", "ingest.internal"),
            ("wist-center", "center.internal"),
        ] {
            let peer_dir = seeds.join(name);
            fs::create_dir_all(&peer_dir).unwrap();
            fs::write(
                peer_dir.join("peer.json"),
                format!(r#"{{"name":"{name}","host":"{host}","audience":"{name}"}}"#),
            )
            .unwrap();
        }

        let registry = registry(&dir);
        registry
            .create(new_peer("wist-ingest"), "alice")
            .expect("runtime peer first");
        let imported = registry.import_dir(&seeds).expect("import");
        assert_eq!(imported, vec!["wist-center".to_string()]);
        // 运行期那条不被种子覆盖（created_by 仍是 alice）。
        assert_eq!(registry.get("wist-ingest").unwrap().created_by, "alice");
        assert_eq!(registry.list().len(), 2);
    }

    #[test]
    fn missing_seed_dir_is_not_fatal() {
        let dir = TempDir::new();
        let registry = registry(&dir);
        assert!(registry.import_dir(&dir.0.join("nope")).unwrap().is_empty());
        assert!(registry.is_empty());
    }

    #[test]
    fn set_endpoint_overwrites_and_clears() {
        let dir = TempDir::new();
        let registry = registry(&dir);
        registry
            .create(new_peer("wist-ingest"), "alice")
            .expect("create");
        registry.set_health(
            "wist-ingest",
            Health::Up {
                at: 1,
                latency_ms: 1,
            },
        );

        let updated = registry
            .set_endpoint(
                "wist-ingest",
                Some("https://other:19443/api/v1/internal/credentials"),
            )
            .expect("set");
        assert_eq!(
            updated.endpoint.as_deref(),
            Some("https://other:19443/api/v1/internal/credentials")
        );
        // 地址变了，旧结论作废。
        assert_eq!(registry.health("wist-ingest"), Health::Unknown);

        let cleared = registry
            .set_endpoint("wist-ingest", Some("  "))
            .expect("clear");
        assert!(cleared.endpoint.is_none());

        let err = registry
            .set_endpoint("wist-ingest", Some("http://plain/creds"))
            .expect_err("plaintext");
        assert!(matches!(err, PeerError::BadRequest(_)), "got {err:?}");

        assert!(matches!(
            registry.set_endpoint("nope", None).expect_err("missing"),
            PeerError::NotFound(_)
        ));
    }

    #[test]
    fn report_only_completes_empty_values() {
        let dir = TempDir::new();
        let registry = registry(&dir);
        let mut input = new_peer("wist-ingest");
        input.host = None;
        input.endpoint = None;
        registry.create(input, "alice").expect("create");

        registry
            .report(
                "wist-ingest",
                Some("ingest.internal"),
                Some("https://ingest.internal:19443/api/v1/internal/credentials"),
                &[],
            )
            .expect("report");
        let peer = registry.get("wist-ingest").unwrap();
        assert_eq!(peer.host.as_deref(), Some("ingest.internal"));
        assert_eq!(
            peer.endpoint.as_deref(),
            Some("https://ingest.internal:19443/api/v1/internal/credentials")
        );

        // 第二次不覆盖。
        registry
            .report(
                "wist-ingest",
                Some("other.internal"),
                Some("https://other.internal:1/x"),
                &[],
            )
            .expect("report again");
        let peer = registry.get("wist-ingest").unwrap();
        assert_eq!(peer.host.as_deref(), Some("ingest.internal"));
        assert_eq!(
            peer.endpoint.as_deref(),
            Some("https://ingest.internal:19443/api/v1/internal/credentials")
        );
    }

    #[test]
    fn report_derives_the_host_from_the_endpoint() {
        let dir = TempDir::new();
        let registry = registry(&dir);
        let mut input = new_peer("wist-ingest");
        input.host = None;
        input.endpoint = None;
        registry.create(input, "alice").expect("create");

        registry
            .report(
                "wist-ingest",
                None,
                Some("https://ingest.internal:19443/api/v1/internal/credentials"),
                &[],
            )
            .expect("report");
        assert_eq!(
            registry.get("wist-ingest").unwrap().host.as_deref(),
            Some("ingest.internal")
        );
    }

    #[test]
    fn report_rejects_a_host_that_disagrees_with_the_endpoint() {
        let dir = TempDir::new();
        let registry = registry(&dir);
        let mut input = new_peer("wist-ingest");
        input.host = None;
        input.endpoint = None;
        registry.create(input, "alice").expect("create");

        let err = registry
            .report(
                "wist-ingest",
                Some("other.internal"),
                Some("https://ingest.internal:19443/api/v1/internal/credentials"),
                &[],
            )
            .expect_err("mismatch");
        assert!(
            err.to_string().contains("does not match"),
            "unexpected: {err}"
        );
        // 没落盘任何东西。
        assert!(registry.get("wist-ingest").unwrap().host.is_none());
    }

    #[test]
    fn creating_with_only_a_name_leaves_identity_to_enrollment() {
        let dir = TempDir::new();
        let registry = registry(&dir);
        let peer = registry
            .create(
                NewPeer {
                    name: "wist-ingest".to_string(),
                    host: None,
                    endpoint: None,
                    healthz: None,
                    roles: Vec::new(),
                },
                "alice",
            )
            .expect("create");
        assert!(peer.host.is_none());
        assert!(peer.endpoint.is_none());
        assert!(peer.probe_url().is_none());
    }

    #[test]
    fn an_endpoint_implies_the_host() {
        let dir = TempDir::new();
        let registry = registry(&dir);
        let peer = registry
            .create(
                NewPeer {
                    name: "wist-ingest".to_string(),
                    host: None,
                    endpoint: Some("https://ingest.internal:19443/x".to_string()),
                    healthz: None,
                    roles: Vec::new(),
                },
                "alice",
            )
            .expect("create");
        assert_eq!(peer.host.as_deref(), Some("ingest.internal"));
        assert_eq!(
            peer.probe_url().as_deref(),
            Some("https://ingest.internal:19443/healthz")
        );
    }

    #[test]
    fn health_defaults_to_unknown_and_is_not_persisted() {
        let dir = TempDir::new();
        {
            let registry = registry(&dir);
            registry
                .create(new_peer("wist-ingest"), "alice")
                .expect("create");
            assert_eq!(registry.health("wist-ingest"), Health::Unknown);
            registry.set_health(
                "wist-ingest",
                Health::Up {
                    at: 1,
                    latency_ms: 7,
                },
            );
            assert!(registry.health("wist-ingest").is_up());
        }
        // 重启后应回到 Unknown，而不是把十分钟前的"在线"当成现在。
        let registry = registry(&dir);
        assert_eq!(registry.health("wist-ingest"), Health::Unknown);
    }

    #[test]
    fn origin_of_strips_path_and_query() {
        assert_eq!(
            origin_of("https://h:19443/a/b?c=1").as_deref(),
            Some("https://h:19443")
        );
        assert_eq!(origin_of("https://h").as_deref(), Some("https://h"));
        assert_eq!(origin_of("http://h"), None);
        assert_eq!(origin_of("https:///x"), None);
    }

    // ── 6 轮机制 review 的回归用例 ─────────────────────────────────────

    #[test]
    fn roles_that_could_escape_a_shell_literal_are_rejected() {
        // 角色会进推送体、进 peers.json，还会被嵌进入接脚本的单引号字面量。
        let dir = TempDir::new();
        let registry = registry(&dir);
        for role in ["bad'role", "a`id`b", "$(id)", "a b", "a\nb"] {
            let mut peer = new_peer("wist-ingest");
            peer.roles = vec![role.to_string()];
            let error = registry.create(peer, "alice").expect_err("must reject");
            assert!(
                matches!(error, PeerError::BadRequest(_)),
                "{role:?} gave {error:?}"
            );
        }
        // 合法字符集仍然通过（含 `:` `/` `@` `*`）。
        let mut peer = new_peer("wist-ingest");
        peer.roles = vec!["investigation:run".into(), "svc/*@team".into()];
        assert!(registry.create(peer, "alice").is_ok());
    }

    #[test]
    fn endpoint_authority_with_shell_metacharacters_is_rejected() {
        let dir = TempDir::new();
        let registry = registry(&dir);
        for endpoint in [
            "https://x';id;'/api",
            "https://$(id)/api",
            "https://x`id`/api",
            "https://x\ny/api",
        ] {
            let mut peer = new_peer("wist-ingest");
            peer.endpoint = Some(endpoint.to_string());
            let error = registry.create(peer, "alice").expect_err("must reject");
            assert!(
                matches!(error, PeerError::BadRequest(_)),
                "{endpoint:?} gave {error:?}"
            );
        }
    }

    #[test]
    fn report_replaces_roles_only_when_it_reports_a_non_empty_set() {
        // 角色是 X 的词汇表：重跑接入命令带 `--roles` 就是改它。
        let dir = TempDir::new();
        let registry = registry(&dir);
        registry
            .create(new_peer("wist-ingest"), "alice")
            .expect("create");

        registry
            .report("wist-ingest", None, None, &["read".to_string()])
            .expect("report");
        assert_eq!(registry.get("wist-ingest").unwrap().roles, vec!["read"]);

        // 空 = 这次没说，不能当清空。
        registry
            .report("wist-ingest", None, None, &[])
            .expect("report empty");
        assert_eq!(registry.get("wist-ingest").unwrap().roles, vec!["read"]);

        // 非法字符集：拒，且旧值不动。
        let error = registry
            .report("wist-ingest", None, None, &["bad'role".to_string()])
            .expect_err("must reject");
        assert!(format!("{error:#}").contains("role name"), "{error:#}");
        assert_eq!(registry.get("wist-ingest").unwrap().roles, vec!["read"]);
    }

    #[test]
    fn a_failed_write_rolls_back_the_in_memory_peer() {
        // 用一个同名目录占住 `peers.tmp`，让 `write` 在 rename 前就失败。
        let dir = TempDir::new();
        let registry = registry(&dir);
        registry
            .create(new_peer("wist-ingest"), "alice")
            .expect("create");

        let tmp = dir.0.join("peers.tmp");
        fs::create_dir(&tmp).expect("block the tmp path");

        let mut second = new_peer("wist-center");
        second.host = Some("center.internal".to_string());
        let error = registry
            .create(second, "alice")
            .expect_err("write must fail");
        assert!(matches!(error, PeerError::Store(_)), "{error:?}");
        // 关键：内存里不能留着这条 —— 否则重试会撞 409，而磁盘上根本没有。
        assert!(
            !registry.contains("wist-center"),
            "failed write must not leave the peer in memory"
        );

        // 修好磁盘路径后，同一个名字能重新建（不是 409）。
        fs::remove_dir(&tmp).expect("unblock");
        let mut retry = new_peer("wist-center");
        retry.host = Some("center.internal".to_string());
        assert!(registry.create(retry, "alice").is_ok());
    }

    #[test]
    fn a_seed_with_an_invalid_endpoint_fails_import() {
        // 种子与 enrol 上报走同一套校验：部署时写字了就能当场发现，而不是等到发命令。
        let dir = TempDir::new();
        let seeds = dir.0.join("onboarding");
        let peer_dir = seeds.join("wist-ingest");
        fs::create_dir_all(&peer_dir).expect("seed dir");
        fs::write(
            peer_dir.join("peer.json"),
            r#"{"name":"wist-ingest","host":"ingest.internal","endpoint":"https://x`id`/api"}"#,
        )
        .expect("write seed");

        let registry = registry(&dir);
        let error = registry.import_dir(&seeds).expect_err("import must fail");
        assert!(format!("{error:#}").contains("endpoint"), "{error:#}");
    }
}
