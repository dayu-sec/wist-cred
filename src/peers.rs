//! 认证系统注册表：**运行期可变**，落 `state/peers.json`。
//!
//! 为什么要可变：接入一个验证方（X）是运维日常动作，不该每次改 `vars.yml` 再 localize。
//! 但也不能只活在内存里 —— 它是「往哪儿推摘要」的唯一来源，重启丢了就等于全部推送中断。
//!
//! 三个来源，优先级从低到高：
//!
//! 1. **PKI 种子**（`onboarding.dir/*/peer.json`）：部署阶段由 `scripts/gen-pki.sh` 写，
//!    首次启动导入一次；已在注册表里的不覆盖。
//! 2. **API 创建**（`POST /api/v1/onboarding/peers`）：人在页面上建，**必须带收数地址**。
//! 3. **登记回填**（`POST /enroll/{券}/certificate`）：X 交 CSR 时可以带上自己的证书 SAN
//!    与角色，**不收收数地址** —— 地址是部署登记的事实，不是接入脚本的参数。
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
/// **`host` 可以是对方向上来的**（证书 SAN），但 **`endpoint` 只能由部署登记**：
/// 它是“cred 往哪儿推、往哪儿探”的真实地址，接入脚本既不能猜也不能代填。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Peer {
    pub name: String,
    /// 证书 SAN / CN。`None` = 还没登记。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// 收摘要的地址（`POST`）。**建的时候就必须给**：没有地址就不能推、不能探，
    /// 也不允许接入（否则就是“登记成功、永远收不到东西”）。`None` 只在撤销地址后出现。
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
    /// 材料目录（接入脚本 `--dir` 的默认值）。`None` = 由脚本按场景自己定
    /// （root → `/etc/wist/<peer>`，否则 `./wist-cred/<peer>`）。
    ///
    /// 为什么要存：部署栈里默认值**一定会被护栏拦下**（私钥不能落在 `identity/` 之外），
    /// 而栈的正确落点只有操作者知道。存下来之后，页面生成的命令直接带上它，
    /// 谁都不用自己拼 —— 与 `restart_cmd` 同一条口径。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_dir: Option<String>,
    /// X 上那份**由人维护**的运行配置（接入脚本 `--config` 的写入目标）。
    /// `None` = 只打印片段，不写任何文件。
    /// 栈部署的服务（center / ingest）**不要填**：它们的配置由 localize 渲染、只读挂载，
    /// 写了也会被下一次渲染覆盖 —— 那些系统改模板。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_path: Option<String>,
    /// 写完配置后让它生效的命令（`--restart`），例如 `systemctl restart x`。
    /// `None` = 只提示重启，不替人执行。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_cmd: Option<String>,
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

/// 验证方默认的收数路径（与 [`wist_cred_peer::DEFAULT_BASE_PATH`] 同一个值）。
///
/// 这里复制一份而不是引运行期依赖：`wist-cred-peer` 只是示例验证方的 dev-dependency，
/// 服务二进制不该为了一行常量多背一个 crate。两边是否一致由
/// `default_push_path_matches_the_peer_crate` 钉住。
pub(crate) const DEFAULT_PUSH_PATH: &str = "/api/v1/internal/credentials";

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

/// 心跳状态。**只活在内存里**（`NoEndpoint` 除外 —— 它是从注册表推导出来的事实）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    /// 这个系统**根本没有收数地址**：永远不会被探、也永远不会收到推送。
    ///
    /// 与 `Unknown`（刚启动 / 还没探过）是两件事：这个状态不会自己变好，
    /// 必须有人把地址补上（`POST /api/v1/peers/{name}/endpoint`）。
    NoEndpoint,
    Unknown,
    Up {
        at: i64,
        latency_ms: u64,
    },
    Down {
        at: i64,
        error: String,
    },
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
        let mut peers: BTreeMap<String, Peer> = data
            .peers
            .into_iter()
            .map(|peer| (peer.name.clone(), peer))
            .collect();
        // 旧记录里的收数地址可能是裸 origin：当时的校验只看了 scheme + authority，
        // 而推送是 `POST` 到 endpoint 原样 —— 不补路径的话，升级后它照样「探活绿、推送 404」。
        let mut migrated = false;
        for peer in peers.values_mut() {
            let Some(endpoint) = peer.endpoint.clone() else {
                continue;
            };
            match normalize_endpoint(&endpoint) {
                Ok(normalized) if normalized != endpoint => {
                    log::warn!(
                        "peer {:?} endpoint {:?} has no push path; using {normalized:?}",
                        peer.name,
                        endpoint
                    );
                    peer.endpoint = Some(normalized);
                    migrated = true;
                }
                Ok(_) => {}
                // 存里的值不合法不该拦住启动：推送时会报出具体原因。
                Err(err) => log::warn!(
                    "peer {:?} endpoint {:?} is not a usable URL: {err}",
                    peer.name,
                    endpoint
                ),
            }
        }
        let me = Self {
            path,
            state: Mutex::new(State {
                peers,
                health: BTreeMap::new(),
                revision: data.revision,
            }),
        };
        if migrated {
            // 落盘失败只告警：内存里的值已经是对的，推送能用；下次写入会再存一次。
            let snapshot = snapshot(&me.lock());
            if let Err(error) = write(&me.path, &snapshot) {
                log::error!(
                    "persisting normalized peer endpoints to {} failed: {error:#}",
                    me.path.display()
                );
            }
        }
        Ok(me)
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
        let peers = self.lock();
        // 「没有收数地址」不是“还没探过”，而是一个**永远不会自愈**的状态：
        // 探针会直接跳过它。所以要单独说出来，不能让它一直显示成 unknown。
        if let Some(peer) = peers.peers.get(name) {
            let no_endpoint = peer
                .endpoint
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty();
            if no_endpoint {
                return Health::NoEndpoint;
            }
        }
        peers.health.get(name).cloned().unwrap_or(Health::Unknown)
    }

    pub fn set_health(&self, name: &str, health: Health) {
        self.lock().health.insert(name.to_string(), health);
    }

    /// 新建一个认证系统。
    ///
    /// **名称与收数地址都是必填**：没有地址的认证系统既不能被探活、也收不到推送，
    /// 而接入脚本已经不接受地址参数（那是部署事实，不是命令行参数），
    /// 所以放进来一条空壳记录只会制造“登记成功、什么都不动”。
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
            .filter(|value| !value.is_empty())
            .map(|value| normalize_endpoint(&value))
            .transpose()?;
        let Some(endpoint) = endpoint else {
            return Err(PeerError::BadRequest(
                "endpoint is required: without it cred can neither probe nor push to this system, \
                 and enrollment is refused rather than leaving a silent shell record"
                    .to_string(),
            ));
        };

        // 只给了地址没给主机名：从地址里取 —— 证书 SAN 必须与推数时连的地址一致。
        if let (Some(host), Some(url_host)) = (host.as_deref(), host_of(&endpoint))
            && host != url_host
        {
            // 签出来的证书 SAN 与 cred 推数时连的地址不一致 → 握手必然失败。
            // 与其让它到心跳里变成一条 TLS 错，不如建的时候就拒。
            return Err(PeerError::BadRequest(format!(
                "host {host:?} does not match the endpoint host {url_host:?}: \
                 the certificate SAN must match where cred connects"
            )));
        }
        let host = host.or_else(|| host_of(&endpoint));

        let peer = Peer {
            name: name.clone(),
            host,
            endpoint: Some(endpoint),
            healthz: input
                .healthz
                .map(|value| value.trim().to_string())
                .filter(|v| !v.is_empty()),
            roles: normalize_roles(input.roles).map_err(PeerError::BadRequest)?,
            created_at: now_secs(),
            created_by: by.to_string(),
            install_dir: clean_setup(
                input.install_dir.as_deref(),
                "install_dir",
                validate_setup_path,
            )?,
            config_path: clean_setup(
                input.config_path.as_deref(),
                "config_path",
                validate_setup_path,
            )?,
            restart_cmd: clean_setup(
                input.restart_cmd.as_deref(),
                "restart_cmd",
                validate_setup_cmd,
            )?,
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

    /// 登记时接收对方上报的**角色**。
    ///
    /// **不收收数地址、也不用 host**：
    /// - 地址是部署登记的事实（页面 / `CRED_PKI_PEERS`），不是接入脚本的参数；
    /// - 主机名在建/种子时就定了（由地址推出或显式给），enroll 已经把“上报的主机名是否
    ///   相符”拦在前面了，这里再写一次只会多一条可能漂移的路径。
    ///
    /// `roles` **上报非空就覆盖**：它是 X 自己的词汇表，重跑接入命令就是改它；
    /// 上报空值只是“这次没说”，不当成清空。
    pub fn report(&self, name: &str, roles: &[String]) -> anyhow::Result<()> {
        validate_report(None, roles).map_err(anyhow::Error::msg)?;

        let mut state = self.lock();
        let Some(peer) = state.peers.get_mut(name) else {
            return Ok(());
        };
        let mut changed = false;
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
    /// 操作者改收数地址（`None` / 空串 = **撤销**：这条系统将不能再接入、也不再被探/推）。
    ///
    /// 与 `report`（只补空）相反：这里**覆盖**，因为是人明确要求的。
    pub fn set_endpoint(&self, name: &str, endpoint: Option<&str>) -> Result<Peer, PeerError> {
        let endpoint = endpoint
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(normalize_endpoint)
            .transpose()?;

        let mut state = self.lock();
        let Some(peer) = state.peers.get_mut(name) else {
            return Err(PeerError::NotFound(name.to_string()));
        };
        let previous = peer.endpoint.clone();
        peer.endpoint = endpoint;
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

    /// 应用部署栈声明的「认证系统 → 材料目录」（`onboarding.peer_dirs`）。
    ///
    /// 规则：
    /// - **只补空**：页面上已经存过的值优先（人可能更清楚，且页面上改过的不该被重启改回去）；
    /// - 声明了一个还不存在的认证系统：跳过 + 告警（它可能是靠页面新建的，还没建）；
    /// - 值不一致：告警，以现有值为准。
    ///
    /// 返回实际写入的系统名（给启动日志用）。
    pub fn seed_install_dirs(&self, dirs: &[(String, String)]) -> anyhow::Result<Vec<String>> {
        if dirs.is_empty() {
            return Ok(Vec::new());
        }
        let mut state = self.lock();
        let before = (state.revision, state.peers.clone());
        let mut applied = Vec::new();
        for (name, dir) in dirs {
            let Some(peer) = state.peers.get_mut(name) else {
                log::warn!("peer_dirs declares {name:?}, but no such auth system is registered");
                continue;
            };
            match &peer.install_dir {
                Some(existing) if existing == dir => {}
                Some(existing) => log::warn!(
                    "peer_dirs declares {name:?} -> {dir:?}, but it already uses {existing:?}; keeping the existing value"
                ),
                None => {
                    peer.install_dir = Some(dir.clone());
                    applied.push(name.clone());
                }
            }
        }
        if applied.is_empty() {
            return Ok(applied);
        }
        state.revision += 1;
        let snapshot = snapshot(&state);
        if let Err(error) = write(&self.path, &snapshot) {
            state.revision = before.0;
            state.peers = before.1;
            return Err(error);
        }
        Ok(applied)
    }

    /// 改“接入落点”：接入脚本要不要顺手写配置、写完要不要重启。
    ///
    /// 与 `set_endpoint` 同一套落盘 / 回滚；这里**不动健康结论** —— 它不改变可达性。
    pub fn set_setup(
        &self,
        name: &str,
        install_dir: Option<&str>,
        config_path: Option<&str>,
        restart_cmd: Option<&str>,
    ) -> Result<Peer, PeerError> {
        let install_dir = clean_setup(install_dir, "install_dir", validate_setup_path)?;
        let config_path = clean_setup(config_path, "config_path", validate_setup_path)?;
        let restart_cmd = clean_setup(restart_cmd, "restart_cmd", validate_setup_cmd)?;

        let mut state = self.lock();
        let Some(peer) = state.peers.get_mut(name) else {
            return Err(PeerError::NotFound(name.to_string()));
        };
        let previous = (
            peer.install_dir.clone(),
            peer.config_path.clone(),
            peer.restart_cmd.clone(),
        );
        peer.install_dir = install_dir;
        peer.config_path = config_path;
        peer.restart_cmd = restart_cmd;
        let updated = peer.clone();
        let revision = state.revision;
        state.revision += 1;
        let snapshot = snapshot(&state);
        if let Err(error) = write(&self.path, &snapshot) {
            if let Some(peer) = state.peers.get_mut(name) {
                peer.install_dir = previous.0;
                peer.config_path = previous.1;
                peer.restart_cmd = previous.2;
            }
            state.revision = revision;
            return Err(PeerError::Store(format!("{error:#}")));
        }
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
    /// 可选：材料目录（接入脚本 `--dir` 的默认值，见 `Peer::install_dir`）。
    pub install_dir: Option<String>,
    /// 可选：接入脚本要不要顺手写配置、写完要不要重启（见 `Peer::config_path`）。
    pub config_path: Option<String>,
    pub restart_cmd: Option<String>,
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

/// 校验并**归一化**收数地址。
///
/// 为什么必须归一：`endpoint` 在两个地方用，口径不一样
/// —— 心跳探活取的是 `origin + /healthz`（`probe_url`），而推送是 `POST` 到
/// `endpoint` **原样**。只填 `https://host:3103` 也能存、也能探活绿，
/// 但每条推送都会打到根路径上 → `404`。
///
/// 规则：
/// - 只收 `https://`（推送是双向 TLS）；
/// - **没有路径**（或只有 `/`）→ 补上默认收数路径；
/// - **有路径**→ 原样保留（X 可以把 listener 挂在别处，那是它的配置自由）。
fn normalize_endpoint(url: &str) -> Result<String, PeerError> {
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

    // origin 之后的部分是「路径 [+ ?query / #fragment]」。
    let rest = &url[origin.len()..];
    let cut = rest.find(['?', '#']).unwrap_or(rest.len());
    let (path, tail) = rest.split_at(cut);
    let path = path.trim_end_matches('/');
    // 路径不清洗：它会原样进推送请求、也进接入脚本。空白 / 控制字符在 URL 里本来就不合法，
    // 放进去只会让脚本多一行、报错时看不出来。
    if rest.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(PeerError::BadRequest(
            "endpoint may not contain whitespace or control characters".to_string(),
        ));
    }
    if path.is_empty() {
        Ok(format!("{origin}{DEFAULT_PUSH_PATH}{tail}"))
    } else {
        Ok(format!("{origin}{path}{tail}"))
    }
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
/// `enroll` 在**烧掉一次性券之前**先调它：主机名 / 角色不合法是“输入错”，
/// 不该把券变成一次性的代价。`report` 也调它，保持两边一套规则。
pub(crate) fn validate_report(host: Option<&str>, roles: &[String]) -> Result<(), String> {
    if let Some(host) = host {
        validate_host(host).map_err(|err| err.to_string())?;
    }
    normalize_roles(roles.to_vec())?;
    Ok(())
}

/// 取值 + 校验一条“接入落点”字段：去空白、空当没给。
fn clean_setup(
    value: Option<&str>,
    field: &str,
    validate: fn(&str) -> Result<(), String>,
) -> Result<Option<String>, PeerError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    validate(value).map_err(|reason| PeerError::BadRequest(format!("{field}: {reason}")))?;
    Ok(Some(value.to_string()))
}

/// 配置文件路径：只挡**不可能是一行路径**的东西（换行/控制字符）。
/// 不做绝对路径要求：相对路径是相对**对方机器当时的 cwd** 解，那是它自己的事。
fn validate_setup_path(value: &str) -> Result<(), String> {
    if value.len() > 512 {
        return Err("must be at most 512 bytes".to_string());
    }
    if value.chars().any(char::is_control) {
        return Err("must not contain control characters".to_string());
    }
    Ok(())
}

/// 重启命令：脚本里是**单行**赋值，换行会把后面的内容变成新的命令。
fn validate_setup_cmd(value: &str) -> Result<(), String> {
    if value.len() > 512 {
        return Err("must be at most 512 bytes".to_string());
    }
    if value.chars().any(char::is_control) {
        return Err("must be a single line without control characters".to_string());
    }
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
            .filter(|value| !value.is_empty())
            // 种子也是写入口之一（`gen-pki.sh` 按 `CRED_PKI_PEERS` 写）：
            // 只校验不归一 → 种子里填裸 origin 照样「探活绿、推送 404」。
            .map(|value| normalize_endpoint(&value))
            .transpose()
            .map_err(|err| anyhow::anyhow!("{}: {err}", self.name))?;
        // 种子也是「上报值」的一种：和 enroll 走同一套校验（host 会进脚本、角色会进推送）。
        validate_report(Some(&host), &self.roles)
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
            // 种子不带接入落点：它是给对方机器看的，不是写配置的。
            config_path: None,
            install_dir: None,
            restart_cmd: None,
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
            config_path: None,
            install_dir: None,
            restart_cmd: None,
        }
    }

    #[test]
    fn setup_fields_round_trip_and_reject_control_characters() {
        let dir = TempDir::new();
        let reg = registry(&dir);
        reg.create(new_peer("ingest"), "alice").unwrap();

        let updated = reg
            .set_setup(
                "ingest",
                Some("./identity/center/cred"),
                Some("  /etc/x/ctrl.toml  "),
                Some("systemctl restart x"),
            )
            .expect("setup persists");
        assert_eq!(
            updated.config_path.as_deref(),
            Some("/etc/x/ctrl.toml"),
            "两端空白要去掉"
        );
        assert_eq!(
            updated.install_dir.as_deref(),
            Some("./identity/center/cred"),
            "材料目录要跟其它接入事实一起存下来"
        );
        assert_eq!(updated.restart_cmd.as_deref(), Some("systemctl restart x"));

        // 重开也能读到（它跟 host / roles 一样是系统事实，不能只在内存里）。
        let reopened = registry(&dir);
        let peer = reopened.get("ingest").expect("peer survives reopen");
        assert_eq!(peer.config_path.as_deref(), Some("/etc/x/ctrl.toml"));
        assert_eq!(peer.install_dir.as_deref(), Some("./identity/center/cred"));

        // 清空 = 回到“只打印片段”。
        let cleared = reg.set_setup("ingest", None, None, None).unwrap();
        assert!(cleared.config_path.is_none() && cleared.restart_cmd.is_none());
        assert!(cleared.install_dir.is_none());

        // 换行会把后面的内容变成新命令：必须拦在写盘之前。
        let err = reg
            .set_setup("ingest", None, Some("/etc/x\nrm -rf /"), None)
            .expect_err("newline must be rejected");
        assert!(matches!(err, PeerError::BadRequest(_)), "got {err:?}");
        let err = reg
            .set_setup("ingest", None, None, Some("a\nb"))
            .expect_err("newline must be rejected");
        assert!(matches!(err, PeerError::BadRequest(_)), "got {err:?}");
        // 材料目录同样不能带换行（它会进脚本的单行赋值）。
        let err = reg
            .set_setup("ingest", Some("./x\ny"), None, None)
            .expect_err("newline must be rejected");
        assert!(matches!(err, PeerError::BadRequest(_)), "got {err:?}");

        let err = reg.set_setup("nope", None, Some("/x"), None).unwrap_err();
        assert!(matches!(err, PeerError::NotFound(_)), "got {err:?}");
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

    // ── 收数地址的归一化（能存、能探活、但发不出去的坑）──────────────────

    #[test]
    fn a_bare_origin_gets_the_push_path() {
        let dir = TempDir::new();
        let created = registry(&dir)
            .create(
                {
                    let mut input = new_peer("wist-center");
                    // 页面/脚本上最自然的填法：只给 origin（主机名由地址推）。
                    input.host = None;
                    input.endpoint = Some("https://center.internal:3103".to_string());
                    input
                },
                "alice",
            )
            .expect("create");
        assert_eq!(
            created.endpoint.as_deref(),
            Some("https://center.internal:3103/api/v1/internal/credentials")
        );
        // 落盘的是归一化后的值，重启不会退回裸 origin。
        let reopened = registry(&dir);
        assert_eq!(
            reopened.get("wist-center").unwrap().endpoint.as_deref(),
            Some("https://center.internal:3103/api/v1/internal/credentials")
        );
    }

    #[test]
    fn a_trailing_slash_is_trimmed_but_an_explicit_path_is_kept() {
        // 只有 `/` → 当作没写路径（axum 的精确路由不认尾斜杠）。
        assert_eq!(
            normalize_endpoint("https://h:19443/").unwrap(),
            "https://h:19443/api/v1/internal/credentials"
        );
        // X 把 listener 挂在别处是它的配置自由，有路径就原样保留。
        assert_eq!(
            normalize_endpoint("https://h:19443/custom/creds/").unwrap(),
            "https://h:19443/custom/creds"
        );
        // 已经是标准形态的：不动（幂等）。
        assert_eq!(
            normalize_endpoint("https://h:19443/api/v1/internal/credentials").unwrap(),
            "https://h:19443/api/v1/internal/credentials"
        );
    }

    #[test]
    fn a_path_with_whitespace_or_control_characters_is_rejected() {
        // 路径会原样进推送请求，也会被嵌进入接脚本 —— 空白 / 换行只会让脚本多几行、
        // 也让报错看不出是哪里坏了。URL 里本来就不该有它们。
        for bad in [
            "https://h:19443/a b",
            "https://h:19443/a\nb",
            "https://h:19443/a\tb",
            "https://h:19443/api/v1/internal/credentials?x=1\ny=2",
        ] {
            let err = normalize_endpoint(bad).expect_err(bad);
            assert!(matches!(err, PeerError::BadRequest(_)), "{bad}: {err:?}");
        }
    }

    #[test]
    fn a_bare_origin_still_yields_the_host() {
        // 归一化不能把 host 推导弄丢：页面上只填「https://h:3103」时，
        // 证书 SAN 必须仍然是 h。
        let dir = TempDir::new();
        let created = registry(&dir)
            .create(
                {
                    let mut input = new_peer("wist-center");
                    input.host = None;
                    input.endpoint = Some("https://h:3103".to_string());
                    input
                },
                "alice",
            )
            .expect("create");
        assert_eq!(created.host.as_deref(), Some("h"));
    }

    #[test]
    fn set_endpoint_normalizes_a_bare_origin() {
        let dir = TempDir::new();
        let registry = registry(&dir);
        registry
            .create(new_peer("wist-center"), "alice")
            .expect("create");
        let updated = registry
            .set_endpoint("wist-center", Some("https://h:3103"))
            .expect("set");
        assert_eq!(
            updated.endpoint.as_deref(),
            Some("https://h:3103/api/v1/internal/credentials")
        );
        // 探活还是从 origin 推：不会变成 `<path>/healthz`。
        assert_eq!(
            updated.probe_url().as_deref(),
            Some("https://h:3103/healthz")
        );
    }

    #[test]
    fn report_never_touches_the_registered_endpoint() {
        // 地址是部署登记的事实，接入上报改不了它 —— 包括归一化也不该由这边做。
        let dir = TempDir::new();
        let registry = registry(&dir);
        registry
            .create(new_peer("wist-center"), "alice")
            .expect("create");
        registry
            .report("wist-center", &["read".to_string()])
            .expect("report");
        assert_eq!(
            registry.get("wist-center").unwrap().endpoint.as_deref(),
            Some("https://wist-center.internal:19443/api/v1/internal/credentials")
        );
    }

    /// 这行常量是 `wist-cred-peer::DEFAULT_BASE_PATH` 的副本（运行期不引那个 crate）：
    /// 两边一漂，cred 就会把摘要发到 X 认的路径之外 —— 那时候只能看到 404。
    #[test]
    fn default_push_path_matches_the_peer_crate() {
        assert_eq!(DEFAULT_PUSH_PATH, wist_cred_peer::DEFAULT_BASE_PATH);
    }

    /// 升级前就存进去的裸 origin（当时校验放行）也要能用：加载时补路径并回写。
    #[test]
    fn a_stored_bare_origin_is_migrated_on_open() {
        let dir = TempDir::new();
        let path = dir.0.join("peers.json");
        fs::write(
            &path,
            r#"{"revision":3,"peers":[{"name":"wist-center","host":"h",
               "endpoint":"https://h:3103","roles":["admin"],
               "created_at":1,"created_by":"alice"}]}"#,
        )
        .expect("seed store");

        let registry = PeerRegistry::open(path.clone()).expect("open");
        assert_eq!(
            registry.get("wist-center").unwrap().endpoint.as_deref(),
            Some("https://h:3103/api/v1/internal/credentials")
        );
        // 回写过了：下次启动不需要再迁移。
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("https://h:3103/api/v1/internal/credentials"),
            "{text}"
        );
        // 迁移不改 revision：它不是一次业务变更。
        assert!(text.contains("\"revision\": 3") || text.contains("\"revision\":3"));
    }

    /// 盘上有坏地址不该拦住启动（历史数据 / 手改过的文件）：
    /// 丢掉那条推送能力可以，丢掉整个服务不行。
    #[test]
    fn a_stored_endpoint_that_is_not_a_url_does_not_block_startup() {
        let dir = TempDir::new();
        let path = dir.0.join("peers.json");
        fs::write(
            &path,
            r#"{"revision":1,"peers":[{"name":"wist-center","host":"h",
               "endpoint":"http://legacy/x","roles":[],
               "created_at":1,"created_by":"alice"}]}"#,
        )
        .expect("seed store");

        let registry = PeerRegistry::open(path.clone()).expect("open must not fail");
        // 原值保留（不在加载时静默改数据），推送时才报具体原因。
        assert_eq!(
            registry.get("wist-center").unwrap().endpoint.as_deref(),
            Some("http://legacy/x")
        );
        // 也没回写：没东西可迁移。
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("http://legacy/x"), "{text}");
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
            config_path: None,
            install_dir: None,
            restart_cmd: None,
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
    fn report_updates_roles_without_touching_identity() {
        let dir = TempDir::new();
        let registry = registry(&dir);
        registry
            .create(new_peer("wist-ingest"), "alice")
            .expect("create");

        registry
            .report("wist-ingest", &["read".to_string()])
            .expect("report");
        let peer = registry.get("wist-ingest").unwrap();
        assert_eq!(peer.roles, vec!["read"]);
        // 身份（host / endpoint）一个都不动。
        assert_eq!(peer.host.as_deref(), Some("wist-ingest.internal"));
        assert_eq!(
            peer.endpoint.as_deref(),
            Some("https://wist-ingest.internal:19443/api/v1/internal/credentials")
        );

        // 空 = 这次没说，不能当清空。
        registry.report("wist-ingest", &[]).expect("empty report");
        assert_eq!(registry.get("wist-ingest").unwrap().roles, vec!["read"]);
    }

    #[test]
    fn create_rejects_a_host_that_disagrees_with_the_endpoint() {
        let dir = TempDir::new();
        let registry = registry(&dir);
        let mut input = new_peer("wist-ingest");
        input.host = Some("other.internal".to_string());
        let err = registry.create(input, "alice").expect_err("mismatch");
        assert!(
            err.to_string().contains("does not match"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn creating_without_an_endpoint_is_refused() {
        // 没有地址的系统永远推不了、也探不了。建下来只会把错误推迟到接入那一刻。
        let dir = TempDir::new();
        let registry = registry(&dir);
        let err = registry
            .create(
                NewPeer {
                    name: "wist-ingest".to_string(),
                    host: None,
                    endpoint: None,
                    healthz: None,
                    roles: Vec::new(),
                    config_path: None,
                    install_dir: None,
                    restart_cmd: None,
                },
                "alice",
            )
            .expect_err("endpoint is required");
        assert!(
            matches!(err, PeerError::BadRequest(_))
                && err.to_string().contains("endpoint is required"),
            "unexpected: {err}"
        );
        assert!(registry.is_empty(), "nothing must be persisted");
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
                    config_path: None,
                    install_dir: None,
                    restart_cmd: None,
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
    fn a_peer_without_an_endpoint_reports_no_endpoint_not_unknown() {
        // 地址被撤销后，这个 peer 永远不会被心跳看到。报 unknown 会让页面说“未探测”，
        // 而实际是“永远不会被探测”—— 这就是之前被藏起来的那个错。
        let dir = TempDir::new();
        let registry = registry(&dir);
        registry
            .create(new_peer("wist-ingest"), "alice")
            .expect("create");
        registry.set_endpoint("wist-ingest", None).expect("clear");
        assert_eq!(registry.health("wist-ingest"), Health::NoEndpoint);

        // 补上地址就回到普通的一生：先是没探过，然后才可能 up/down。
        registry
            .set_endpoint(
                "wist-ingest",
                Some("https://ingest.internal:19443/api/v1/internal/credentials"),
            )
            .expect("set");
        assert_eq!(registry.health("wist-ingest"), Health::Unknown);

        // 再次清空又回到不可探。
        registry.set_endpoint("wist-ingest", None).expect("clear");
        assert_eq!(registry.health("wist-ingest"), Health::NoEndpoint);
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
            .report("wist-ingest", &["read".to_string()])
            .expect("report");
        assert_eq!(registry.get("wist-ingest").unwrap().roles, vec!["read"]);

        // 空 = 这次没说，不能当清空。
        registry.report("wist-ingest", &[]).expect("report empty");
        assert_eq!(registry.get("wist-ingest").unwrap().roles, vec!["read"]);

        // 非法字符集：拒，且旧值不动。
        let error = registry
            .report("wist-ingest", &["bad'role".to_string()])
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
        second.host = None;
        second.endpoint = Some("https://center.internal:19443/x".to_string());
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
        retry.host = None;
        retry.endpoint = Some("https://center.internal:19443/x".to_string());
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

    /// 种子是第三条写入口：`gen-pki.sh` 的 `CRED_PKI_PEERS` 里只写 origin 时，
    /// 导入后必须是能推送的完整地址。
    #[test]
    fn a_seed_with_a_bare_origin_is_normalized_on_import() {
        let dir = TempDir::new();
        let seeds = dir.0.join("onboarding");
        let peer_dir = seeds.join("wist-center");
        fs::create_dir_all(&peer_dir).expect("seed dir");
        fs::write(
            peer_dir.join("peer.json"),
            r#"{"name":"wist-center","host":"center.internal","endpoint":"https://center.internal:3103"}"#,
        )
        .expect("write seed");

        let registry = registry(&dir);
        assert_eq!(
            registry.import_dir(&seeds).expect("import"),
            vec!["wist-center".to_string()]
        );
        assert_eq!(
            registry.get("wist-center").unwrap().endpoint.as_deref(),
            Some("https://center.internal:3103/api/v1/internal/credentials")
        );
    }

    // ── 部署栈声明的材料目录（`CRED_PEER_DIRS`）──

    #[test]
    fn declared_peer_dirs_fill_only_the_empty_slot() {
        let dir = TempDir::new();
        let reg = registry(&dir);
        reg.create(new_peer("wist-center"), "alice").unwrap();
        reg.create(new_peer("wist-ingest"), "alice").unwrap();
        // 人已经在页面上选过的那个不许被重启改回去。
        reg.set_setup("wist-ingest", Some("./picked/by/human"), None, None)
            .unwrap();

        let applied = reg
            .seed_install_dirs(&[
                (
                    "wist-center".to_string(),
                    "./identity/center/cred".to_string(),
                ),
                ("wist-ingest".to_string(), "./other".to_string()),
                // 还没注册的系统：跳过，不拦住启动。
                ("ghost".to_string(), "./ghost".to_string()),
            ])
            .expect("seed");

        assert_eq!(applied, vec!["wist-center".to_string()]);
        assert_eq!(
            reg.get("wist-center").unwrap().install_dir.as_deref(),
            Some("./identity/center/cred")
        );
        assert_eq!(
            reg.get("wist-ingest").unwrap().install_dir.as_deref(),
            Some("./picked/by/human"),
            "页面上存过的优先"
        );
        // 落盘了：重启不再需要重新声明。
        assert_eq!(
            registry(&dir)
                .get("wist-center")
                .unwrap()
                .install_dir
                .as_deref(),
            Some("./identity/center/cred")
        );
    }

    #[test]
    fn seeding_the_same_value_again_is_a_no_op() {
        let dir = TempDir::new();
        let reg = registry(&dir);
        reg.create(new_peer("wist-center"), "alice").unwrap();
        let decl = vec![(
            "wist-center".to_string(),
            "./identity/center/cred".to_string(),
        )];
        assert_eq!(reg.seed_install_dirs(&decl).unwrap().len(), 1);
        assert!(
            reg.seed_install_dirs(&decl).unwrap().is_empty(),
            "第二次不应再算作写入（否则每次重启都 bump revision）"
        );
    }
}
