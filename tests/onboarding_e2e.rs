//! 端到端：把签发出来的 `join.sh` **真的用 bash 跑一遍**。
//!
//! 为什么不用“渲染文本断言”：我们连撞过几个只有运行时才暴露的错 ——
//!   · `$CRED_FILE（`：bash 把全角括号当成变量名的一部分（unbound variable）；
//!   · 在部署栈里把身份材料落到 `./wist-cred/<peer>`（私钥出现在 `git status`）；
//!   · `--config` 指到目录 / 与材料不同目录。
//! 文本断言一个都抓不到。这里起一个真 cred（axum + 真实 CA），用 `curl` 取脚本、
//! 用 `bash` 执行，然后看磁盘上留下了什么。
//!
//! 运行时依赖：`bash` / `curl` / `openssl` —— 与脚本自身的硬前置一致。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use wist_cred::api::{self, AppState};
use wist_cred::config::{
    AuthMode, Config, IssueConfig, OnboardingConfig, ServerConfig, StorageConfig,
};
use wist_cred::onboarding::TicketStore;
use wist_cred::peers::{NewPeer, PeerRegistry};
use wist_cred::store::Store;
use wist_pki::CertificateAuthority;

const OPERATOR_HEADER: &str = "x-wist-operator";

struct Harness {
    addr: SocketAddr,
    dir: PathBuf,
    boarding: Arc<TicketStore>,
}

fn unique_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("wist-cred-e2e-{tag}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// 起一个真 cred：真实 CA（测试里现场生成）、一个已登记的认证系统。
async fn start(tag: &str) -> Harness {
    start_with(
        tag,
        Some("https://center.internal:19443/api/v1/internal/credentials".to_string()),
    )
    .await
}

/// 同 `start`，但可以决定这个认证系统**有没有收数地址**。
///
/// 没地址是新接入最容易踩的坑：脚本能跑、登记也“成功”，但 cred 永远不会探它、
/// 也不会给它推送 —— 所以脚本默认拒绝，必须显式 `--manual`。
async fn start_with(tag: &str, endpoint: Option<String>) -> Harness {
    let dir = unique_dir(tag);

    // CA-S：签发 X 的服务器证书。同一张证书也当 CA-I 的信任锚下发（测试里够用）。
    let (authority, ca_cert_pem, ca_key_pem) =
        CertificateAuthority::generate("WistCred E2E CA").expect("generate CA");
    let ca_cert = dir.join("ca.crt");
    let ca_key = dir.join("ca.key");
    std::fs::write(&ca_cert, ca_cert_pem).expect("write ca cert");
    std::fs::write(&ca_key, ca_key_pem).expect("write ca key");

    let config = Config {
        server: ServerConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            mode: AuthMode::Ingress,
            ingress_header: OPERATOR_HEADER.to_string(),
            admin_password_hash: String::new(),
            trusted_peers: vec!["127.0.0.1/32".to_string()],
            // 故意不配：走 Host 头推（curl 会带端口），顺便钉住这条路径。
            public_base_url: None,
        },
        storage: StorageConfig {
            path: dir.join("credentials.db"),
        },
        issue: IssueConfig {
            digest: "sha256".to_string(),
            max_ttl_seconds: 2_592_000,
            break_glass_max_ttl_seconds: 7_776_000,
            overlap_seconds: 300,
            // 不配签发钥：顺便覆盖“没公钥就不写 require_signature”的分支。
            signing_key: None,
        },
        push: None,
        onboarding: OnboardingConfig {
            dir: None,
            peer_dirs: Vec::new(),
            store_path: dir.join("peers.json"),
            script_ttl_seconds: 900,
            ca_cert: Some(ca_cert.clone()),
            ca_key: Some(ca_key.clone()),
            client_ca: Some(ca_cert),
            peer_cert_ttl_seconds: 7_776_000,
            heartbeat_seconds: 0,
        },
    };

    let peers = Arc::new(PeerRegistry::open(config.onboarding.store_path.clone()).expect("peers"));
    peers
        .create(
            NewPeer {
                name: "wist-center".to_string(),
                host: Some("center.internal".to_string()),
                endpoint,
                healthz: None,
                roles: vec!["admin".to_string(), "read".to_string()],
                install_dir: None,
                config_path: None,
                restart_cmd: None,
            },
            "e2e",
        )
        .expect("create peer");

    let boarding = Arc::new(TicketStore::new(config.onboarding.script_ttl_seconds));
    let state = AppState {
        config: Arc::new(config),
        store: Arc::new(Store::open(dir.join("credentials.db")).expect("store")),
        push: None,
        boarding: boarding.clone(),
        signer: Some(Arc::new(authority)),
        peers,
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        // 必须带 connect info：处理函数要从 `ConnectInfo<SocketAddr>` 取对端 IP 做 peer 白名单。
        let service = api::router(state).into_make_service_with_connect_info::<SocketAddr>();
        let _ = axum::serve(listener, service).await;
    });

    Harness {
        addr,
        dir,
        boarding,
    }
}

impl Harness {
    /// 真的走一遍 `curl … -o join.sh`：连路由一起测。
    fn fetch_script(&self, into: &Path) -> PathBuf {
        let (token, _ttl) = self.boarding.mint("wist-center");
        let url = format!("http://{}/enroll/{token}/join.sh", self.addr);
        let out = Command::new("curl")
            .args(["-fsSL", &url, "-o"])
            .arg(into)
            .output()
            .expect("run curl");
        assert!(
            out.status.success(),
            "取脚本失败：{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        into.to_path_buf()
    }

    fn run_script(cwd: &Path, script: &Path, args: &[&str]) -> Output {
        let mut command = Command::new("bash");
        command.arg(script).args(args).current_dir(cwd);
        // 固定成 UTF-8 locale：`$VAR（` 这类错**只在 UTTF-8 locale 下复现**
        // （bash 会把多字节字符当成变量名的一部分）。C locale 下测试会假绿。
        if let Some(locale) = utf8_locale() {
            command.env("LC_ALL", &locale).env("LANG", &locale);
        }
        command.output().expect("run join.sh")
    }
}

/// 本机能用的 UTF-8 locale（优先 en_US，再 C）。
fn utf8_locale() -> Option<String> {
    let out = Command::new("locale").arg("-a").output().ok()?;
    let listing = String::from_utf8_lossy(&out.stdout);
    for want in ["en_US.UTF-8", "en_US.utf8", "C.UTF-8", "C.utf8"] {
        if listing.lines().any(|line| line.trim() == want) {
            return Some(want.to_string());
        }
    }
    None
}

fn stdout_of(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn happy_path_writes_materials_and_cred_toml() {
    let harness = start("happy").await;
    let script = harness.fetch_script(&harness.dir.join("join.sh"));
    let material_dir = harness.dir.join("identity/cred-client");

    let out = Harness::run_script(
        &harness.dir,
        &script,
        &["--dir", material_dir.to_str().unwrap()],
    );
    let text = stdout_of(&out);
    assert!(out.status.success(), "脚本应当成功：\n{text}");
    assert!(
        text.contains("▶ 完成"),
        "脚本没走到最后（中途退出了）：\n{text}"
    );

    for name in ["server.crt", "server.key", "client-ca.pem", "cred.toml"] {
        assert!(
            material_dir.join(name).is_file(),
            "{name} 没落盘；输出：\n{text}"
        );
    }

    let cred_toml = std::fs::read_to_string(material_dir.join("cred.toml")).expect("cred.toml");
    assert!(cred_toml.contains("[identity]"), "{cred_toml}");
    assert!(
        cred_toml.contains("cert      = \"server.crt\""),
        "{cred_toml}"
    );
    // 本测试没配签发钥 ⇒ 不能开验签（开了就会拿不存在的文件去验）。
    assert!(
        !cred_toml
            .lines()
            .any(|line| line == "require_signature = true"),
        "没下发公钥却开了验签：\n{cred_toml}"
    );
    assert!(
        cred_toml.contains("# require_signature = true"),
        "{cred_toml}"
    );
    // 上报了角色就写进文件。
    assert!(
        cred_toml.contains("roles = [\"admin\", \"read\"]"),
        "{cred_toml}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stack_root_refuses_outside_identity_and_keeps_the_ticket() {
    let harness = start("stack").await;
    let script = harness.fetch_script(&harness.dir.join("join.sh"));

    // 造一个“部署栈”的现场：栈根有 sys-prj.yml + identity/。
    let stack = harness.dir.join("stack");
    std::fs::create_dir_all(stack.join("identity")).expect("stack dirs");
    std::fs::write(stack.join("sys-prj.yml"), "system: {}\n").expect("sys-prj");

    let out = Harness::run_script(&stack, &script, &[]);
    let text = stdout_of(&out);
    assert!(!out.status.success(), "栈里不带 --dir 必须失败：\n{text}");
    assert!(text.contains("身份材料要落在 identity/ 下"), "{text}");
    // 管道进来的调用者没法“加个参数再跑”：报错必须自带完整命令。
    assert!(
        text.contains("curl -fsSLk '") && text.contains("| bash -s -- --dir"),
        "没给出可直接重跑的完整命令：\n{text}"
    );
    assert!(
        !stack.join("wist-cred").exists(),
        "失败时不该创建任何目录：\n{text}"
    );

    // 关键：券没被烧掉 —— 同一条命令加 --dir 还能跑通。
    let out = Harness::run_script(&stack, &script, &["--dir", "./identity/cred-client"]);
    let text = stdout_of(&out);
    assert!(out.status.success(), "补上 --dir 应当成功：\n{text}");
    assert!(text.contains("▶ 完成"), "没走到最后：\n{text}");
    assert!(
        stack.join("identity/cred-client/cred.toml").is_file(),
        "{text}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stack_with_one_identity_dir_suggests_the_dir_its_consumer_expects() {
    let harness = start("suggest").await;
    let script = harness.fetch_script(&harness.dir.join("join.sh"));

    // 栈里已经有一个服务身份目录（center-stack 的真实布局：identity/center）。
    let stack = harness.dir.join("stack-suggest");
    std::fs::create_dir_all(stack.join("identity/center")).expect("stack dirs");
    std::fs::write(stack.join("sys-prj.yml"), "system: {}\n").expect("sys-prj");

    let out = Harness::run_script(&stack, &script, &[]);
    let text = stdout_of(&out);
    assert!(!out.status.success(), "{text}");
    // 建议 = 唯一子目录 + /cred，而不是写死的 ./identity/<peer>。
    assert!(text.contains("--dir ./identity/center/cred"), "{text}");

    // 把建议原样拿来重跑：券还在，必须跑通，且材料落在消费方会看的位置。
    let out = Harness::run_script(&stack, &script, &["--dir", "./identity/center/cred"]);
    let text = stdout_of(&out);
    assert!(out.status.success(), "按建议重跑应当成功：\n{text}");
    assert!(
        stack.join("identity/center/cred/cred.toml").is_file(),
        "{text}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stored_material_dir_makes_the_bare_command_work_inside_a_stack() {
    // 用户视角的底线：页面给的那一行命令**原样粘过去就能跑**，不需要自己拼 --dir。
    let harness = start("stored-dir").await;
    let api = format!("http://{}/api/v1/peers/wist-center/setup", harness.addr);
    let body = r#"{"install_dir":"./identity/center/cred"}"#;
    let out = Command::new("curl")
        .args([
            "-sS",
            "-X",
            "POST",
            "-H",
            &format!("{OPERATOR_HEADER}: alice"),
            "-H",
            "content-type: application/json",
            "-d",
            body,
            &api,
        ])
        .output()
        .expect("curl setup");
    assert!(
        out.status.success(),
        "setup 失败：{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 重新签发（脚本是签发时渲染的），再在栈根**不带任何参数**地跑。
    let script = harness.fetch_script(&harness.dir.join("join-stored.sh"));
    let stack = harness.dir.join("stack-stored");
    std::fs::create_dir_all(stack.join("identity")).expect("stack dirs");
    std::fs::write(stack.join("sys-prj.yml"), "system: {}\n").expect("sys-prj");

    let out = Harness::run_script(&stack, &script, &[]);
    let text = stdout_of(&out);
    assert!(out.status.success(), "裸命令应当直接跑通：\n{text}");
    assert!(
        stack.join("identity/center/cred/cred.toml").is_file(),
        "材料应当落在页面存的目录里：\n{text}"
    );
    assert!(
        !stack.join("wist-cred").exists(),
        "不该再回退到默认目录：\n{text}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_outside_the_material_dir_is_refused() {
    let harness = start("config").await;
    let script = harness.fetch_script(&harness.dir.join("join.sh"));

    let material = harness.dir.join("materials");
    let elsewhere = harness.dir.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("elsewhere");

    let out = Harness::run_script(
        &harness.dir,
        &script,
        &[
            "--dir",
            material.to_str().unwrap(),
            "--config",
            elsewhere.join("cred.toml").to_str().unwrap(),
        ],
    );
    let text = stdout_of(&out);
    assert!(
        !out.status.success(),
        "跨目录写 cred.toml 必须失败：\n{text}"
    );
    assert!(text.contains("必须与材料同目录"), "{text}");
    assert!(
        !elsewhere.join("cred.toml").exists(),
        "失败时不该写任何文件"
    );
}

/// 「注册成功了，但什么都不动」—— 之前就是这样把错藏起来的。
///
/// 没有收数地址的 peer：脚本能跑、登记也能成功，但 cred 永远不会探它，
/// 也不会给它推送凭据。所以默认拒跑，要退化必须 `--manual`，并且把后果说出来。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_without_an_endpoint_is_refused_unless_manual() {
    let harness = start_with("no-endpoint", None).await;
    let script = harness.fetch_script(&harness.dir.join("join.sh"));
    let material = harness.dir.join("materials");

    let out = Harness::run_script(
        &harness.dir,
        &script,
        &["--dir", material.to_str().unwrap()],
    );
    let text = stdout_of(&out);
    assert!(!out.status.success(), "没地址时必须拒跑：\n{text}");
    assert!(text.contains("--advertise"), "要给出补救办法：\n{text}");
    assert!(text.contains("--manual"), "要给出显式退化的办法：\n{text}");
    assert!(
        !material.join("cred.toml").exists(),
        "拒跑时不能落下半套材料：\n{text}"
    );

    // 券没被烧掉：同一张券加上 --manual 还能跑完，并且结果被明说。
    let out = Harness::run_script(
        &harness.dir,
        &script,
        &["--dir", material.to_str().unwrap(), "--manual"],
    );
    let text = stdout_of(&out);
    assert!(out.status.success(), "--manual 应当允许跑完：\n{text}");
    assert!(text.contains("手工分发模式"), "要明说后果：\n{text}");
    assert!(text.contains("不会收到推送"), "{text}");
    assert!(material.join("cred.toml").is_file(), "{text}");
}

/// 显式给了 `--advertise` 时，地址必须被登记（不能只写进脚本就当完事）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn advertise_without_a_baked_endpoint_is_actually_reported() {
    let harness = start_with("advertise", None).await;
    let script = harness.fetch_script(&harness.dir.join("join.sh"));
    let material = harness.dir.join("materials");

    let out = Harness::run_script(
        &harness.dir,
        &script,
        &[
            "--dir",
            material.to_str().unwrap(),
            "--advertise",
            "https://center.internal:19443/api/v1/internal/credentials",
        ],
    );
    let text = stdout_of(&out);
    assert!(out.status.success(), "应当跑通：\n{text}");
    assert!(text.contains("▶ 完成"), "{text}");

    let stored = std::fs::read_to_string(harness.dir.join("peers.json")).expect("peers.json");
    assert!(
        stored.contains("https://center.internal:19443/api/v1/internal/credentials"),
        "收数地址没被登记：\n{stored}"
    );
}
