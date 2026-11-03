//! 接入包（onboarding）：把「验证方 X 接入双向认证」压成一条 `curl … | bash`。
//!
//! 口径与 `wist-center` ↔ `wist-gwlinkd` 的入场流程一致（那是平台上成熟的一套）：
//!
//! - **私钥在 X 本机生成，永不上送**。X 只交一张 CSR（只含公钥），本服务按 CSR 签。
//! - **一次性券门控签发**。券 32 字节随机、只存 `sha256`、分钟级 TTL、兑现即废。
//! - **主体由签发方填**。CSR 里声明的 subject / 扩展一律忽略，CN 与 DNS SAN 取自
//!   `peer.json`，做不到「自己给自己申请一个别人的名字」。
//! - **坏 CSR 不消耗券**：先做无状态的 CSR 解析，再原子兑现券。
//! - **失败不区分原因**：券不存在 / 过期 / 已兑现 / peer 消失，对外都是同一个响应，
//!   避免把公开端点变成券的枚举接口。
//!
//! 与 center 的差异（有意为之，不是照抄）：
//!
//! - 券是**随机数**，不是 HMAC 派生 —— 派生会让同一个明文可以被重复签发成多行，
//!   把「一次性」变脆（center 里 enrollment token 就是这个形态）。
//! - **peer 绑在券里**，兑现时从券本身取，不做「外部声称的 id + 表查询」两段式，
//!   从根上消掉「券有效但对象不存在」这个探测面。
//! - TTL 与链接同一量级（分钟），不给 30 天。
//! - 不引入任何「看起来是第二因子、实际只是盐」的东西。

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::peers::Peer;

/// 接入脚本模板（`bash` 方言；占位符是 `__NAME__`，不用 `{}`——bash 里到处都是花括号）。
const TEMPLATE: &str = include_str!("../assets/onboarding.sh.tpl");

/// 票据状态：`Pending` 可取脚本、可兑现；`Consumed` 两种都不行。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketState {
    Pending,
    Consumed,
}

/// 一次性票据。`peer` 绑在票里——兑现时不再信任请求方声称的任何身份。
#[derive(Debug, Clone)]
pub struct Ticket {
    pub peer: String,
    pub expires_at: i64,
    pub state: TicketState,
}

/// 票据表：**只活在进程内存里**。
///
/// 落盘没有意义：重启最坏是让运维重开一条链接，而磁盘上多一份「能换出证书的摘要」
/// 是净损失。TTL 本身只有分钟级。
pub struct TicketStore {
    ttl_seconds: u64,
    tickets: Mutex<BTreeMap<String, Ticket>>,
}

impl TicketStore {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            ttl_seconds,
            tickets: Mutex::new(BTreeMap::new()),
        }
    }

    /// 签发一张票，返回 `(token, expires_in_seconds)`。
    pub fn mint(&self, peer: &str) -> (String, u64) {
        let now = now_secs();
        let token = format!("wot_{}", random_hex(32));
        let mut tickets = self.lock();
        // 顺手清掉过期的：表很小，但没必要让它长起来。
        tickets.retain(|_, ticket| ticket.expires_at > now);
        tickets.insert(
            digest_hex(&token),
            Ticket {
                peer: peer.to_string(),
                expires_at: now + self.ttl_seconds as i64,
                state: TicketState::Pending,
            },
        );
        (token, self.ttl_seconds)
    }

    /// 取脚本时用：券必须存在、未过期、**尚未兑现**。不改变状态（脚本可重取，
    /// 它只有公开材料 + 自己的券，重取一次无害）。
    pub fn peek(&self, token: &str) -> Option<Ticket> {
        let now = now_secs();
        let tickets = self.lock();
        let ticket = tickets.get(&digest_hex(token))?;
        (ticket.expires_at > now && ticket.state == TicketState::Pending).then(|| ticket.clone())
    }

    /// 登记时用：`Pending → Consumed`，原子。已兑现 / 过期 / 未知都返回 `None`。
    ///
    /// 先兑现再签发：两个并发请求不能都拿到证书。
    pub fn consume(&self, token: &str) -> Option<Ticket> {
        let now = now_secs();
        let mut tickets = self.lock();
        let ticket = tickets.get_mut(&digest_hex(token))?;
        if ticket.expires_at <= now || ticket.state != TicketState::Pending {
            return None;
        }
        ticket.state = TicketState::Consumed;
        Some(ticket.clone())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Ticket>> {
        self.tickets.lock().unwrap_or_else(|err| err.into_inner())
    }
}

/// 把接入脚本渲染成一段自包含的 bash。
///
/// `enroll_url` 是**绝对地址**（页面按请求的 Host / X-Forwarded-Proto 拼出来），
/// 脚本里可以用 `--endpoint <base>` 覆盖。
pub fn render_script(
    peer: &Peer,
    client_ca_pem: &str,
    enroll_url: &str,
    issuer_public_hex: Option<&str>,
) -> anyhow::Result<String> {
    if !client_ca_pem.contains("-----BEGIN") {
        anyhow::bail!("client CA is not a PEM");
    }
    if let Some(hex) = issuer_public_hex
        && (hex.len() != 64 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()))
    {
        anyhow::bail!("issuer signing public key must be 32-byte hex");
    }
    Ok(TEMPLATE
        .replace("__PEER_NAME__", &shell_single_quoted(&peer.name))
        .replace("__PEER_HOST__", &shell_single_quoted(peer.host()))
        .replace(
            "__PEER_ENDPOINT__",
            &shell_single_quoted(peer.endpoint.as_deref().unwrap_or("")),
        )
        .replace(
            "__PEER_ROLES__",
            &shell_single_quoted(&peer.roles.join(",")),
        )
        .replace("__ENROLL_URL__", &shell_single_quoted(enroll_url))
        .replace("__ISSUER_SIGNING_PUB__", issuer_public_hex.unwrap_or(""))
        .replace("__CLIENT_CA_PEM__", client_ca_pem.trim_end()))
}

/// 单引号字面量里的值：把 `'` 变成 `'\''`，其余原样。
///
/// 模板里每个占位符都包在一对单引号里（`PEER_HOST='__PEER_HOST__'`），
/// 所以这里只需处理“跳出字面量”的那一个字符。上游已经限了字符集（host / endpoint /
/// roles 都是白名单），这一层是**冗余但便宜**的兜底：少一层校验就多一个命令注入面。
fn shell_single_quoted(value: &str) -> String {
    value.replace('\'', r"'\''")
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    if getrandom::fill(&mut buffer).is_err() {
        // 拿不到熵就不要发票：宁可 500，也不要可预测的一次性凭据。
        panic!("system entropy unavailable");
    }
    buffer.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest_hex(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> TicketStore {
        TicketStore::new(900)
    }

    #[test]
    fn ticket_is_single_use_for_enrollment() {
        let store = store();
        let (token, ttl) = store.mint("wist-ingest");
        assert_eq!(ttl, 900);
        assert_eq!(
            store.consume(&token).expect("first consume").peer,
            "wist-ingest"
        );
        assert!(store.consume(&token).is_none(), "second consume must fail");
    }

    #[test]
    fn script_can_be_fetched_until_the_ticket_is_consumed() {
        let store = store();
        let (token, _) = store.mint("wist-ingest");

        // 重取脚本是允许的：脚本里没有长期秘密。
        assert!(store.peek(&token).is_some());
        assert!(store.peek(&token).is_some());

        store.consume(&token).expect("consume");
        assert!(
            store.peek(&token).is_none(),
            "consumed ticket serves nothing"
        );
    }

    #[test]
    fn unknown_token_is_rejected() {
        let store = store();
        assert!(store.consume("wot_nope").is_none());
        assert!(store.peek("wot_nope").is_none());
    }

    #[test]
    fn expired_ticket_is_rejected() {
        let store = store();
        let (token, _) = store.mint("wist-ingest");
        // 直接改过期时间，避免测试真的睡。
        {
            let mut tickets = store.lock();
            for ticket in tickets.values_mut() {
                ticket.expires_at = now_secs() - 1;
            }
        }
        assert!(store.consume(&token).is_none());
        assert!(store.peek(&token).is_none());
    }

    #[test]
    fn mint_returns_distinct_tokens() {
        let store = store();
        let (first, _) = store.mint("a");
        let (second, _) = store.mint("a");
        assert_ne!(first, second, "tokens must be random, not derived");
        assert!(first.starts_with("wot_"));
        assert_eq!(first.len(), "wot_".len() + 64);
    }

    #[test]
    fn render_embeds_public_material_only() {
        let peer = Peer {
            name: "wist-ingest".to_string(),
            host: Some("ingest.internal".to_string()),
            endpoint: Some("https://ingest.internal:19443/api/v1/internal/credentials".to_string()),
            healthz: None,
            roles: vec![],
            created_at: 0,
            created_by: "alice".to_string(),
        };
        let ca = "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n";
        let script = render_script(
            &peer,
            ca,
            "https://cred.internal/onboarding/enroll/wot_x",
            Some(&"ab".repeat(32)),
        )
        .expect("render");

        assert!(script.contains("PEER_NAME='wist-ingest'"));
        assert!(script.contains("PEER_HOST='ingest.internal'"));
        assert!(script.contains("AUDIENCE=\"$PEER_NAME\""));
        assert!(
            script.contains(
                "PEER_ENDPOINT='https://ingest.internal:19443/api/v1/internal/credentials'"
            )
        );
        assert!(script.contains("ENROLL_URL='https://cred.internal/onboarding/enroll/wot_x'"));
        assert!(script.contains("-----BEGIN CERTIFICATE-----"));
        assert!(!script.contains("__PEER_NAME__"), "placeholder left behind");
        assert!(
            !script.contains("__PEER_ENDPOINT__"),
            "placeholder left behind"
        );
        assert!(
            !script.contains("PRIVATE KEY"),
            "the link must never carry a private key"
        );
        assert!(script.starts_with("#!/usr/bin/env bash"));
    }

    #[test]
    fn render_escapes_single_quotes_in_embedded_values() {
        // 上游已经限了字符集；万一漏进来一个 `'`，也不能让它跳出 shell 字面量。
        let peer = Peer {
            name: "wist-ingest".to_string(),
            host: Some("ingest.internal".to_string()),
            endpoint: Some("https://ingest.internal:19443/x'y".to_string()),
            healthz: None,
            roles: vec!["read".to_string(), "weird'role".to_string()],
            created_at: 0,
            created_by: "alice".to_string(),
        };
        let ca = "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n";
        let script = render_script(&peer, ca, "https://cred.internal/x", None).expect("render");
        assert!(
            script.contains(r"PEER_ROLES='read,weird'\''role'"),
            "role quote must be escaped, got: {script}"
        );
        assert!(
            script.contains(r"PEER_ENDPOINT='https://ingest.internal:19443/x'\''y'"),
            "endpoint quote must be escaped, got: {script}"
        );
    }

    #[test]
    fn render_rejects_a_non_pem_client_ca() {
        let peer = Peer {
            name: "wist-ingest".to_string(),
            host: Some("h".to_string()),
            endpoint: None,
            healthz: None,
            roles: vec![],
            created_at: 0,
            created_by: "alice".to_string(),
        };
        let err = render_script(&peer, "not a pem", "https://x/y", None).expect_err("must reject");
        assert!(err.to_string().contains("not a PEM"), "unexpected: {err}");
    }

    #[test]
    fn issuer_public_key_is_embedded_and_validated() {
        let peer = Peer {
            name: "wist-ingest".to_string(),
            host: Some("ingest.internal".to_string()),
            endpoint: None,
            healthz: None,
            roles: Vec::new(),
            created_at: 0,
            created_by: "alice".to_string(),
        };
        let ca = "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n";
        let hex = "ab".repeat(32);
        let script =
            render_script(&peer, ca, "https://cred.internal/x", Some(&hex)).expect("render");
        assert!(script.contains(&hex), "public key must be embedded");
        let err = render_script(&peer, ca, "https://cred.internal/x", Some("zz"))
            .expect_err("must reject");
        assert!(err.to_string().contains("hex"), "unexpected: {err}");
    }
}
