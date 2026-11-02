//! 凭据存储：单文件 JSON，原子替换，`0600`。
//!
//! **只存摘要**（`sha256` 十六进制），明文从不落盘（设计文档 D5）——
//! 所以这里没有"取回 token"的操作，也不应该有。
//!
//! 表很小（脚本条数级别），读改写整文件就够；并发用一把进程内锁。

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialRecord {
    pub credential_id: String,
    /// `sha256(token)` 的小写 hex。**不是** token 本身。
    pub digest: String,
    /// 程序名（凭据归属的程序）。
    pub subject: String,
    /// 谁申请的：来自人机面的操作者，不接受请求体覆盖。
    pub owner: String,
    pub purpose: String,
    pub roles: Vec<String>,
    #[serde(default)]
    pub resources: BTreeMap<String, Vec<String>>,
    pub audience: String,
    #[serde(default)]
    pub break_glass: bool,
    pub issued_at: i64,
    pub expires_at: i64,
    /// 每次状态变化 +1（签发 = 1，撤销 = 2…）。
    pub revision: u64,
    #[serde(default)]
    pub revoked_at: Option<i64>,
    /// 预留：X 低频回传后才有值（设计文档 §13 #6）。
    #[serde(default)]
    pub last_used_at: Option<i64>,
}

impl CredentialRecord {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct FileData {
    #[serde(default)]
    revision: u64,
    #[serde(default)]
    credentials: Vec<CredentialRecord>,
}

pub struct Store {
    path: PathBuf,
    lock: Mutex<()>,
}

impl Store {
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .with_context(|| format!("create store dir {}", parent.display()))?;
        }
        Ok(Self {
            path,
            lock: Mutex::new(()),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn insert(&self, record: CredentialRecord) -> anyhow::Result<()> {
        let _guard = self.lock.lock().unwrap_or_else(|err| err.into_inner());
        let mut data = self.read()?;
        if data
            .credentials
            .iter()
            .any(|item| item.credential_id == record.credential_id)
        {
            bail!("duplicate credential_id {}", record.credential_id);
        }
        data.revision += 1;
        data.credentials.push(record);
        self.write(&data)
    }

    pub fn get(&self, credential_id: &str) -> anyhow::Result<Option<CredentialRecord>> {
        let _guard = self.lock.lock().unwrap_or_else(|err| err.into_inner());
        Ok(self
            .read()?
            .credentials
            .into_iter()
            .find(|item| item.credential_id == credential_id))
    }

    pub fn list(&self) -> anyhow::Result<Vec<CredentialRecord>> {
        let _guard = self.lock.lock().unwrap_or_else(|err| err.into_inner());
        let mut items = self.read()?.credentials;
        items.sort_by_key(|item| std::cmp::Reverse(item.issued_at));
        Ok(items)
    }

    /// 幂等：已撤销时返回当前记录，不改状态。
    pub fn revoke(&self, credential_id: &str, at: i64) -> anyhow::Result<Option<CredentialRecord>> {
        let _guard = self.lock.lock().unwrap_or_else(|err| err.into_inner());
        let mut data = self.read()?;
        let Some(index) = data
            .credentials
            .iter()
            .position(|item| item.credential_id == credential_id)
        else {
            return Ok(None);
        };
        if data.credentials[index].is_revoked() {
            return Ok(Some(data.credentials[index].clone()));
        }
        data.credentials[index].revoked_at = Some(at);
        data.credentials[index].revision += 1;
        data.revision += 1;
        let updated = data.credentials[index].clone();
        self.write(&data)?;
        Ok(Some(updated))
    }

    fn read(&self) -> anyhow::Result<FileData> {
        match fs::read_to_string(&self.path) {
            Ok(text) => serde_json::from_str(&text)
                .with_context(|| format!("parse store {}", self.path.display())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(FileData::default()),
            Err(err) => Err(err).with_context(|| format!("read store {}", self.path.display())),
        }
    }

    /// 先写临时文件再 rename：崩在中间不会留下半个 JSON。
    fn write(&self, data: &FileData) -> anyhow::Result<()> {
        let text = serde_json::to_string_pretty(data)?;
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, text).with_context(|| format!("write {}", tmp.display()))?;
        set_private_perms(&tmp)?;
        fs::rename(&tmp, &self.path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), self.path.display()))?;
        Ok(())
    }
}

#[cfg(unix)]
fn set_private_perms(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_perms(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str) -> CredentialRecord {
        CredentialRecord {
            credential_id: id.to_string(),
            digest: format!("digest-{id}"),
            subject: "ci-nightly".to_string(),
            owner: "alice".to_string(),
            purpose: "nightly disk inspection".to_string(),
            roles: vec!["investigation:run".to_string()],
            resources: BTreeMap::new(),
            audience: "wist-center".to_string(),
            break_glass: false,
            issued_at: 1_700_000_000,
            expires_at: 1_700_086_400,
            revision: 1,
            revoked_at: None,
            last_used_at: None,
        }
    }

    fn temp_store() -> (tempdir::TempDirGuard, Store) {
        let dir = tempdir::TempDirGuard::new();
        let store = Store::open(dir.path.join("credentials.db")).expect("open store");
        (dir, store)
    }

    #[test]
    fn insert_then_get_round_trips() {
        let (_dir, store) = temp_store();
        store.insert(record("cred_1")).unwrap();
        let found = store.get("cred_1").unwrap().expect("record");
        assert_eq!(found.subject, "ci-nightly");
        assert_eq!(found.revision, 1);
    }

    #[test]
    fn revoke_is_idempotent_and_bumps_revision_once() {
        let (_dir, store) = temp_store();
        store.insert(record("cred_1")).unwrap();

        let first = store
            .revoke("cred_1", 1_700_000_500)
            .unwrap()
            .expect("record");
        assert_eq!(first.revoked_at, Some(1_700_000_500));
        assert_eq!(first.revision, 2);

        let second = store
            .revoke("cred_1", 1_700_000_900)
            .unwrap()
            .expect("record");
        assert_eq!(second.revoked_at, Some(1_700_000_500));
        assert_eq!(second.revision, 2);
    }

    #[test]
    fn revoke_unknown_returns_none() {
        let (_dir, store) = temp_store();
        assert!(store.revoke("nope", 1).unwrap().is_none());
    }

    /// 最小的临时目录：不引第三方 crate，用完删掉。
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
                let path = std::env::temp_dir().join(format!("wist-cred-test-{name}"));
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
