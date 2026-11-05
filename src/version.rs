//! 版本端点：`GET /api/v1/version`（**公开、无鉴权**）。
//!
//! 页面右上角要同时显示三个版本号：页面自己（`wist-cred-web`）、凭据服务（`wist-cred`）、
//! 部署栈（`wist-cred-stack`）。后两个只有服务端知道，所以由这里一次答全：
//!
//! * `version` 取编译期烧入的 `CARGO_PKG_VERSION` —— 「这个二进制是哪版」，与发布制品一致；
//! * `stack_version` 取运行期读到的 **stack 的 `version.txt`** —— 「这套部署是哪版」。
//!   栈与组件分开发版（`0.6.x` vs `0.1.x`），二进制自己不可能知道，所以由栈把
//!   `version.txt` 只读挂进容器（默认 `/config/stack-version.txt`），或直接给
//!   `WIST_CRED_STACK_VERSION`。
//!
//! 读不到就**不返回该字段**（而不是编一个值）：页面据此显示 `—`。旧 cred 没有这条路由，
//! 新页面必须仍能工作 —— 这是新增路由而不是改 `/version` 形状的原因。
//!
//! 为什么公开：与 `/healthz`、`/version` 同一条口径 —— 这是「我在连哪个版本」的探针信息，
//! 不含任何凭据/业务数据；挂在页面口令之后反而让“还没登录”时答不出来。
//!
//! 与网关的 `api/version.rs` 同一套取值规则（环境变量优先、其次文件、空串当没有），
//! 只是环境变量前缀换成 `WIST_CRED_`。

use std::path::Path;

use axum::Json;
use serde::Serialize;

/// 直接给全栈版本的环境变量（优先于文件）。
const STACK_VERSION_ENV: &str = "WIST_CRED_STACK_VERSION";
/// 指定全栈版本文件路径的环境变量。
const STACK_VERSION_FILE_ENV: &str = "WIST_CRED_STACK_VERSION_FILE";
/// 默认挂载点：stack 的 `version.txt` 由 compose 只读挂到这里。
const DEFAULT_STACK_VERSION_FILE: &str = "/config/stack-version.txt";

/// 版本响应体：`name` / `version` 必有，`stack_version` 可省。
#[derive(Debug, Serialize)]
pub struct CredVersion {
    pub name: &'static str,
    pub version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_version: Option<String>,
}

/// `GET /api/v1/version`：公开、无鉴权，返回 cred（后端）版本与部署栈版本。
pub async fn cred_version() -> Json<CredVersion> {
    Json(CredVersion {
        name: "wist-cred",
        version: env!("CARGO_PKG_VERSION"),
        stack_version: stack_version(),
    })
}

/// 运行期解析全栈版本：环境变量优先，其次读文件；空串一律当「没有」。
fn stack_version() -> Option<String> {
    let env_value = std::env::var(STACK_VERSION_ENV).ok();
    let path = std::env::var(STACK_VERSION_FILE_ENV)
        .ok()
        .filter(|path| !path.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_STACK_VERSION_FILE.to_string());
    let file_value = std::fs::read_to_string(Path::new(path.trim())).ok();
    resolve_stack_version(env_value.as_deref(), file_value.as_deref())
}

/// 纯函数形式的取值规则（便于测试）：先环境变量、后文件；trim 后为空则跳过。
fn resolve_stack_version(env_value: Option<&str>, file_value: Option<&str>) -> Option<String> {
    [env_value, file_value]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_version_prefers_the_explicit_environment_value() {
        assert_eq!(
            resolve_stack_version(Some(" 0.1.7 \n"), Some("0.1.6")),
            Some("0.1.7".to_string())
        );
    }

    #[test]
    fn stack_version_falls_back_to_the_file() {
        assert_eq!(
            resolve_stack_version(None, Some("0.1.6\n")),
            Some("0.1.6".to_string())
        );
    }

    #[test]
    fn blank_values_count_as_missing() {
        assert_eq!(resolve_stack_version(Some("   "), Some("")), None);
        assert_eq!(resolve_stack_version(None, None), None);
    }
}
