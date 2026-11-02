//! `wist-cred` —— 凭据服务（C）。
//!
//! 只做三件事：为**程序**签发凭据、撤销凭据、把摘要推给各验证方（X）。
//! 它不验业务请求，也不持有任何业务数据。
//!
//! 设计口径见 `wist-design/doc/design/foundation/auth-token-verification.md`。

pub mod api;
pub mod config;
pub mod store;
