//! MindOne 客户端与服务端共享的基础能力。
//!
//! 本 crate 不包含业务状态，专门提供稳定错误码、目录约定、安全配置、
//! Secret 存储抽象、传输地址校验以及哈希与脱敏工具。

pub mod bounded_file;
pub mod config;
pub mod error;
pub mod hash;
pub mod paths;
pub mod redact;
pub mod secret;
pub mod transport;

pub use bounded_file::{
    read_bounded_regular_file, sha256_bounded_regular_file, BoundedFileContents, BoundedFileDigest,
    BoundedFileError,
};
pub use config::{Config, ConfigKey, LogLevel, UpdateChannel};
pub use error::{ErrorBody, ErrorEnvelope, ExitCode, MindOneError, Result};
pub use hash::{constant_time_sha256_eq, sha256_bytes, sha256_file};
pub use paths::MindOnePaths;
pub use secret::{KeyringSecretStore, MemorySecretStore, SecretStore};
pub use transport::{validate_endpoint, validate_url, TransportSecurity};
