//! MindOne 使用的 PostgreSQL-only SQLx API 门面。
//!
//! 上游 `sqlx` 门面包在锁文件中保留所有可选数据库驱动；这会把未启用的
//! MySQL RSA 实现带进供应链清单。MindOne 只支持 PostgreSQL，因此直接、精确
//! 锁定 `sqlx-core` 与 `sqlx-postgres`，并仅重导出协调器实际需要的稳定表面。

pub use sqlx_core::error::{Error, Result};
pub use sqlx_core::migrate;
pub use sqlx_core::query::query;
pub use sqlx_core::query_as::query_as;
pub use sqlx_core::query_scalar::query_scalar;
pub use sqlx_core::raw_sql::raw_sql;
pub use sqlx_core::row::Row;
pub use sqlx_core::transaction::Transaction;
pub use sqlx_postgres::{self as postgres, PgConnection, PgPool, PgTransaction, Postgres};
