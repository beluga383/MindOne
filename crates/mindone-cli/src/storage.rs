use std::io::Write;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{CliError, CliResult};

pub fn read_json_or_default<T>(path: &Path) -> CliResult<T>
where
    T: DeserializeOwned + Default,
{
    if !path.exists() {
        return Ok(T::default());
    }
    let bytes = std::fs::read(path).map_err(|error| {
        CliError::General(format!("无法读取状态文件 {}：{error}", path.display()))
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|error| CliError::General(format!("状态文件格式无效 {}：{error}", path.display())))
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> CliResult<T> {
    let bytes = std::fs::read(path).map_err(|error| {
        CliError::General(format!("无法读取状态文件 {}：{error}", path.display()))
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|error| CliError::General(format!("状态文件格式无效 {}：{error}", path.display())))
}

pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> CliResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| CliError::General(format!("状态路径缺少父目录：{}", path.display())))?;
    std::fs::create_dir_all(parent).map_err(|error| {
        CliError::General(format!("无法创建状态目录 {}：{error}", parent.display()))
    })?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| CliError::General(format!("无法创建临时状态文件：{error}")))?;
    serde_json::to_writer_pretty(&mut temporary, value)
        .map_err(|error| CliError::General(format!("无法序列化状态：{error}")))?;
    temporary
        .write_all(b"\n")
        .map_err(|error| CliError::General(format!("无法写入状态文件：{error}")))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| CliError::General(format!("无法同步状态文件：{error}")))?;
    temporary.persist(path).map_err(|error| {
        CliError::General(format!(
            "无法原子替换状态文件 {}：{}",
            path.display(),
            error.error
        ))
    })?;
    Ok(())
}
