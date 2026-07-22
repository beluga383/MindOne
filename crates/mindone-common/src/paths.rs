use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::error::{MindOneError, Result};

/// MindOne 所有本地状态的绝对路径集合。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MindOnePaths {
    pub home: PathBuf,
    pub config: PathBuf,
    pub models: PathBuf,
    pub engines: PathBuf,
    pub runtime: PathBuf,
    pub logs: PathBuf,
    pub cache: PathBuf,
}

impl MindOnePaths {
    /// 优先使用 `MINDONE_HOME`，否则使用当前平台的用户数据目录。
    pub fn discover() -> Result<Self> {
        if let Some(value) = env::var_os("MINDONE_HOME") {
            if value.is_empty() {
                return Err(MindOneError::Config(
                    "MINDONE_HOME 不能为空；请删除该变量或设置绝对路径".to_owned(),
                ));
            }
            return Self::from_home(PathBuf::from(value));
        }

        Self::from_home(default_home()?)
    }

    pub fn from_home(home: impl Into<PathBuf>) -> Result<Self> {
        let home = home.into();
        validate_data_home_candidate(&home)?;

        Ok(Self {
            config: home.join("config.toml"),
            models: home.join("models"),
            engines: home.join("engines"),
            runtime: home.join("runtime"),
            logs: home.join("logs"),
            cache: home.join("cache"),
            home,
        })
    }

    /// 创建只包含 MindOne 自有数据的目录，不触碰任何外部路径。
    pub fn ensure_directories(&self) -> Result<()> {
        validate_data_home_candidate(&self.home)?;
        ensure_private_directory(&self.home, "MindOne 数据目录")?;
        for directory in [
            &self.models,
            &self.engines,
            &self.runtime,
            &self.logs,
            &self.cache,
        ] {
            ensure_private_directory(directory, "MindOne 受管子目录")?;
        }
        Ok(())
    }

    #[must_use]
    pub fn is_within_home(&self, path: &Path) -> bool {
        path.is_absolute()
            && !path
                .components()
                .any(|component| matches!(component, Component::ParentDir))
            && path.starts_with(&self.home)
    }

    /// 将不可信相对路径安全拼接到 MindOne 主目录，拒绝绝对路径和 `..`。
    pub fn secure_join(&self, relative: &Path) -> Result<PathBuf> {
        if relative.as_os_str().is_empty()
            || relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(MindOneError::Config(
                "相对路径为空、包含路径穿越或使用了绝对路径".to_owned(),
            ));
        }
        Ok(self.home.join(relative))
    }
}

/// 验证 MindOne 数据根目录的安全边界，但不创建或修改文件。
///
/// 路径来自环境变量或配置文件，不能只检查 `is_absolute`：根目录、HOME、系统宽泛
/// 目录以及任一现有 symlink/reparse 父链都会让后续创建、停止或卸载越过 MindOne
/// 所有权边界。
pub fn validate_data_home_candidate(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(MindOneError::Config(
            "MindOne 数据目录必须是绝对路径".to_owned(),
        ));
    }
    let text = path
        .to_str()
        .ok_or_else(|| MindOneError::Config("MindOne 数据目录必须是有效 UTF-8 路径".to_owned()))?;
    if text.is_empty() || text.chars().any(char::is_control) {
        return Err(MindOneError::Config(
            "MindOne 数据目录不能为空或包含控制字符".to_owned(),
        ));
    }
    if has_unnormalized_syntax(text)
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(MindOneError::Config(format!(
            "MindOne 数据目录包含重复分隔符、尾部分隔符或未规范化的 . / .. 路径组件：{}",
            path.display()
        )));
    }

    assert_no_reparse_points(path)?;
    reject_broad_data_home(path)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.is_dir() || is_reparse_point(&metadata) {
            return Err(MindOneError::Config(format!(
                "MindOne 数据路径不是普通目录：{}",
                path.display()
            )));
        }
    }

    #[cfg(windows)]
    validate_windows_private_location(path)?;
    Ok(())
}

#[cfg(unix)]
fn has_unnormalized_syntax(text: &str) -> bool {
    text.ends_with('/')
        || text.contains("//")
        || text
            .split('/')
            .any(|component| matches!(component, "." | ".."))
}

#[cfg(windows)]
fn has_unnormalized_syntax(text: &str) -> bool {
    text.ends_with('/')
        || text.ends_with('\\')
        || text.contains("//")
        || text.contains("\\\\")
        || text
            .split(['/', '\\'])
            .any(|component| matches!(component, "." | ".."))
}

#[cfg(not(any(unix, windows)))]
fn has_unnormalized_syntax(text: &str) -> bool {
    text.ends_with('/')
        || text.contains("//")
        || text
            .split('/')
            .any(|component| matches!(component, "." | ".."))
}

fn ensure_private_directory(path: &Path, label: &str) -> Result<()> {
    assert_no_reparse_points(path)?;
    match fs::create_dir_all(path) {
        Ok(()) => {}
        Err(error) => {
            return Err(MindOneError::Io(format!(
                "无法创建{label} {}：{error}",
                path.display()
            )));
        }
    }
    assert_no_reparse_points(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(MindOneError::Config(format!(
            "{label}不是普通目录：{}",
            path.display()
        )));
    }

    #[cfg(unix)]
    ensure_private_unix_permissions(path, &metadata, label)?;
    Ok(())
}

fn assert_no_reparse_points(path: &Path) -> Result<()> {
    for candidate in path.ancestors() {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) if is_reparse_point(&metadata) => {
                return Err(MindOneError::Config(format!(
                    "MindOne 数据目录或其现有父目录是符号链接/重解析点：{}",
                    candidate.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(MindOneError::Io(format!(
                    "无法检查 MindOne 数据目录父链 {}：{error}",
                    candidate.display()
                )));
            }
        }
    }
    Ok(())
}

fn reject_broad_data_home(path: &Path) -> Result<()> {
    let mut protected = system_protected_roots(path);
    if let Some(home) = env::var_os("HOME").filter(|value| !value.is_empty()) {
        let home = PathBuf::from(home);
        protected.push(home.clone());
        if let Some(parent) = home.parent() {
            protected.push(parent.to_path_buf());
        }
        protected.extend([
            home.join(".local"),
            home.join(".local/share"),
            home.join("Library"),
            home.join("Library/Application Support"),
        ]);
    }
    if let Some(root) = env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
        protected.push(PathBuf::from(root));
    }
    for variable in [
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
        "SystemRoot",
        "ProgramData",
        "ProgramFiles",
        "ProgramFiles(x86)",
    ] {
        if let Some(value) = env::var_os(variable).filter(|value| !value.is_empty()) {
            let value = PathBuf::from(value);
            if variable == "USERPROFILE" {
                if let Some(parent) = value.parent() {
                    protected.push(parent.to_path_buf());
                }
            }
            protected.push(value);
        }
    }
    if protected
        .iter()
        .any(|candidate| paths_equal(path, candidate))
    {
        return Err(MindOneError::Config(format!(
            "拒绝把 MindOne 数据目录设为根目录、HOME 或宽泛用户/系统目录：{}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn system_protected_roots(path: &Path) -> Vec<PathBuf> {
    let root = path
        .ancestors()
        .last()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"));
    [
        root,
        PathBuf::from("/bin"),
        PathBuf::from("/sbin"),
        PathBuf::from("/usr"),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/usr/sbin"),
        PathBuf::from("/usr/local"),
        PathBuf::from("/etc"),
        PathBuf::from("/var"),
        PathBuf::from("/var/tmp"),
        PathBuf::from("/tmp"),
        PathBuf::from("/private"),
        PathBuf::from("/private/tmp"),
        PathBuf::from("/opt"),
        PathBuf::from("/srv"),
        PathBuf::from("/Applications"),
        PathBuf::from("/Library"),
        PathBuf::from("/System"),
    ]
    .into_iter()
    .collect()
}

#[cfg(windows)]
fn system_protected_roots(path: &Path) -> Vec<PathBuf> {
    path.ancestors()
        .last()
        .map(Path::to_path_buf)
        .into_iter()
        .collect()
}

#[cfg(not(any(unix, windows)))]
fn system_protected_roots(path: &Path) -> Vec<PathBuf> {
    path.ancestors()
        .last()
        .map(Path::to_path_buf)
        .into_iter()
        .collect()
}

#[cfg(unix)]
fn ensure_private_unix_permissions(
    path: &Path,
    metadata: &fs::Metadata,
    label: &str,
) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let effective_uid = nix::unistd::Uid::effective().as_raw();
    if metadata.uid() != effective_uid {
        return Err(MindOneError::Config(format!(
            "{label}不属于当前用户，拒绝使用：{}",
            path.display()
        )));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        MindOneError::Io(format!(
            "无法把{label}权限收紧为 0700 {}：{error}",
            path.display()
        ))
    })?;
    let actual_mode = fs::symlink_metadata(path)?.permissions().mode() & 0o777;
    if actual_mode != 0o700 {
        return Err(MindOneError::Config(format!(
            "{label}权限不是 0700，拒绝继续：{}（实际 {:03o}）",
            path.display(),
            actual_mode
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_windows_private_location(path: &Path) -> Result<()> {
    let private_roots = [env::var_os("LOCALAPPDATA"), env::var_os("USERPROFILE")]
        .into_iter()
        .flatten()
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if private_roots.is_empty()
        || !private_roots
            .iter()
            .any(|root| path_starts_with(path, root))
    {
        return Err(MindOneError::Config(format!(
            "Windows 自定义数据目录必须位于当前用户的 LOCALAPPDATA 或 USERPROFILE 内，才能继承私有 ACL：{}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn path_starts_with(path: &Path, root: &Path) -> bool {
    let path = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    let root = root
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    path == root || path.starts_with(&format!("{root}\\"))
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        left.to_string_lossy()
            .replace('/', "\\")
            .eq_ignore_ascii_case(&right.to_string_lossy().replace('/', "\\"))
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(target_os = "macos")]
fn default_home() -> Result<PathBuf> {
    let user_home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| MindOneError::Config("无法确定用户 HOME 目录".to_owned()))?;
    Ok(PathBuf::from(user_home)
        .join("Library")
        .join("Application Support")
        .join("MindOne"))
}

#[cfg(target_os = "windows")]
fn default_home() -> Result<PathBuf> {
    let local_app_data = env::var_os("LOCALAPPDATA")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| MindOneError::Config("无法确定 LOCALAPPDATA 目录".to_owned()))?;
    Ok(PathBuf::from(local_app_data).join("MindOne"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn default_home() -> Result<PathBuf> {
    if let Some(xdg_data_home) = env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(xdg_data_home).join("mindone"));
    }
    let user_home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| MindOneError::Config("无法确定用户 HOME 目录".to_owned()))?;
    Ok(PathBuf::from(user_home)
        .join(".local")
        .join("share")
        .join("mindone"))
}

#[cfg(not(any(unix, target_os = "windows")))]
fn default_home() -> Result<PathBuf> {
    Err(MindOneError::Config(
        "当前平台无法自动确定 MindOne 数据目录，请设置 MINDONE_HOME".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_all_paths_from_explicit_home() {
        let home = env::current_dir()
            .expect("应读取当前目录")
            .join("target/mindone-path-layout-test");
        let paths = MindOnePaths::from_home(&home).expect("受控绝对目录应有效");
        assert_eq!(paths.config, home.join("config.toml"));
        assert_eq!(paths.models, home.join("models"));
        assert!(paths.is_within_home(&paths.runtime.join("serve.json")));
        assert!(!paths.is_within_home(&home.with_file_name("outside")));
        assert!(!paths.is_within_home(&home.join("../outside")));
        assert_eq!(
            paths
                .secure_join(Path::new("models/safe.gguf"))
                .expect("安全相对路径应通过"),
            home.join("models/safe.gguf")
        );
        assert!(paths.secure_join(Path::new("../outside")).is_err());
    }

    #[test]
    fn rejects_relative_home() {
        let result = MindOnePaths::from_home("relative/mindone");
        assert!(matches!(result, Err(MindOneError::Config(_))));
    }

    #[test]
    fn rejects_lexically_unnormalized_absolute_home() {
        let base = env::current_dir().expect("应读取当前目录");
        let with_dot = format!("{}/target/./mindone-data", base.display());
        let repeated_separator = format!("{}//target/mindone-data", base.display());
        let trailing_separator = format!("{}/target/mindone-data/", base.display());
        assert!(MindOnePaths::from_home(with_dot).is_err());
        assert!(MindOnePaths::from_home(repeated_separator).is_err());
        assert!(MindOnePaths::from_home(trailing_separator).is_err());
    }

    #[test]
    fn creates_owned_directories() {
        let current = env::current_dir().expect("应读取当前目录");
        let temporary = tempfile::tempdir_in(current).expect("应可创建受控临时目录");
        let home = temporary.path().join("mindone");
        let paths = MindOnePaths::from_home(home).expect("临时路径是绝对路径");
        paths.ensure_directories().expect("应可创建目录");
        assert!(paths.models.is_dir());
        assert!(paths.engines.is_dir());
        assert!(paths.runtime.is_dir());
        assert!(paths.logs.is_dir());
        assert!(paths.cache.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&paths.home)
                    .expect("应读取数据目录元数据")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&paths.runtime)
                    .expect("应读取运行目录元数据")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn rejects_root_home_and_broad_system_directories() {
        let root = env::current_dir()
            .expect("应读取当前目录")
            .ancestors()
            .last()
            .expect("绝对路径应有根目录")
            .to_path_buf();
        assert!(MindOnePaths::from_home(root).is_err());

        if let Some(home) = env::var_os("HOME").filter(|value| !value.is_empty()) {
            assert!(MindOnePaths::from_home(PathBuf::from(home)).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_anywhere_in_existing_parent_chain() {
        use std::os::unix::fs::symlink;

        let current = env::current_dir().expect("应读取当前目录");
        let temporary = tempfile::tempdir_in(current).expect("应创建受控临时目录");
        let real = temporary.path().join("real");
        fs::create_dir(&real).expect("应创建真实目录");
        let link = temporary.path().join("link");
        symlink(&real, &link).expect("应创建符号链接");

        let error = MindOnePaths::from_home(link.join("data")).expect_err("符号链接父链必须拒绝");
        assert!(error.to_string().contains("符号链接"));
    }
}
