use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use thiserror::Error;

const READ_BUFFER_BYTES: usize = 64 * 1024;

/// 已通过路径、文件身份和读取后复核的有界文件内容。
pub struct BoundedFileContents {
    bytes: Vec<u8>,
    metadata: Metadata,
}

impl BoundedFileContents {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    #[must_use]
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}

/// 已通过路径、文件身份和读取后复核的有界文件 SHA-256。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedFileDigest {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Error)]
pub enum BoundedFileError {
    #[error("路径必须使用规范绝对路径，且父链不得包含符号链接")]
    NonCanonicalPath,
    #[error("文件不存在或不可访问")]
    Unavailable(#[source] io::Error),
    #[error("路径必须指向非符号链接普通文件")]
    NotRegularFile,
    #[error("文件超过 {maximum_bytes} 字节安全上限")]
    TooLarge { maximum_bytes: u64 },
    #[error("无法安全打开文件")]
    Open(#[source] io::Error),
    #[error("读取文件失败")]
    Read(#[source] io::Error),
    #[error("文件大小超出平台范围或发生溢出")]
    SizeOverflow,
    #[error("无法为文件内容分配有界内存")]
    Allocation,
    #[error("文件或其路径在读取期间发生变化")]
    ConcurrentModification,
}

/// 从规范绝对路径安全读取一个有界普通文件。
///
/// 最终路径通过 `O_NOFOLLOW`（Unix）打开；打开后的文件身份、大小和修改时间
/// 必须与预检一致。读取完成后还会同时复核打开句柄、当前路径与无符号链接父链。
pub fn read_bounded_regular_file(
    path: &Path,
    maximum_bytes: u64,
) -> Result<BoundedFileContents, BoundedFileError> {
    let mut opened = OpenedBoundedRegularFile::open(path, maximum_bytes)?;
    let mut bytes = Vec::new();
    let total = opened.consume_chunks(|chunk| {
        bytes
            .try_reserve(chunk.len())
            .map_err(|_| BoundedFileError::Allocation)?;
        bytes.extend_from_slice(chunk);
        Ok(())
    })?;
    let metadata = opened.finish(total)?;
    Ok(BoundedFileContents { bytes, metadata })
}

/// 从规范绝对路径流式计算一个有界普通文件的 SHA-256。
///
/// 此函数不会按文件大小分配内存，并执行与 [`read_bounded_regular_file`] 相同的
/// 文件身份和读取期间替换检测。
pub fn sha256_bounded_regular_file(
    path: &Path,
    maximum_bytes: u64,
) -> Result<BoundedFileDigest, BoundedFileError> {
    let mut opened = OpenedBoundedRegularFile::open(path, maximum_bytes)?;
    let mut digest = Sha256::new();
    let total = opened.consume_chunks(|chunk| {
        digest.update(chunk);
        Ok(())
    })?;
    opened.finish(total)?;
    Ok(BoundedFileDigest {
        sha256: hex::encode(digest.finalize()),
        size_bytes: total,
    })
}

struct OpenedBoundedRegularFile {
    path: PathBuf,
    canonical_path: PathBuf,
    before: Metadata,
    opened: Metadata,
    maximum_bytes: u64,
    file: File,
}

impl OpenedBoundedRegularFile {
    fn open(path: &Path, maximum_bytes: u64) -> Result<Self, BoundedFileError> {
        if !path.is_absolute() {
            return Err(BoundedFileError::NonCanonicalPath);
        }

        let before = fs::symlink_metadata(path).map_err(BoundedFileError::Unavailable)?;
        if before.file_type().is_symlink() || !before.is_file() {
            return Err(BoundedFileError::NotRegularFile);
        }
        if before.len() > maximum_bytes {
            return Err(BoundedFileError::TooLarge { maximum_bytes });
        }

        let canonical_path = fs::canonicalize(path).map_err(BoundedFileError::Unavailable)?;
        if canonical_path != path || !parent_chain_is_directories_without_symlinks(path)? {
            return Err(BoundedFileError::NonCanonicalPath);
        }

        let file = open_no_follow(path).map_err(BoundedFileError::Open)?;
        let opened = file.metadata().map_err(BoundedFileError::Open)?;
        if !opened.is_file() || !metadata_snapshot_unchanged(&before, &opened) {
            return Err(BoundedFileError::ConcurrentModification);
        }

        Ok(Self {
            path: path.to_path_buf(),
            canonical_path,
            before,
            opened,
            maximum_bytes,
            file,
        })
    }

    fn consume_chunks<F>(&mut self, mut consume: F) -> Result<u64, BoundedFileError>
    where
        F: FnMut(&[u8]) -> Result<(), BoundedFileError>,
    {
        let mut buffer = [0_u8; READ_BUFFER_BYTES];
        let mut total = 0_u64;
        loop {
            let read_bytes = match self.file.read(&mut buffer) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(BoundedFileError::Read(error)),
            };
            if read_bytes == 0 {
                break;
            }
            let read = u64::try_from(read_bytes).map_err(|_| BoundedFileError::SizeOverflow)?;
            total = total
                .checked_add(read)
                .ok_or(BoundedFileError::SizeOverflow)?;
            if total > self.maximum_bytes {
                return Err(BoundedFileError::TooLarge {
                    maximum_bytes: self.maximum_bytes,
                });
            }
            consume(&buffer[..read_bytes])?;
        }
        Ok(total)
    }

    fn finish(self, total: u64) -> Result<Metadata, BoundedFileError> {
        let after = self
            .file
            .metadata()
            .map_err(|_| BoundedFileError::ConcurrentModification)?;
        if total != self.before.len()
            || !metadata_snapshot_unchanged(&self.opened, &after)
            || !path_still_names_opened_file(&self.path, &self.canonical_path, &after)
        {
            return Err(BoundedFileError::ConcurrentModification);
        }
        Ok(after)
    }
}

fn open_no_follow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        // O_NONBLOCK prevents a pre-open replacement with a FIFO/device from blocking the
        // operator process; the opened metadata check still rejects every non-regular file.
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    options.open(path)
}

fn parent_chain_is_directories_without_symlinks(path: &Path) -> Result<bool, BoundedFileError> {
    let parent = path.parent().ok_or(BoundedFileError::NonCanonicalPath)?;
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(BoundedFileError::Unavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn path_still_names_opened_file(path: &Path, canonical: &Path, opened: &Metadata) -> bool {
    let Ok(path_metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return false;
    }
    let Ok(canonical_after) = fs::canonicalize(path) else {
        return false;
    };
    if canonical_after != canonical || canonical_after != path {
        return false;
    }
    if !matches!(parent_chain_is_directories_without_symlinks(path), Ok(true)) {
        return false;
    }
    metadata_snapshot_unchanged(opened, &path_metadata)
}

#[cfg(unix)]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

fn metadata_snapshot_unchanged(before: &Metadata, after: &Metadata) -> bool {
    if !same_file_identity(before, after)
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || before.permissions().readonly() != after.permissions().readonly()
    {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
            && before.mode() == after.mode()
            && before.uid() == after.uid()
            && before.gid() == after.gid()
            && before.nlink() == after.nlink()
    }
    #[cfg(not(unix))]
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_tempdir() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("应创建测试目录");
        let canonical = fs::canonicalize(directory.path()).expect("测试目录应可规范化");
        (directory, canonical)
    }

    #[test]
    fn reads_and_hashes_only_within_the_bound() {
        let (_guard, directory) = canonical_tempdir();
        let path = directory.join("evidence.bin");
        fs::write(&path, b"abc").expect("应写入测试文件");

        let contents = read_bounded_regular_file(&path, 3).expect("有界普通文件应可读取");
        assert_eq!(contents.as_bytes(), b"abc");
        assert_eq!(contents.metadata().len(), 3);
        assert_eq!(
            sha256_bounded_regular_file(&path, 3).expect("有界普通文件应可哈希"),
            BoundedFileDigest {
                sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                    .to_owned(),
                size_bytes: 3,
            }
        );
        assert!(matches!(
            read_bounded_regular_file(&path, 2),
            Err(BoundedFileError::TooLarge { maximum_bytes: 2 })
        ));
        assert!(matches!(
            read_bounded_regular_file(Path::new("relative.bin"), 3),
            Err(BoundedFileError::NonCanonicalPath)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_final_and_parent_symlinks() {
        use std::os::unix::fs::symlink;

        let (_guard, directory) = canonical_tempdir();
        let real_directory = directory.join("real");
        fs::create_dir(&real_directory).expect("应创建真实目录");
        let real_file = real_directory.join("evidence.bin");
        fs::write(&real_file, b"evidence").expect("应写入真实文件");

        let final_link = directory.join("final-link.bin");
        symlink(&real_file, &final_link).expect("应创建文件符号链接");
        assert!(matches!(
            read_bounded_regular_file(&final_link, 64),
            Err(BoundedFileError::NotRegularFile)
        ));

        let parent_link = directory.join("parent-link");
        symlink(&real_directory, &parent_link).expect("应创建父目录符号链接");
        assert!(matches!(
            sha256_bounded_regular_file(&parent_link.join("evidence.bin"), 64),
            Err(BoundedFileError::NonCanonicalPath)
        ));
    }

    #[test]
    fn rejects_same_size_path_swap_after_open() {
        let (_guard, directory) = canonical_tempdir();
        let path = directory.join("artifact.bin");
        let displaced = directory.join("artifact.original.bin");
        fs::write(&path, b"original").expect("应写入原文件");

        let mut opened = OpenedBoundedRegularFile::open(&path, 64).expect("应安全打开原文件");
        fs::rename(&path, &displaced).expect("应移走原路径");
        fs::write(&path, b"replaced").expect("应在原路径放入同大小替换文件");

        let total = opened
            .consume_chunks(|_| Ok(()))
            .expect("已打开的原文件仍应可读取");
        assert!(matches!(
            opened.finish(total),
            Err(BoundedFileError::ConcurrentModification)
        ));
    }
}
