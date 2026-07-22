use std::fs::File;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::Result;

#[must_use]
pub fn sha256_bytes(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(bytes.as_ref()))
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

#[must_use]
pub fn constant_time_sha256_eq(left: &str, right: &str) -> bool {
    let Ok(left_bytes) = hex::decode(left) else {
        return false;
    };
    let Ok(right_bytes) = hex::decode(right) else {
        return false;
    };
    left_bytes.len() == 32 && right_bytes.len() == 32 && bool::from(left_bytes.ct_eq(&right_bytes))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn hashes_bytes_and_files() {
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(sha256_bytes(b"abc"), expected);

        let mut file = tempfile::NamedTempFile::new().expect("应可创建临时文件");
        file.write_all(b"abc").expect("应可写入临时文件");
        assert_eq!(
            sha256_file(file.path()).expect("应可计算文件哈希"),
            expected
        );
    }

    #[test]
    fn compares_only_valid_sha256_in_constant_time() {
        let hash = sha256_bytes(b"mindone");
        assert!(constant_time_sha256_eq(&hash, &hash));
        assert!(!constant_time_sha256_eq(&hash, &sha256_bytes(b"other")));
        assert!(!constant_time_sha256_eq("not-hex", "not-hex"));
        assert!(!constant_time_sha256_eq("00", "00"));
    }
}
