use std::{process::ExitStatus, time::Duration};

use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Child,
    time::timeout,
};

#[derive(Debug, Error)]
pub(crate) enum BoundedProcessError {
    #[error("子进程 I/O 失败")]
    Io,
    #[error("子进程超时")]
    Timeout,
    #[error("子进程输出超过限制")]
    OutputTooLarge,
}

pub(crate) struct BoundedOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
}

pub(crate) async fn communicate(
    child: &mut Child,
    input: &[u8],
    deadline: Duration,
    maximum_stdout: usize,
) -> Result<BoundedOutput, BoundedProcessError> {
    let mut stdin = child.stdin.take().ok_or(BoundedProcessError::Io)?;
    let stdout = child.stdout.take().ok_or(BoundedProcessError::Io)?;
    let operation = async {
        stdin
            .write_all(input)
            .await
            .map_err(|_| BoundedProcessError::Io)?;
        stdin
            .shutdown()
            .await
            .map_err(|_| BoundedProcessError::Io)?;
        drop(stdin);

        let mut stdout = stdout.take(maximum_stdout.saturating_add(1) as u64);
        let mut bytes = Vec::with_capacity(maximum_stdout.min(64 * 1024));
        let first = {
            let read = stdout.read_to_end(&mut bytes);
            let wait = child.wait();
            tokio::pin!(read);
            tokio::pin!(wait);
            tokio::select! {
                read_result = &mut read => {
                    read_result.map_err(|_| BoundedProcessError::Io)?;
                    None
                }
                status = &mut wait => Some(status.map_err(|_| BoundedProcessError::Io)?),
            }
        };
        if bytes.len() > maximum_stdout {
            return Err(BoundedProcessError::OutputTooLarge);
        }
        let status = if let Some(status) = first {
            stdout
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| BoundedProcessError::Io)?;
            if bytes.len() > maximum_stdout {
                return Err(BoundedProcessError::OutputTooLarge);
            }
            status
        } else {
            child.wait().await.map_err(|_| BoundedProcessError::Io)?
        };
        Ok(BoundedOutput {
            status,
            stdout: bytes,
        })
    };
    let result = timeout(deadline, operation).await;
    match result {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(error)) => {
            terminate(child).await;
            Err(error)
        }
        Err(_) => {
            terminate(child).await;
            Err(BoundedProcessError::Timeout)
        }
    }
}

async fn terminate(child: &mut Child) {
    let _ = child.start_kill();
    let _ = timeout(Duration::from_secs(2), child.wait()).await;
}

#[cfg(all(test, unix))]
mod tests {
    use std::process::Stdio;

    use super::*;
    use tokio::process::Command;

    #[tokio::test]
    async fn infinite_stdout_is_cut_off_and_process_is_terminated() {
        let mut command = Command::new("/usr/bin/yes");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn().expect("测试 yes 应可启动");
        let result = communicate(&mut child, b"", Duration::from_secs(2), 1_024).await;
        assert!(matches!(result, Err(BoundedProcessError::OutputTooLarge)));
        assert!(child.try_wait().expect("应可读取子进程状态").is_some());
    }
}
