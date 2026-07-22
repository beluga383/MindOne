use std::io::Write;

use serde::Serialize;
use serde_json::Value;

use crate::error::{CliError, CliResult, ErrorEnvelope};

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub human: String,
    pub data: Value,
    pub exit_code: u8,
}

impl CommandOutput {
    pub fn new<T: Serialize>(human: impl Into<String>, data: T) -> CliResult<Self> {
        let data = serde_json::to_value(data)
            .map_err(|error| CliError::General(format!("无法序列化命令结果：{error}")))?;
        Ok(Self {
            human: human.into(),
            data,
            exit_code: 0,
        })
    }

    pub const fn with_exit_code(mut self, exit_code: u8) -> Self {
        self.exit_code = exit_code;
        self
    }

    pub fn message(message: impl Into<String>) -> CliResult<Self> {
        let message = message.into();
        Self::new(message.clone(), serde_json::json!({ "message": message }))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct OutputMode {
    pub json: bool,
    pub quiet: bool,
    pub verbose: u8,
}

impl OutputMode {
    pub fn write_success(self, output: &CommandOutput, writer: &mut dyn Write) -> CliResult<()> {
        if self.json {
            let envelope = serde_json::json!({
                "ok": output.exit_code == 0,
                "code": output.exit_code,
                "data": output.data,
            });
            write_json_line(writer, &envelope)
        } else if self.quiet {
            Ok(())
        } else {
            writeln!(writer, "{}", output.human)
                .map_err(|error| CliError::General(format!("无法写入命令输出：{error}")))
        }
    }

    pub fn write_error(self, error: &CliError, writer: &mut dyn Write) -> CliResult<()> {
        if self.json {
            write_json_line(writer, &ErrorEnvelope::from(error))
        } else {
            writeln!(writer, "错误：{error}").map_err(|write_error| {
                CliError::General(format!("无法写入错误输出：{write_error}"))
            })
        }
    }
}

fn write_json_line<T: Serialize>(writer: &mut dyn Write, value: &T) -> CliResult<()> {
    serde_json::to_writer(&mut *writer, value)
        .map_err(|error| CliError::General(format!("无法生成 JSON 输出：{error}")))?;
    writeln!(writer).map_err(|error| CliError::General(format!("无法写入 JSON 输出：{error}")))
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{CommandOutput, OutputMode};
    use crate::error::CliError;

    #[test]
    fn json_error_has_stable_contract() {
        let mode = OutputMode {
            json: true,
            quiet: false,
            verbose: 0,
        };
        let mut bytes = Vec::new();
        mode.write_error(
            &CliError::ModelValidation("检测到不安全的模型格式".to_owned()),
            &mut bytes,
        )
        .expect("JSON 错误应可写入");
        let parsed: Value = serde_json::from_slice(&bytes).expect("应为合法 JSON");
        assert_eq!(parsed["ok"], false);
        assert_eq!(parsed["code"], 21);
        assert_eq!(parsed["error"]["type"], "model_validation_failed");
        assert_eq!(parsed["error"]["message"], "检测到不安全的模型格式");
    }

    #[test]
    fn quiet_suppresses_success_but_not_error() {
        let mode = OutputMode {
            json: false,
            quiet: true,
            verbose: 0,
        };
        let output = CommandOutput::message("成功").expect("应创建输出");
        let mut bytes = Vec::new();
        mode.write_success(&output, &mut bytes)
            .expect("应写入成功输出");
        assert!(bytes.is_empty());
        mode.write_error(&CliError::General("失败".to_owned()), &mut bytes)
            .expect("应写入错误输出");
        assert!(!bytes.is_empty());
    }

    #[test]
    fn trust_downgrade_json_is_not_ok_and_preserves_complete_data() {
        let mode = OutputMode {
            json: true,
            quiet: false,
            verbose: 0,
        };
        let output = CommandOutput::new(
            "[警告] 沙盒能力：实际最高信任为 StandardLimited",
            serde_json::json!({
                "checks": [{
                    "name": "沙盒能力",
                    "status": "warning",
                    "message": "实际最高信任为 StandardLimited",
                }],
                "summary": {
                    "passed": 10,
                    "warnings": 1,
                    "failures": 0,
                    "trust_downgrades": 1,
                },
            }),
        )
        .expect("应创建降级输出")
        .with_exit_code(31);
        let mut bytes = Vec::new();
        mode.write_success(&output, &mut bytes)
            .expect("应写入 JSON 降级输出");
        let parsed: Value = serde_json::from_slice(&bytes).expect("应为合法 JSON");
        assert_eq!(parsed["ok"], false);
        assert_eq!(parsed["code"], 31);
        assert_eq!(parsed["data"], output.data);
    }

    #[test]
    fn human_and_quiet_modes_only_control_rendering_not_exit_code() {
        let output = CommandOutput::message("信任等级已降级")
            .expect("应创建降级输出")
            .with_exit_code(31);

        let human_mode = OutputMode {
            json: false,
            quiet: false,
            verbose: 0,
        };
        let mut human_bytes = Vec::new();
        human_mode
            .write_success(&output, &mut human_bytes)
            .expect("人类可读输出应可写入");
        assert_eq!(String::from_utf8_lossy(&human_bytes), "信任等级已降级\n");

        let quiet_mode = OutputMode {
            json: false,
            quiet: true,
            verbose: 0,
        };
        let mut quiet_bytes = Vec::new();
        quiet_mode
            .write_success(&output, &mut quiet_bytes)
            .expect("静默模式应可处理降级输出");
        assert!(quiet_bytes.is_empty());
        assert_eq!(output.exit_code, 31);
    }
}
