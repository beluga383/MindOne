use std::env;
use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use clap::error::ErrorKind;
use clap::FromArgMatches;
use mindone_cli::{execute, tui, Cli, CliError, OutputMode};

/// 图形界面的启动意图。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UiLaunch {
    /// 不启动图形界面，按正常命令行流程处理。
    No,
    /// 裸调用 `mindone`（无任何参数）：仅在交互式终端下启动图形界面。
    Bare,
    /// 显式 `mindone ui`：请求图形界面；非终端时返回明确错误。
    Explicit,
    /// 显示终端图形界面的中文帮助，不进入 raw 模式。
    Help,
    /// 显示版本；与 CLI 的全局版本保持同源。
    Version,
}

/// 根据参数判断是否启动图形界面。纯函数，便于测试；不检查 TTY（交给调用方）。
///
/// - 只有程序名 → `Bare`
/// - 恰好 `ui` 一个参数 → `Explicit`
/// - 其余（含带全局旗标或子命令）→ `No`，交给 clap 正常解析
fn ui_launch_from_args(arguments: &[OsString]) -> UiLaunch {
    match arguments.len() {
        1 => UiLaunch::Bare,
        2 if arguments[1] == "ui" => UiLaunch::Explicit,
        3 if arguments[1] == "ui" && (arguments[2] == "--help" || arguments[2] == "-h") => {
            UiLaunch::Help
        }
        3 if arguments[1] == "ui" && (arguments[2] == "--version" || arguments[2] == "-V") => {
            UiLaunch::Version
        }
        _ => UiLaunch::No,
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let arguments: Vec<OsString> = env::args_os().collect();

    // 裸 `mindone`（交互式终端）或显式 `mindone ui` 启动终端图形界面。
    match ui_launch_from_args(&arguments) {
        UiLaunch::Bare if tui::stdout_is_interactive() => return run_tui().await,
        UiLaunch::Bare => return write_cli_help(),
        UiLaunch::Explicit => return run_tui().await,
        UiLaunch::Help => return write_tui_help(),
        UiLaunch::Version => return write_tui_version(),
        UiLaunch::No => {}
    }

    let json_requested = arguments.iter().any(|argument| argument == "--json");
    let mut command = Cli::localized_command();
    let matches = match command.try_get_matches_from_mut(&arguments) {
        Ok(matches) => matches,
        Err(error) => {
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp
                    | ErrorKind::DisplayVersion
                    | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            ) {
                let code = if error.use_stderr() { 1 } else { 0 };
                if let Err(print_error) = error.print() {
                    eprintln!("错误：无法显示命令帮助：{print_error}");
                    return ExitCode::from(1);
                }
                return ExitCode::from(code);
            }
            let parse_error = CliError::CliParse(localized_parse_error(error.kind()));
            return render_error_and_code(
                OutputMode {
                    json: json_requested,
                    quiet: false,
                    verbose: 0,
                },
                &parse_error,
            );
        }
    };
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(_) => {
            let parse_error = CliError::CliParse(
                "命令参数无法转换为内部结构；请使用 --help 检查命令格式".to_owned(),
            );
            return render_error_and_code(
                OutputMode {
                    json: json_requested,
                    quiet: false,
                    verbose: 0,
                },
                &parse_error,
            );
        }
    };
    initialize_tracing(cli.verbose);
    let fallback_mode = OutputMode {
        json: cli.json,
        quiet: cli.quiet,
        verbose: cli.verbose,
    };
    match execute(cli).await {
        Ok((mode, output)) => {
            let mut stdout = io::stdout().lock();
            if let Err(error) = mode.write_success(&output, &mut stdout) {
                let _ = writeln!(io::stderr().lock(), "错误：{error}");
                return ExitCode::from(1);
            }
            ExitCode::from(output.exit_code)
        }
        Err(error) => render_error_and_code(fallback_mode, &error),
    }
}

fn write_tui_help() -> ExitCode {
    let help = concat!(
        "mindone ",
        env!("CARGO_PKG_VERSION"),
        "\nMindOne 终端图形界面\n\n",
        "用法：mindone ui\n\n",
        "选项：\n",
        "  -h, --help       显示帮助\n",
        "  -V, --version    显示版本\n\n",
        "说明：\n",
        "  在交互式终端中打开 10 类、40 个公开命令的操作界面。\n",
        "  M 打开模型库，R 生成本机推荐，D 自动部署首选模型，? 显示帮助。\n",
        "  非交互式脚本请直接使用 `mindone <命令>`。\n",
    );
    write_stdout(help)
}

fn write_cli_help() -> ExitCode {
    let mut command = Cli::localized_command();
    write_stdout(&command.render_long_help().to_string())
}

fn write_tui_version() -> ExitCode {
    write_stdout(concat!("mindone ", env!("CARGO_PKG_VERSION"), "\n"))
}

fn write_stdout(content: &str) -> ExitCode {
    let mut stdout = io::stdout().lock();
    match stdout.write_all(content.as_bytes()) {
        Ok(()) => ExitCode::from(0),
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "错误：无法显示终端界面信息：{error}");
            ExitCode::from(1)
        }
    }
}

async fn run_tui() -> ExitCode {
    // 图形界面独占备用屏幕，tracing 输出会破坏画面；只保留错误级别。
    initialize_tracing(0);
    match tui::run().await {
        Ok(exit_code) => ExitCode::from(exit_code),
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "错误：{error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn localized_parse_error(kind: ErrorKind) -> String {
    let reason = match kind {
        ErrorKind::InvalidValue => "参数值不在允许范围内",
        ErrorKind::UnknownArgument => "存在无法识别的参数或命令",
        ErrorKind::InvalidSubcommand => "子命令无法识别",
        ErrorKind::NoEquals => "该选项要求使用等号赋值",
        ErrorKind::ValueValidation => "参数值未通过校验",
        ErrorKind::TooManyValues => "为参数提供了过多的值",
        ErrorKind::TooFewValues => "为参数提供的值不足",
        ErrorKind::WrongNumberOfValues => "参数值数量不正确",
        ErrorKind::ArgumentConflict => "使用了互相冲突的参数",
        ErrorKind::MissingRequiredArgument => "缺少必需参数",
        ErrorKind::MissingSubcommand => "缺少必需子命令",
        ErrorKind::InvalidUtf8 => "参数包含无效 UTF-8 文本",
        ErrorKind::Io => "读写命令输入输出时失败",
        ErrorKind::Format => "生成命令诊断信息时失败",
        ErrorKind::DisplayHelp
        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        | ErrorKind::DisplayVersion => "需要显示帮助或版本",
        _ => "命令参数无效",
    };
    format!("{reason}；请使用 --help 查看完整中文用法")
}

fn initialize_tracing(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(level)
        .with_target(false)
        .with_writer(io::stderr)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

fn render_error_and_code(mode: OutputMode, error: &CliError) -> ExitCode {
    let mut stderr = io::stderr().lock();
    if let Err(output_error) = mode.write_error(error, &mut stderr) {
        let _ = writeln!(stderr, "错误：{output_error}");
    }
    ExitCode::from(error.exit_code())
}

#[cfg(test)]
mod tests {
    use super::{ui_launch_from_args, UiLaunch};
    use std::ffi::OsString;

    fn args(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    #[test]
    fn bare_invocation_requests_ui() {
        assert_eq!(ui_launch_from_args(&args(&["mindone"])), UiLaunch::Bare);
    }

    #[test]
    fn explicit_ui_subcommand_requests_ui() {
        assert_eq!(
            ui_launch_from_args(&args(&["mindone", "ui"])),
            UiLaunch::Explicit
        );
    }

    #[test]
    fn explicit_ui_help_and_version_do_not_enter_raw_mode() {
        assert_eq!(
            ui_launch_from_args(&args(&["mindone", "ui", "--help"])),
            UiLaunch::Help
        );
        assert_eq!(
            ui_launch_from_args(&args(&["mindone", "ui", "-h"])),
            UiLaunch::Help
        );
        assert_eq!(
            ui_launch_from_args(&args(&["mindone", "ui", "--version"])),
            UiLaunch::Version
        );
        assert_eq!(
            ui_launch_from_args(&args(&["mindone", "ui", "-V"])),
            UiLaunch::Version
        );
    }

    #[test]
    fn subcommands_and_flags_never_launch_ui() {
        assert_eq!(
            ui_launch_from_args(&args(&["mindone", "doctor"])),
            UiLaunch::No
        );
        assert_eq!(
            ui_launch_from_args(&args(&["mindone", "--json"])),
            UiLaunch::No,
            "带全局旗标但无子命令时交给 clap（显示帮助），不进入 UI"
        );
        assert_eq!(
            ui_launch_from_args(&args(&["mindone", "ui", "extra"])),
            UiLaunch::No
        );
        assert_eq!(
            ui_launch_from_args(&args(&["mindone", "auth", "status"])),
            UiLaunch::No
        );
    }
}
