use std::{error::Error, path::PathBuf, process::ExitCode, sync::Arc};

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use mindone_accounting::ReservePurpose;
use mindone_coordinator::{
    anti_abuse::{ControlledAsnResolver, LocalAsnResolver, NoAsnResolver},
    auth::build_provider,
    config::Config,
    db::{
        connect, migrate, prepare_private_evaluation_runtime, prepare_runtime,
        verify_runtime_schema,
    },
    operator_billing::{record_operator_billing_profile, OperatorBillingProfileRequest},
    operator_grant::{grant_operator_quota, OperatorQuotaGrantRequest},
    operator_quality::{record_operator_quality_evidence, OperatorQualityRecordRequest},
    operator_sla::{
        record_operator_sla_exclusion, OperatorSlaExclusionRequest, CONTENT_POLICY_REFUSAL,
        FORCE_MAJEURE,
    },
    router, run_hidden_expiry_sweeper,
    settlement::{release_reserve, ReserveReleaseCommand},
    AppState,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::{net::TcpListener, sync::watch};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const HELP_TEMPLATE: &str = "{before-help}{name} {version}\n{about-with-newline}\n\
用法：{usage}\n\n{all-args}{after-help}";

#[derive(Debug, Parser)]
#[command(
    name = "mindone-coordinator",
    version,
    about = "MindOne 协调服务器与受控运维命令",
    help_template = HELP_TEMPLATE,
    disable_help_subcommand = true,
    subcommand_help_heading = "命令",
    next_help_heading = "选项"
)]
struct CommandLine {
    #[command(subcommand)]
    command: Option<CoordinatorCommand>,
}

impl CommandLine {
    fn localized_command() -> clap::Command {
        let mut command = <Self as CommandFactory>::command();
        command.build();
        localize_command(command)
    }
}

fn localize_command(command: clap::Command) -> clap::Command {
    command
        .help_template(HELP_TEMPLATE)
        .subcommand_help_heading("命令")
        .subcommand_value_name("命令")
        .next_help_heading("选项")
        .mut_args(|argument| {
            let is_positional = argument.get_index().is_some();
            let argument_id = argument.get_id().as_str().to_owned();
            let argument = argument
                .help_heading(if is_positional { "参数" } else { "选项" })
                .hide_default_value(true)
                .hide_env_values(true);
            match argument_id.as_str() {
                "help" => argument.help("显示帮助").long_help("显示完整帮助"),
                "version" => argument.help("显示版本").long_help("显示版本"),
                _ => argument,
            }
        })
        .mut_subcommands(localize_command)
}

#[derive(Debug, Subcommand)]
enum CoordinatorCommand {
    /// 复用服务器启动合同校验配置；可显式连接依赖但不迁移、不发信
    #[command(name = "config-check")]
    ConfigCheck(ConfigCheckArgs),
    /// 使用数据库 owner 连接完整应用结构迁移与 Standard 旧数据升级
    #[command(name = "database-migrate")]
    DatabaseMigrate,
    /// 通过服务器数据库事务向既有用户追加一笔可审计额度
    #[command(name = "quota-grant")]
    QuotaGrant(QuotaGrantArgs),
    /// 验证受信 evaluator 的签名 evidence 并原子更新模型质量与 Tier
    #[command(name = "quality-record")]
    QualityRecord(QualityRecordArgs),
    /// 从本地证据原子发布一个不可变、可审计的物理计费 profile
    #[command(name = "billing-profile-record")]
    BillingProfileRecord(BillingProfileRecordArgs),
    /// 从网络准备金执行一笔有 operator 归属且只追加审计的释放
    #[command(name = "reserve-release")]
    ReserveRelease(ReserveReleaseArgs),
    /// 依据独立本地证据为终态任务记录一个只追加 SLA 排除决定
    #[command(name = "sla-exclusion-record")]
    SlaExclusionRecord(SlaExclusionRecordArgs),
}

#[derive(Debug, Args)]
struct ConfigCheckArgs {
    /// 显式连接数据库并逐项比对 schema；邮箱模式同时建立一次不发信的 SMTP 会话
    #[arg(long)]
    live: bool,
}

#[derive(Debug, Args)]
struct QuotaGrantArgs {
    /// 已存在的生产用户 UUID
    #[arg(long, value_name = "UUID")]
    user_id: Uuid,
    /// 正整数 microquota，单笔不超过 1000000000000
    #[arg(long, value_name = "MICRO")]
    amount_micro: i64,
    /// 全局唯一、可安全重试的 ASCII 幂等键
    #[arg(long, value_name = "KEY")]
    idempotency_key: String,
    /// 可审计的 ASCII 运维者标识
    #[arg(long, value_name = "ID")]
    operator: String,
    /// 8 到 512 个字符的业务理由
    #[arg(long, value_name = "TEXT")]
    reason: String,
}

#[derive(Debug, Args)]
struct QualityRecordArgs {
    /// 受信 evaluator 生成的签名 JSON manifest，必须是规范绝对普通文件
    #[arg(long, value_name = "FILE")]
    evidence_file: PathBuf,
    /// manifest 中 artifact_sha256 对应的原始评价证据文件
    #[arg(long, value_name = "FILE")]
    artifact_file: PathBuf,
    /// 可审计的 ASCII 运维者标识
    #[arg(long, value_name = "ID")]
    operator: String,
    /// 8 到 512 个字符的业务理由
    #[arg(long, value_name = "TEXT")]
    reason: String,
}

#[derive(Debug, Args)]
struct BillingProfileRecordArgs {
    /// 已存在的规范模型 UUID
    #[arg(long, value_name = "UUID")]
    model_id: Uuid,
    /// 该模型尚未使用的正整数 profile version
    #[arg(long, value_name = "N")]
    profile_version: i64,
    /// 生成参考上界的稳定硬件类别
    #[arg(long, value_name = "CLASS")]
    reference_hardware_class: String,
    /// 允许授权的最大输入 token
    #[arg(long, value_name = "TOKENS")]
    maximum_input_tokens: i64,
    /// 允许授权的最大输出 token
    #[arg(long, value_name = "TOKENS")]
    maximum_output_tokens: i64,
    /// 每个请求固定参考 GPU 时间，单位微秒
    #[arg(long, value_name = "MICROSECONDS")]
    fixed_gpu_time_us: i64,
    /// 每 1,000 个授权 token 增加的参考 GPU 微秒
    #[arg(long, value_name = "MICROSECONDS")]
    gpu_time_us_per_1k_tokens: i64,
    /// 参考显存，单位 MiB
    #[arg(long, value_name = "MIB")]
    reference_vram_mib: i64,
    /// 每 1,000 个 token 的整数 microquota 费率
    #[arg(long, value_name = "MICRO")]
    token_rate_micro_per_1k: i64,
    /// 每参考 GPU 秒的整数 microquota 费率
    #[arg(long, value_name = "MICRO")]
    gpu_rate_micro_per_second: i64,
    /// 每参考 GiB 秒显存积分的整数 microquota 费率
    #[arg(long, value_name = "MICRO")]
    vram_rate_micro_per_gib_second: i64,
    /// 独立测量证据，必须是规范绝对普通文件；只持久化 SHA-256
    #[arg(long, value_name = "FILE")]
    evidence_file: PathBuf,
    /// profile 生效时间，RFC 3339，最多微秒精度
    #[arg(long, value_name = "RFC3339", value_parser = parse_rfc3339_microseconds)]
    valid_from: OffsetDateTime,
    /// profile 失效时间，RFC 3339，最多微秒精度
    #[arg(long, value_name = "RFC3339", value_parser = parse_rfc3339_microseconds)]
    valid_until: OffsetDateTime,
    /// 可审计的 ASCII 运维者标识
    #[arg(long, value_name = "ID")]
    operator: String,
    /// 8 到 512 个字符的业务理由
    #[arg(long, value_name = "TEXT")]
    reason: String,
    /// 全局唯一、可安全重试的 ASCII 幂等键
    #[arg(long, value_name = "KEY")]
    idempotency_key: String,
}

fn parse_rfc3339_microseconds(value: &str) -> Result<OffsetDateTime, String> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| "必须是有效的 RFC 3339 时间".to_owned())?;
    if parsed.nanosecond() % 1_000 != 0 {
        return Err("RFC 3339 时间最多允许微秒精度".to_owned());
    }
    Ok(parsed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ReservePurposeArg {
    ResultValidation,
    FailedRetry,
    BandwidthSubsidy,
    PeakGuarantee,
}

impl From<ReservePurposeArg> for ReservePurpose {
    fn from(value: ReservePurposeArg) -> Self {
        match value {
            ReservePurposeArg::ResultValidation => Self::ResultValidation,
            ReservePurposeArg::FailedRetry => Self::FailedRetry,
            ReservePurposeArg::BandwidthSubsidy => Self::BandwidthSubsidy,
            ReservePurposeArg::PeakGuarantee => Self::PeakGuarantee,
        }
    }
}

#[derive(Debug, Args)]
struct ReserveReleaseArgs {
    /// 允许的准备金用途
    #[arg(long, value_enum)]
    purpose: ReservePurposeArg,
    /// 正整数 microquota，单笔不超过 1000000000000
    #[arg(long, value_name = "MICRO")]
    amount_micro: i64,
    /// 对应验证、重算、带宽或高峰保障事件的审计引用
    #[arg(long, value_name = "ID")]
    reference: String,
    /// 全局唯一、可安全重试的 ASCII 幂等键
    #[arg(long, value_name = "KEY")]
    idempotency_key: String,
    /// 可审计的 ASCII 运维者标识
    #[arg(long, value_name = "ID")]
    operator: String,
    /// 8 到 512 个字符的业务理由
    #[arg(long, value_name = "TEXT")]
    reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SlaExclusionCategoryArg {
    ContentPolicyRefusal,
    ForceMajeure,
}

impl SlaExclusionCategoryArg {
    const fn as_contract_str(self) -> &'static str {
        match self {
            Self::ContentPolicyRefusal => CONTENT_POLICY_REFUSAL,
            Self::ForceMajeure => FORCE_MAJEURE,
        }
    }
}

#[derive(Debug, Args)]
struct SlaExclusionRecordArgs {
    /// 已经进入 failed 或 cancelled 终态的任务 UUID
    #[arg(long, value_name = "UUID")]
    job_id: Uuid,
    /// 审计类别，只允许 content-policy-refusal 或 force-majeure
    #[arg(long, value_enum)]
    category: SlaExclusionCategoryArg,
    /// 独立事件证据，必须是规范绝对普通文件；只持久化 SHA-256
    #[arg(long, value_name = "FILE")]
    evidence_file: PathBuf,
    /// 可审计的 ASCII 运维者标识
    #[arg(long, value_name = "ID")]
    operator: String,
    /// 8 到 512 个字符的业务理由
    #[arg(long, value_name = "TEXT")]
    reason: String,
    /// 全局唯一、可安全重试的 ASCII 幂等键
    #[arg(long, value_name = "KEY")]
    idempotency_key: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("错误：{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn Error + Send + Sync>> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("mindone_coordinator=info,tower_http=info,sqlx=warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_current_span(true)
        .with_span_list(false)
        .try_init()?;

    let matches = CommandLine::localized_command().get_matches();
    let command_line = CommandLine::from_arg_matches(&matches)?;
    let config = Config::from_env()?;
    match command_line.command {
        Some(CoordinatorCommand::ConfigCheck(args)) => {
            let smtp = if config.auth_provider
                == mindone_coordinator::config::AuthProviderKind::Email
            {
                let smtp = mindone_coordinator::email::SmtpConfig::from_env(config.environment)?;
                smtp.validate()?;
                Some(smtp)
            } else {
                None
            };
            if args.live {
                let pool = connect(&config).await.map_err(|_| {
                    std::io::Error::other(
                        "数据库连接检查失败；请核对地址、TLS、凭据与网络，DATABASE_URL 已隐去",
                    )
                })?;
                verify_runtime_schema(&pool).await?;
                pool.close().await;
                if let Some(smtp) = smtp {
                    tokio::task::spawn_blocking(move || smtp.test_connection())
                        .await
                        .map_err(|_| std::io::Error::other("SMTP 连接检查任务异常终止"))??;
                }
                println!("配置与依赖检查通过；数据库 schema 完全匹配，未迁移且未发送邮件");
            } else {
                println!("离线配置检查通过；未连接数据库、SMTP 或外部服务");
            }
            return Ok(());
        }
        Some(CoordinatorCommand::DatabaseMigrate) => {
            let pool = connect(&config).await?;
            migrate(&pool, &config.standard_data_key).await?;
            println!("数据库迁移已完成");
            return Ok(());
        }
        Some(CoordinatorCommand::QuotaGrant(args)) => {
            let pool = connect(&config).await?;
            prepare_runtime(&pool, &config.standard_data_key).await?;
            let result = grant_operator_quota(
                &pool,
                &OperatorQuotaGrantRequest {
                    user_id: args.user_id,
                    amount_micro: args.amount_micro,
                    idempotency_key: args.idempotency_key,
                    operator_id: args.operator,
                    reason: args.reason,
                },
            )
            .await?;
            println!("{}", serde_json::to_string(&result)?);
            return Ok(());
        }
        Some(CoordinatorCommand::QualityRecord(args)) => {
            let trusted_keys_dir = config.quality_evaluator_keys_dir.clone().ok_or_else(|| {
                std::io::Error::other("quality-record 要求配置 MINDONE_QUALITY_EVALUATOR_KEYS_DIR")
            })?;
            let pool = connect(&config).await?;
            prepare_runtime(&pool, &config.standard_data_key).await?;
            let result = record_operator_quality_evidence(
                &pool,
                &OperatorQualityRecordRequest {
                    evidence_path: args.evidence_file,
                    artifact_path: args.artifact_file,
                    trusted_keys_dir,
                    operator_id: args.operator,
                    reason: args.reason,
                },
            )
            .await?;
            println!("{}", serde_json::to_string(&result)?);
            return Ok(());
        }
        Some(CoordinatorCommand::BillingProfileRecord(args)) => {
            let pool = connect(&config).await?;
            prepare_runtime(&pool, &config.standard_data_key).await?;
            let result = record_operator_billing_profile(
                &pool,
                &OperatorBillingProfileRequest {
                    model_id: args.model_id,
                    profile_version: args.profile_version,
                    reference_hardware_class: args.reference_hardware_class,
                    maximum_input_tokens: args.maximum_input_tokens,
                    maximum_output_tokens: args.maximum_output_tokens,
                    fixed_gpu_time_us: args.fixed_gpu_time_us,
                    gpu_time_us_per_1k_tokens: args.gpu_time_us_per_1k_tokens,
                    reference_vram_mib: args.reference_vram_mib,
                    token_rate_micro_per_1k: args.token_rate_micro_per_1k,
                    gpu_rate_micro_per_second: args.gpu_rate_micro_per_second,
                    vram_rate_micro_per_gib_second: args.vram_rate_micro_per_gib_second,
                    evidence_path: args.evidence_file,
                    valid_from: args.valid_from,
                    valid_until: args.valid_until,
                    operator_id: args.operator,
                    reason: args.reason,
                    idempotency_key: args.idempotency_key,
                },
            )
            .await?;
            println!("{}", serde_json::to_string(&result)?);
            return Ok(());
        }
        Some(CoordinatorCommand::ReserveRelease(args)) => {
            let pool = connect(&config).await?;
            prepare_runtime(&pool, &config.standard_data_key).await?;
            let result = release_reserve(
                &pool,
                ReserveReleaseCommand {
                    purpose: args.purpose.into(),
                    amount_micro: args.amount_micro,
                    reference_id: args.reference,
                    idempotency_key: args.idempotency_key,
                    operator_id: args.operator,
                    reason: args.reason,
                },
            )
            .await?;
            println!("{}", serde_json::to_string(&result)?);
            return Ok(());
        }
        Some(CoordinatorCommand::SlaExclusionRecord(args)) => {
            let pool = connect(&config).await?;
            prepare_runtime(&pool, &config.standard_data_key).await?;
            let result = record_operator_sla_exclusion(
                &pool,
                &OperatorSlaExclusionRequest {
                    job_id: args.job_id,
                    category: args.category.as_contract_str().to_owned(),
                    evidence_path: args.evidence_file,
                    operator_id: args.operator,
                    reason: args.reason,
                    idempotency_key: args.idempotency_key,
                },
            )
            .await?;
            println!("{}", serde_json::to_string(&result)?);
            return Ok(());
        }
        None => {}
    }
    let bind_addr = config.bind_addr;
    let asn_resolver: Arc<dyn ControlledAsnResolver> = match config.asn_map_path.as_deref() {
        Some(path) => {
            let resolver = LocalAsnResolver::from_file(path)?;
            tracing::info!(
                asn_signal_available = true,
                asn_map_entries = resolver.entry_count(),
                "已加载部署方控制的本地 ASN 映射"
            );
            Arc::new(resolver)
        }
        None => {
            tracing::warn!(
                asn_signal_available = false,
                "未配置本地 ASN 映射，反滥用将明确降级为无 ASN 信号"
            );
            Arc::new(NoAsnResolver)
        }
    };
    let pool = connect(&config).await?;
    prepare_runtime(&pool, &config.standard_data_key).await?;
    let private_evaluation_security = prepare_private_evaluation_runtime(&pool, &config).await?;
    let provider = build_provider(&config, pool.clone())?;
    let state = AppState::new(pool, config, provider)
        .with_asn_resolver(asn_resolver)
        .with_private_evaluation_security(private_evaluation_security);
    let app = router(state.clone())?;
    let listener = TcpListener::bind(bind_addr).await?;
    let (sweeper_shutdown_sender, sweeper_shutdown_receiver) = watch::channel(false);
    let sweeper = tokio::spawn(run_hidden_expiry_sweeper(state, sweeper_shutdown_receiver));
    tracing::info!(address = %bind_addr, "MindOne 协调服务器已启动");
    let signal_shutdown_sender = sweeper_shutdown_sender.clone();
    let server_result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        let _ = signal_shutdown_sender.send(true);
    })
    .await;
    let _ = sweeper_shutdown_sender.send(true);
    let sweeper_result = sweeper.await;
    server_result?;
    sweeper_result?;
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let terminate = signal(SignalKind::terminate());
    let Ok(mut terminate) = terminate else {
        tracing::error!("无法监听 SIGTERM，退回 Ctrl-C 关闭");
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("MindOne 协调服务器正在关闭");
        return;
    };
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                tracing::error!(error = %error, "无法监听 Ctrl-C");
            }
        }
        _ = terminate.recv() => {}
    }
    tracing::info!("MindOne 协调服务器正在关闭");
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(error = %error, "无法监听关闭信号");
    }
    tracing::info!("MindOne 协调服务器正在关闭");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_help_is_localized(mut command: clap::Command) {
        let subcommands = command.get_subcommands().cloned().collect::<Vec<_>>();
        let help = command.render_long_help().to_string();
        assert!(help.contains("用法："), "帮助缺少中文用法：{help}");
        for english in ["Usage:", "Commands:", "Options:", "Print help"] {
            assert!(
                !help.contains(english),
                "帮助仍包含英文 clap 文案 {english}：{help}"
            );
        }
        for subcommand in subcommands {
            assert_help_is_localized(subcommand);
        }
    }

    #[test]
    fn coordinator_help_tree_is_fully_localized() {
        assert_help_is_localized(CommandLine::localized_command());
    }

    #[test]
    fn no_arguments_keeps_server_start_mode() {
        let parsed = CommandLine::try_parse_from(["mindone-coordinator"])
            .expect("无参数必须保留服务器启动模式");
        assert!(parsed.command.is_none());
    }

    #[test]
    fn parses_database_migrate_command() {
        let parsed = CommandLine::try_parse_from(["mindone-coordinator", "database-migrate"])
            .expect("database-migrate 子命令应解析");
        assert!(matches!(
            parsed.command,
            Some(CoordinatorCommand::DatabaseMigrate)
        ));
    }

    #[test]
    fn parses_offline_and_live_config_check() {
        let offline = CommandLine::try_parse_from(["mindone-coordinator", "config-check"])
            .expect("离线 config-check 应解析");
        assert!(matches!(
            offline.command,
            Some(CoordinatorCommand::ConfigCheck(ConfigCheckArgs {
                live: false
            }))
        ));

        let live = CommandLine::try_parse_from(["mindone-coordinator", "config-check", "--live"])
            .expect("live config-check 应解析");
        assert!(matches!(
            live.command,
            Some(CoordinatorCommand::ConfigCheck(ConfigCheckArgs {
                live: true
            }))
        ));
    }

    #[test]
    fn parses_complete_quota_grant_command() {
        let user_id = Uuid::now_v7();
        let parsed = CommandLine::try_parse_from([
            "mindone-coordinator",
            "quota-grant",
            "--user-id",
            &user_id.to_string(),
            "--amount-micro",
            "1000000",
            "--idempotency-key",
            "launch-2026-0001",
            "--operator",
            "ops/oncall",
            "--reason",
            "生产网络首批供应启动额度",
        ])
        .expect("完整赠额参数应解析");
        let Some(CoordinatorCommand::QuotaGrant(args)) = parsed.command else {
            panic!("应解析为 quota-grant 子命令");
        };
        assert_eq!(args.user_id, user_id);
        assert_eq!(args.amount_micro, 1_000_000);
        assert_eq!(args.operator, "ops/oncall");
    }

    #[test]
    fn rejects_incomplete_quota_grant_command() {
        assert!(CommandLine::try_parse_from([
            "mindone-coordinator",
            "quota-grant",
            "--user-id",
            &Uuid::nil().to_string(),
        ])
        .is_err());
    }

    #[test]
    fn parses_quality_record_without_naked_score_fields() {
        let parsed = CommandLine::try_parse_from([
            "mindone-coordinator",
            "quality-record",
            "--evidence-file",
            "/srv/mindone/evidence/quality.json",
            "--artifact-file",
            "/srv/mindone/evidence/quality.bin",
            "--operator",
            "ops/quality",
            "--reason",
            "导入独立 evaluator 已签名质量证据",
        ])
        .expect("完整签名 evidence 参数应解析");
        let Some(CoordinatorCommand::QualityRecord(args)) = parsed.command else {
            panic!("应解析为 quality-record 子命令");
        };
        assert_eq!(args.operator, "ops/quality");
        assert!(CommandLine::try_parse_from([
            "mindone-coordinator",
            "quality-record",
            "--score-normalized",
            "1000000",
        ])
        .is_err());
    }

    #[test]
    fn parses_complete_billing_profile_record_command() {
        let model_id = Uuid::now_v7();
        let parsed = CommandLine::try_parse_from([
            "mindone-coordinator",
            "billing-profile-record",
            "--model-id",
            &model_id.to_string(),
            "--profile-version",
            "3",
            "--reference-hardware-class",
            "nvidia-h100-sxm-80gb",
            "--maximum-input-tokens",
            "4096",
            "--maximum-output-tokens",
            "1024",
            "--fixed-gpu-time-us",
            "100000",
            "--gpu-time-us-per-1k-tokens",
            "2000000",
            "--reference-vram-mib",
            "81920",
            "--token-rate-micro-per-1k",
            "1000",
            "--gpu-rate-micro-per-second",
            "2000",
            "--vram-rate-micro-per-gib-second",
            "3000",
            "--evidence-file",
            "/srv/mindone/evidence/h100-profile.txt",
            "--valid-from",
            "2026-07-20T00:00:00Z",
            "--valid-until",
            "2026-08-20T00:00:00Z",
            "--operator",
            "ops/billing",
            "--reason",
            "根据独立硬件基准证据发布生产费率",
            "--idempotency-key",
            "billing-h100-2026-0003",
        ])
        .expect("完整计费 profile 参数应解析");
        let Some(CoordinatorCommand::BillingProfileRecord(args)) = parsed.command else {
            panic!("应解析为 billing-profile-record 子命令");
        };
        assert_eq!(args.model_id, model_id);
        assert_eq!(args.profile_version, 3);
        assert_eq!(args.reference_vram_mib, 81_920);
    }

    #[test]
    fn rejects_incomplete_or_nanosecond_billing_profile_command() {
        assert!(CommandLine::try_parse_from([
            "mindone-coordinator",
            "billing-profile-record",
            "--model-id",
            &Uuid::nil().to_string(),
        ])
        .is_err());
        assert!(parse_rfc3339_microseconds("2026-07-20T00:00:00.000000001Z").is_err());
    }

    #[test]
    fn parses_complete_reserve_release_command() {
        let parsed = CommandLine::try_parse_from([
            "mindone-coordinator",
            "reserve-release",
            "--purpose",
            "result-validation",
            "--amount-micro",
            "1000",
            "--reference",
            "validation:job-123",
            "--idempotency-key",
            "reserve-2026-0001",
            "--operator",
            "ops/oncall",
            "--reason",
            "支付独立结果验证算力成本",
        ])
        .expect("完整准备金释放参数应解析");
        let Some(CoordinatorCommand::ReserveRelease(args)) = parsed.command else {
            panic!("应解析为 reserve-release 子命令");
        };
        assert_eq!(args.purpose, ReservePurposeArg::ResultValidation);
        assert_eq!(args.amount_micro, 1_000);
    }

    #[test]
    fn parses_complete_sla_exclusion_record_command() {
        let job_id = Uuid::now_v7();
        let parsed = CommandLine::try_parse_from([
            "mindone-coordinator",
            "sla-exclusion-record",
            "--job-id",
            &job_id.to_string(),
            "--category",
            "content-policy-refusal",
            "--evidence-file",
            "/srv/mindone/evidence/incident-2026-0001.txt",
            "--operator",
            "ops/governance",
            "--reason",
            "经独立证据确认属于内容政策拒绝",
            "--idempotency-key",
            "sla-exclusion-2026-0001",
        ])
        .expect("完整 SLA 排除参数应解析");
        let Some(CoordinatorCommand::SlaExclusionRecord(args)) = parsed.command else {
            panic!("应解析为 sla-exclusion-record 子命令");
        };
        assert_eq!(args.job_id, job_id);
        assert_eq!(args.category.as_contract_str(), "content_policy_refusal");
    }

    #[test]
    fn rejects_unknown_sla_exclusion_category() {
        assert!(CommandLine::try_parse_from([
            "mindone-coordinator",
            "sla-exclusion-record",
            "--job-id",
            &Uuid::nil().to_string(),
            "--category",
            "worker-error",
            "--evidence-file",
            "/srv/mindone/evidence/incident.txt",
            "--operator",
            "ops/governance",
            "--reason",
            "节点自报错误不得成为 SLA 排除",
            "--idempotency-key",
            "sla-exclusion-invalid",
        ])
        .is_err());
    }
}
