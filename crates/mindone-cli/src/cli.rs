use std::path::PathBuf;

use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand, ValueEnum};

pub const HELP_TEMPLATE: &str = "{before-help}{name} {version}\n{about-with-newline}\n\
用法：{usage}\n\n{all-args}{after-help}";

#[derive(Debug, Clone, Parser)]
#[command(
    name = "mindone",
    version,
    about = "MindOne AI 算力与模型共享网络客户端",
    long_about = "MindOne AI 算力与模型共享网络客户端\n\n安全管理本地模型与推理引擎，发布贡献节点，并通过统一额度使用网络算力。",
    help_template = HELP_TEMPLATE,
    subcommand_required = true,
    arg_required_else_help = true,
    disable_help_subcommand = false,
    subcommand_help_heading = "命令",
    next_help_heading = "选项",
    after_help = "终端图形界面：在交互式终端运行 `mindone` 或 `mindone ui`。"
)]
pub struct Cli {
    /// 以稳定 JSON 格式输出结果
    #[arg(long, global = true)]
    pub json: bool,

    /// 安静模式：只输出错误
    #[arg(long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// 输出更详细的诊断信息，可重复使用
    #[arg(long, short = 'v', global = true, action = ArgAction::Count, conflicts_with = "quiet")]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    /// 返回已本地化的完整 clap 命令树。
    ///
    /// clap 的自动 `help` 子命令和 `--help` / `--version` 参数只有在
    /// build 阶段才会出现，因此必须先构建再递归本地化，避免叶子命令
    /// 回退到 clap 的英文默认文案。
    pub fn localized_command() -> clap::Command {
        let mut command = <Self as CommandFactory>::command();
        command.build();
        localize_command(command)
    }
}

fn localize_command(command: clap::Command) -> clap::Command {
    let command_name = command.get_name().to_owned();
    let mut command = command
        .help_template(HELP_TEMPLATE)
        .subcommand_help_heading("命令")
        .subcommand_value_name("命令")
        .next_help_heading("选项")
        .mut_args(|argument| {
            let argument_id = argument.get_id().as_str().to_owned();
            let is_positional = argument.get_index().is_some();
            let argument = argument
                .help_heading(if is_positional { "参数" } else { "选项" })
                .hide_default_value(true)
                .hide_possible_values(true)
                .hide_env_values(true);
            match argument_id.as_str() {
                "help" => argument.help("显示帮助").long_help("显示完整帮助"),
                "version" => argument.help("显示版本").long_help("显示版本"),
                _ => argument,
            }
        })
        .mut_subcommands(localize_command);
    if command_name == "help" {
        command = command.about("显示当前命令或指定子命令的帮助");
    }
    command
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// 管理身份、系统凭证和远程证明
    Auth(AuthArgs),
    /// 管理远程推理 API Key、地址和模型发现
    Api(ApiArgs),
    /// 管理本地模型并执行安全验证
    Model(ModelArgs),
    /// 管理隔离安装的推理引擎
    Engine(EngineArgs),
    /// 在强化沙盒中运行本地推理服务
    Serve(ServeArgs),
    /// 将本地模型发布到 MindOne 网络
    Share(ShareArgs),
    /// 查询和使用可用额度与贡献值
    Quota(QuotaArgs),
    /// 管理节点策略、路由否决和硬件阈值
    Node(NodeArgs),
    /// 管理全局非敏感配置
    Config(ConfigArgs),
    /// 检查本机环境、网络与服务状态
    Doctor(DoctorArgs),
    /// MindOne 内部工作进程；不属于公开接口
    #[command(name = "__worker", hide = true)]
    Worker(WorkerArgs),
}

#[derive(Debug, Clone, Args)]
#[command(help_template = HELP_TEMPLATE)]
pub struct ApiArgs {
    #[command(subcommand)]
    pub command: ApiCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ApiCommand {
    /// 显示 OpenAI 兼容 Base URL、端点和速度后缀
    Info,
    /// 创建只用于远程推理的 API Key；Secret 只显示一次
    Create(ApiCreateArgs),
    /// 列出 API Key 前缀、创建时间和撤销状态
    List,
    /// 撤销 API Key
    Revoke(ApiRevokeArgs),
    /// 查看远程可用模型及三档速度名称
    Models,
}

#[derive(Debug, Clone, Args)]
pub struct ApiCreateArgs {
    /// API Key 名称
    #[arg(long)]
    pub name: String,
}

#[derive(Debug, Clone, Args)]
pub struct ApiRevokeArgs {
    /// API Key ID
    pub id: uuid::Uuid,
}

#[derive(Debug, Clone, Args)]
#[command(help_template = HELP_TEMPLATE)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum AuthCommand {
    /// 使用 OAuth 2.0 设备流程登录
    Login(AuthLoginArgs),
    /// 撤销服务端会话并清除本机凭证
    Logout,
    /// 显示当前用户、信任等级和设备密钥指纹
    Status,
    /// 检测并提交真实硬件远程证明
    Attest,
}

#[derive(Debug, Clone, Args)]
pub struct AuthLoginArgs {
    /// 不自动打开浏览器，适合无图形界面的终端
    #[arg(long)]
    pub no_open: bool,
}

#[derive(Debug, Clone, Args)]
#[command(help_template = HELP_TEMPLATE)]
pub struct ModelArgs {
    #[command(subcommand)]
    pub command: ModelCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ModelCommand {
    /// 列出已下载模型、哈希和验证状态
    List,
    /// 浏览官方支持的 Hugging Face 模型目录
    Catalog(ModelCatalogArgs),
    /// 根据本机硬件保守推荐模型
    Recommend(ModelRecommendArgs),
    /// 小流量确认 Hugging Face 下载能够开始，不写入模型文件
    Probe(ModelProbeArgs),
    /// 选择目录模型后自动下载、安装引擎并启动服务
    Deploy(ModelDeployArgs),
    /// 从可信平台下载并验证模型
    Download(ModelDownloadArgs),
    /// 删除本地模型及登记记录
    Delete(ModelDeleteArgs),
    /// 重新计算哈希并验证模型结构
    Verify(ModelTargetArgs),
}

#[derive(Debug, Clone, Args)]
pub struct ModelCatalogArgs {
    /// 按厂商或模型名称筛选
    #[arg(long)]
    pub query: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub struct ModelRecommendArgs {
    /// 最多显示的推荐数量
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(1..=10))]
    pub limit: u8,
}

#[derive(Debug, Clone, Args)]
pub struct ModelProbeArgs {
    /// 官方目录中的 Hugging Face 仓库 ID
    pub model: String,
    /// 仓库分支或版本
    #[arg(long, default_value = "main")]
    pub branch: String,
    /// 指定要探测的 GGUF 或 safetensors 文件；默认自动选择一个安全候选
    #[arg(long)]
    pub file: Option<String>,
    /// 探测自动部署实际选择的 GGUF，而不是官方仓库中的原生权重
    #[arg(long, conflicts_with = "file")]
    pub deployment: bool,
    /// 只解析 HF 清单、候选仓库、分片和 LFS 哈希，不请求任何权重字节
    #[arg(long)]
    pub metadata_only: bool,
}

#[derive(Debug, Clone, Args)]
pub struct ModelDeployArgs {
    /// 官方目录模型 ID；使用 auto 时按本机硬件选择首选模型
    #[arg(default_value = "auto")]
    pub model: String,
    /// 本地推理服务回环端口
    #[arg(
        long,
        default_value_t = 8080,
        value_parser = clap::value_parser!(u16).range(1..)
    )]
    pub port: u16,
    /// 如果另一个受管模型正在运行，先安全停止再切换
    #[arg(long)]
    pub replace: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ModelPlatform {
    #[value(name = "huggingface")]
    HuggingFace,
    #[value(name = "modelscope")]
    ModelScope,
}

impl ModelPlatform {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HuggingFace => "huggingface",
            Self::ModelScope => "modelscope",
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct ModelDownloadArgs {
    /// 下载平台
    #[arg(long, value_enum)]
    pub platform: ModelPlatform,
    /// 模型仓库，例如 org/model
    #[arg(long)]
    pub repo: String,
    /// 仓库分支或版本
    #[arg(long, default_value = "main")]
    pub branch: String,
    /// 本地模型名称；默认由仓库名生成
    #[arg(long)]
    pub name: Option<String>,
    /// 仓库内的具体 GGUF 或 safetensors 文件
    #[arg(long)]
    pub file: Option<String>,
    /// 用户提供的预期 SHA-256（64 位十六进制）
    #[arg(long, value_parser = parse_sha256)]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub struct ModelDeleteArgs {
    /// 已登记模型名称或 ID
    pub model: String,
    /// 不询问确认，直接删除指定模型
    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[derive(Debug, Clone, Args)]
pub struct ModelTargetArgs {
    /// 已登记模型名称或 ID
    pub model: String,
}

#[derive(Debug, Clone, Args)]
#[command(help_template = HELP_TEMPLATE)]
pub struct EngineArgs {
    #[command(subcommand)]
    pub command: EngineCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum EngineCommand {
    /// 列出可用和已安装的推理引擎
    List,
    /// 将推理引擎安装到 MindOne 隔离目录
    Install(EngineInstallArgs),
    /// 探测操作系统、CPU、内存、GPU 与后端
    Detect,
    /// 设置默认推理引擎
    SetDefault(EngineTargetArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EngineName {
    #[value(name = "vllm")]
    Vllm,
    #[value(name = "llama.cpp")]
    LlamaCpp,
    #[value(name = "ollama")]
    Ollama,
    #[value(name = "tensorrt-llm")]
    TensorRtLlm,
}

impl EngineName {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vllm => "vllm",
            Self::LlamaCpp => "llama.cpp",
            Self::Ollama => "ollama",
            Self::TensorRtLlm => "tensorrt-llm",
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct EngineInstallArgs {
    /// 推理引擎名称
    #[arg(long, value_enum)]
    pub name: EngineName,
    /// 发行版本；省略时 llama.cpp 使用受审计固定版，其他引擎使用 latest
    #[arg(long)]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub struct EngineTargetArgs {
    /// 已安装引擎名称
    #[arg(value_enum)]
    pub engine: EngineName,
}

#[derive(Debug, Clone, Args)]
#[command(help_template = HELP_TEMPLATE)]
pub struct ServeArgs {
    #[command(subcommand)]
    pub command: ServeCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ServeCommand {
    /// 启动受管本地推理服务
    Run(ServeRunArgs),
    /// 优雅停止本地推理服务
    Stop(ServeStopArgs),
    /// 检查真实进程、健康状态和资源使用
    Status(ServeStatusArgs),
}

#[derive(Debug, Clone, Args)]
pub struct ServeRunArgs {
    /// 已验证模型名称或路径
    #[arg(long)]
    pub model: String,
    /// 覆盖默认推理引擎
    #[arg(long, value_enum)]
    pub engine: Option<EngineName>,
    /// 本地监听端口
    #[arg(
        long,
        default_value_t = 8080,
        value_parser = clap::value_parser!(u16).range(1..)
    )]
    pub port: u16,
    /// 高级 YAML 配置文件
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct ServeStopArgs {
    /// 要停止的本地服务端口
    #[arg(
        long,
        default_value_t = 8080,
        value_parser = clap::value_parser!(u16).range(1..)
    )]
    pub port: u16,
    /// 优雅退出等待秒数，超时后终止
    #[arg(long, default_value_t = 10)]
    pub timeout: u64,
}

#[derive(Debug, Clone, Args)]
pub struct ServeStatusArgs {
    /// 要检查的本地服务端口
    #[arg(
        long,
        default_value_t = 8080,
        value_parser = clap::value_parser!(u16).range(1..)
    )]
    pub port: u16,
}

#[derive(Debug, Clone, Args)]
#[command(help_template = HELP_TEMPLATE)]
pub struct ShareArgs {
    #[command(subcommand)]
    pub command: ShareCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ShareCommand {
    /// 注册节点并发布本地模型
    Publish(SharePublishArgs),
    /// 停止领取新任务，排空后取消发布
    Unpublish(ShareUnpublishArgs),
    /// 显示请求、性能、信任和收益统计
    Stats,
}

#[derive(Debug, Clone, Args)]
pub struct SharePublishArgs {
    /// 要发布的已验证模型
    #[arg(long)]
    pub model: String,
    /// 节点自定义别名
    #[arg(long)]
    pub alias: Option<String>,
    /// 用于路由的逗号分隔标签
    #[arg(long, value_delimiter = ',')]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Args)]
pub struct ShareUnpublishArgs {
    /// 指定模型实例 ID；省略时使用本机活动实例
    #[arg(long, conflicts_with = "model", value_parser = parse_uuid)]
    pub id: Option<String>,
    /// 指定已发布模型；省略时使用本机活动实例
    #[arg(long, conflicts_with = "id")]
    pub model: Option<String>,
    /// 等待已有任务完成的最长秒数
    #[arg(long, default_value_t = 30)]
    pub timeout: u64,
}

#[derive(Debug, Clone, Args)]
#[command(help_template = HELP_TEMPLATE)]
pub struct QuotaArgs {
    #[command(subcommand)]
    pub command: QuotaCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum QuotaCommand {
    /// 显示可用额度、贡献值、等级和准备金统计
    Balance,
    /// 分页查询不可变账本历史
    History(QuotaHistoryArgs),
    /// 显示指定交易的荣誉账单
    Receipt(QuotaReceiptArgs),
    /// 启动本地 OpenAI 兼容额度代理
    Use(QuotaUseArgs),
}

#[derive(Debug, Clone, Args)]
pub struct QuotaHistoryArgs {
    /// 页码，从 1 开始
    #[arg(
        long,
        default_value_t = 1,
        value_parser = clap::value_parser!(u32).range(1..=10_000)
    )]
    pub page: u32,
    /// 每页记录数，最大 200
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u16).range(1..=200))]
    pub page_size: u16,
    /// 起始时间（RFC 3339）
    #[arg(long, value_parser = parse_rfc3339)]
    pub from: Option<String>,
    /// 结束时间（RFC 3339）
    #[arg(long, value_parser = parse_rfc3339)]
    pub to: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub struct QuotaReceiptArgs {
    /// 荣誉账单交易 ID
    #[arg(long, value_parser = parse_uuid)]
    pub id: String,
}

#[derive(Debug, Clone, Args)]
pub struct QuotaUseArgs {
    /// 虚拟模型名称；auto 表示自动路由
    #[arg(long, default_value = "auto")]
    pub model: String,
    /// 本地 OpenAI 兼容代理端口
    #[arg(
        long,
        default_value_t = 9090,
        value_parser = clap::value_parser!(u16).range(1..)
    )]
    pub port: u16,
    /// 数据机密模式；regulated 会在本机复验硬件证据并使用真实 E2EE
    #[arg(long, value_enum, default_value_t = ConfidentialityArg::Standard)]
    pub confidentiality: ConfidentialityArg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ConfidentialityArg {
    Standard,
    Regulated,
}

#[derive(Debug, Clone, Args)]
#[command(help_template = HELP_TEMPLATE)]
pub struct NodeArgs {
    #[command(subcommand)]
    pub command: NodeCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum NodeCommand {
    /// 查看或设置路由否决策略
    Policy(NodePolicyArgs),
    /// 查看或设置硬件保护阈值
    Threshold(NodeThresholdArgs),
    /// 根据真实性能指标给出确定性优化建议
    Optimize,
}

#[derive(Debug, Clone, Args)]
pub struct NodePolicyArgs {
    #[command(subcommand)]
    pub command: NodePolicyCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum NodePolicyCommand {
    /// 显示当前路由策略
    Show,
    /// 更新拒绝标签和并发上限
    Set(NodePolicySetArgs),
}

#[derive(Debug, Clone, Args)]
pub struct NodePolicySetArgs {
    /// 逗号分隔的拒绝标签
    #[arg(
        long,
        value_delimiter = ',',
        required_unless_present = "max_concurrent"
    )]
    pub reject_tags: Option<Vec<String>>,
    /// 最大并发贡献任务数；slot 0 保留给本机，贡献端可选择 1 到 3
    #[arg(
        long,
        required_unless_present = "reject_tags",
        value_parser = clap::value_parser!(u16).range(1..=3)
    )]
    pub max_concurrent: Option<u16>,
}

#[derive(Debug, Clone, Args)]
pub struct NodeThresholdArgs {
    #[command(subcommand)]
    pub command: NodeThresholdCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum NodeThresholdCommand {
    /// 显示当前硬件保护阈值
    Show,
    /// 更新温度与显存保留阈值
    Set(NodeThresholdSetArgs),
}

#[derive(Debug, Clone, Args)]
pub struct NodeThresholdSetArgs {
    /// GPU 温度上限（摄氏度）
    #[arg(
        long,
        required_unless_present = "vram_reserve",
        value_parser = clap::value_parser!(u16).range(30..=110)
    )]
    pub gpu_temp_limit: Option<u16>,
    /// 为宿主系统保留的显存（GB）
    #[arg(
        long,
        required_unless_present = "gpu_temp_limit",
        value_parser = parse_nonnegative_finite
    )]
    pub vram_reserve: Option<f64>,
}

fn parse_sha256(value: &str) -> Result<String, String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(value.to_ascii_lowercase())
    } else {
        Err("SHA-256 必须是 64 位十六进制字符串".to_owned())
    }
}

fn parse_uuid(value: &str) -> Result<String, String> {
    uuid::Uuid::parse_str(value)
        .map(|parsed| parsed.to_string())
        .map_err(|_| "ID 必须是合法 UUID".to_owned())
}

fn parse_rfc3339(value: &str) -> Result<String, String> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map(|_| value.to_owned())
        .map_err(|_| "时间必须是合法 RFC 3339".to_owned())
}

fn parse_nonnegative_finite(value: &str) -> Result<f64, String> {
    value
        .parse::<f64>()
        .ok()
        .filter(|parsed| parsed.is_finite() && *parsed >= 0.0)
        .ok_or_else(|| "显存保留必须是非负有限数值".to_owned())
}

#[derive(Debug, Clone, Args)]
#[command(help_template = HELP_TEMPLATE)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ConfigCommand {
    /// 设置一个受支持的非敏感配置项
    Set(ConfigSetArgs),
    /// 获取一个配置值
    Get(ConfigGetArgs),
    /// 列出全部非敏感配置
    List,
}

#[derive(Debug, Clone, Args)]
pub struct ConfigSetArgs {
    /// 配置键，例如 server.url
    pub key: String,
    /// 配置值
    pub value: String,
}

#[derive(Debug, Clone, Args)]
pub struct ConfigGetArgs {
    /// 配置键
    pub key: String,
}

#[derive(Debug, Clone, Args)]
pub struct DoctorArgs {
    /// 同时检查仅协调服务器需要的数据库配置
    #[arg(long)]
    pub server_mode: bool,
}

#[derive(Debug, Clone, Args)]
pub struct WorkerArgs {
    #[command(subcommand)]
    pub command: WorkerCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum WorkerCommand {
    /// 运行节点心跳和任务领取循环
    Share,
    /// 持续轮转受管推理进程日志
    LogMonitor(LogMonitorArgs),
    /// 在公开回环端口代理受管 llama.cpp，并在每次推理终态执行 slot erase
    ServeProxy(ServeProxyArgs),
    /// 向已验证的卸载器输出当前实际数据目录
    ResolveDataDir,
    /// 向已验证的卸载器输出配置控制目录
    ResolveConfigHome,
    /// 探测 Landlock 与 seccomp-bpf 是否可在当前进程完整应用
    SandboxProbe,
    /// 独立探测 seccomp-bpf，供无 Landlock 的较旧 Linux 内核降级
    SandboxSeccompProbe,
    /// 应用 Landlock/seccomp-bpf 后 exec 指定推理引擎
    SandboxExec(SandboxExecArgs),
    /// 仅应用 seccomp-bpf 后 exec 指定推理引擎
    SandboxSeccompExec(SandboxExecArgs),
    /// 在长期持有的 Windows Job Object 中执行推理引擎
    WindowsJobExec(WindowsJobExecArgs),
    /// Windows Job Object 集成测试使用的确定性退出子进程
    WindowsJobSmokeExit(WindowsJobSmokeExitArgs),
}

#[derive(Debug, Clone, Args)]
pub struct ServeProxyArgs {
    /// 对本机应用开放的回环端口
    #[arg(long)]
    pub listen_port: u16,
    /// llama.cpp 实际监听的内部回环端口
    #[arg(long)]
    pub backend_port: u16,
    /// 受管 llama.cpp PID
    #[arg(long)]
    pub target_pid: u32,
    /// 受管 llama.cpp 稳定启动标记
    #[arg(long)]
    pub target_marker: String,
    /// 目标命令中必须逐项精确出现的身份参数
    #[arg(long = "expected-command", required = true)]
    pub expected_command: Vec<String>,
    /// 不含 Prompt/Response 的清理状态文件
    #[arg(long)]
    pub status_path: PathBuf,
}

#[derive(Debug, Clone, Args)]
pub struct LogMonitorArgs {
    /// 受管推理进程正在写入的绝对日志路径
    #[arg(long)]
    pub path: PathBuf,
    /// 受管推理进程 PID
    #[arg(long)]
    pub pid: u32,
    /// 受管推理进程的稳定启动标记
    #[arg(long)]
    pub marker: String,
    /// 目标命令中必须逐项精确出现的身份参数
    #[arg(long = "expected-command", required = true)]
    pub expected_command: Vec<String>,
    /// monitor 完成首轮身份校验与轮转后原子创建的 ready 路径
    #[arg(long, requires = "ready_token")]
    pub ready_path: Option<PathBuf>,
    /// 写入 ready 路径的一次性随机 token
    #[arg(long, requires = "ready_path")]
    pub ready_token: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub struct SandboxExecArgs {
    /// 经过外层 namespace 固定挂载的推理引擎绝对路径
    #[arg(long)]
    pub executable: PathBuf,
    /// 可读取的可信引擎/动态库路径
    #[arg(long = "read-execute")]
    pub read_execute: Vec<PathBuf>,
    /// 只允许读取的数据文件或目录
    #[arg(long = "read-only")]
    pub read_only: Vec<PathBuf>,
    /// 允许运行期读写的目录
    #[arg(long = "read-write")]
    pub read_write: Vec<PathBuf>,
    /// 原样传给推理引擎的参数；必须置于 `--` 之后
    #[arg(last = true, allow_hyphen_values = true)]
    pub engine_args: Vec<String>,
}

#[derive(Debug, Clone, Args)]
pub struct WindowsJobExecArgs {
    /// 经过规范化校验的推理引擎绝对路径
    #[arg(long)]
    pub executable: PathBuf,
    /// 输出不含敏感内容的 Job Object PID 验证事件
    #[arg(long)]
    pub emit_proof: bool,
    /// 原样传给推理引擎的参数；必须置于 `--` 之后
    #[arg(last = true, allow_hyphen_values = true)]
    pub engine_args: Vec<String>,
}

#[derive(Debug, Clone, Args)]
pub struct WindowsJobSmokeExitArgs {
    /// 集成测试需要传递的退出码
    #[arg(long)]
    pub code: u8,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use clap::error::ErrorKind;
    use clap::Parser;

    use super::{
        Cli, Command, EngineCommand, EngineName, ModelCommand, NodeCommand, WorkerCommand,
    };

    #[test]
    fn root_help_contains_all_public_commands_and_chinese() {
        let help = Cli::localized_command().render_long_help().to_string();
        for command in [
            "auth", "api", "model", "engine", "serve", "share", "quota", "node", "config",
            "doctor", "help",
        ] {
            assert!(help.contains(command), "缺少命令 {command}");
        }
        assert!(help.contains("用法"));
        assert!(help.contains("算力"));
        assert!(!help.contains("__worker"));
        assert_help_is_fully_localized(&help);
    }

    #[test]
    fn global_flags_work_after_subcommands() {
        let cli = Cli::try_parse_from(["mindone", "quota", "balance", "--json", "-vv"])
            .expect("应成功解析全局参数");
        assert!(cli.json);
        assert_eq!(cli.verbose, 2);
    }

    #[test]
    fn parses_model_download_defaults() {
        let cli = Cli::try_parse_from([
            "mindone",
            "model",
            "download",
            "--platform",
            "huggingface",
            "--repo",
            "org/model",
        ])
        .expect("应成功解析模型下载参数");
        let Command::Model(args) = cli.command else {
            unreachable!("测试命令类型固定");
        };
        let ModelCommand::Download(args) = args.command else {
            unreachable!("测试子命令类型固定");
        };
        assert_eq!(args.branch, "main");
    }

    #[test]
    fn parses_llama_cpp_engine_name() {
        let cli = Cli::try_parse_from(["mindone", "engine", "install", "--name", "llama.cpp"])
            .expect("应成功解析 llama.cpp");
        let Command::Engine(args) = cli.command else {
            unreachable!("测试命令类型固定");
        };
        let EngineCommand::Install(args) = args.command else {
            unreachable!("测试子命令类型固定");
        };
        assert_eq!(args.name, EngineName::LlamaCpp);
    }

    #[test]
    fn parses_nested_node_policy() {
        let cli = Cli::try_parse_from([
            "mindone",
            "node",
            "policy",
            "set",
            "--reject-tags",
            "nsfw,heavy-math",
            "--max-concurrent",
            "1",
        ])
        .expect("应成功解析节点策略");
        let Command::Node(args) = cli.command else {
            unreachable!("测试命令类型固定");
        };
        assert!(matches!(args.command, NodeCommand::Policy(_)));
    }

    #[test]
    fn quiet_conflicts_with_verbose() {
        let result = Cli::try_parse_from(["mindone", "doctor", "--quiet", "--verbose"]);
        assert!(result.is_err());
    }

    #[test]
    fn every_public_leaf_command_has_a_successful_parse_case() {
        let cases = public_leaf_parse_cases();
        let covered = cases
            .iter()
            .map(|(path, _)| (*path).to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(covered.len(), cases.len(), "公开叶子命令用例不得重复");

        let mut discovered = BTreeSet::new();
        collect_public_leaf_paths(&Cli::localized_command(), "", &mut discovered);
        assert_eq!(covered, discovered, "每个公开叶子命令都必须有解析用例");

        for (path, argv) in cases {
            Cli::try_parse_from(argv)
                .unwrap_or_else(|error| panic!("命令 {path} 应可解析：{error}"));
        }
    }

    #[test]
    fn every_required_public_parameter_has_a_missing_value_case() {
        let cases: &[(&str, &[&str])] = &[
            (
                "model download --platform/--repo",
                &["mindone", "model", "download"],
            ),
            ("model probe model", &["mindone", "model", "probe"]),
            ("api create --name", &["mindone", "api", "create"]),
            ("api revoke id", &["mindone", "api", "revoke"]),
            (
                "model download --repo",
                &["mindone", "model", "download", "--platform", "huggingface"],
            ),
            ("model delete model", &["mindone", "model", "delete"]),
            ("model verify model", &["mindone", "model", "verify"]),
            ("engine install --name", &["mindone", "engine", "install"]),
            (
                "engine set-default engine",
                &["mindone", "engine", "set-default"],
            ),
            ("serve run --model", &["mindone", "serve", "run"]),
            ("share publish --model", &["mindone", "share", "publish"]),
            ("quota receipt --id", &["mindone", "quota", "receipt"]),
            (
                "node policy set 至少一项",
                &["mindone", "node", "policy", "set"],
            ),
            (
                "node threshold set 至少一项",
                &["mindone", "node", "threshold", "set"],
            ),
            ("config set key/value", &["mindone", "config", "set"]),
            (
                "config set value",
                &["mindone", "config", "set", "server.url"],
            ),
            ("config get key", &["mindone", "config", "get"]),
        ];
        for (name, argv) in cases {
            let error = match Cli::try_parse_from(*argv) {
                Ok(_) => panic!("{name} 缺失必填值时必须拒绝"),
                Err(error) => error,
            };
            assert_eq!(
                error.kind(),
                ErrorKind::MissingRequiredArgument,
                "{name} 应按缺失必填参数拒绝"
            );
        }
    }

    #[test]
    fn typed_ranges_formats_and_enums_fail_during_clap_parsing() {
        let cases: &[(&str, &[&str])] = &[
            (
                "platform",
                &[
                    "mindone",
                    "model",
                    "download",
                    "--platform",
                    "unknown",
                    "--repo",
                    "org/model",
                ],
            ),
            (
                "sha256",
                &[
                    "mindone",
                    "model",
                    "download",
                    "--platform",
                    "huggingface",
                    "--repo",
                    "org/model",
                    "--sha256",
                    "xyz",
                ],
            ),
            (
                "engine",
                &["mindone", "engine", "install", "--name", "unknown"],
            ),
            (
                "serve port",
                &["mindone", "serve", "run", "--model", "demo", "--port", "0"],
            ),
            (
                "share instance UUID",
                &["mindone", "share", "unpublish", "--id", "not-a-uuid"],
            ),
            (
                "history page",
                &["mindone", "quota", "history", "--page", "0"],
            ),
            (
                "history page-size",
                &["mindone", "quota", "history", "--page-size", "201"],
            ),
            (
                "history RFC3339",
                &["mindone", "quota", "history", "--from", "yesterday"],
            ),
            (
                "receipt UUID",
                &["mindone", "quota", "receipt", "--id", "receipt-1"],
            ),
            (
                "quota proxy port",
                &["mindone", "quota", "use", "--port", "0"],
            ),
            (
                "confidentiality",
                &["mindone", "quota", "use", "--confidentiality", "secret"],
            ),
            (
                "max-concurrent",
                &["mindone", "node", "policy", "set", "--max-concurrent", "0"],
            ),
            (
                "max-concurrent managed-slot-limit",
                &["mindone", "node", "policy", "set", "--max-concurrent", "4"],
            ),
            (
                "gpu-temp-limit",
                &[
                    "mindone",
                    "node",
                    "threshold",
                    "set",
                    "--gpu-temp-limit",
                    "29",
                ],
            ),
            (
                "vram-reserve",
                &[
                    "mindone",
                    "node",
                    "threshold",
                    "set",
                    "--vram-reserve",
                    "NaN",
                ],
            ),
        ];
        for (name, argv) in cases {
            let error = match Cli::try_parse_from(*argv) {
                Ok(_) => panic!("{name} 的非法值必须拒绝"),
                Err(error) => error,
            };
            assert!(
                matches!(
                    error.kind(),
                    ErrorKind::InvalidValue | ErrorKind::ValueValidation
                ),
                "{name} 应按非法值拒绝，实际为 {:?}",
                error.kind()
            );
        }
    }

    #[test]
    fn every_public_conflict_contract_is_enforced() {
        let cases: &[(&str, &[&str])] = &[
            (
                "quiet/verbose",
                &["mindone", "doctor", "--quiet", "--verbose"],
            ),
            (
                "share unpublish id/model",
                &[
                    "mindone",
                    "share",
                    "unpublish",
                    "--id",
                    "01900000-0000-7000-8000-000000000001",
                    "--model",
                    "demo",
                ],
            ),
        ];
        for (name, argv) in cases {
            let error = match Cli::try_parse_from(*argv) {
                Ok(_) => panic!("{name} 冲突必须拒绝"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        }
    }

    #[test]
    fn documented_defaults_are_stable() {
        let cli = Cli::try_parse_from(["mindone", "quota", "history"]).expect("历史默认值应可解析");
        let Command::Quota(args) = cli.command else {
            panic!("应为 quota 命令");
        };
        let super::QuotaCommand::History(args) = args.command else {
            panic!("应为 history 命令");
        };
        assert_eq!((args.page, args.page_size), (1, 50));

        let cli = Cli::try_parse_from(["mindone", "quota", "use"]).expect("代理默认值应可解析");
        let Command::Quota(args) = cli.command else {
            panic!("应为 quota 命令");
        };
        let super::QuotaCommand::Use(args) = args.command else {
            panic!("应为 use 命令");
        };
        assert_eq!(args.model, "auto");
        assert_eq!(args.port, 9090);
        assert_eq!(args.confidentiality, super::ConfidentialityArg::Standard);

        let cli = Cli::try_parse_from(["mindone", "serve", "run", "--model", "demo"])
            .expect("服务默认值应可解析");
        let Command::Serve(args) = cli.command else {
            panic!("应为 serve 命令");
        };
        let super::ServeCommand::Run(args) = args.command else {
            panic!("应为 run 命令");
        };
        assert_eq!(args.port, 8080);
    }

    #[test]
    fn parses_internal_log_monitor_identity_and_ready_pair() {
        let cli = Cli::try_parse_from([
            "mindone",
            "__worker",
            "log-monitor",
            "--path",
            "/tmp/mindone-serve.log",
            "--pid",
            "123",
            "--marker",
            "456",
            "--expected-command",
            "llama-server",
            "--expected-command",
            "/models/example.gguf",
            "--ready-path",
            "/tmp/mindone-monitor.ready",
            "--ready-token",
            "ready-token-0123456789abcdef",
        ])
        .expect("应成功解析内部日志 monitor 参数");
        let Command::Worker(args) = cli.command else {
            unreachable!("测试命令类型固定");
        };
        let WorkerCommand::LogMonitor(args) = args.command else {
            unreachable!("测试子命令类型固定");
        };
        assert_eq!(args.pid, 123);
        assert_eq!(args.marker, "456");
        assert_eq!(
            args.expected_command,
            ["llama-server", "/models/example.gguf"]
        );
        assert_eq!(
            args.ready_token.as_deref(),
            Some("ready-token-0123456789abcdef")
        );
    }

    #[test]
    fn log_monitor_requires_identity_and_complete_ready_pair() {
        let base = [
            "mindone",
            "__worker",
            "log-monitor",
            "--path",
            "/tmp/mindone-serve.log",
            "--pid",
            "123",
            "--marker",
            "456",
        ];
        assert!(Cli::try_parse_from(base).is_err());

        let mut ready_without_token = base.to_vec();
        ready_without_token.extend([
            "--expected-command",
            "llama-server",
            "--ready-path",
            "/tmp/mindone-monitor.ready",
        ]);
        assert!(Cli::try_parse_from(ready_without_token).is_err());

        let mut token_without_ready = base.to_vec();
        token_without_ready.extend([
            "--expected-command",
            "llama-server",
            "--ready-token",
            "ready-token-0123456789abcdef",
        ]);
        assert!(Cli::try_parse_from(token_without_ready).is_err());
    }

    #[test]
    fn parses_internal_serve_proxy_identity_and_ports() {
        let cli = Cli::try_parse_from([
            "mindone",
            "__worker",
            "serve-proxy",
            "--listen-port",
            "8080",
            "--backend-port",
            "18080",
            "--target-pid",
            "123",
            "--target-marker",
            "456",
            "--expected-command",
            "llama-server",
            "--expected-command",
            "/models/example.gguf",
            "--status-path",
            "/tmp/mindone-cleanup.json",
        ])
        .expect("应成功解析内部 serve proxy 参数");
        let Command::Worker(args) = cli.command else {
            unreachable!("测试命令类型固定");
        };
        let WorkerCommand::ServeProxy(args) = args.command else {
            unreachable!("测试子命令类型固定");
        };
        assert_eq!((args.listen_port, args.backend_port), (8080, 18080));
        assert_eq!(args.target_pid, 123);
        assert_eq!(args.target_marker, "456");
        assert_eq!(args.expected_command.len(), 2);
    }

    #[test]
    fn every_public_help_page_is_fully_localized() {
        let mut command = Cli::localized_command();
        assert_command_help_is_localized(&mut command);
    }

    fn assert_command_help_is_localized(command: &mut clap::Command) {
        if !command.is_hide_set() {
            let help = command.render_long_help().to_string();
            assert_help_is_fully_localized(&help);
        }
        for child in command.get_subcommands_mut() {
            assert_command_help_is_localized(child);
        }
    }

    fn assert_help_is_fully_localized(help: &str) {
        for english_marker in [
            "Usage:",
            "Commands:",
            "Options:",
            "Arguments:",
            "Print help",
            "Print version",
            "possible values",
            "default:",
        ] {
            assert!(
                !help.contains(english_marker),
                "帮助中仍包含英文 clap 文案 {english_marker:?}\n{help}"
            );
        }
        assert!(help.contains("用法："), "帮助缺少中文用法标题\n{help}");
    }

    fn public_leaf_parse_cases() -> Vec<(&'static str, Vec<&'static str>)> {
        let sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let uuid = "01900000-0000-7000-8000-000000000001";
        vec![
            ("auth login", vec!["mindone", "auth", "login", "--no-open"]),
            ("auth logout", vec!["mindone", "auth", "logout"]),
            ("auth status", vec!["mindone", "auth", "status"]),
            ("auth attest", vec!["mindone", "auth", "attest"]),
            ("api info", vec!["mindone", "api", "info"]),
            (
                "api create",
                vec!["mindone", "api", "create", "--name", "production"],
            ),
            ("api list", vec!["mindone", "api", "list"]),
            (
                "api revoke",
                vec![
                    "mindone",
                    "api",
                    "revoke",
                    "01900000-0000-7000-8000-000000000001",
                ],
            ),
            ("api models", vec!["mindone", "api", "models"]),
            ("model list", vec!["mindone", "model", "list"]),
            (
                "model catalog",
                vec!["mindone", "model", "catalog", "--query", "qwen"],
            ),
            (
                "model recommend",
                vec!["mindone", "model", "recommend", "--limit", "3"],
            ),
            (
                "model probe",
                vec![
                    "mindone",
                    "model",
                    "probe",
                    "Qwen/Qwen3-0.6B",
                    "--deployment",
                    "--metadata-only",
                ],
            ),
            (
                "model deploy",
                vec![
                    "mindone",
                    "model",
                    "deploy",
                    "Qwen/Qwen3-0.6B",
                    "--port",
                    "18080",
                    "--replace",
                ],
            ),
            (
                "model download",
                vec![
                    "mindone",
                    "model",
                    "download",
                    "--platform",
                    "huggingface",
                    "--repo",
                    "org/model",
                    "--branch",
                    "main",
                    "--name",
                    "demo",
                    "--file",
                    "weights/model.gguf",
                    "--sha256",
                    sha256,
                ],
            ),
            (
                "model delete",
                vec!["mindone", "model", "delete", "demo", "--yes"],
            ),
            ("model verify", vec!["mindone", "model", "verify", "demo"]),
            ("engine list", vec!["mindone", "engine", "list"]),
            (
                "engine install",
                vec![
                    "mindone",
                    "engine",
                    "install",
                    "--name",
                    "llama.cpp",
                    "--version",
                    "b10064",
                ],
            ),
            ("engine detect", vec!["mindone", "engine", "detect"]),
            (
                "engine set-default",
                vec!["mindone", "engine", "set-default", "llama.cpp"],
            ),
            (
                "serve run",
                vec![
                    "mindone",
                    "serve",
                    "run",
                    "--model",
                    "demo",
                    "--engine",
                    "llama.cpp",
                    "--port",
                    "18080",
                    "--config",
                    "/tmp/mindone-advanced.yml",
                ],
            ),
            (
                "serve stop",
                vec!["mindone", "serve", "stop", "--timeout", "12"],
            ),
            ("serve status", vec!["mindone", "serve", "status"]),
            (
                "share publish",
                vec![
                    "mindone",
                    "share",
                    "publish",
                    "--model",
                    "demo",
                    "--alias",
                    "node-a",
                    "--tags",
                    "code,math",
                ],
            ),
            (
                "share unpublish",
                vec![
                    "mindone",
                    "share",
                    "unpublish",
                    "--id",
                    uuid,
                    "--timeout",
                    "45",
                ],
            ),
            ("share stats", vec!["mindone", "share", "stats"]),
            ("quota balance", vec!["mindone", "quota", "balance"]),
            (
                "quota history",
                vec![
                    "mindone",
                    "quota",
                    "history",
                    "--page",
                    "2",
                    "--page-size",
                    "100",
                    "--from",
                    "2026-07-01T00:00:00Z",
                    "--to",
                    "2026-07-18T00:00:00Z",
                ],
            ),
            (
                "quota receipt",
                vec!["mindone", "quota", "receipt", "--id", uuid],
            ),
            (
                "quota use",
                vec![
                    "mindone",
                    "quota",
                    "use",
                    "--model",
                    "auto",
                    "--port",
                    "19090",
                    "--confidentiality",
                    "regulated",
                ],
            ),
            (
                "node policy show",
                vec!["mindone", "node", "policy", "show"],
            ),
            (
                "node policy set",
                vec![
                    "mindone",
                    "node",
                    "policy",
                    "set",
                    "--reject-tags",
                    "nsfw,heavy-math",
                    "--max-concurrent",
                    "1",
                ],
            ),
            (
                "node threshold show",
                vec!["mindone", "node", "threshold", "show"],
            ),
            (
                "node threshold set",
                vec![
                    "mindone",
                    "node",
                    "threshold",
                    "set",
                    "--gpu-temp-limit",
                    "75",
                    "--vram-reserve",
                    "4.0",
                ],
            ),
            ("node optimize", vec!["mindone", "node", "optimize"]),
            (
                "config set",
                vec![
                    "mindone",
                    "config",
                    "set",
                    "cloudflare.hostname",
                    "api.example.com",
                ],
            ),
            (
                "config get",
                vec!["mindone", "config", "get", "cloudflare.hostname"],
            ),
            ("config list", vec!["mindone", "config", "list"]),
            ("doctor", vec!["mindone", "doctor", "--server-mode"]),
        ]
    }

    fn collect_public_leaf_paths(
        command: &clap::Command,
        prefix: &str,
        output: &mut BTreeSet<String>,
    ) {
        for child in command
            .get_subcommands()
            .filter(|child| !child.is_hide_set() && child.get_name() != "help")
        {
            let path = if prefix.is_empty() {
                child.get_name().to_owned()
            } else {
                format!("{prefix} {}", child.get_name())
            };
            let has_public_children = child
                .get_subcommands()
                .any(|grandchild| !grandchild.is_hide_set() && grandchild.get_name() != "help");
            if has_public_children {
                collect_public_leaf_paths(child, &path, output);
            } else {
                output.insert(path);
            }
        }
    }
}
