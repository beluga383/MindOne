//! MindOne 终端图形界面（TUI）。
//!
//! 直接在交互式终端输入 `mindone`（或 `mindone ui`）时启动。界面维护与公开
//! Clap 命令树精确对应的动作目录；用户可以编辑完整命令行，TUI 只负责安全分词，
//! 随后仍由本地化 Clap 命令树解析，并交给与 CLI 相同的 `app::execute` 执行。
//! 不通过 shell，不允许调用隐藏的内部 worker。

use std::io::{self, IsTerminal, Write};
use std::time::Duration;

use clap::{error::ErrorKind, FromArgMatches};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap,
};
use ratatui::{Frame, Terminal};
use tracing::instrument::WithSubscriber;

use crate::cli::Cli;
use crate::context::AppContext;
use crate::error::{CliError, CliResult};
use crate::output::{CommandOutput, OutputMode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionRisk {
    ReadOnly,
    Confirm,
}

impl ActionRisk {
    const fn label(self) -> &'static str {
        match self {
            Self::ReadOnly => "只读，可直接执行",
            Self::Confirm => "会认证、写入或启动/停止服务，执行前必须再次确认",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CommandSpec {
    path: &'static str,
    title: &'static str,
    usage: &'static str,
    description: &'static str,
    risk: ActionRisk,
}

#[derive(Debug, Clone, Copy)]
struct CategorySpec {
    title: &'static str,
    description: &'static str,
    start: usize,
    len: usize,
}

const CATEGORIES: [CategorySpec; 10] = [
    CategorySpec {
        title: "身份",
        description: "登录、会话、身份状态与远程证明",
        start: 0,
        len: 4,
    },
    CategorySpec {
        title: "远程 API",
        description: "创建 Key，查看 Base URL、模型和速度档",
        start: 4,
        len: 5,
    },
    CategorySpec {
        title: "模型",
        description: "浏览、推荐、探测、下载、验证和管理本地模型",
        start: 9,
        len: 8,
    },
    CategorySpec {
        title: "引擎",
        description: "探测、安装、列出和选择推理引擎",
        start: 17,
        len: 4,
    },
    CategorySpec {
        title: "服务",
        description: "启动、停止和检查本地推理服务",
        start: 21,
        len: 3,
    },
    CategorySpec {
        title: "共享",
        description: "发布、取消发布和查看贡献统计",
        start: 24,
        len: 3,
    },
    CategorySpec {
        title: "额度",
        description: "余额、账本、账单和 OpenAI 兼容代理",
        start: 27,
        len: 4,
    },
    CategorySpec {
        title: "节点",
        description: "路由策略、硬件阈值与优化建议",
        start: 31,
        len: 5,
    },
    CategorySpec {
        title: "配置",
        description: "读取和更新白名单非敏感配置",
        start: 36,
        len: 3,
    },
    CategorySpec {
        title: "诊断",
        description: "检查客户端或协调服务器环境",
        start: 39,
        len: 1,
    },
];

// 此目录是 TUI 的公开能力合同。测试会从 Clap 树递归发现全部公开叶子并做精确集合比较，
// 因而 CLI 新增命令而 TUI 未同步时会确定性失败。
const COMMANDS: [CommandSpec; 40] = [
    CommandSpec {
        path: "auth login",
        title: "登录",
        usage: "mindone auth login [--no-open]",
        description: "使用 OAuth 2.0 设备流程登录；--no-open 不自动打开浏览器。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "auth logout",
        title: "注销",
        usage: "mindone auth logout",
        description: "撤销服务端会话并清除本机安全凭证。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "auth status",
        title: "身份状态",
        usage: "mindone auth status",
        description: "查询服务器确认的用户、信任等级和设备密钥状态。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "auth attest",
        title: "硬件证明",
        usage: "mindone auth attest",
        description: "检测真实 TEE 能力并向协调服务器提交远程证明。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "api info",
        title: "API 使用信息",
        usage: "mindone api info",
        description: "显示 OpenAI 兼容 Base URL、三个端点和 fast/standard/slow 说明。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "api create",
        title: "创建 API Key",
        usage: "mindone api create --name <名称>",
        description: "创建只用于远程推理的 API Key；Secret 只显示一次。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "api list",
        title: "API Key 列表",
        usage: "mindone api list",
        description: "列出 Key ID、名称、不可逆前缀和撤销状态，不返回 Secret。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "api revoke",
        title: "撤销 API Key",
        usage: "mindone api revoke <API_KEY_ID>",
        description: "立即撤销指定推理 Key；重复撤销保持幂等。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "api models",
        title: "远程模型",
        usage: "mindone api models",
        description: "显示当前在线模型及 -fast、无后缀、-slow 三种调用名称。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "model list",
        title: "模型列表",
        usage: "mindone model list",
        description: "列出本地登记模型、哈希、路径和当前验证状态。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "model catalog",
        title: "官方模型目录",
        usage: "mindone model catalog [--query <厂商或模型>]",
        description: "浏览 65 个官方目标模型；下载链接均指向 Hugging Face，实际下载发生在当前用户设备。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "model recommend",
        title: "推荐模型",
        usage: "mindone model recommend [--limit <1..10>]",
        description: "探测本机内存、GPU 与后端，保守推荐适合的目录模型。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "model probe",
        title: "探测下载",
        usage: "mindone model probe <官方模型ID> [--deployment] [--metadata-only] [--branch <分支>] [--file <文件>]",
        description: "默认从 HF 最多读取 64 KiB 后主动中止；--metadata-only 只核验清单、分片和 LFS 哈希，--deployment 使用一键部署实际选择。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "model deploy",
        title: "一键部署模型",
        usage: "mindone model deploy [<官方模型ID|auto>] [--port <端口>] [--replace]",
        description: "自动选择可运行 GGUF、预检内存、从 HF 下载校验、安装受管引擎并启动健康服务。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "model download",
        title: "下载模型",
        usage: "mindone model download --platform <huggingface|modelscope> --repo <org/model> [--branch <分支>] [--name <名称>] [--file <文件>] [--sha256 <64位十六进制>]",
        description: "从可信平台下载 GGUF/safetensors，并完成哈希和结构验证。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "model delete",
        title: "删除模型",
        usage: "mindone model delete <模型名称或ID> [-y|--yes]",
        description: "删除未被使用的本地模型及其登记；未加 --yes 时还会在普通终端确认。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "model verify",
        title: "验证模型",
        usage: "mindone model verify <模型名称或ID>",
        description: "重新计算模型哈希、验证结构并更新验证登记。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "engine list",
        title: "引擎列表",
        usage: "mindone engine list",
        description: "列出平台能力、实际安装、完整性和默认引擎。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "engine install",
        title: "安装引擎",
        usage: "mindone engine install --name <vllm|llama.cpp|ollama|tensorrt-llm> [--version <版本>]",
        description: "下载并验证官方发行资产，安装到 MindOne 隔离目录。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "engine detect",
        title: "硬件探测",
        usage: "mindone engine detect",
        description: "探测真实 OS、CPU、内存、GPU、Metal/CUDA 和推荐后端。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "engine set-default",
        title: "设置默认引擎",
        usage: "mindone engine set-default <vllm|llama.cpp|ollama|tensorrt-llm>",
        description: "将已安装、完整且有受管 serve 适配器的引擎设为默认值。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "serve run",
        title: "启动推理服务",
        usage: "mindone serve run --model <模型> [--engine <引擎>] [--port <1..65535>] [--config <YAML路径>]",
        description: "在强化沙盒中启动回环推理服务；端口默认 8080。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "serve stop",
        title: "停止推理服务",
        usage: "mindone serve stop [--port <1..65535>] [--timeout <秒>]",
        description: "复验进程身份后优雅停止服务；超时默认 10 秒。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "serve status",
        title: "服务状态",
        usage: "mindone serve status [--port <1..65535>]",
        description: "检查真实进程、健康、资源、沙盒和请求后清理状态。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "share publish",
        title: "发布节点",
        usage: "mindone share publish --model <模型> [--alias <节点别名>] [--tags <逗号分隔标签>]",
        description: "注册节点和模型实例，启动持久 worker 并等待首次心跳。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "share unpublish",
        title: "取消发布",
        usage: "mindone share unpublish [--id <UUID>|--model <模型>] [--timeout <秒>]",
        description: "停止领取、排空任务并取消发布；默认等待 30 秒。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "share stats",
        title: "共享统计",
        usage: "mindone share stats",
        description: "查询权威请求、性能、Trust、Tier、收益与荣誉进度。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "quota balance",
        title: "额度余额",
        usage: "mindone quota balance",
        description: "查询可支配/预留/可用额度、贡献值、Tier 和准备金。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "quota history",
        title: "账本历史",
        usage: "mindone quota history [--page <1..10000>] [--page-size <1..200>] [--from <RFC3339>] [--to <RFC3339>]",
        description: "分页读取不可变账本；页码默认 1，每页默认 50 条。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "quota receipt",
        title: "荣誉账单",
        usage: "mindone quota receipt --id <UUID>",
        description: "查询并显示指定交易的荣誉账单和结算证据。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "quota use",
        title: "启动额度代理",
        usage: "mindone quota use [--model <模型|auto>] [--port <1..65535>] [--confidentiality <standard|regulated>]",
        description: "前台启动回环 OpenAI 兼容代理；默认模型 auto、端口 9090。按 Ctrl-C 停止后返回 TUI。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "node policy show",
        title: "查看路由策略",
        usage: "mindone node policy show",
        description: "显示拒绝标签与当前最大并发任务数。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "node policy set",
        title: "设置路由策略",
        usage: "mindone node policy set [--reject-tags <逗号分隔标签>] [--max-concurrent <1..3>]",
        description: "至少提供一项，原子更新路由否决策略。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "node threshold show",
        title: "查看硬件阈值",
        usage: "mindone node threshold show",
        description: "显示 GPU 温度/显存保护阈值和当前硬件指标。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "node threshold set",
        title: "设置硬件阈值",
        usage: "mindone node threshold set [--gpu-temp-limit <30..110>] [--vram-reserve <非负GB>]",
        description: "至少提供一项，原子更新硬件保护阈值。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "node optimize",
        title: "优化建议",
        usage: "mindone node optimize",
        description: "根据真实 TPS、首 Token TTFT 和错误率生成确定性建议。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "config set",
        title: "设置配置",
        usage: "mindone config set <白名单键> <值>",
        description: "原子更新非敏感配置；敏感键和不安全网络地址会被拒绝。",
        risk: ActionRisk::Confirm,
    },
    CommandSpec {
        path: "config get",
        title: "读取配置",
        usage: "mindone config get <白名单键>",
        description: "读取一个白名单非敏感配置值。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "config list",
        title: "配置列表",
        usage: "mindone config list",
        description: "列出全部白名单非敏感配置。",
        risk: ActionRisk::ReadOnly,
    },
    CommandSpec {
        path: "doctor",
        title: "环境诊断",
        usage: "mindone doctor [--server-mode]",
        description: "检查客户端环境；--server-mode 额外检查协调服务器就绪状态。",
        risk: ActionRisk::ReadOnly,
    },
];

fn command_spec(path: &str) -> Option<&'static CommandSpec> {
    COMMANDS.iter().find(|spec| spec.path == path)
}

fn category_commands(category: usize) -> &'static [CommandSpec] {
    let Some(category) = CATEGORIES.get(category) else {
        return &[];
    };
    &COMMANDS[category.start..category.start + category.len]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Category,
    Action,
    Editor,
}

impl Focus {
    const fn next(self) -> Self {
        match self {
            Self::Category => Self::Action,
            Self::Action => Self::Editor,
            Self::Editor => Self::Category,
        }
    }

    const fn previous(self) -> Self {
        match self {
            Self::Category => Self::Editor,
            Self::Action => Self::Category,
            Self::Editor => Self::Action,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Category => "分类",
            Self::Action => "动作",
            Self::Editor => "命令编辑",
        }
    }
}

#[derive(Debug, Clone)]
struct Confirmation {
    command_line: String,
    path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PickerModel {
    repository: String,
    memory: String,
    recommended_rank: Option<usize>,
}

/// TUI 内的模型选择器只保存公开目录和本机推荐结果；它不会预取权重，也不会把
/// “目录中存在”冒充成“当前仓库一定有可运行 GGUF”。真正部署仍复用 model deploy
/// 的实时 HF 清单、哈希、格式和内存检查。
#[derive(Debug, Clone)]
struct ModelPicker {
    query: String,
    selected: usize,
    models: Vec<PickerModel>,
}

impl ModelPicker {
    fn new() -> Self {
        let (_, recommendations) = crate::model_catalog::recommend(5);
        let ranks = recommendations
            .iter()
            .map(|item| (item.repository, item.rank))
            .collect::<std::collections::BTreeMap<_, _>>();
        Self::from_recommendation_ranks(&ranks)
    }

    fn from_recommendation_ranks(ranks: &std::collections::BTreeMap<&str, usize>) -> Self {
        let mut models = crate::model_catalog::catalog(None)
            .into_iter()
            .map(|model| PickerModel {
                repository: model.repository.to_owned(),
                memory: model
                    .estimated_q4_memory_bytes
                    .map(picker_human_bytes)
                    .unwrap_or_else(|| "部署时核验".to_owned()),
                recommended_rank: ranks.get(model.repository).copied(),
            })
            .collect::<Vec<_>>();
        models.sort_by(|left, right| {
            left.recommended_rank
                .unwrap_or(usize::MAX)
                .cmp(&right.recommended_rank.unwrap_or(usize::MAX))
                .then_with(|| left.repository.cmp(&right.repository))
        });
        Self {
            query: String::new(),
            selected: 0,
            models,
        }
    }

    fn visible_indices(&self) -> Vec<usize> {
        let query = self.query.trim().to_ascii_lowercase();
        self.models
            .iter()
            .enumerate()
            .filter_map(|(index, model)| {
                (query.is_empty() || model.repository.to_ascii_lowercase().contains(&query))
                    .then_some(index)
            })
            .collect()
    }

    fn select_previous(&mut self) {
        let len = self.visible_indices().len();
        if len > 0 {
            self.selected = if self.selected == 0 {
                len - 1
            } else {
                self.selected - 1
            };
        }
    }

    fn select_next(&mut self) {
        let len = self.visible_indices().len();
        if len > 0 {
            self.selected = (self.selected + 1) % len;
        }
    }

    fn selected_repository(&self) -> Option<String> {
        let visible = self.visible_indices();
        let index = visible.get(self.selected.min(visible.len().saturating_sub(1)))?;
        self.models
            .get(*index)
            .map(|model| model.repository.clone())
    }

    fn push_query(&mut self, character: char) {
        self.query.push(character);
        self.selected = 0;
    }

    fn pop_query(&mut self) {
        self.query.pop();
        self.selected = 0;
    }
}

fn picker_human_bytes(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / (1024_f64 * 1024_f64 * 1024_f64))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UiIntent {
    None,
    Prepare(String),
    ExecuteConfirmed(String),
}

/// 纯状态机：不涉及终端或业务 I/O，便于确定性测试。
#[derive(Debug, Clone)]
struct DashboardState {
    category: usize,
    action: usize,
    focus: Focus,
    command_line: String,
    cursor: usize,
    content: Vec<String>,
    scroll: u16,
    status: String,
    confirmation: Option<Confirmation>,
    model_picker: Option<ModelPicker>,
    show_help: bool,
    should_quit: bool,
    last_output: Option<CommandOutput>,
    last_exit_code: Option<u8>,
}

impl Default for DashboardState {
    fn default() -> Self {
        let mut state = Self {
            category: 0,
            action: 0,
            focus: Focus::Category,
            command_line: String::new(),
            cursor: 0,
            content: vec![
                "从这里开始".to_owned(),
                String::new(),
                "1. 登录账户：身份 > 登录".to_owned(),
                "2. 按 R 获取本机推荐，或按 M 打开 65 个模型的选择器".to_owned(),
                "3. 选择模型后自动进入下载、校验、引擎安装和部署流程".to_owned(),
                "4. 通过共享发布贡献算力，或创建 API Key 调用远程模型".to_owned(),
                String::new(),
                "所有下载都发生在当前用户设备；写操作执行前会再次确认。".to_owned(),
            ],
            scroll: 0,
            status: "就绪".to_owned(),
            confirmation: None,
            model_picker: None,
            show_help: false,
            should_quit: false,
            last_output: None,
            last_exit_code: None,
        };
        state.reset_editor_to_selection();
        state
    }
}

impl DashboardState {
    fn selected_spec(&self) -> &'static CommandSpec {
        // CATEGORIES 与 COMMANDS 是编译期固定合同；状态方法始终把索引约束在其范围内。
        let category = &CATEGORIES[self.category];
        &COMMANDS[category.start + self.action]
    }

    fn reset_editor_to_selection(&mut self) {
        self.command_line = format!("mindone {}", self.selected_spec().path);
        self.cursor = self.command_line.chars().count();
    }

    fn select_previous(&mut self) {
        match self.focus {
            Focus::Category => {
                self.category = if self.category == 0 {
                    CATEGORIES.len() - 1
                } else {
                    self.category - 1
                };
                self.action = 0;
                self.reset_editor_to_selection();
            }
            Focus::Action => {
                let len = category_commands(self.category).len();
                self.action = if self.action == 0 {
                    len.saturating_sub(1)
                } else {
                    self.action - 1
                };
                self.reset_editor_to_selection();
            }
            Focus::Editor => {}
        }
        self.scroll = 0;
    }

    fn select_next(&mut self) {
        match self.focus {
            Focus::Category => {
                self.category = (self.category + 1) % CATEGORIES.len();
                self.action = 0;
                self.reset_editor_to_selection();
            }
            Focus::Action => {
                let len = category_commands(self.category).len();
                if len > 0 {
                    self.action = (self.action + 1) % len;
                    self.reset_editor_to_selection();
                }
            }
            Focus::Editor => {}
        }
        self.scroll = 0;
    }

    fn select_category(&mut self, index: usize) {
        if index < CATEGORIES.len() {
            self.category = index;
            self.action = 0;
            self.reset_editor_to_selection();
            self.scroll = 0;
        }
    }

    fn select_command(&mut self, path: &str, command_line: &str) {
        if let Some((command_index, _)) = COMMANDS
            .iter()
            .enumerate()
            .find(|(_, spec)| spec.path == path)
        {
            if let Some((category_index, category)) =
                CATEGORIES.iter().enumerate().find(|(_, category)| {
                    command_index >= category.start
                        && command_index < category.start.saturating_add(category.len)
                })
            {
                self.category = category_index;
                self.action = command_index - category.start;
            }
        }
        self.command_line = command_line.to_owned();
        self.cursor = self.command_line.chars().count();
        self.scroll = 0;
    }

    fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(4);
    }

    fn scroll_down(&mut self) {
        let max = self.content.len().saturating_sub(1) as u16;
        self.scroll = self.scroll.saturating_add(4).min(max);
    }

    fn insert_char(&mut self, character: char) {
        let mut characters = self.command_line.chars().collect::<Vec<_>>();
        let cursor = self.cursor.min(characters.len());
        characters.insert(cursor, character);
        self.command_line = characters.into_iter().collect();
        self.cursor = cursor + 1;
    }

    fn insert_text(&mut self, text: &str) {
        for character in text.chars() {
            self.insert_char(character);
        }
    }

    fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let mut characters = self.command_line.chars().collect::<Vec<_>>();
        let cursor = self.cursor.min(characters.len());
        characters.remove(cursor - 1);
        self.command_line = characters.into_iter().collect();
        self.cursor = cursor - 1;
    }

    fn delete(&mut self) {
        let mut characters = self.command_line.chars().collect::<Vec<_>>();
        if self.cursor >= characters.len() {
            return;
        }
        characters.remove(self.cursor);
        self.command_line = characters.into_iter().collect();
    }

    fn move_cursor_left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    fn move_cursor_right(&mut self) {
        self.cursor = self
            .cursor
            .saturating_add(1)
            .min(self.command_line.chars().count());
    }

    fn clear_editor(&mut self) {
        self.command_line.clear();
        self.cursor = 0;
    }

    fn request_confirmation(&mut self, command_line: String, path: String) {
        self.confirmation = Some(Confirmation { command_line, path });
        self.status = "等待二次确认".to_owned();
    }

    fn cancel_confirmation(&mut self) {
        self.confirmation = None;
        self.status = "已取消，未执行任何操作".to_owned();
    }

    fn set_parse_error(&mut self, error: &CliError) {
        self.content = vec!["命令未执行".to_owned(), String::new(), format!("{error}")];
        self.scroll = 0;
        self.status = "命令参数无效".to_owned();
        self.last_output = None;
        self.last_exit_code = Some(error.exit_code());
    }

    fn set_output(&mut self, path: &str, mode: OutputMode, output: CommandOutput) {
        let mut bytes = Vec::new();
        let rendered = match mode.write_success(&output, &mut bytes) {
            Ok(()) => String::from_utf8_lossy(&bytes).trim_end().to_owned(),
            Err(error) => format!("无法按请求的输出模式生成结果：{error}"),
        };
        let exit_code = output.exit_code;
        self.content = vec![
            format!("命令：mindone {path}"),
            format!("退出码：{exit_code}"),
            String::new(),
        ];
        if !rendered.is_empty() {
            self.content.extend(rendered.lines().map(str::to_owned));
        }
        self.scroll = 0;
        self.status = if exit_code == 0 {
            "完成（退出码 0）".to_owned()
        } else {
            format!("命令返回非零退出码 {exit_code}")
        };
        self.last_exit_code = Some(exit_code);
        self.last_output = Some(output);
    }

    fn set_execution_error(&mut self, path: &str, error: CliError) {
        let exit_code = error.exit_code();
        self.content = vec![
            format!("命令：mindone {path}"),
            format!("退出码：{exit_code}"),
            String::new(),
            format!("错误：{error}"),
        ];
        self.scroll = 0;
        self.status = format!("失败（退出码 {exit_code}）");
        self.last_output = None;
        self.last_exit_code = Some(exit_code);
    }

    fn append_context_error(&mut self, error: &CliError) {
        self.content.push(String::new());
        self.content
            .push(format!("警告：命令结束后刷新界面上下文失败：{error}"));
        self.status = "命令已结束，但界面上下文刷新失败".to_owned();
    }

    fn last_result_summary(&self) -> String {
        match (&self.last_output, self.last_exit_code) {
            (Some(output), _) => format!("最近退出码: {}", output.exit_code),
            (None, Some(exit_code)) => format!("最近退出码: {exit_code}"),
            (None, None) => "尚未执行".to_owned(),
        }
    }

    fn process_exit_code(&self) -> u8 {
        self.last_exit_code.unwrap_or(0)
    }

    fn handle_key(&mut self, key: KeyEvent) -> UiIntent {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return UiIntent::None;
        }

        if self.show_help {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('?')) {
                self.show_help = false;
                self.status = "帮助已关闭".to_owned();
            }
            return UiIntent::None;
        }

        if self.confirmation.is_some() {
            return match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    if let Some(confirmation) = self.confirmation.take() {
                        self.status = format!("正在执行 {}", confirmation.path);
                        UiIntent::ExecuteConfirmed(confirmation.command_line)
                    } else {
                        UiIntent::None
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.cancel_confirmation();
                    UiIntent::None
                }
                _ => UiIntent::None,
            };
        }

        if self.model_picker.is_some() {
            let mut selected_repository = None;
            let mut close = false;
            if let Some(picker) = self.model_picker.as_mut() {
                match key.code {
                    KeyCode::Esc => close = true,
                    KeyCode::Up => picker.select_previous(),
                    KeyCode::Down => picker.select_next(),
                    KeyCode::PageUp => {
                        for _ in 0..8 {
                            picker.select_previous();
                        }
                    }
                    KeyCode::PageDown => {
                        for _ in 0..8 {
                            picker.select_next();
                        }
                    }
                    KeyCode::Backspace => picker.pop_query(),
                    KeyCode::Enter => selected_repository = picker.selected_repository(),
                    KeyCode::Char(character)
                        if !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                    {
                        picker.push_query(character);
                    }
                    _ => {}
                }
            }
            if close {
                self.model_picker = None;
                self.status = "已关闭模型选择器".to_owned();
            }
            if let Some(repository) = selected_repository {
                self.model_picker = None;
                let command_line = format!("mindone model deploy {repository}");
                self.select_command("model deploy", &command_line);
                self.status = format!("已选择 {repository}，等待确认部署");
                return UiIntent::Prepare(command_line);
            }
            return UiIntent::None;
        }

        match key.code {
            KeyCode::Char('?') if self.focus != Focus::Editor => {
                self.show_help = true;
                self.status = "快捷键帮助".to_owned();
            }
            KeyCode::Char('m' | 'M') if self.focus != Focus::Editor => {
                self.model_picker = Some(ModelPicker::new());
                self.status = "选择要自动下载和部署的模型".to_owned();
            }
            KeyCode::Char('r' | 'R') if self.focus != Focus::Editor => {
                let command_line = "mindone model recommend --limit 5".to_owned();
                self.select_command("model recommend", &command_line);
                self.status = "正在生成本机模型推荐".to_owned();
                return UiIntent::Prepare(command_line);
            }
            KeyCode::Char('d' | 'D') if self.focus != Focus::Editor => {
                let command_line = "mindone model deploy auto".to_owned();
                self.select_command("model deploy", &command_line);
                self.status = "自动部署将先进行安全预检".to_owned();
                return UiIntent::Prepare(command_line);
            }
            KeyCode::Tab => self.focus = self.focus.next(),
            KeyCode::BackTab => self.focus = self.focus.previous(),
            KeyCode::Up if self.focus != Focus::Editor => self.select_previous(),
            KeyCode::Down if self.focus != Focus::Editor => self.select_next(),
            KeyCode::Left if self.focus == Focus::Action => self.focus = Focus::Category,
            KeyCode::Right if self.focus == Focus::Category => self.focus = Focus::Action,
            KeyCode::Right if self.focus == Focus::Action => self.focus = Focus::Editor,
            KeyCode::PageUp => self.scroll_up(),
            KeyCode::PageDown => self.scroll_down(),
            KeyCode::Enter => match self.focus {
                Focus::Category => self.focus = Focus::Action,
                Focus::Action => self.focus = Focus::Editor,
                Focus::Editor => return UiIntent::Prepare(self.command_line.clone()),
            },
            KeyCode::Esc => match self.focus {
                Focus::Editor => self.focus = Focus::Action,
                Focus::Action => self.focus = Focus::Category,
                Focus::Category => self.should_quit = true,
            },
            KeyCode::Char('q') if self.focus != Focus::Editor => self.should_quit = true,
            KeyCode::Char('e') if self.focus == Focus::Action => self.focus = Focus::Editor,
            KeyCode::Char(digit @ '1'..='9') if self.focus == Focus::Category => {
                if let Some(index) = digit.to_digit(10) {
                    self.select_category((index as usize).saturating_sub(1));
                }
            }
            KeyCode::Char('0') if self.focus == Focus::Category => self.select_category(9),
            KeyCode::Left if self.focus == Focus::Editor => self.move_cursor_left(),
            KeyCode::Right if self.focus == Focus::Editor => self.move_cursor_right(),
            KeyCode::Home if self.focus == Focus::Editor => self.cursor = 0,
            KeyCode::End if self.focus == Focus::Editor => {
                self.cursor = self.command_line.chars().count();
            }
            KeyCode::Backspace if self.focus == Focus::Editor => self.backspace(),
            KeyCode::Delete if self.focus == Focus::Editor => self.delete(),
            KeyCode::Char('u')
                if self.focus == Focus::Editor && key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.clear_editor();
            }
            KeyCode::Char(character)
                if self.focus == Focus::Editor
                    && !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.insert_char(character);
            }
            _ => {}
        }
        UiIntent::None
    }
}

#[derive(Debug, Clone)]
struct PreparedCommand {
    cli: Cli,
    path: String,
    risk: ActionRisk,
}

fn prepare_command_line(input: &str) -> CliResult<PreparedCommand> {
    let mut words = split_command_line(input).map_err(CliError::CliParse)?;
    if words.is_empty() {
        return Err(CliError::CliParse("命令不能为空".to_owned()));
    }
    if words.first().is_none_or(|word| word != "mindone") {
        words.insert(0, "mindone".to_owned());
    }

    let mut command = Cli::localized_command();
    let matches = command.try_get_matches_from_mut(words).map_err(|error| {
        CliError::CliParse(format!(
            "{}；请根据右侧用法编辑命令后重试",
            localized_tui_parse_error(error.kind())
        ))
    })?;
    let path = leaf_path(&matches)
        .ok_or_else(|| CliError::CliParse("必须选择一个完整的公开叶子命令".to_owned()))?;
    let spec = command_spec(&path).ok_or_else(|| {
        CliError::CliParse(format!(
            "TUI 只允许执行公开命令；{path} 不在 40 个公开叶子命令目录中"
        ))
    })?;
    let cli = Cli::from_arg_matches(&matches)
        .map_err(|_| CliError::CliParse("命令参数无法转换为内部结构，请检查命令格式".to_owned()))?;
    Ok(PreparedCommand {
        cli,
        path,
        risk: spec.risk,
    })
}

fn leaf_path(matches: &clap::ArgMatches) -> Option<String> {
    let mut current = matches;
    let mut parts = Vec::new();
    while let Some((name, nested)) = current.subcommand() {
        parts.push(name);
        current = nested;
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

fn localized_tui_parse_error(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => "参数值未通过校验",
        ErrorKind::UnknownArgument => "存在无法识别的参数或命令",
        ErrorKind::InvalidSubcommand => "子命令无法识别",
        ErrorKind::NoEquals => "该选项要求使用等号赋值",
        ErrorKind::TooManyValues => "为参数提供了过多的值",
        ErrorKind::TooFewValues => "为参数提供的值不足",
        ErrorKind::WrongNumberOfValues => "参数值数量不正确",
        ErrorKind::ArgumentConflict => "使用了互相冲突的参数",
        ErrorKind::MissingRequiredArgument => "缺少必需参数",
        ErrorKind::MissingSubcommand => "缺少必需子命令",
        ErrorKind::InvalidUtf8 => "参数包含无效 UTF-8 文本",
        ErrorKind::DisplayHelp
        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        | ErrorKind::DisplayVersion => "帮助和版本请在普通 CLI 中查看",
        ErrorKind::Io | ErrorKind::Format => "生成命令诊断信息失败",
        _ => "命令参数无效",
    }
}

/// 仅做命令行分词，不执行任何 shell 展开或程序。
///
/// 支持空白分隔、单引号、双引号和反斜杠转义；不解释 `$`、反引号、管道、重定向、
/// 分号或命令替换。它们只会作为普通参数字符交给 Clap，并通常因参数合同不匹配而拒绝。
fn split_command_line(input: &str) -> Result<Vec<String>, String> {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Quote {
        Single,
        Double,
    }

    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut token_started = false;
    let mut characters = input.chars().peekable();

    while let Some(character) = characters.next() {
        match quote {
            Some(Quote::Single) => {
                if character == '\'' {
                    quote = None;
                } else {
                    current.push(character);
                }
            }
            Some(Quote::Double) => match character {
                '"' => quote = None,
                '\\' if characters.peek().is_some_and(|next| matches!(next, '"')) => {
                    if let Some(escaped) = characters.next() {
                        current.push(escaped);
                    }
                }
                _ => current.push(character),
            },
            None => match character {
                '\'' => {
                    quote = Some(Quote::Single);
                    token_started = true;
                }
                '"' => {
                    quote = Some(Quote::Double);
                    token_started = true;
                }
                '\\' if characters
                    .peek()
                    .is_some_and(|next| next.is_whitespace() || matches!(next, '\'' | '"')) =>
                {
                    if let Some(escaped) = characters.next() {
                        current.push(escaped);
                    }
                    token_started = true;
                }
                value if value.is_whitespace() => {
                    if token_started {
                        words.push(std::mem::take(&mut current));
                        token_started = false;
                    }
                }
                _ => {
                    current.push(character);
                    token_started = true;
                }
            },
        }
    }

    if let Some(quote) = quote {
        return Err(match quote {
            Quote::Single => "命令包含未闭合的单引号".to_owned(),
            Quote::Double => "命令包含未闭合的双引号".to_owned(),
        });
    }
    if token_started {
        words.push(current);
    }
    Ok(words)
}

/// 顶部信息条：只读本地会话与配置，不触发网络。
#[derive(Debug, Clone)]
struct HeaderInfo {
    user: String,
    trust: String,
    server: String,
}

fn read_header(context: &AppContext) -> HeaderInfo {
    let (user, trust) = match context.vault.load_session() {
        Ok(session) => {
            let user = if session.user.trim().is_empty() {
                session.uid.clone()
            } else {
                session.user.clone()
            };
            let trust = if session.local_sandbox_trust_level.trim().is_empty() {
                "未知".to_owned()
            } else {
                session.local_sandbox_trust_level.clone()
            };
            (user, trust)
        }
        Err(_) => ("未登录".to_owned(), "—".to_owned()),
    };
    HeaderInfo {
        user,
        trust,
        server: context.config.server_url.clone(),
    }
}

/// 备用屏幕/raw 模式守卫。命令执行前可暂离 TUI，完成后再恢复；任何中间错误都尽量
/// 把终端留在普通、非 raw 状态。
struct TerminalGuard {
    active: bool,
}

impl TerminalGuard {
    fn enter() -> CliResult<Self> {
        enable_raw_mode()
            .map_err(|error| CliError::General(format!("无法进入终端 raw 模式：{error}")))?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(CliError::General(format!("无法进入备用终端屏幕：{error}")));
        }
        Ok(Self { active: true })
    }

    fn suspend(&mut self) -> CliResult<()> {
        if !self.active {
            return Ok(());
        }
        disable_raw_mode()
            .map_err(|error| CliError::General(format!("无法退出终端 raw 模式：{error}")))?;
        if let Err(error) = execute!(io::stdout(), LeaveAlternateScreen) {
            let _ = enable_raw_mode();
            return Err(CliError::General(format!("无法离开备用终端屏幕：{error}")));
        }
        self.active = false;
        Ok(())
    }

    fn resume(&mut self) -> CliResult<()> {
        if self.active {
            return Ok(());
        }
        enable_raw_mode()
            .map_err(|error| CliError::General(format!("无法恢复终端 raw 模式：{error}")))?;
        if let Err(error) = execute!(io::stdout(), EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(CliError::General(format!("无法恢复备用终端屏幕：{error}")));
        }
        self.active = true;
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            self.active = false;
        }
    }
}

fn render(frame: &mut Frame<'_>, header: &HeaderInfo, state: &DashboardState) {
    frame.render_widget(
        Block::default().style(Style::default().bg(theme_bg()).fg(theme_text())),
        frame.area(),
    );
    if frame.area().width < 68 || frame.area().height < 20 {
        render_terminal_too_small(frame);
        return;
    }

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(4),
            Constraint::Length(2),
        ])
        .split(frame.area());

    let header_line = Line::from(vec![
        Span::styled(
            " ◈ MINDONE ",
            Style::default()
                .fg(theme_bg())
                .bg(theme_accent())
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  v{}  ", env!("CARGO_PKG_VERSION")),
            Style::default().fg(theme_muted()),
        ),
        Span::styled("账户 ", Style::default().fg(theme_muted())),
        Span::styled(
            header.user.clone(),
            Style::default()
                .fg(theme_text())
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("   信任 ", Style::default().fg(theme_muted())),
        Span::styled(header.trust.clone(), Style::default().fg(theme_blue())),
        Span::styled("   协调器 ", Style::default().fg(theme_muted())),
        Span::styled(header.server.clone(), Style::default().fg(theme_text())),
    ]);
    frame.render_widget(
        Paragraph::new(header_line)
            .style(Style::default().bg(theme_surface()))
            .block(
                Block::default()
                    .borders(Borders::BOTTOM)
                    .border_style(Style::default().fg(theme_border())),
            ),
        rows[0],
    );

    let journey = if frame.area().width >= 108 {
        Line::from(vec![
            Span::styled("  快速开始  ", badge_style(theme_blue())),
            Span::styled("  登录账户  ", Style::default().fg(theme_text())),
            Span::styled("›", Style::default().fg(theme_muted())),
            Span::styled(" 选择模型  ", Style::default().fg(theme_text())),
            Span::styled("›", Style::default().fg(theme_muted())),
            Span::styled(" 自动部署  ", Style::default().fg(theme_text())),
            Span::styled("›", Style::default().fg(theme_muted())),
            Span::styled(" 贡献或调用  ", Style::default().fg(theme_text())),
            Span::styled(
                "     M 模型库   R 本机推荐   D 自动部署",
                Style::default()
                    .fg(theme_accent())
                    .add_modifier(Modifier::BOLD),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled("  QUICK  ", badge_style(theme_blue())),
            Span::styled(
                "  M 模型库    R 本机推荐    D 自动部署    ? 帮助",
                Style::default()
                    .fg(theme_accent())
                    .add_modifier(Modifier::BOLD),
            ),
        ])
    };
    frame.render_widget(
        Paragraph::new(journey)
            .style(Style::default().bg(theme_bg()))
            .block(
                Block::default()
                    .borders(Borders::BOTTOM)
                    .border_style(Style::default().fg(theme_border())),
            ),
        rows[1],
    );

    if frame.area().width >= 108 {
        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(22),
                Constraint::Length(29),
                Constraint::Min(36),
            ])
            .split(rows[2]);
        render_categories(frame, body[0], state);
        render_actions(frame, body[1], state);
        render_detail(frame, body[2], state);
    } else {
        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(18),
                Constraint::Length(24),
                Constraint::Min(26),
            ])
            .split(rows[2]);
        render_categories(frame, body[0], state);
        render_actions(frame, body[1], state);
        render_detail(frame, body[2], state);
    }

    frame.render_widget(
        Paragraph::new(vec![
            editor_line(state),
            Line::from(Span::styled(
                "Enter 执行 · 命令仅由 MindOne 解析，不经过 shell",
                Style::default().fg(theme_muted()),
            )),
        ])
        .style(Style::default().bg(theme_surface()).fg(theme_text()))
        .block(panel_block(
            " COMMAND  命令预览与参数编辑 ",
            state.focus == Focus::Editor,
            theme_blue(),
        ))
        .wrap(Wrap { trim: false }),
        rows[3],
    );

    let footer = vec![
        Line::from(vec![Span::styled(
            "  Tab/←/→ 切换  ↑/↓ 选择  Enter 继续  Esc 返回  ? 帮助  q 退出",
            Style::default().fg(theme_muted()),
        )]),
        Line::from(vec![
            Span::styled("  ● ", Style::default().fg(status_color(state))),
            Span::styled(state.status.clone(), Style::default().fg(theme_text())),
            Span::styled(
                format!(
                    "    焦点 {} · {}",
                    state.focus.label(),
                    state.last_result_summary()
                ),
                Style::default().fg(theme_muted()),
            ),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(footer).style(Style::default().bg(theme_surface())),
        rows[4],
    );

    if let Some(confirmation) = &state.confirmation {
        render_confirmation(frame, confirmation);
    } else if let Some(picker) = &state.model_picker {
        render_model_picker(frame, picker);
    } else if state.show_help {
        render_help(frame);
    }
}

fn render_categories(frame: &mut Frame<'_>, area: Rect, state: &DashboardState) {
    let categories = CATEGORIES
        .iter()
        .enumerate()
        .map(|(index, category)| {
            let shortcut = if index == 9 {
                "0".to_owned()
            } else {
                (index + 1).to_string()
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {shortcut} "), badge_style(theme_surface_alt())),
                Span::raw(format!("  {:<8}", category.title)),
                Span::styled(
                    format!("{:>2}", category.len),
                    Style::default().fg(theme_muted()),
                ),
            ]))
        })
        .collect::<Vec<_>>();
    let widget = List::new(categories)
        .block(panel_block(
            format!(" SPACE  {:02}/{:02} ", state.category + 1, CATEGORIES.len()),
            state.focus == Focus::Category,
            theme_accent(),
        ))
        .highlight_style(highlight_style())
        .highlight_symbol("▌");
    let mut list_state = ListState::default();
    list_state.select(Some(state.category));
    frame.render_stateful_widget(widget, area, &mut list_state);
}

fn render_actions(frame: &mut Frame<'_>, area: Rect, state: &DashboardState) {
    let actions = category_commands(state.category)
        .iter()
        .enumerate()
        .map(|(index, spec)| {
            let marker = match spec.risk {
                ActionRisk::ReadOnly => "○",
                ActionRisk::Confirm => "◆",
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {marker} "),
                    Style::default().fg(match spec.risk {
                        ActionRisk::ReadOnly => theme_blue(),
                        ActionRisk::Confirm => theme_warning(),
                    }),
                ),
                Span::raw(format!("{:02}  {}", index + 1, spec.title)),
            ]))
        })
        .collect::<Vec<_>>();
    let widget = List::new(actions)
        .block(panel_block(
            format!(" ACTION  {} ", CATEGORIES[state.category].title),
            state.focus == Focus::Action,
            theme_blue(),
        ))
        .highlight_style(highlight_style())
        .highlight_symbol("▌");
    let mut list_state = ListState::default();
    list_state.select(Some(state.action));
    frame.render_stateful_widget(widget, area, &mut list_state);
}

fn render_detail(frame: &mut Frame<'_>, area: Rect, state: &DashboardState) {
    let selected = state.selected_spec();
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Min(4)])
        .split(area);
    let risk_color = match selected.risk {
        ActionRisk::ReadOnly => theme_blue(),
        ActionRisk::Confirm => theme_warning(),
    };
    let overview = vec![
        Line::from(vec![
            Span::styled(
                selected.title,
                Style::default()
                    .fg(theme_text())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  {}  ", selected.risk.label()),
                badge_style(risk_color),
            ),
        ]),
        Line::from(Span::styled(
            CATEGORIES[state.category].description,
            Style::default().fg(theme_muted()),
        )),
        Line::from(selected.description),
        Line::from(vec![
            Span::styled("用法  ", Style::default().fg(theme_muted())),
            Span::styled(selected.usage, Style::default().fg(theme_accent())),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(overview)
            .style(Style::default().bg(theme_surface()).fg(theme_text()))
            .block(panel_block(" OVERVIEW  当前操作 ", false, theme_border()))
            .wrap(Wrap { trim: false }),
        sections[0],
    );

    let mut content = vec![Line::from(vec![
        Span::styled("● ", Style::default().fg(status_color(state))),
        Span::styled(state.status.clone(), Style::default().fg(theme_text())),
    ])];
    content.push(Line::from(""));
    content.extend(state.content.iter().cloned().map(Line::from));
    frame.render_widget(
        Paragraph::new(content)
            .style(Style::default().bg(theme_surface()).fg(theme_text()))
            .block(panel_block(" ACTIVITY  结果与记录 ", false, theme_border()))
            .wrap(Wrap { trim: false })
            .scroll((state.scroll, 0)),
        sections[1],
    );
}

fn render_confirmation(frame: &mut Frame<'_>, confirmation: &Confirmation) {
    let area = centered_rect(72, 42, frame.area());
    frame.render_widget(Clear, area);
    let text = vec![
        Line::from(vec![
            Span::styled(" ◆ 需要确认 ", badge_style(theme_warning())),
            Span::styled(
                "  此操作会改变本地或远端状态",
                Style::default()
                    .fg(theme_text())
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("动作  ", Style::default().fg(theme_muted())),
            Span::styled(confirmation.path.clone(), Style::default().fg(theme_blue())),
        ]),
        Line::from(vec![
            Span::styled("命令  ", Style::default().fg(theme_muted())),
            Span::styled(
                confirmation.command_line.clone(),
                Style::default().fg(theme_accent()),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Y  执行  ", badge_style(theme_accent())),
            Span::raw("   "),
            Span::styled("  N / Esc  取消  ", badge_style(theme_surface_alt())),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .style(Style::default().bg(theme_surface()).fg(theme_text()))
            .block(panel_block(" CONFIRM  二次确认 ", true, theme_warning()))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_model_picker(frame: &mut Frame<'_>, picker: &ModelPicker) {
    let area = centered_rect(86, 82, frame.area());
    frame.render_widget(Clear, area);
    let outer = panel_block(" MODEL LIBRARY  选择并自动部署 ", true, theme_accent())
        .style(Style::default().bg(theme_surface()).fg(theme_text()));
    let inner = outer.inner(area);
    frame.render_widget(outer, area);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(2),
        ])
        .split(inner);
    let visible = picker.visible_indices();
    let query = if picker.query.is_empty() {
        "输入厂商或模型名进行过滤…".to_owned()
    } else {
        format!("{}█", picker.query)
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" / ", badge_style(theme_blue())),
            Span::styled(
                format!("  {query}"),
                Style::default().fg(if picker.query.is_empty() {
                    theme_muted()
                } else {
                    theme_text()
                }),
            ),
            Span::styled(
                format!("   {} / {}", visible.len(), picker.models.len()),
                Style::default().fg(theme_muted()),
            ),
        ]))
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(theme_border())),
        ),
        rows[0],
    );

    let repository_width = usize::from(rows[1].width).saturating_sub(30).clamp(18, 60);
    let items = visible
        .iter()
        .filter_map(|index| picker.models.get(*index))
        .map(|model| {
            let rank = model
                .recommended_rank
                .map(|rank| format!("★ 推荐 {rank}"))
                .unwrap_or_else(|| "          ".to_owned());
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {rank:<10} "),
                    Style::default().fg(if model.recommended_rank.is_some() {
                        theme_warning()
                    } else {
                        theme_muted()
                    }),
                ),
                Span::styled(
                    format!(
                        "{:<width$}",
                        picker_repository_label(&model.repository, repository_width),
                        width = repository_width
                    ),
                    Style::default().fg(theme_text()),
                ),
                Span::styled(model.memory.clone(), Style::default().fg(theme_blue())),
            ]))
        })
        .collect::<Vec<_>>();
    let mut list_state = ListState::default();
    if !items.is_empty() {
        list_state.select(Some(picker.selected.min(items.len() - 1)));
    }
    frame.render_stateful_widget(
        List::new(items)
            .highlight_style(highlight_style())
            .highlight_symbol("▌"),
        rows[1],
        &mut list_state,
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" ↑/↓ ", badge_style(theme_surface_alt())),
            Span::raw(" 选择   "),
            Span::styled(" Enter ", badge_style(theme_accent())),
            Span::raw(" 下载并部署   "),
            Span::styled(" Esc ", badge_style(theme_surface_alt())),
            Span::raw(" 关闭  ·  推荐仅表示内存适配，部署仍会实时核验 HF 产物"),
        ]))
        .wrap(Wrap { trim: false }),
        rows[2],
    );
}

fn picker_repository_label(repository: &str, width: usize) -> String {
    if repository.chars().count() <= width {
        return repository.to_owned();
    }
    if width <= 1 {
        return "…".to_owned();
    }
    let mut label = repository.chars().take(width - 1).collect::<String>();
    label.push('…');
    label
}

fn render_help(frame: &mut Frame<'_>) {
    let area = centered_rect(72, 66, frame.area());
    frame.render_widget(Clear, area);
    let text = vec![
        Line::from(Span::styled(
            "导航",
            Style::default()
                .fg(theme_accent())
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("Tab / Shift-Tab / ← / →  切换区域    ↑ / ↓  选择"),
        Line::from("Enter 进入或执行    Esc 返回    q 退出"),
        Line::from(""),
        Line::from(Span::styled(
            "模型快捷操作",
            Style::default()
                .fg(theme_accent())
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("M 打开 65 模型选择器    R 生成本机推荐    D 自动部署首选模型"),
        Line::from("模型选择器内可直接输入关键词；Enter 后仍会显示安全确认。"),
        Line::from(""),
        Line::from(Span::styled(
            "安全",
            Style::default()
                .fg(theme_accent())
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("命令编辑器不调用 shell；认证、写入和生命周期操作必须二次确认。"),
        Line::from("模型下载发生在当前设备，并在运行前执行哈希、格式与内存校验。"),
        Line::from(""),
        Line::from(Span::styled(
            "按 ? 或 Esc 关闭帮助",
            badge_style(theme_blue()),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .style(Style::default().bg(theme_surface()).fg(theme_text()))
            .block(panel_block(" HELP  操作指南 ", true, theme_blue()))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_terminal_too_small(frame: &mut Frame<'_>) {
    let message = vec![
        Line::from(Span::styled(
            "◈ MINDONE",
            Style::default()
                .fg(theme_accent())
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("当前终端窗口太小，无法安全展示完整操作界面。"),
        Line::from(format!(
            "当前 {}×{}；请调整到至少 68×20。",
            frame.area().width,
            frame.area().height
        )),
    ];
    frame.render_widget(
        Paragraph::new(message)
            .style(Style::default().bg(theme_bg()).fg(theme_text()))
            .block(panel_block(" TERMINAL SIZE ", true, theme_warning()))
            .wrap(Wrap { trim: false }),
        centered_rect(72, 48, frame.area()),
    );
}

fn panel_block(title: impl Into<String>, focused: bool, accent: Color) -> Block<'static> {
    let style = if focused {
        Style::default().fg(accent).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme_border())
    };
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(title.into())
        .border_style(style)
}

fn highlight_style() -> Style {
    Style::default()
        .bg(theme_selection())
        .fg(theme_text())
        .add_modifier(Modifier::BOLD)
}

fn badge_style(background: Color) -> Style {
    Style::default()
        .bg(background)
        .fg(theme_text())
        .add_modifier(Modifier::BOLD)
}

fn status_color(state: &DashboardState) -> Color {
    match state.last_exit_code {
        Some(0) | None => theme_accent(),
        Some(_) => theme_error(),
    }
}

const fn theme_bg() -> Color {
    Color::Rgb(8, 12, 21)
}

const fn theme_surface() -> Color {
    Color::Rgb(15, 23, 38)
}

const fn theme_surface_alt() -> Color {
    Color::Rgb(31, 43, 63)
}

const fn theme_selection() -> Color {
    Color::Rgb(31, 62, 77)
}

const fn theme_border() -> Color {
    Color::Rgb(50, 65, 88)
}

const fn theme_text() -> Color {
    Color::Rgb(226, 234, 247)
}

const fn theme_muted() -> Color {
    Color::Rgb(128, 146, 173)
}

const fn theme_accent() -> Color {
    Color::Rgb(53, 211, 179)
}

const fn theme_blue() -> Color {
    Color::Rgb(103, 155, 255)
}

const fn theme_warning() -> Color {
    Color::Rgb(245, 183, 65)
}

const fn theme_error() -> Color {
    Color::Rgb(248, 100, 116)
}

fn editor_line(state: &DashboardState) -> Line<'static> {
    if state.focus != Focus::Editor {
        return Line::from(state.command_line.clone());
    }
    let characters = state.command_line.chars().collect::<Vec<_>>();
    let cursor = state.cursor.min(characters.len());
    let before = characters[..cursor].iter().collect::<String>();
    let current = characters
        .get(cursor)
        .map(char::to_string)
        .unwrap_or_else(|| " ".to_owned());
    let after = characters
        .get(cursor.saturating_add(1)..)
        .unwrap_or_default()
        .iter()
        .collect::<String>();
    Line::from(vec![
        Span::raw(before),
        Span::styled(current, Style::default().bg(theme_accent()).fg(theme_bg())),
        Span::raw(after),
    ])
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

/// 当前进程的 stdin/stdout 是否为交互式终端。非 TTY（管道、重定向、CI）不进入 raw 模式。
pub fn stdout_is_interactive() -> bool {
    io::stdout().is_terminal() && io::stdin().is_terminal()
}

fn command_trace_level(verbose: u8) -> &'static str {
    match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    }
}

/// 启动 TUI 主循环。
pub async fn run() -> CliResult<u8> {
    if !stdout_is_interactive() {
        return Err(CliError::General(
            "图形界面需要交互式终端。请在真实终端中运行 `mindone`；若在管道或脚本中使用，请改用具体子命令（见 `mindone --help`）"
                .to_owned(),
        ));
    }

    let mut context = AppContext::load()?;
    let mut header = read_header(&context);
    let mut guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)
        .map_err(|error| CliError::General(format!("无法初始化终端界面：{error}")))?;
    let mut state = DashboardState::default();

    loop {
        terminal
            .draw(|frame| render(frame, &header, &state))
            .map_err(|error| CliError::General(format!("终端界面渲染失败：{error}")))?;
        if state.should_quit {
            break;
        }

        let has_event = event::poll(Duration::from_millis(200))
            .map_err(|error| CliError::General(format!("读取终端事件失败：{error}")))?;
        if !has_event {
            continue;
        }
        let next_event = event::read()
            .map_err(|error| CliError::General(format!("读取终端事件失败：{error}")))?;
        let intent = match next_event {
            Event::Key(key) if key.kind == KeyEventKind::Press => state.handle_key(key),
            Event::Paste(text) if state.focus == Focus::Editor && state.confirmation.is_none() => {
                state.insert_text(&text);
                UiIntent::None
            }
            _ => UiIntent::None,
        };

        let command_line = match intent {
            UiIntent::None => continue,
            UiIntent::Prepare(command_line) => match prepare_command_line(&command_line) {
                Ok(prepared) if prepared.risk == ActionRisk::Confirm => {
                    state.request_confirmation(command_line, prepared.path);
                    continue;
                }
                Ok(_) => command_line,
                Err(error) => {
                    state.set_parse_error(&error);
                    continue;
                }
            },
            UiIntent::ExecuteConfirmed(command_line) => command_line,
        };

        // 二次确认完成后重新解析，确保真正执行的结构与确认时完全相同；确认弹窗期间
        // 编辑器不可变，重复解析仍能防止将未校验结构带入业务分发。
        let prepared = match prepare_command_line(&command_line) {
            Ok(prepared) => prepared,
            Err(error) => {
                state.set_parse_error(&error);
                continue;
            }
        };
        state.status = format!("正在执行 {}", prepared.path);
        terminal
            .draw(|frame| render(frame, &header, &state))
            .map_err(|error| CliError::General(format!("终端界面渲染失败：{error}")))?;
        terminal
            .show_cursor()
            .map_err(|error| CliError::General(format!("无法恢复终端光标：{error}")))?;
        guard.suspend()?;

        println!(
            "MindOne TUI 已暂停，正在执行 `mindone {}`。长期运行的命令可按 Ctrl-C 停止。",
            prepared.path
        );
        io::stdout()
            .flush()
            .map_err(|error| CliError::General(format!("无法显示命令执行提示：{error}")))?;
        let path = prepared.path;
        let verbose = prepared.cli.verbose;
        let command_subscriber = tracing_subscriber::fmt()
            .with_env_filter(command_trace_level(verbose))
            .with_target(false)
            .with_writer(io::stderr)
            .finish();
        let result = crate::app::execute(prepared.cli)
            .with_subscriber(command_subscriber)
            .await;
        let refreshed_context = AppContext::load();

        // 无论业务命令成功或失败，都先恢复终端，再在 TUI 中展示结构化结果。
        guard.resume()?;
        terminal
            .clear()
            .map_err(|error| CliError::General(format!("无法清理恢复后的终端界面：{error}")))?;
        terminal
            .hide_cursor()
            .map_err(|error| CliError::General(format!("无法隐藏终端光标：{error}")))?;

        match result {
            Ok((mode, output)) => state.set_output(&path, mode, output),
            Err(error) => state.set_execution_error(&path, error),
        }
        match refreshed_context {
            Ok(refreshed) => {
                context = refreshed;
                header = read_header(&context);
            }
            Err(error) => state.append_context_error(&error),
        }
    }

    let exit_code = state.process_exit_code();
    terminal
        .show_cursor()
        .map_err(|error| CliError::General(format!("无法恢复终端光标：{error}")))?;
    Ok(exit_code)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use clap::CommandFactory;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use super::{
        category_commands, command_spec, command_trace_level, prepare_command_line, render,
        split_command_line, ActionRisk, DashboardState, Focus, HeaderInfo, ModelPicker, UiIntent,
        CATEGORIES, COMMANDS,
    };
    use crate::cli::{Cli, Command, ConfigCommand, QuotaCommand};
    use crate::output::{CommandOutput, OutputMode};

    #[test]
    fn tui_catalog_exactly_matches_every_public_clap_leaf() {
        let catalog = COMMANDS
            .iter()
            .map(|spec| spec.path.to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(catalog.len(), 40, "TUI 公开命令目录不得重复或缺项");

        let mut discovered = BTreeSet::new();
        collect_public_leaf_paths(&Cli::localized_command(), "", &mut discovered);
        assert_eq!(catalog, discovered, "TUI 必须与公开 Clap 叶子精确对等");
        assert!(!catalog.iter().any(|path| path.starts_with("__worker")));
    }

    #[test]
    fn categories_partition_all_commands() {
        assert_eq!(CATEGORIES.len(), 10);
        let mut next_start = 0;
        for (index, category) in CATEGORIES.iter().enumerate() {
            assert_eq!(category.start, next_start, "分类 {index} 必须连续分区");
            assert!(category.len > 0, "每个分类至少包含一个动作");
            assert_eq!(category_commands(index).len(), category.len);
            next_start += category.len;
        }
        assert_eq!(next_start, COMMANDS.len());
    }

    #[test]
    fn quote_parser_supports_quotes_escapes_and_empty_values_without_shell_expansion() {
        assert_eq!(
            split_command_line(
                r#"mindone config set cloudflare.hostname "api.example.com" 'literal $HOME' empty\ value "" C:\models\demo.gguf"#
            )
            .expect("应安全分词"),
            [
                "mindone",
                "config",
                "set",
                "cloudflare.hostname",
                "api.example.com",
                "literal $HOME",
                "empty value",
                "",
                r"C:\models\demo.gguf",
            ]
        );
        assert!(split_command_line("mindone config get 'server.url").is_err());
        assert_eq!(
            split_command_line(r#"mindone serve run --model "C:\My Models\demo.gguf""#)
                .expect("Windows 路径中的反斜杠必须保留"),
            [
                "mindone",
                "serve",
                "run",
                "--model",
                r"C:\My Models\demo.gguf"
            ]
        );
    }

    #[test]
    fn localized_clap_parses_quoted_public_commands_and_optional_program_name() {
        let prepared =
            prepare_command_line(r#"mindone config set cloudflare.hostname "api.example.com""#)
                .expect("配置命令应解析");
        assert_eq!(prepared.path, "config set");
        assert_eq!(prepared.risk, ActionRisk::Confirm);
        let Command::Config(args) = prepared.cli.command else {
            panic!("应为 config 命令");
        };
        let ConfigCommand::Set(args) = args.command else {
            panic!("应为 config set 命令");
        };
        assert_eq!(args.key, "cloudflare.hostname");
        assert_eq!(args.value, "api.example.com");

        let prepared = prepare_command_line("quota history --page 2 --page-size 25")
            .expect("省略程序名也应解析");
        assert_eq!(prepared.path, "quota history");
        let Command::Quota(args) = prepared.cli.command else {
            panic!("应为 quota 命令");
        };
        let QuotaCommand::History(args) = args.command else {
            panic!("应为 quota history 命令");
        };
        assert_eq!((args.page, args.page_size), (2, 25));
    }

    #[test]
    fn global_output_flags_parse_before_or_after_public_leaf_commands() {
        let before = prepare_command_line("mindone --json quota balance -vv")
            .expect("全局参数应可位于叶子命令之前");
        assert_eq!(before.path, "quota balance");
        assert!(before.cli.json);
        assert!(!before.cli.quiet);
        assert_eq!(before.cli.verbose, 2);

        let between = prepare_command_line("mindone quota --json balance -v")
            .expect("全局参数应可位于命令层级之间");
        assert_eq!(between.path, "quota balance");
        assert!(between.cli.json);
        assert_eq!(between.cli.verbose, 1);

        let after = prepare_command_line("mindone quota balance --quiet")
            .expect("全局参数应可位于叶子命令之后");
        assert_eq!(after.path, "quota balance");
        assert!(!after.cli.json);
        assert!(after.cli.quiet);
        assert_eq!(after.cli.verbose, 0);

        assert!(prepare_command_line("mindone doctor --quiet --verbose").is_err());
        assert_eq!(command_trace_level(0), "warn");
        assert_eq!(command_trace_level(1), "info");
        assert_eq!(command_trace_level(2), "debug");
        assert_eq!(command_trace_level(3), "trace");
    }

    #[test]
    fn hidden_worker_and_incomplete_or_invalid_commands_are_rejected() {
        let worker = prepare_command_line("mindone __worker resolve-data-dir")
            .expect_err("隐藏 worker 不得从 TUI 执行");
        assert!(worker.to_string().contains("只允许执行公开命令"));
        assert!(prepare_command_line("mindone model download").is_err());
        assert!(prepare_command_line("mindone quota history --page 0").is_err());
    }

    #[test]
    fn every_auth_write_and_lifecycle_action_requires_confirmation() {
        let confirmed = COMMANDS
            .iter()
            .filter(|spec| spec.risk == ActionRisk::Confirm)
            .map(|spec| spec.path)
            .collect::<BTreeSet<_>>();
        let expected = [
            "auth attest",
            "auth login",
            "auth logout",
            "api create",
            "api revoke",
            "config set",
            "engine install",
            "engine set-default",
            "model delete",
            "model deploy",
            "model download",
            "model verify",
            "node policy set",
            "node threshold set",
            "quota use",
            "serve run",
            "serve stop",
            "share publish",
            "share unpublish",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(confirmed, expected);
        for path in [
            "auth status",
            "api info",
            "api list",
            "api models",
            "model catalog",
            "model list",
            "model probe",
            "model recommend",
            "engine detect",
            "serve status",
            "share stats",
            "quota history",
            "node optimize",
            "config list",
            "doctor",
        ] {
            assert_eq!(
                command_spec(path).map(|spec| spec.risk),
                Some(ActionRisk::ReadOnly),
                "只读动作 {path} 不应要求写操作确认"
            );
        }
    }

    #[test]
    fn state_machine_navigates_edits_and_confirms_without_executing() {
        let mut state = DashboardState::default();
        assert_eq!(state.focus, Focus::Category);
        assert_eq!(state.command_line, "mindone auth login");
        assert_eq!(state.process_exit_code(), 0);

        assert_eq!(state.handle_key(key(KeyCode::Char('9'))), UiIntent::None);
        assert_eq!(state.category, 8);
        assert_eq!(state.command_line, "mindone config set");
        state.handle_key(key(KeyCode::Enter));
        assert_eq!(state.focus, Focus::Action);
        state.handle_key(key(KeyCode::Down));
        assert_eq!(state.command_line, "mindone config get");
        state.handle_key(key(KeyCode::Enter));
        assert_eq!(state.focus, Focus::Editor);
        state.insert_text(" server.url");
        assert_eq!(
            state.handle_key(key(KeyCode::Enter)),
            UiIntent::Prepare("mindone config get server.url".to_owned())
        );

        state.request_confirmation(
            "mindone config set log.level debug".to_owned(),
            "config set".to_owned(),
        );
        assert_eq!(state.handle_key(key(KeyCode::Char('n'))), UiIntent::None);
        assert!(state.confirmation.is_none());
        assert!(state.status.contains("已取消"));

        state.request_confirmation(
            "mindone config set log.level debug".to_owned(),
            "config set".to_owned(),
        );
        assert_eq!(
            state.handle_key(key(KeyCode::Char('y'))),
            UiIntent::ExecuteConfirmed("mindone config set log.level debug".to_owned())
        );
        assert!(state.confirmation.is_none());
    }

    #[test]
    fn model_picker_contains_catalog_prioritizes_recommendations_and_filters() {
        let ranks =
            std::collections::BTreeMap::from([("Qwen/Qwen3.5-0.8B", 1), ("Qwen/Qwen3-0.6B", 2)]);
        let mut picker = ModelPicker::from_recommendation_ranks(&ranks);
        assert_eq!(picker.models.len(), 65);
        assert_eq!(picker.models[0].recommended_rank, Some(1));
        assert_eq!(picker.models[1].recommended_rank, Some(2));
        assert_eq!(picker.visible_indices().len(), 65);

        for character in "phi-4".chars() {
            picker.push_query(character);
        }
        let matches = picker
            .visible_indices()
            .into_iter()
            .map(|index| picker.models[index].repository.clone())
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 2);
        assert!(matches
            .iter()
            .all(|repository| repository.contains("Phi-4")));
        assert!(picker.selected_repository().is_some());
    }

    #[test]
    fn quick_actions_and_picker_route_through_normal_command_preparation() {
        let mut state = DashboardState::default();
        assert_eq!(
            state.handle_key(key(KeyCode::Char('R'))),
            UiIntent::Prepare("mindone model recommend --limit 5".to_owned())
        );
        assert_eq!(state.selected_spec().path, "model recommend");

        assert_eq!(
            state.handle_key(key(KeyCode::Char('D'))),
            UiIntent::Prepare("mindone model deploy auto".to_owned())
        );
        assert_eq!(state.selected_spec().path, "model deploy");

        assert_eq!(state.handle_key(key(KeyCode::Char('M'))), UiIntent::None);
        let picker = state.model_picker.as_mut().expect("应打开模型选择器");
        picker.query = "Qwen/Qwen3-0.6B".to_owned();
        picker.selected = 0;
        assert_eq!(
            state.handle_key(key(KeyCode::Enter)),
            UiIntent::Prepare("mindone model deploy Qwen/Qwen3-0.6B".to_owned())
        );
        assert!(state.model_picker.is_none());
        assert_eq!(state.selected_spec().path, "model deploy");
    }

    #[test]
    fn required_mvp_user_journeys_parse_through_the_same_tui_cli_bridge() {
        let journeys = [
            ("mindone auth login --no-open", "auth login", ActionRisk::Confirm),
            ("mindone auth status", "auth status", ActionRisk::ReadOnly),
            ("mindone quota balance", "quota balance", ActionRisk::ReadOnly),
            ("mindone share stats", "share stats", ActionRisk::ReadOnly),
            ("mindone api info", "api info", ActionRisk::ReadOnly),
            ("mindone api create --name desktop", "api create", ActionRisk::Confirm),
            ("mindone api list", "api list", ActionRisk::ReadOnly),
            (
                "mindone api revoke 018f8f5d-9148-7f2a-8c21-6c01b0176a22",
                "api revoke",
                ActionRisk::Confirm,
            ),
            ("mindone api models", "api models", ActionRisk::ReadOnly),
            (
                "mindone model catalog --query qwen",
                "model catalog",
                ActionRisk::ReadOnly,
            ),
            (
                "mindone model recommend --limit 5",
                "model recommend",
                ActionRisk::ReadOnly,
            ),
            (
                "mindone model probe Qwen/Qwen3-0.6B --deployment --metadata-only",
                "model probe",
                ActionRisk::ReadOnly,
            ),
            (
                "mindone model deploy Qwen/Qwen3-0.6B --port 8081 --replace",
                "model deploy",
                ActionRisk::Confirm,
            ),
            (
                "mindone model download --platform huggingface --repo ggml-org/Qwen3-0.6B-GGUF --file Qwen3-0.6B-Q4_0.gguf",
                "model download",
                ActionRisk::Confirm,
            ),
            ("mindone model list", "model list", ActionRisk::ReadOnly),
            (
                "mindone model verify qwen3-0.6b",
                "model verify",
                ActionRisk::Confirm,
            ),
            (
                "mindone model delete qwen3-0.6b --yes",
                "model delete",
                ActionRisk::Confirm,
            ),
            (
                "mindone serve run --model qwen3-0.6b --port 8082",
                "serve run",
                ActionRisk::Confirm,
            ),
            (
                "mindone serve status --port 8081",
                "serve status",
                ActionRisk::ReadOnly,
            ),
            (
                "mindone serve status --port 8082",
                "serve status",
                ActionRisk::ReadOnly,
            ),
            (
                "mindone serve stop --port 8081",
                "serve stop",
                ActionRisk::Confirm,
            ),
            (
                "mindone node policy set --max-concurrent 3",
                "node policy set",
                ActionRisk::Confirm,
            ),
        ];

        for (command_line, expected_path, expected_risk) in journeys {
            let prepared = prepare_command_line(command_line)
                .unwrap_or_else(|error| panic!("TUI 必须接受 `{command_line}`：{error}"));
            assert_eq!(prepared.path, expected_path, "命令：{command_line}");
            assert_eq!(prepared.risk, expected_risk, "命令：{command_line}");
        }
    }

    #[test]
    fn redesigned_dashboard_and_model_picker_render_on_wide_and_compact_terminals() {
        let header = HeaderInfo {
            user: "测试用户".to_owned(),
            trust: "Standard".to_owned(),
            server: "https://api.holarchic.cn/".to_owned(),
        };
        let state = DashboardState::default();
        let wide = render_to_text(140, 40, &header, &state);
        for expected in [
            "MINDONE", "SPACE", "ACTION", "OVERVIEW", "ACTIVITY", "COMMAND",
        ] {
            assert!(wide.contains(expected), "宽屏应包含 {expected}");
        }

        let compact = render_to_text(90, 30, &header, &state);
        assert!(compact.contains("MINDONE"));
        assert!(compact.contains("SPACE"));
        assert!(compact.contains("ACTIVITY"));

        let picker_state = DashboardState {
            model_picker: Some(ModelPicker::new()),
            ..DashboardState::default()
        };
        let picker = render_to_text(140, 40, &header, &picker_state);
        assert!(picker.contains("MODEL LIBRARY"));
        assert!(picker.contains("Qwen/"));
    }

    #[test]
    fn command_output_and_nonzero_exit_code_are_preserved() {
        let mut state = DashboardState::default();
        let output = CommandOutput::new("[警告] 沙盒能力已降级", serde_json::json!({"checks": 12}))
            .expect("应创建输出")
            .with_exit_code(31);
        state.set_output(
            "doctor",
            OutputMode {
                json: false,
                quiet: false,
                verbose: 0,
            },
            output,
        );
        assert_eq!(state.last_exit_code, Some(31));
        assert_eq!(state.process_exit_code(), 31);
        let preserved = state.last_output.as_ref().expect("应保留完整命令输出");
        assert_eq!(preserved.exit_code, 31);
        assert_eq!(preserved.data["checks"], 12);
        assert!(state.status.contains("31"));
        assert!(state.content.iter().any(|line| line == "退出码：31"));
    }

    #[test]
    fn quiet_mode_preserves_result_metadata_but_suppresses_human_body() {
        let mut state = DashboardState::default();
        let output = CommandOutput::new(
            "此业务正文不得在 quiet 模式显示",
            serde_json::json!({"value": 7}),
        )
        .expect("应创建输出");
        state.set_output(
            "config list",
            OutputMode {
                json: false,
                quiet: true,
                verbose: 0,
            },
            output,
        );

        assert_eq!(state.last_exit_code, Some(0));
        assert_eq!(state.process_exit_code(), 0);
        assert!(state.last_output.is_some(), "应保留完整 CommandOutput");
        assert!(state.content.iter().any(|line| line == "退出码：0"));
        assert!(!state
            .content
            .iter()
            .any(|line| line.contains("此业务正文不得")));
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn render_to_text(
        width: u16,
        height: u16,
        header: &HeaderInfo,
        state: &DashboardState,
    ) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("应创建测试终端");
        terminal
            .draw(|frame| render(frame, header, state))
            .expect("应渲染 TUI");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<Vec<_>>()
            .join("")
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

    #[test]
    fn clap_command_factory_still_builds_the_same_root_for_catalog_test() {
        // 显式使用 CommandFactory，避免将目录测试意外退化为只验证手写常量。
        let command = <Cli as CommandFactory>::command();
        assert_eq!(command.get_name(), "mindone");
    }
}
