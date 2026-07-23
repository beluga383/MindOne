# MindOne CLI v1.0.2 合规矩阵

本文件覆盖 `docs/specs/mindone_cli_1.0.0.md` 与总任务的并集；冲突时以总任务为准。这里记录的是当前源码与已经取得的证据，不把“代码存在”写成“验收通过”。

状态定义：

- `完成（本地自动测试）`：当前工作树中的对应确定性测试已在本机实际通过。
- `完成（本机实测）`：依赖本机平台能力的专门 smoke 已实际通过。
- `部分完成`：本地实现和测试已存在，但完整合同还依赖 PostgreSQL、真实进程或外部联调。
- `待最终复验`：此前已有证据，但并行改动后尚未重新跑最终门禁，不宣称当前提交通过。
- `待外部验证`：必须依赖 GitHub/GitHub Actions、Cloudflare、多平台 runner、真实 TEE/GPU 硬件或正式签名。

下表中的 `模块::tests::用例` 表示测试与同一行列出的真实源码文件同置；独立集成测试均写出完整文件路径。

各功能行保留的是最近一次与该行为直接相关的证据；是否已经满足**当前工作树**的最终发布门禁，以第 0 节和第 13 节为准。当前源码为连续 `0001..0039`：`0038` 增加三档任务速度，`0039` 增加 HMAC-only 推理 API Key 及只追加审计事件。本机 live production 仍停留在已经验证的 26 个 migration；下文 fresh-v36/v37 和 workspace `556/0/5` 均是新增 0038/0039 前的历史阶段证据，不能冒充当前全量门禁。

## 0. 当前证据快照（2026-07-23）

| 已实际运行的命令/检查 | 结果 | 未覆盖内容 |
|---|---|---|
| 当前 workspace fmt/check/strict Clippy/tests | macOS 主机全 workspace all-target/all-feature check 和 `-D warnings` 退出 0；全 workspace 31 个 result set 为 `590 passed / 0 failed / 5 ignored`。Windows x86_64 MSVC 交叉环境也已完成全 workspace/all-target/all-feature check 与严格 Clippy，公开 Windows Runner 原生编译已通过 | ignored 保留外部资源/平台门禁；Windows 交互式系统能力仍须真机验证 |
| 当前 CLI/TUI 完整门禁 | CLI lib `176 passed / 0 failed / 1 ignored`；40 叶子/10 分类精确对等、多端口与平台资产映射均通过 | 回环/真实 macOS capability 测试须在未受额外沙箱限制的本机运行；已退出 worker 的回收测试先确定性等待并回收子进程，再验证启动失败合同，不再依赖 2 秒调度窗口 |
| 历史 workspace fmt/check/strict Clippy/tests | 29 个 result set 合计 `556 passed / 0 failed / 5 ignored`，退出 0 | 早于 0038/0039、模型目录与公网网关，仅作基线 |
| 历史 fresh PostgreSQL `mindone_gate_0036_full_20260719b` 上的 13 个 coordinator integration binary | 合计 `41/41`、无 skip；sqlx metadata `36|1|36|t` | 只证明历史 v36；证据库必须保留，不得复用或清理 |
| 当前 migration / fresh v39 数据库 | migration 文件连续 `0001..0039`；一次性 PostgreSQL 17 上 16 个 binary 各用独立数据库，合计 `49/49`、无 skip；持久库 metadata `39|1|39|t` | 独立数据库避免 `database_role` 的故意错误 HMAC commitment 污染其他 binary；不替代 production 升级 |
| macOS Seatbelt ignored/env-gated gate | 当前显式运行 `MINDONE_REAL_SEATBELT_TEST=1` 为 1/1 passed，覆盖允许目标写入、拒绝越权写入和拒绝 sibling 模型；普通 workspace 测试仍保持 ignored | 当前本机真实门禁通过；仍需 macOS Actions 在干净 runner 复验 |
| Shell / release 安装卸载 smoke | 当前 `mindone 1.0.2` / `aarch64-apple-darwin` 二进制已通过归档 SHA-256、安装、`--check`、重装、中文帮助/版本、doctor JSON、默认保留数据卸载与 purge；公开 latest 资产又在隔离目录完成远程安装和真实 80×24 PTY 裸 TUI 渲染/退出 | v1.0.2 Release、五平台资产、SBOM、Sigstore 与 provenance 已另行验证；Apple/Windows 平台原生签名仍未配置 |
| RustSec、cargo-deny、Gitleaks、actionlint | 当前树使用 cargo-audit 0.22.2 联网刷新到 1167 条 advisory 后扫描 489 个 lockfile 依赖，0 vulnerability / 0 warning；`cargo deny check` 与 actionlint 1.7.12 退出 0，3 个 workflow YAML 均可解析；Gitleaks 8.30.1 对排除本机构建缓存后的 237 个实际项目文件（约 4.38 MB）扫描通过。公开 Security workflow 的 RustSec、cargo-deny 与完整 Git 历史 Gitleaks 已在候选提交上 3/3 通过。TUI 已升级到 ratatui 0.30.2 / crossterm 0.29，移除旧 `lru 0.12.5` 与 `paste`，advisory ignore 为空 | 依赖数据库已在本轮刷新；正式发行仍要求标签所指精确提交的 Security 与 CI 同时全绿 |
| Compose 静态配置门禁 | base、Cloudflare public overlay、quality operator overlay、dev 的规范化 Compose 断言全部通过，4/4 | 只证明当前配置结构；专用 Cloudflare tunnel、hostname 与公网请求仍待用户确认后的外部验证 |
| 本机 production 备份、升级与切换 | 当前 v26 custom dump 已校验 328 项 TOC 并恢复到独立 PostgreSQL 17；修复 migration 14 末尾空行 checksum 漂移后，恢复副本真实 `26→39` 成功，metadata `39|1|39|t`，0037/0038/0039 对象与零业务行保持均已核对；live 仍为 `26|1|26|t` | live coordinator 尚未停止、迁移或切换；短时 API 中断需单独明确确认，不能把恢复副本冒充 production |
| `scripts/e2e-test.sh` | 历史 debug CPU-only E2E 从头退出 0；当前公开 Linux E2E 又以四槽/统一 KV 参数实际完成 fresh PostgreSQL v39、两个隔离 Home/账号/device、官方 llama.cpp b10064、Qwen3-0.6B-Q4_0 GGUF、public canary、chat/completions 非流式、两类 SSE、游标恢复、Standard 密文、三轨唯一结算、策略改变拒绝零结算、Regulated `stream:true` 拒绝和安全清理 | Prompt/Response 审计现从 `serve --json` 的权威 `log_path` 定位非默认端口活动/轮转日志；发行结论只取精确候选完整 Actions 终态 |

## 1. 全局 CLI 合同

| 规范项 | 真实实现 | 自动化证据 | 状态 |
|---|---|---|---|
| 根命令与版本 | `crates/mindone-cli/src/cli.rs`、workspace version `1.0.2` | `crates/mindone-cli/tests/cli_contract.rs` 中的 root help/version 用例 | 完成（本地自动测试） |
| 全部帮助简体中文 | `crates/mindone-cli/src/cli.rs::localized_command` | `cli::tests::every_public_help_page_is_fully_localized` | 完成（本地自动测试） |
| `-h` / `--help` / `-V` / `--version` | `crates/mindone-cli/src/cli.rs` | `cli_contract.rs`、`cli::tests::global_flags_work_after_subcommands` | 完成（本地自动测试） |
| `--json` 稳定成功/错误 envelope | `crates/mindone-cli/src/output.rs`、`crates/mindone-common/src/error.rs` | `output::tests::{json_error_has_stable_contract,trust_downgrade_json_is_not_ok_and_preserves_complete_data}`、`cli_contract.rs::json_parse_error_uses_stable_contract_and_chinese_message` | 完成（本地自动测试） |
| `--quiet` 不吞 JSON/错误，且只抑制人类可读输出而不改退出码 | `crates/mindone-cli/src/output.rs` | `output::tests::{quiet_suppresses_success_but_not_error,human_and_quiet_modes_only_control_rendering_not_exit_code}` | 完成（本地自动测试） |
| `--verbose` 与 quiet 冲突；TUI 命令按自身 verbose 级别输出日志 | `crates/mindone-cli/src/cli.rs`、`crates/mindone-cli/src/tui.rs` | `cli::tests::quiet_conflicts_with_verbose`、TUI 全局参数解析测试 | 完成（本地自动测试）；TUI 执行期间按命令级 subscriber 应用 warn/info/debug/trace |
| 公开子命令集合 | `auth api model engine serve share quota node config doctor help`；内部 worker 隐藏于 `crates/mindone-cli/src/cli.rs` | `root_help_contains_all_public_commands_and_chinese`、`every_public_leaf_command_has_a_successful_parse_case`、缺失/非法/冲突三组参数矩阵；当前 40 个公开叶子全覆盖 | 完成（本地定向测试） |
| 终端图形界面（TUI）：交互式终端裸 `mindone` 或 `mindone ui` 启动；新版工作台用 Space/Action/Overview/Activity/Command 分层，10 类/40 个动作与全部公开 CLI 叶子精确对应；`M` 打开 65 模型选择器、推荐置顶并可过滤，`R` 推荐、`D` 自动部署、`?` 帮助；可编辑完整参数并复用同一 Clap 与 `app::execute`；非 TTY 回退帮助/明确错误 | `crates/mindone-cli/src/tui.rs`、`crates/mindone-cli/src/main.rs` | `tui::tests` 确定性覆盖连续分区、40 公开叶子精确集合、模型选择器 65 项/推荐/过滤/命令路由、宽屏与紧凑渲染、安全分词、内部 worker/不完整参数拒绝、确认风险全集、状态机和非零 `exit_code` 保留；`cli_contract` 另验证非 TTY 裸调用输出中文帮助并成功退出；真实 80×24 PTY 检查主界面、模型弹层和终端恢复 | 完成（本地自动与 PTY 测试）；`1-9`/`0` 访问全部 10 类，低于 68×20 明确提示调整窗口 |
| 远程单命令安装后直接进入 TUI | Unix `install.sh --launch`、Windows `install.ps1 -Launch`；交互式终端启动已安装 CLI，非交互/CI 安全降级为真实帮助页；默认只写当前用户受管 PATH，可显式关闭 | Unix release smoke 验证受管 PATH 唯一性、新 shell 裸 `mindone` 与卸载清理；Windows Actions 验证用户 PATH/当前进程 PATH、裸命令、`-Launch` 降级与卸载；v1.0.2 latest 资产和 checksum 直链返回 200 | 远程安装资产已发布；Windows 交互 TUI 和模型启动仍待用户真机 |

### 1.1 公开叶子命令与参数合同

`cli::tests::every_public_leaf_command_has_a_successful_parse_case` 会从 Clap 命令树递归枚举所有非隐藏叶子，并与下表同源的 40 个成功解析用例做精确集合比较；新增或遗漏任何公开叶子都会让测试失败。`every_required_public_parameter_has_a_missing_value_case`、`typed_ranges_formats_and_enums_fail_during_clap_parsing`、`every_public_conflict_contract_is_enforced` 分别覆盖缺失必填、非法格式/范围/枚举和冲突。

| 公开叶子命令 | 位置参数与选项合同 | 主要行为与业务错误码 | 解析状态 |
|---|---|---|---|
| `auth login` | `--no-open` 可选，默认自动打开浏览器 | 设备流登录与系统凭证库；认证错误 `10` | 完成 |
| `auth logout` | 无业务参数 | 服务端撤销并清理本机凭证；`10` | 完成 |
| `auth status` | 无业务参数 | 查询权威身份/Trust；`10` | 完成 |
| `auth attest` | 无业务参数 | 真实硬件证明，无能力时拒绝；`30`/`31` | 完成；真实 TEE 待外部验证 |
| `api info` | 无业务参数 | 显示 Base URL、端点和三档速度说明 | 完成 |
| `api create` | 必填 `--name` | 创建 HMAC-only 推理 Key，Secret 只显示一次；`10` | fresh-v39 真实 PostgreSQL E2E 通过 |
| `api list` | 无业务参数 | 只列 Key ID/名称/前缀/状态；`10` | fresh-v39 真实 PostgreSQL E2E 通过 |
| `api revoke` | 必填 UUID | 幂等撤销推理 Key；`10` | fresh-v39 真实 PostgreSQL E2E 通过 |
| `api models` | 无业务参数 | 在线模型与 fast/standard/slow 名称；`10` | 实现完成；公网待验证 |
| `model list` | 无业务参数 | 读取真实登记与当前验证状态；`1`/`21` | 完成 |
| `model catalog` | 可选 `--query` | 65 项 HF 目标目录，下载位置为 client | 完成 |
| `model recommend` | `--limit=3`，范围 1..=10 | 真实硬件探测与 70% 保守预算 | 完成 |
| `model probe` | 必填目录模型；可选 `--deployment/--metadata-only/--branch/--file` | `--metadata-only` 只读 HF 清单；普通模式最多 64 KiB 后中止，均不落盘 | 确定性测试与 Qwen3-0.6B 公网探测通过；全目录纯元数据审计由 `scripts/audit-hf-model-catalog.sh` 显式执行 |
| `model deploy` | `model=auto`；`--port=8080`；可选 `--replace` | 自动选择 GGUF、下载校验、安装引擎并健康启动 | 当前日常审计只做 Qwen3-0.6B 的 64 KiB 探测；公开 Linux E2E 已对同一小模型完成整包下载、验证、启动和业务链 |
| `model download` | 必填 `--platform huggingface\|modelscope` 与 `--repo`；`--branch=main`；可选 `--name`、`--file`、`--sha256` 64-hex | TLS 下载、可信清单解析、哈希和格式验证；`1`/`21` | 本地确定性测试完成；ModelScope 真实公网 artifact 待外部 smoke |
| `model delete` | 必填位置参数 `model`；`-y/--yes` 可选 | 在用保护、确认后删除真实文件与登记；`1`/`21` | 完成 |
| `model verify` | 必填位置参数 `model` | 重算哈希与结构；`21` | 完成 |
| `engine list` | 无业务参数 | 列出实际可用/已安装引擎；`20` | 完成 |
| `engine install` | 必填 `--name vllm\|llama.cpp\|ollama\|tensorrt-llm`；`--version=latest` | 隔离安装并验证官方资产；`20` | 完成；平台真实 smoke 分项验证 |
| `engine detect` | 无业务参数 | 探测真实 OS/CPU/RAM/GPU 能力；`20` | 完成 |
| `engine set-default` | 必填位置引擎枚举 | 只接受已安装、未篡改且可服务的适配器；`1`/`20` | 完成 |
| `serve run` | 必填 `--model`；可选 `--engine`、`--config`；`--port=8080`且范围 `1..=65535` | 强化沙箱中启动回环推理服务；健康等待按完整模型 GiB 从 60 秒递增并封顶 30 分钟；`20`/`21` | 完成 |
| `serve stop` | `--port=8080`；`--timeout=10`（秒） | PID/启动标记复验后优雅停止指定端口实例；`20` | 完成 |
| `serve status` | `--port=8080` | 指定端口的真实进程、health、沙箱和资源状态；`20` | 完成 |
| `share publish` | 必填 `--model`；`--port=8080`；可选 `--alias`、逗号分隔 `--tags` | 绑定指定端口的健康受管实例，注册节点/实例、首次心跳后上线；`10`/`20`/`21` | 完成 |
| `share unpublish` | `--id UUID` 与 `--model` 互斥；`--timeout=30` | 停止领取、排空、取消发布；`1`/`10`/`20` | 完成 |
| `share stats` | 无业务参数 | 权威请求/性能/Trust/Tier/收益；`10` | 完成 |
| `quota balance` | 无业务参数 | 可用额度、贡献值、Tier 与准备金；`10` | 完成 |
| `quota history` | `--page=1` 且 `1..=10000`；`--page-size=50` 且 `1..=200`；`--from/--to` 必须 RFC 3339，运行时要求 from < to | 分页查询不可变账本；`1`/`10` | 完成 |
| `quota receipt` | 必填 `--id UUID` | 查询指定荣誉账单；`1`/`10` | 完成 |
| `quota use` | `--model=auto`；`--port=9090`且 `1..=65535`；`--confidentiality=standard\|regulated` | 启动回环 OpenAI 兼容代理；`10`/`30`/`40`/`50` | 完成；Regulated 硬件待验证 |
| `node policy show` | 无业务参数 | 显示当前路由否决策略；`1` | 完成 |
| `node policy set` | `--reject-tags` 与 `--max-concurrent` 至少一项；受管 llama.cpp 提供三个真实贡献 slot，`--max-concurrent` 接受 `1..=3` | 原子更新拒绝标签/并发上限；越界与损坏持久配置失败关闭；`1`/`50` | 完成 |
| `node threshold show` | 无业务参数 | 显示温度/显存阈值与实测指标；`1` | 完成 |
| `node threshold set` | `--gpu-temp-limit 30..=110` 与非负有限 `--vram-reserve` 至少一项 | 原子更新硬件保护阈值；`1`/`50` | 完成 |
| `node optimize` | 无业务参数 | 只使用真实 TPS/首 Token TTFT/错误率生成确定性建议；`1` | 完成 |
| `config set` | 必填位置 `key value`；只允许白名单非敏感键 | 原子写入配置；敏感键拒绝；`1` | 完成 |
| `config get` | 必填位置 `key` | 读取白名单配置；`1` | 完成 |
| `config list` | 无业务参数 | 只列出非敏感配置；`1` | 完成 |
| `doctor` | `--server-mode` 可选 | 检查客户端能力；server-mode 额外检查 DB；失败 `1`、信任降级 `31` | 完成；connector 公网待外部验证 |

全局参数 `--json`、`--quiet`、`-v/--verbose` 可位于叶子命令之后；`quiet` 与 `verbose` 互斥。`--help`/`--version` 由本地化后的 Clap 树处理。参数解析失败统一是稳定 JSON/human `cli_parse_failed` 与退出码 `1`，不向用户暴露 Clap 英文默认文案。

## 2. 身份认证与凭证

| 命令/合同 | 真实实现 | 自动化证据 | 状态 |
|---|---|---|---|
| `auth login` Device Flow | `crates/mindone-cli/src/auth.rs`、`crates/mindone-coordinator/src/routes/auth_routes.rs`、`crates/mindone-coordinator/src/auth.rs` | 协议/PostgreSQL/E2E 覆盖本地 provider；验证 URI 严格跟随实际 loopback bind；GitHub 重定向策略有单元测试 | 本地完整闭环通过；真实 GitHub OAuth 待外部验证 |
| email 浏览器授权仍绑定 Ed25519 Device Flow | `crates/mindone-coordinator/src/web_auth.rs`、`email.rs`、`migrations/0037_email_password_auth.sql`、`crates/mindone-cli/src/auth.rs` | 同源 `/auth/login` 无 query/fragment；用户手工输入终端 12 位 `user_code`；浏览器不收 bearer；verification token HMAC-only；最终 poll 必须设备签名 | fresh-v37 PostgreSQL/ACL 已进入 `43/43` 门禁；production 要求 HTTPS 与 SMTP TLS/STARTTLS；password reset 未实现 |
| Token/设备私钥只进系统凭证库 | `crates/mindone-cli/src/vault.rs`、`crates/mindone-common/src/secret.rs` | `vault::tests::{memory_store_round_trip_and_clear_are_scoped,debug_output_redacts_tokens_and_x25519_private_key}`；共享业务单元测试统一用仅 `cfg(test)` 可见的内存 SecretStore，不再依赖 Linux 桌面 DBus；无桌面 Linux 可显式选择真实内核 keyutils | 完成（本地自动测试）；production 构建仍只能创建系统凭证库，Linux keyutils 类型门禁已在 Rust 1.88 容器通过；各平台真实 Keychain/Credential Manager/Secret Service smoke 待外部验证 |
| 401 后单次 refresh 与重试，refresh 继续证明设备私钥持有 | `crates/mindone-cli/src/auth.rs`、`crates/mindone-cli/src/context.rs`、`crates/mindone-coordinator/src/routes/auth_routes.rs`、`migrations/0017_refresh_pop_and_verified_uptime.sql` | context 单次重试测试；protocol/coordinator challenge-token-key 绑定测试；PostgreSQL token-only、错 key、成功轮换与旧请求重放正反例 | 完成（本地自动测试）；迁移前旧会话无 challenge 时 fail closed 并要求重新登录 |
| `auth logout` 服务端撤销、本机清理、幂等 | `crates/mindone-cli/src/auth.rs`、`crates/mindone-coordinator/src/routes/auth_routes.rs` | fresh v36 PostgreSQL `postgres_integration` 11/11 中覆盖撤销、重复 logout 与 revoked refresh | 完成（本地自动测试）；真实 OAuth 会话待外部验证 |
| `auth status` 权威服务端身份/Trust | `crates/mindone-cli/src/auth.rs` | `auth::tests::status_uses_authoritative_server_identity_and_separates_local_trust` | 完成（本地自动测试）；真实 OAuth 会话待外部验证 |
| `auth attest` nonce、哈希绑定、防重放、过期拒绝 | `crates/mindone-cli/src/auth.rs`、`crates/mindone-sandbox/src/attestation.rs`、`crates/mindone-sandbox/src/external_attester.rs`、`crates/mindone-sandbox/src/tee_runtime.rs`、`crates/mindone-coordinator/src/attestation.rs`、`crates/mindone-coordinator/src/routes/attestation_routes.rs` | sandbox/protocol/coordinator attestation 单元测试与 PostgreSQL Regulated 场景通过 | 部分完成；真实 AMD SEV-SNP / Intel TDX 硬件待外部验证 |
| 无可用硬件时明确拒绝，不伪造 Enhanced | `crates/mindone-sandbox/src/capability.rs` | `capability::tests::report_never_claims_enhanced_without_provider` | 完成（本地自动测试） |

## 3. 模型管理

| 命令/合同 | 真实实现 | 自动化证据 | 状态 |
|---|---|---|---|
| `model list` 真实登记、绝对路径、哈希与验证状态 | `crates/mindone-cli/src/model.rs`、`crates/mindone-engine/src/model.rs` | `model::tests::{registry_is_atomic_and_detects_mutation,tampered_registry_cannot_list_or_find_model_outside_managed_root}` | 完成（本地自动测试） |
| `model download` 参数、默认 branch 与平台 artifact 解析 | `crates/mindone-cli/src/cli.rs`、`crates/mindone-cli/src/model.rs` | `cli::tests::parses_model_download_defaults`、`model::tests::{rejects_path_traversal,modelscope_manifest_resolves_the_only_safe_artifact_and_sha256,modelscope_manifest_uses_file_to_disambiguate_multiple_artifacts}` | 完成（本地 mock 官方 API 形状）；ModelScope 公网待 smoke |
| 下载续传、`.part`、原子落盘、不跟随链接、TLS | `crates/mindone-engine/src/download.rs` | 下载安全单测、`builds_official_modelscope_resolve_url`；最终 E2E 从 Hugging Face 下载并校验 429 MB GGUF | 完成（本机实测 Hugging Face）；ModelScope 真实 artifact 待外部验证 |
| 可信 checksum 失败关闭 | `crates/mindone-cli/src/model.rs`、`crates/mindone-engine/src/download.rs` | `model::tests::{modelscope_manifest_fails_closed_without_trusted_sha256,modelscope_explicit_file_and_user_sha256_preserve_offline_manifest_compatibility,trusted_platform_and_user_sha256_must_not_conflict}` | ModelScope 只接受官方清单 `Sha256` 或用户显式 64-hex；不会信任模糊 ETag/文件 ID |
| `model delete` 确认/`--yes`、在用保护、清理登记 | `crates/mindone-cli/src/model.rs`、`crates/mindone-engine/src/model.rs` | `model::tests::delete_removes_file_and_record_but_honors_in_use_guard` | 完成（本地自动测试） |
| `model verify` 重算 SHA-256、结构与变更检测 | `crates/mindone-cli/src/model.rs`、`crates/mindone-engine/src/model.rs`、`crates/mindone-engine/src/validation.rs` | validation 结构/边界测试、`model::tests::verification_detects_same_size_weight_replacement` | 完成（本地自动测试） |
| 只允许 GGUF/safetensors；危险格式错误码 21 | `crates/mindone-engine/src/validation.rs`、`crates/mindone-cli/src/error.rs` | `validation::tests::rejects_dangerous_extension_and_spoofed_extension`、`cli_contract.rs::json_model_validation_error_has_required_exit_code` | 完成（本地自动测试） |
| safetensors 无重复 key/空洞/重叠/尾随；GGUF 量化块完整 | `crates/mindone-engine/src/validation.rs` | `validation::tests::{safetensors_rejects_holes_trailing_bytes_and_duplicate_keys,gguf_quantized_tensors_require_complete_blocks}` | 完成（本地自动测试） |

## 4. 推理引擎

| 命令/合同 | 真实实现 | 自动化证据 | 状态 |
|---|---|---|---|
| `engine list` 真实已安装版本/路径/checksum/default | `crates/mindone-cli/src/engine.rs`、`crates/mindone-engine/src/install.rs` | registry 完整性、版本选择和外部路径篡改测试 | 完成（本地自动测试） |
| `engine install --name/--version` | `crates/mindone-cli/src/cli.rs`、`crates/mindone-cli/src/engine.rs`、`crates/mindone-engine/src/install.rs` | llama.cpp/Ollama 官方 release adapter；vLLM/TensorRT-LLM 官方 OCI adapter；engine 安装、完整性与平台边界测试 | 完成（本地自动测试）；平台真实 smoke 分项见下 |
| 发行 OS/arch 匹配、checksum、大小上限、隔离目录、不改 PATH | `crates/mindone-engine/src/install.rs` | release 资产映射、digest/checksum、cache、archive、managed directory、OCI descriptor 与 registry TLS/mirror 拒绝测试 | 完成（本地自动测试） |
| Ollama 官方完整资产与真实入口，不导入 PATH 单文件 | `crates/mindone-engine/src/install.rs`、`crates/mindone-engine/tests/real_install.rs` | `ollama_assets_are_explicit_for_every_supported_platform`；`MINDONE_REAL_OLLAMA_INSTALL=1 ... installs_verifies_and_executes_official_ollama -- --ignored` | 完成（macOS arm64 本机实测）：官方 latest 下载、SHA-256、受管 manifest、真实 `--version` 与 registry 反查通过 |
| vLLM/TensorRT-LLM 完整 CUDA/容器依赖闭包，不导入 PATH/Python 单文件 | `crates/mindone-engine/src/hardware.rs`、`crates/mindone-engine/src/install.rs`、`crates/mindone-engine/tests/real_install.rs` | `external_adapters_require_complete_platform_backend_and_runtime`、`oci_manifest_selection_requires_exact_platform_sha256`、`container_registry_rejects_insecure_or_mirrored_sources`、`container_runtime_binary_must_be_root_owned_and_not_writable_by_others`、`container_launcher_and_bundle_are_digest_pinned_and_fully_manifested`、`unsupported_accelerator_engines_never_register_path_binaries`；Linux 可显式运行 ignored 真实 OCI smoke | `detect/list/install` adapter 完成（本地确定性测试）；v1 `serve` 不启动 OCI launcher；真实 Linux x86_64+CUDA 官方镜像安装需对应主机显式 smoke |
| archive 路径穿越/硬链接/危险 symlink 拒绝，安全内部 symlink 物化 | `crates/mindone-engine/src/install.rs` | `archive_paths_cannot_escape_install_directory`、两个 tar symlink 测试 | 完成（本地自动测试） |
| 官方 llama.cpp 审计发行物真实下载并执行 | `crates/mindone-engine/tests/real_install.rs`、`scripts/e2e-test.sh` | 历史 debug CPU-only E2E 从官方发行渠道取得并真实执行 llama.cpp b10064；当前 macOS 隔离轮完成 Qwen3-0.6B-Q4_0 整包下载、验证和非默认端口健康启动，公开 Linux E2E 又用当前四槽参数完成动态推理、SSE、结算和清理 | 当前 CPU-only Standard 链已真实执行；其他 OS/arch、GPU backend 仍待相应平台验证 |
| `engine detect` OS/CPU/RAM/GPU/Metal/CUDA | `crates/mindone-cli/src/engine.rs`、`crates/mindone-engine/src/hardware.rs` | `hardware::tests::detects_real_nonzero_host_resources` | 完成（本机自动测试）；GPU/多平台准确性待外部验证 |
| `engine set-default` / `config set engine.default` 只接受已安装、未篡改且 v1 `serve` 有可运行适配器的引擎 | `crates/mindone-cli/src/engine.rs`、`crates/mindone-cli/src/app.rs`、`crates/mindone-engine/src/install.rs` | `default_engine_guard_rejects_install_only_adapters`、`installed_engine_without_serve_adapter_cannot_become_default`、registry integrity tests | 完成（本地自动测试）；Ollama/vLLM/TensorRT-LLM 可安装但不能成为 v1 默认服务引擎 |

## 5. 本地服务与沙盒

| 命令/合同 | 真实实现 | 自动化证据 | 状态 |
|---|---|---|---|
| `serve run` 默认 `127.0.0.1:8080`，已验证模型与绝对引擎路径 | `crates/mindone-cli/src/serve.rs`、`crates/mindone-engine/src/process.rs` | 参数边界、重定向拒绝；最终 E2E 在 127.0.0.1 启动真实 llama-server 并通过 `/health` | 完成（本机实测）；其他平台待 Actions |
| CPU-only 是类型化受管策略，附加参数和环境不能覆盖 | `crates/mindone-cli/src/serve.rs`、`crates/mindone-engine/src/process.rs` | `ServeRequest.cpu_only` 单独传递；引擎统一注入 device/GPU layer/KV-op offload 禁用参数、清除对应环境覆盖，并对冲突附加参数失败关闭；定向测试、历史 E2E 与当前公开 Linux 四槽真实小模型链均已执行 | 类型化边界完成；GPU backend 仍待对应平台验证 |
| 沙盒只读精确模型、引擎执行路径、runtime 写目录 | `crates/mindone-sandbox/src/launch.rs` | launch path/canonicalization/Seatbelt profile 单元测试；Linux/macOS 真实 gate 为 ignored + env-gated，并已在公开 Actions 显式运行通过 | macOS Seatbelt 与 Linux 四层门禁已有 Runner 证据；Windows 当前只承诺 Experimental Job Object |
| macOS Seatbelt 允许目标操作并拒绝越权写入与 sibling 模型 | `crates/mindone-sandbox/tests/macos_seatbelt.rs` | 当前显式执行 `MINDONE_REAL_SEATBELT_TEST=1 cargo test -p mindone-sandbox --test macos_seatbelt -- --ignored --nocapture` 为 1/1 passed；公开 `.github/workflows/ci.yml::macos-sandbox-gate` 也在干净 runner 通过 | 本机与 Actions 均已实测；macOS 最高为 Standard-Limited |
| Linux namespaces + no-new-privs + seccomp + Landlock，缺能力 fail closed | `crates/mindone-sandbox/src/launch.rs`、`crates/mindone-sandbox/src/linux_supervisor.rs`、`crates/mindone-sandbox/src/capability.rs`、`crates/mindone-cli/tests/linux_sandbox.rs` | 测试为 `#[ignore]` 且要求 `MINDONE_REAL_LINUX_SANDBOX_TEST=1`；`.github/workflows/ci.yml::linux-sandbox-gate` 安装可信 bubblewrap、只临时调整 runner sysctl，并真实验证允许目标、拒绝 sibling、允许已接受回环 TCP 响应、拒绝主动 `connect` 与 UDP socket | 实现与确定性测试完成；发布只接受精确候选提交的原生 Actions gate |
| Windows 仅把实际 Job Object 报告为 Experimental，不冒充文件/网络沙箱或 Standard | `crates/mindone-sandbox/src/capability.rs`、`crates/mindone-sandbox/src/launch.rs`、`crates/mindone-sandbox/src/windows_supervisor.rs`、`crates/mindone-cli/src/share.rs`、`crates/mindone-cli/src/doctor.rs` | 启动计划只在监督进程实际创建并持有 `KILL_ON_JOB_CLOSE` Job Object 时把它加入 `applied`；没有监督进程时 `applied` 为空。Windows capability 单测保持 `Experimental`、空 `applicable`，公开 Windows runner 的真实 supervisor smoke 已通过 | Job Object 生命周期已由 Runner 实测；它只约束进程生命周期，不宣称文件系统、网络、AppContainer 或 Hyper-V 沙箱，也不能产生 Standard |
| `serve status` 核验引擎与日志 monitor 的 PID/启动标记/命令身份、health、资源/指标 | `crates/mindone-cli/src/serve.rs`、`crates/mindone-engine/src/process.rs` | 单测与最终 E2E 均得到 `running/process_verified/log_monitor_verified/healthy=true` | 完成（本机实测） |
| 日志轮转持续有界且 fail closed | `crates/mindone-engine/src/logging.rs`、内部 `__worker log-monitor` | 10 MiB/5 代、同 inode copy+truncate、ready 握手、路径替换、symlink/reparse/hardlink、进程身份与运行期 containment 共 9 项定向测试；最终 E2E 验证真实 monitor 生命周期 | 完成（本机实测）；Windows identity/reparse 由 Actions 重跑 |
| 受管引擎不记录 Prompt/Response，并启用请求后 slot erase 所需的动作端点 | `crates/mindone-engine/src/process.rs`、`crates/mindone-engine/src/logging.rs`、`crates/mindone-cli/src/serve.rs` | 仅允许已审计 llama.cpp `b10064`；启动前受限 `--help` 能力探测并固定 `--parallel 4 --kv-unified` 等安全参数；`process::tests`、fake-engine/canary、逐槽清理定向测试与当前四槽公开 E2E 的日志扫描/终态清理均通过 | 当前参数的确定性门禁和四槽真实小模型 E2E 完成 |
| `serve stop` 优雅停止后超时终止，防 PID 复用并等待日志 monitor 自退 | `crates/mindone-cli/src/serve.rs`、`crates/mindone-engine/src/process.rs` | 进程句柄/marker 单测；最终 E2E `serve stop` 成功、端口关闭且状态清理 | 完成（本机实测） |
| standalone `serve` 每请求 KV/主机缓冲只报告真实 best-effort 清理 | `crates/mindone-cli/src/serve_proxy.rs`、`crates/mindone-engine/src/process.rs`、`crates/mindone-cli/src/serve.rs` | llama.cpp 仅监听随机内部回环端口；公开代理强制覆盖任意来访 `id_slot` 为本机 slot 0 并禁用 prompt cache，每个 chat/completions 或 completions 真实响应终态（含上游失败、消费者断开）后同步调用 b10064 `/slots/0?action=erase`，失败状态无正文持久化并阻止下一次推理；贡献 worker 只直连 slot 1..3。代理清理定向测试、贡献双槽并发/独立 erase、`owned_buffers_are_actually_zeroized` 与当前四槽真实 E2E 均通过 | 只承诺可控逻辑 sequence、受管 slot erase 与 MindOne 自有缓冲 best-effort 覆写，不冒充驱动/物理内存清零 |

## 6. 网络共享与任务 worker

| 命令/合同 | 真实实现 | 自动化证据 | 状态 |
|---|---|---|---|
| `share publish --port` 注册节点/硬件、发布指定受管实例、启动 worker/心跳 | `crates/mindone-cli/src/share.rs`、`crates/mindone-coordinator/src/routes/nodes_models.rs` | share/PostgreSQL 测试；状态持久化实际 serve 端口，attestation、worker 绑定和旧状态 `8080` 兼容均有确定性回归；历史 E2E 得到真实 worker PID、首次心跳与在线状态 | 实现和本地自动测试完成；非默认端口真实 E2E 待当前流水线复验 |
| 出站领取、精确实例绑定、租约/续租、二次策略检查、真实本地推理 | `crates/mindone-protocol/src/jobs.rs`、`crates/mindone-cli/src/share.rs`、`crates/mindone-coordinator/src/routes/jobs.rs` | claim 必须同时提交 `node_id + model_instance_id`；worker 实例错配单测、PostgreSQL 全局二阶段路由与最终 E2E 通过 | 完成（本机实测 Standard）；Regulated 硬件另列待验证 |
| 公开 canary 只混入普通 jobs wire；exact-instance 风险隔离与恢复 | `crates/mindone-coordinator/src/routes/evaluations.rs`、`crates/mindone-coordinator/src/routes/jobs.rs`、`migrations/0018_hidden_evaluation_jobs.sql`、`migrations/0023_instance_canary_quarantine.sql` | PostgreSQL 回归覆盖普通/canary 最小 ACK、UUIDv4、幂等、过期、0 结算、隔离/恢复、同事务收口与只追加风险事件；历史 E2E 先确定性完成一次 public canary worker 终态并隔离后续普通任务 | 完成（历史本机实测）；有限公开模板仍可按语义/时序/零结算分类，只是有界 canary 风险信号，不是模型真实性证明；不改全局质量/Tier，不伪造消费者或账本 |
| 节点、普通 attempt 和隐藏 challenge 精确绑定登录设备 | `crates/mindone-coordinator/src/routes/nodes_models.rs`、`crates/mindone-coordinator/src/routes/jobs.rs`、`crates/mindone-coordinator/src/routes/evaluations.rs`、`migrations/0030_node_device_binding.sql` | `schema_v31` 覆盖 26→28→31 legacy 保留、活动普通/attempt-only/隐藏租约拒迁、node-first 真实竞态、部分绑定与 owner/device/claim identity 变更拒绝；fresh v36 PostgreSQL 5/5 | 完成（本地自动测试）；迁移前旧节点保持 offline/`device_rebind_required`，不能在未重新注册绑定前接单；production v26 尚未迁移 |
| private `hidden_benchmark` 新签发使用 HMAC v2 keyed commitments 与 opaque terminal capability | `crates/mindone-coordinator/src/private_evaluation_catalog.rs`、`crates/mindone-coordinator/src/lib.rs`、`crates/mindone-coordinator/src/routes/evaluations.rs`、`migrations/0028_private_hidden_benchmark.sql`、`migrations/0031_private_hidden_hmac_budget.sql` | 仓库外短期 Ed25519 签名 catalog 仍绑定权重/seed/输出边界；v2 对 catalog/evaluator/prompt/expected/account/device/node 做域分离 HMAC，数据库 raw identifier 与裸 `prompt_hash`/`expected_hash` 为 `NULL`。coordinator lib 111/111 与 fresh v36 `private_hidden_benchmark_binds_model_rejects_replay_and_arbitrates_instances` 覆盖 key-state、错权重/错实例/重放、terminal capability、只追加仲裁与零结算 | 完成（本地自动测试）；无 key/预算或 catalog 无效时只能回退 public canary；legacy private v1 行保留裸 SHA/原始标识并只走兼容终态路径，新 challenge 不再签发 v1；live production v26 尚未部署 |
| private 四级预算、cooldown 与样本 reserve | `crates/mindone-coordinator/src/config.rs`、`crates/mindone-coordinator/src/routes/evaluations.rs`、`migrations/0031_private_hidden_hmac_budget.sql` | budget 必须完整显式配置；在 availability 前取得全局 advisory xact lock，对目录全部 entry 的 legacy/v2 entry、Prompt、expected 唯一键冲突做去重并集，再按 `catalog → account → device → node` 固定顺序锁 scope。跨 catalog 真重叠、两个独立 `PgPool` 回归已进入 fresh-v37 `43/43` | 数据库门禁完成；预算不是抗 Sybil 证明，production 未启用 |
| 任务 TTFT/TPS/设备集合显存峰值风险指纹 | `crates/mindone-cli/src/share.rs`、`crates/mindone-protocol/src/jobs.rs`、`crates/mindone-coordinator/src/execution_fingerprint.rs`、`crates/mindone-coordinator/src/settlement.rs`、`migrations/0019_latency_vram_fingerprint.sql` | 多 choice 聚合、响应重建、引擎 TPS、采样峰值/未知降级和幂等指纹定向测试通过；历史真实 GGUF E2E 实测 TTFT/TPS | 完成（历史本机实测 Standard）；遥测仅为 node-reported risk signal，不进入计费金额 |
| Regulated 固定路由、本机复验、证明绑定 X25519 key、opaque envelope、TEE 内解密/加密 | `crates/mindone-protocol/src/jobs.rs`、`crates/mindone-protocol/src/endpoints.rs`、`crates/mindone-protocol/src/auth.rs`、`crates/mindone-cli/src/e2ee.rs`、`crates/mindone-cli/src/quota.rs`、`crates/mindone-cli/src/share.rs`、`crates/mindone-sandbox/src/client_verifier.rs`、`crates/mindone-sandbox/src/tee_runtime.rs`、`crates/mindone-coordinator/src/routes/regulated_jobs.rs`、`crates/mindone-coordinator/src/routes/attestation_routes.rs`、`migrations/0009_regulated_e2ee_data_plane.sql`、`migrations/0012_regulated_idempotency_fingerprints.sql` | protocol/CLI/sandbox 确定性测试与 `postgres_integration.rs::regulated_e2ee_route_is_one_time_bound_opaque_and_capacity_safe` 覆盖 AAD、篡改、报告错配、过期、重放、容量和幂等失败关闭 | 部分完成；软件数据面已实现，真实 SNP/TDX 硬件、collateral、verifier 与 adapter E2E 待外部验证 |
| Standard 载荷/结果只做 Base64 编码，且拒绝 `regulated_aead_v1` 混入 | `crates/mindone-protocol/src/jobs.rs`、`crates/mindone-cli/src/quota.rs`、`crates/mindone-cli/src/share.rs` | Standard payload、未知字段、授权上限及 regulated encoding 拒绝测试 | 完成（本地自动测试）；明确不提供保密性，不适用于敏感/受监管数据 |
| 结果/失败提交幂等、401 refresh、瞬时失败重试、响应硬上限 | `crates/mindone-cli/src/share.rs` | result/failure/retry/body-limit 单元测试与 PostgreSQL 结算场景通过；reasoning-only 无可见 `content` 立即失败；确定性 HTTP 400 转为一次脱敏 terminal failure，远端 message/Prompt/Response 不进入 failure 或 tracing | 完成（本地自动测试）；真实跨进程网络故障 E2E 待外部验证 |
| worker PID 身份/启动标记/命令匹配，旧状态不授权 signal | `crates/mindone-cli/src/share.rs` | `worker_identity_requires_matching_marker_executable_and_command`、`legacy_share_state_never_authorizes_an_automatic_signal` | 完成（本地自动测试） |
| `share unpublish` drain、远端取消发布、失败时保留真实状态 | `crates/mindone-cli/src/share.rs`、`crates/mindone-coordinator/src/routes/nodes_models.rs` | 单元/PostgreSQL 测试；最终 E2E 优雅排空、`unpublished`、`active_jobs=0`、本地状态删除 | 完成（本机实测） |
| `share stats` 返回真实终态请求/性能/Trust/Tier/收益与动态贡献标签 | `crates/mindone-cli/src/share.rs`、`crates/mindone-protocol/src/nodes.rs`、`crates/mindone-coordinator/src/routes/nodes_models.rs`、`migrations/0017_refresh_pop_and_verified_uptime.sql` | `honor_observation_uses_only_valid_server_aggregates`、coordinator 的 midrank/隐私阈值/里程碑/UTC 连续日确定性测试与 PostgreSQL 正向聚合断言 | 完成（本地自动测试）；`requests` 只计已终态 attempt，领取/执行中不提前增加；percentile 少于 5 节点时按隐私策略返回未知，uptime 只累计相邻已验证心跳且离线不增长 |
| 节点无需公网入站，llama-server 不得公开 | `crates/mindone-cli/src/share.rs`、`deploy/docker-compose.yml`、`deploy/docker-compose.cloudflared.yml` | 本地 worker 只访问 loopback；公网 overlay 不发布 origin，只允许固定 IP 的专用 connector；仓库未取得真实公网 hostname 验收证据 | 待外部验证 |

## 7. 双轨经济、账本与本地代理

| 命令/合同 | 真实实现 | 自动化证据 | 状态 |
|---|---|---|---|
| `quota balance/history/receipt` 只读权威 API | `crates/mindone-cli/src/quota.rs`、`crates/mindone-coordinator/src/routes/quota.rs` | protocol/accounting 单元测试与 PostgreSQL balance/history/receipt 场景通过 | 完成（本地自动测试） |
| microquota 全程整数、显示两位小数 | `crates/mindone-accounting/src/fixed.rs`、`crates/mindone-cli/src/quota.rs` | `fixed::tests::matches_all_whitepaper_golden_values`、`quota::tests::formats_microquota_without_float` | 完成（本地自动测试） |
| `quota use` 只绑定 loopback；OpenAI `GET /v1/models` 与 `POST /v1/chat/completions` | `crates/mindone-cli/src/quota.rs`、`crates/mindone-protocol/src/openai.rs` | `model_proxy_prefers_internal_models_over_openai_data` 锁定协调器同时返回 OpenAI `data` 与内部 `models` 时的解析优先级；当前四槽公开 E2E 覆盖动态 chat 非流式/SSE、游标恢复与唯一结算 | 完成（当前公开 Linux Standard E2E） |
| OpenAI 兼容 `POST /v1/completions` | `crates/mindone-cli/src/quota.rs`、`crates/mindone-cli/src/share.rs`、`crates/mindone-protocol/src/openai.rs` | 自动测试覆盖 prompt shape、授权上限、worker endpoint 映射；当前四槽公开 E2E 完成 completion 非流式/SSE、密文与唯一结算 | 完成（当前公开 Linux Standard E2E） |
| `stream:true` 只在 Standard 双端点启用；Regulated 明确拒绝且不降级 | `crates/mindone-cli/src/quota.rs` | 自动测试与当前四槽公开 E2E 均验证 HTTP 400 `unsupported_stream`，不创建任务或 receipt | 完成（当前公开 Linux Standard E2E） |
| perf/trust/quota/points 定点公式 | `crates/mindone-accounting/src/fixed.rs` | 3 个 fixed golden/边界测试 | 完成（本地自动测试） |
| 事务结算：消费、节点额度、贡献值、准备金与 complete 同事务；失败不扣 | `crates/mindone-coordinator/src/settlement.rs`、`crates/mindone-coordinator/src/routes/jobs.rs` | fresh v36 `crates/mindone-coordinator/tests/postgres_integration.rs` 11/11 | 完成（本地自动测试） |
| Standard receipt/哈希链不冒充密码学执行证明 | `crates/mindone-coordinator/src/settlement.rs`、`crates/mindone-accounting/src/ledger.rs` | 实际 Token/结果由节点上报并受授权上限约束；哈希用于事务一致性、幂等和审计 | 边界已明确；不证明真实执行、精确用量或输出正确性 |
| 账本只追加、唯一 ID、前后余额、请求 ID、canonical 哈希与权威链头 | `crates/mindone-accounting/src/ledger.rs`、`migrations/0001_initial.sql`、`migrations/0003_reserve_release_audit.sql`、`migrations/0024_authoritative_ledger_heads.sql`、`migrations/0027_canonical_ledger_hashes.sql` | 旧链不改 hash/head 冻结为 legacy v1；新行统一为 length-prefixed UTF-8 v2，覆盖 scope/ID/request/idempotency/type/delta/前后余额/PG 微秒时间/prev/排序 metadata；数据库 BEFORE trigger 自行重算，任意 64hex 或篡改必须拒绝。Rust canonical 链 3/3；fresh v36 `ledger_heads` 3/3、`ledger_integrity` 10/10、`ledger_migration` 2/2 | 完成（本地自动测试）；canonical hash 用于事务一致性、幂等和审计，不冒充外部执行、精确用量或输出正确性证明 |
| production 数据库 owner/runtime 分离，runtime 不执行 schema migration | `crates/mindone-coordinator/src/db.rs`、`crates/mindone-coordinator/src/main.rs`、`migrations/0026_runtime_database_role.sql`、`deploy/docker-compose.yml`、`deploy/postgres-ensure-runtime-role.sh` | 历史 fresh v36/v37 门禁；当前 fresh PostgreSQL 17 上 `runtime_schema` `2/2` 与 `database_role` 已通过，并覆盖 0039 两表最小权限 | 当前定向数据库门禁已通过；live production 仍为 v26，未授权升级 |
| production 零初始余额与服务器侧受控运营赠额 | `crates/mindone-coordinator/src/operator_grant.rs`、`crates/mindone-coordinator/src/main.rs`、`migrations/0020_operator_quota_grants.sql` | 参数/命令解析单测；真实 PostgreSQL 1/1 覆盖账户锁后的余额、quota 哈希账本、审计绑定、同请求重放、同键变更冲突、不存在用户拒绝及 UPDATE/DELETE 拒绝 | 完成（本地自动测试）；无自动注册赠额和 HTTP admin 路由；这是任务公式之外的显式外生启动供给，不生成虚假 job/receipt/准备金/贡献 |
| 准备金四种用途、幂等释放、不得透支、余额可查 | `crates/mindone-accounting/src/reserve.rs`、`crates/mindone-coordinator/src/settlement.rs`、`crates/mindone-coordinator/src/main.rs`、`crates/mindone-coordinator/src/routes/quota.rs`、`migrations/0021_operational_quality_and_reserve.sql` | `reserve-release` 命令解析与 fresh v36 PostgreSQL 41/41 门禁覆盖：锁余额、独立 reserve ledger、operator 审计绑定、完全重放、同键变更、透支拒绝及审计 UPDATE/DELETE 拒绝 | 完成（本地自动测试）；无 HTTP admin 路由 |
| 两阶段模型/节点路由、签名 evidence 驱动的动态质量与 Tier | `crates/mindone-accounting/src/routing.rs`、`crates/mindone-accounting/src/quality.rs`、`crates/mindone-accounting/src/glicko2.rs`、`crates/mindone-accounting/src/tier.rs`、`crates/mindone-coordinator/src/quality.rs`、`crates/mindone-coordinator/src/operator_quality.rs`、`crates/mindone-coordinator/src/main.rs`、`migrations/0021_operational_quality_and_reserve.sql`、`migrations/0025_model_tier_transition_audit.sql` | artifact/signature/时效单测、`quality-record` 裸分数拒绝及 fresh v36 PostgreSQL 41/41 门禁覆盖：签名 benchmark/盲测、同名全 cohort Tier 重算、派生转换只追加审计、过期且公钥轮换后的精确重放、同键变更与无效签名零写入 | 完成（本地自动测试）；无 HTTP 质量写路由，原始评分入口为 crate-private；private hidden 仲裁不写入全局质量/Tier |
| Phase 2 使用独立 coordinator RTT，不以 TTFT 冒充网络延迟 | `crates/mindone-cli/src/share.rs`、`crates/mindone-protocol/src/nodes.rs`、`crates/mindone-accounting/src/routing.rs`、两条 coordinator route、`migrations/0029_node_coordinator_rtt.sql` | fresh-v37 PostgreSQL `43/43` 覆盖 RTT/TTFT 反向排序；workspace tests、strict Clippy 与历史真实 E2E 已通过 | 完成（历史本机实测 Standard）；node-reported RTT 只是弱路由信号，不进入 Trust/Tier/结算 |

## 8. 节点策略与硬件保护

| 命令/合同 | 真实实现 | 自动化证据 | 状态 |
|---|---|---|---|
| `node policy show/set` 拒绝标签与最大并发 | `crates/mindone-cli/src/node.rs`、`crates/mindone-accounting/src/policy.rs` | `policy::tests::enforces_tags_and_concurrency_deterministically`、CLI policy test | 完成（本地自动测试） |
| 领取前与执行前各检查一次 | `crates/mindone-coordinator/src/routes/jobs.rs`、`crates/mindone-cli/src/share.rs` | worker 单测、PostgreSQL 场景和历史 E2E 覆盖领取后策略改变在 llama HTTP 前拒绝、零 receipt/结算 | 完成（历史本机实测 Standard）；并发槽确定性回归已通过 |
| 活动 worker 严格读取已持久化策略 | `crates/mindone-cli/src/node.rs`、`crates/mindone-cli/src/share.rs` | `active_worker_policy_read_fails_closed_after_deletion_or_corruption`、`policy_reader_rejects_symbolic_links`；publish 通过 `save_policy` 落盘 | 完成（本地自动测试）；运行期缺失、损坏、非普通文件或符号链接不回退默认值 |
| `node threshold show/set` 温度与显存保留 | `crates/mindone-cli/src/node.rs`、`crates/mindone-accounting/src/policy.rs` | hysteresis 与 metrics 缺失 fail-closed 测试 | 完成（本地自动测试）；真实 GPU telemetry 待外部验证 |
| 超温暂停、5°C 滞回恢复 | `crates/mindone-cli/src/share.rs`、`crates/mindone-accounting/src/policy.rs` | `temperature_pause_uses_five_degree_hysteresis_and_fails_closed` | 完成（本地自动测试） |
| `node optimize` 基于引擎 TPS、首 Token TTFT 实测与版本化已观测基线生成确定性建议 | `crates/mindone-cli/src/node.rs`、`crates/mindone-cli/src/share.rs`、`crates/mindone-accounting/src/optimize.rs` | accounting optimize 3 项测试、`optimization_uses_authoritative_metrics_and_observed_baseline`、`performance_baseline_uses_only_real_positive_observations`、流式 TTFT 定向测试 | 完成（本地自动测试）；`local-observed-best-v1` 只承诺恢复同 worker/模型在当前采集口径下已观测的 TPS 与实测 TTFT，不虚构 Tier 晋升 |
| 策略拒绝稳定错误码 50，失败不扣额度 | CLI error/proxy、worker、coordinator jobs/settlement | `structured_policy_error_wins_over_http_403_auth_fallback`、proxy policy test 与 PostgreSQL policy failure 场景通过 | 完成（本地自动测试） |

## 9. 配置与诊断

| 命令/合同 | 真实实现 | 自动化证据 | 状态 |
|---|---|---|---|
| 全新客户端默认官方协调器 `https://api.holarchic.cn`；独立 API 子域避免覆盖现有官网；已存在配置不覆盖；loopback 只由开发者显式设置 | `crates/mindone-common/src/config.rs`、`crates/mindone-cli/src/context.rs` | `config::tests::fresh_client_defaults_to_official_tls_origin`、配置原子 round-trip | 完成（代码与自动测试）；当前子域 TLS/route 尚未配置，公网 E2E 待外部验收 |
| `config set/get/list` 仅白名单、原子写 | `crates/mindone-cli/src/config.rs`、`crates/mindone-common/src/config.rs` | shared config 与 CLI config 白名单、原子写及默认引擎绕过测试 | 完成（本地自动测试） |
| Token/password/secret/私钥/DB URL 禁止保存或列出 | `crates/mindone-common/src/config.rs`、`crates/mindone-cli/src/vault.rs` | `only_accepts_whitelisted_non_sensitive_keys`、CLI contract secret test | 完成（本地自动测试） |
| `doctor` 检查 OS/arch、目录、凭证库、网络、server、engine/model/port/sandbox/GPU 和 MindOne 专用 connector | `crates/mindone-cli/src/doctor.rs`、`crates/mindone-common/src/config.rs` | 决策单测覆盖 `1 > 31 > 0`；connector 只按 Compose project/service label 定位，验证 running/healthy、digest-pinned 官方镜像、容器内 loopback `/ready`、公网 HTTPS `/ready`、`CF-Ray` 与 origin 身份一致；缺失、未就绪、origin 失败、route mismatch、正常共 6 类定向测试通过，不读 token/argv/logs | 完成（本地自动测试）；真实 connector/hostname 待用户授权后外部验证 |
| `doctor --server-mode` 才检查数据库配置 | `crates/mindone-cli/src/doctor.rs` | 单元/安装 smoke 覆盖普通模式；生产 Compose 单独验证数据库配置 | 完成（本机实测）；server-mode 多平台待 Actions |
| `MINDONE_HOME` 绝对隔离目录 | `crates/mindone-common/src/paths.rs` | `paths::tests::{builds_all_paths_from_explicit_home,rejects_relative_home,creates_owned_directories}` | 完成（本地自动测试） |
| 远程网络必须 TLS；仅显式 loopback dev HTTP | `crates/mindone-common/src/transport.rs`、CLI coordinator/model/engine clients | common/CLI/engine transport tests | 完成（本地自动测试） |

## 10. 稳定退出码

| 码 | 含义 | 真实实现与自动化证据 | 状态 |
|---:|---|---|---|
| 0 | 成功 | `crates/mindone-common/src/error.rs`、`crates/mindone-cli/src/error.rs` | 完成（本地自动测试） |
| 1 | 通用错误 | 同上；`required_exit_codes_are_stable` | 完成（本地自动测试） |
| 10 | 认证/系统凭证库失败 | 同上；`every_business_error_maps_to_required_code` | 完成（本地自动测试） |
| 20 | 引擎安装/沙盒初始化失败 | 同上 | 完成（本地自动测试） |
| 21 | 模型安全校验失败 | 同上；CLI JSON contract test | 完成（本地自动测试） |
| 30 | 远程证明失败 | 同上 | 完成（本地自动测试） |
| 31 | 信任等级降级警告 | 结构化服务端 `code=31` / `type=trust_downgraded` 已映射；`doctor` 在无失败且实际沙盒仅为 Standard-Limited/Experimental Warning 时返回 31，失败仍优先返回 1，其他 warning 仍为 0；JSON 为 `ok=false/code=31` 且保留完整 data，human 照常，quiet 不改退出码 | 完成（真实 macOS capability 路径与确定性测试）；`auth attest` 的显式升级/证明失败仍为 30 |
| 40 | 可用额度不足 | 同上 | 完成（本地自动测试） |
| 50 | 节点策略拒绝 | 同上；结构化 policy error 测试 | 完成（本地自动测试） |

## 11. 规范业务场景

| 场景 | 真实实现 | 自动化证据 | 状态 |
|---|---|---|---|
| A：base 1.00、High/Standard 1.50、quota 1.20、points 1.80、reserve 0.30 | `crates/mindone-accounting/src/fixed.rs`、coordinator settlement/quota receipt | fixed golden 与完整 receipt/账本 PostgreSQL 场景通过 | 完成（本地自动测试） |
| B：75°C、保留 4GB、拒绝 `nsfw,heavy-math`、三个隔离贡献 slot（最大并发可收紧为 1..3） | accounting policy、CLI node/share、coordinator jobs | 策略/滞回/并发、独立绑定/erase 与并发 refresh 自动测试通过；当前四槽公开 GGUF E2E 覆盖两次策略检查与拒绝零结算 | CPU-only 四槽真实小模型完成；真实 GPU 传感器仍待相应平台验证 |

## 12. 安装、卸载与发布安全

| 合同 | 真实实现 | 自动化证据 | 状态 |
|---|---|---|---|
| 开发 Compose smoke 的 Secret、CLI Home、临时材料与清理边界 | `scripts/mvp-dev-smoke.sh`、`scripts/mvp-dev-smoke-contract-test.sh`、`.dockerignore`、`.github/workflows/ci.yml` | Secret 只接受 `MINDONE_DEV_POSTGRES_PASSWORD` / `MINDONE_DEV_STANDARD_DATA_KEY` 专用环境变量；旧 Secret 参数启动 Docker 前拒绝且不回显；CLI 统一绑定临时目录下的隔离 `MINDONE_HOME`；合同测试验证仓库外 `0700` 目录、文件权限、正常/信号退出清理和构建上下文排除，并已接入 CI | 安全合同测试本机通过；不连接 Docker 或网络，本轮未重跑完整开发 Compose/Docker smoke |
| Unix 安装：HTTPS/有限跳转、SHA-256、archive 白名单、原子暂存、受管用户 PATH | `scripts/install.sh` | 本地 release smoke 验证归档、安装、`--check`、重装、中文 help、doctor JSON、唯一受管块及新 shell 裸 `mindone`；公开 v1.0.2 latest 资产又完成 macOS 隔离安装与 PTY 裸 TUI | v1.0.2 已发布；Linux/macOS 原生构建和 Unix 安装门禁均由公开 Actions 覆盖，平台包未做 Apple 原生签名 |
| Unix 卸载：默认保留数据，显式 purge，父链/目标 symlink、宽路径、孤儿服务状态与非 MindOne 文件 fail closed | `scripts/uninstall.sh` | release smoke 验证默认卸载保留数据、移除受管 PATH 块与 `--purge-data`；负向门禁有定向证据 | 三个 Unix 用户态目标与公开 Linux 安装/卸载门禁通过 |
| Windows 安装：与 Unix 对齐的合同、checksum、zip 精确清单、原子覆盖更新、拒绝重解析链、用户 PATH | `scripts/install.ps1`、`.cargo/config.toml`、`scripts/verify-windows-self-contained.ps1` | PowerShell 7.5 解析、x86_64 MSVC 交叉 check/严格 Clippy/静态 PE 审计通过；公开 Windows Runner 进一步验证原生编译、`dumpbin`、用户/进程 PATH、裸命令、`-Launch`、`-NoModifyPath`、空项/空格/尾分隔符无损保留、替换与拒绝边界 | 原生安装合同已通过 Actions；交互 TUI、Credential Manager、Job Object 生命周期和模型启动仍待用户真机 |
| Windows 卸载：默认保留数据，`-PurgeData` 才删除；精确清理安装目录 PATH；拒绝 root/user/reparse/非规范/外部项/缺 CLI 的服务状态 | `scripts/uninstall.ps1` | Windows Actions 已覆盖保留、彻底删除、其他 PATH 项逐字节恢复、服务安全停止与拒绝边界 | 原生 Actions 通过；用户真机仍作最终平台验收 |
| 多平台构建、发行 checksum、SBOM/provenance、可选平台签名 | `.github/workflows/ci.yml`、`.github/workflows/release.yml`、`.github/workflows/security.yml`、`deny.toml` | v1.0.2 先验证标签与 `main`，再复用完整 CI、安全/数据库复验并生成五平台包；11 个 Release 资产、SPDX SBOM、Sigstore bundle 均已上传，五个包的 GitHub provenance 已逐个验证 | 发行完成；Apple Developer ID/notarization 与 Windows Authenticode 未配置并已如实披露 |
| Apple Developer ID / notarization、Windows Authenticode | `.github/workflows/release.yml`、发行 `CODE_SIGNING.txt` | 只有配置真实证书 Secret 才签名；macOS notarization 尚未接入。正式 SemVer 与预发布通道只由标签决定，签名状态则在发行页 `SIGNING_STATUS.txt` 和包内 `CODE_SIGNING.txt` 独立、如实披露，稳定通道不代表已有平台原生签名 | 待外部验证 |

## 13. 完成时总体验收

| 验收 | 必须取得的证据 | 当前状态 |
|---|---|---|
| 最终 fmt、strict clippy、workspace tests | 当前 31 个 result set 为 `590 passed / 0 failed / 5 ignored`，退出 0；macOS 本机、Windows x86_64 MSVC 交叉环境与公开 Actions 的核心质量门均通过 | 5 ignored 是外部/平台门禁，不冒充通过；发行仍要求精确候选完整 CI 终态 |
| Rust 1.88 MSRV | 当前 all-target/all-feature check 与公开 Actions MSRV 门禁已通过 | 后续精确发行候选仍须重跑 |
| PostgreSQL migrations、最小权限角色与完整 API 集成 | 当前源码连续 `0001..0039`；fresh-v39 16 个 binary 各用独立数据库，合计 `49/49`、无 skip，覆盖最小 ACL、速度档调度与 API Key/OpenAI JSON + Standard SSE 网关 E2E | live production 仍为 `26|1|26|t`，严禁把测试结果冒充 production 切换 |
| 两个隔离 Home 的真实 llama.cpp + GGUF E2E | 历史 debug 树从头通过；v1.0.2 精确标签的公开 Linux Actions 又以当前四槽/统一 KV 参数和 PostgreSQL v39 完成双账号/device、public canary、非流式双端点、两类 SSE、游标恢复、密文、三轨唯一结算、策略拒绝零结算、Regulated 流式拒绝、slot erase、端口感知日志审计与清理 | 当前 CPU-only Standard 单模型链完成；private 双 GGUF、真实 TEE、外部 SMTP 和 production 不在该证据内 |
| private HMAC v2、预算与 terminal capability | fresh-v39 `49/49` 覆盖跨 catalog 真重叠双 `PgPool`、key-state、v2 raw-null、设备绑定与 terminal capability | production v26 未配置 key/预算/catalog，不能宣称启用 |
| Cloudflare 五项公网安全测试 | HTTPS、未认证拒绝、正确 Token、数据库与 llama-server 端口不可见 | 待外部验证；执行路由保存前需用户确认 |
| 安装、版本、中文帮助、doctor、卸载无残留 | `mindone 1.0.2` 已在 macOS arm64 完成本地 release smoke；Linux 用户态、公开 Windows Actions 及五平台 Release 资产也完成相应分层合同 | 远程资产已发布；Windows 交互 TUI 和模型启动由用户真机验收 |
| Linux 四层沙盒与 macOS Seatbelt 真实 allow/deny | 两项真实测试均为 `#[ignore]` 并分别要求显式环境开关；当前 macOS 本机和公开 Actions、Linux 四层公开 Actions 均已通过，普通 workspace test 不能把 ignored/unavailable 当通过 | 精确发行候选仍须复用同一门禁 |
| RustSec、cargo-deny、Gitleaks 与 workflow/script 静态门禁 | cargo-audit 0.22.2 本轮联网刷新到 1167 条 advisory 后为 0 vulnerability / 0 warning；`cargo deny check`、actionlint、workflow/Shell 语法和本地 Gitleaks 均退出 0；公开 Security workflow 的三项 job 已在候选提交通过 | 正式发行要求标签所指精确提交再次全绿 |
| 正式代码签名/notarization | Apple/Windows 官方工具的签名与验证输出；未取得证据时发行页与包内必须明确标为未签名/notarization 未完成，不能把稳定版本通道冒充为已签名 | 待外部验证；当前 workflow 会按实际 Secret 结果披露，不伪造签名 |
| 真实 SEV-SNP/TDX 证明与 Regulated E2E | 目标 guest 的真实 quote/report、厂商 collateral、固定 verifier、measurement allowlist、TEE adapter、密文推理与结果解密 | 待外部验证；软件测试通过不能替代 |
| 分支推送与 GitHub Actions | 代码/工作流精确提交、CI/Security URL 与绿色终态；本轮经用户授权直接推送，不虚构不存在的 PR | 发布仓库上下文修复基线 `f4adc51` 已推送；CI `29988119866` 与 Security `29988121928` 全绿 |

当前源码的 40 个公开叶子参数矩阵和 TUI 10 类映射已落盘并通过完整 CLI 与 workspace 门禁；HF 日常小模型部署探测只读取 64 KiB 后断开。按端口并行运行多个本地受管实例已实现并通过状态隔离/在用保护的确定性测试，没有下载第二个真实模型。当前 workspace `590/0/5`、fresh-v39 `49/49`、Unix/Windows 安装门禁、macOS Seatbelt、Linux 四层沙盒、五目标原生编译、当前四槽 CPU-only 小模型业务链、API Key 网关 JSON/SSE 数据库 E2E 和 v1.0.2 五平台发行均已有真实证据；Windows 真机交互/模型启动、公网 API 子域 TLS、外部 SMTP、Apple/Windows 平台原生签名、private 双 GGUF、真实 TEE 与 production live 切换仍未完成。
