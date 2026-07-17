# MindOne CLI v1.0.0 合规矩阵

本文件覆盖 `docs/specs/mindone_cli_1.0.0.md` 与总任务的并集。总任务对冲突项优先。
状态标记：`规划` 表示尚在实现，`完成` 只在对应自动化测试实际通过后使用。

## 1. 全局合同

| 规范项 | 参数/行为 | 计划实现 | 自动化验证 | 状态 |
|---|---|---|---|---|
| 根命令 | 程序名 `mindone`，版本 `1.0.0`，公益网络定位 | `crates/mindone-cli/src/cli.rs` | `crates/mindone-cli/tests/cli_compliance.rs` | 规划 |
| 中文帮助 | 根命令和全部子命令默认简体中文 | `mindone-cli/src/cli.rs` | `cli_compliance::help_is_chinese` | 规划 |
| 全局帮助 | `-h`, `--help` | `mindone-cli/src/cli.rs` | `cli_compliance::global_flags` | 规划 |
| 全局版本 | `-V`, `--version` | `mindone-cli/src/cli.rs` | `cli_compliance::global_flags` | 规划 |
| JSON | `--json`；稳定成功/错误 envelope | `mindone-cli/src/output.rs` | `cli_compliance::json_contract` | 规划 |
| 静默 | `--quiet`；不吞掉 JSON | `mindone-cli/src/output.rs` | `cli_compliance::quiet_contract` | 规划 |
| 详细日志 | `--verbose`；与 quiet 冲突 | `mindone-cli/src/cli.rs` | `cli_compliance::verbosity_conflict` | 规划 |
| 子命令 | `auth model engine serve share quota node config doctor help` | `mindone-cli/src/cli.rs` | `cli_compliance::root_commands` | 规划 |

## 2. 身份认证

| 命令 | 参数与行为 | 计划实现 | 自动化验证 | 状态 |
|---|---|---|---|---|
| `auth login` | OAuth 2.0 Device Flow；显示 code/URI；默认打开浏览器；生成并绑定设备密钥；Token/私钥仅进系统凭证库 | `commands/auth.rs`, `credential.rs` | `auth_integration::device_login_and_key_binding` | 规划 |
| `auth logout` | 服务端撤销会话/设备密钥；清理系统凭证；幂等 | `commands/auth.rs` | `auth_integration::logout_revokes_and_clears` | 规划 |
| `auth status` | 用户、UID、实际 Trust、指纹、登录时间、服务器地址；核验服务端状态 | `commands/auth.rs` | `auth_integration::status_is_authoritative` | 规划 |
| `auth attest` | 探测真实 provider；验证 nonce/防重放/时间/策略/运行时/模型哈希；无硬件明确拒绝 | `commands/auth.rs`, `mindone-sandbox/src/attestation.rs` | `attestation_tests`; macOS smoke test | 规划 |

## 3. 模型管理

| 命令 | 参数与行为 | 计划实现 | 自动化验证 | 状态 |
|---|---|---|---|---|
| `model list` | 名称、格式、大小、绝对路径、哈希、验证状态、兼容引擎 | `commands/model.rs`, `mindone-engine/src/model.rs` | `model_registry_tests::list_fields` | 规划 |
| `model download` | `--platform <huggingface|modelscope>`、`--repo`、`--branch` 默认 main、`--name`、补充 `--file` 与 `--sha256` | `commands/model.rs`, `mindone-engine/src/download.rs` | `download_integration::*` | 规划 |
| `model download` 行为 | 续传、进度、`.part`、原子重命名、路径穿越防护、可信 checksum | `mindone-engine/src/download.rs` | `download_integration::resume_atomic_safe_path` | 规划 |
| `model delete <MODEL>` | 默认确认；`--yes` 自动确认；拒绝删除运行/发布模型；清理登记 | `commands/model.rs` | `model_registry_tests::safe_delete` | 规划 |
| `model verify <MODEL>` | 重算 SHA-256、magic/结构/边界；文件变化使旧结果失效 | `commands/model.rs`, `mindone-engine/src/validation.rs` | `validation_tests::*` | 规划 |
| 安全格式 | 允许 GGUF/safetensors；拒绝 pkl/pickle/pt/pth 及伪扩展；错误码 21 | `mindone-engine/src/validation.rs` | `validation_tests::rejects_unsafe_and_spoofed` | 规划 |

## 4. 推理引擎

| 命令 | 参数与行为 | 计划实现 | 自动化验证 | 状态 |
|---|---|---|---|---|
| `engine list` | 可用与已安装、版本、路径、能力、checksum、默认项 | `commands/engine.rs` | `engine_tests::list_truthful` | 规划 |
| `engine install` | `--name <vllm|llama.cpp|ollama|tensorrt-llm>`、`--version` 默认 latest | `commands/engine.rs`, `mindone-engine/src/adapters/*` | `engine_install_tests::*` | 规划 |
| `engine install` 行为 | llama.cpp 真实安装；匹配 OS/arch；校验 checksum；独立目录；不改 PATH；不支持明确拒绝 | `mindone-engine/src/install.rs` | `engine_install_tests::isolated_checksum`；真实 smoke | 规划 |
| `engine detect` | OS、arch、CPU、RAM、GPU、VRAM、Metal/CUDA、后端 | `commands/engine.rs`, `mindone-engine/src/hardware.rs` | `hardware_tests`; 本机 smoke | 规划 |
| `engine set-default <ENGINE>` | 仅接受已安装且可执行引擎；原子写配置 | `commands/engine.rs` | `engine_tests::installed_default_only` | 规划 |

## 5. 本地服务

| 命令 | 参数与行为 | 计划实现 | 自动化验证 | 状态 |
|---|---|---|---|---|
| `serve run` | `--model`、`--engine`、`--port 8080`、`--config`；默认绑定 127.0.0.1 | `commands/serve.rs`, `mindone-engine/src/process.rs` | `serve_integration::loopback_and_health` | 规划 |
| `serve run` 安全 | 已验证且兼容模型；绝对引擎路径；实际沙盒；PID/时间/日志/状态；拒绝重复；真实 health；日志轮转 | `mindone-engine/src/process.rs`, `mindone-sandbox` | `serve_integration::*` | 规划 |
| `serve status` | 核验真实进程身份而非仅读文件；TPS、RAM/VRAM、模型、端口、沙盒与 Trust | `commands/serve.rs` | `serve_integration::status_checks_process` | 规划 |
| `serve stop` | 先优雅停止、超时后终止；防 PID 复用；安全清理状态 | `commands/serve.rs` | `serve_integration::graceful_then_force` | 规划 |
| 缓冲清理 | 仅报告实际完成的 KV cache/主机缓冲 best-effort 清理 | `mindone-engine/src/process.rs` | `cleanup_capability_tests` | 规划 |

## 6. 网络共享

| 命令 | 参数与行为 | 计划实现 | 自动化验证 | 状态 |
|---|---|---|---|---|
| `share publish` | `--model`、`--alias`、`--tags`；注册节点/硬件，发布模型哈希，启动心跳和 worker | `commands/share.rs`, `worker.rs` | `share_integration::publish_registers_worker` | 规划 |
| 任务执行 | 出站 TLS 领取、租约/续租/超时/重试、二次策略检查、本地真实推理、幂等结果、错误分类、断线恢复 | `worker.rs` | `job_e2e::*` | 规划 |
| `share unpublish` | 支持实例选择；停止新领取、drain 已有任务、取消发布并停心跳 | `commands/share.rs` | `share_integration::unpublish_drains` | 规划 |
| `share stats` | 请求、成功率、uptime、TTFT、TPS、失败、Tier、Trust、收益 | `commands/share.rs` | `share_integration::real_stats` | 规划 |
| 网络边界 | 节点无需入站公网；绝不公开 llama-server | `worker.rs`, `deploy/*` | E2E 监听端口审计 | 规划 |

## 7. 双轨经济与本地代理

| 命令 | 参数与行为 | 计划实现 | 自动化验证 | 状态 |
|---|---|---|---|---|
| `quota balance` | 权威服务器余额；可用额度、贡献值、Tier、准备金统计分栏 | `commands/quota.rs` | `accounting_integration::balance` | 规划 |
| `quota history` | `--page`、`--page-size`、`--from`、`--to`；JSON；只追加账项 | `commands/quota.rs` | `accounting_integration::history_filters` | 规划 |
| `quota receipt --id` | 完整荣誉账单、两位显示、内部整数 | `commands/quota.rs` | `receipt_tests`; 场景 A golden | 规划 |
| `quota use` | `--model` 默认 auto、`--port` 默认 9090；只绑定 127.0.0.1 | `commands/quota.rs`, `proxy.rs` | `proxy_integration::loopback` | 规划 |
| `GET /v1/models` | OpenAI 兼容模型列表 | `proxy.rs` | `proxy_integration::models` | 规划 |
| `POST /v1/chat/completions` | 创建真实远程 job 并等待真实节点响应 | `proxy.rs` | 真实 GGUF E2E | 规划 |
| `POST /v1/completions` | 创建真实远程 job 并映射 OpenAI 响应 | `proxy.rs` | 真实 GGUF E2E | 规划 |
| 流式 | 能力不支持时对 `stream:true` 明确报错；支持时才返回 SSE | `proxy.rs` | `proxy_integration::stream_contract` | 规划 |
| 定点公式 | perf 1.5/1.0/0.7；trust 1.1/1.0/0.5；quota 0.8；points 1.2 | `mindone-accounting/src/settlement.rs` | `settlement_tests::*` | 规划 |
| 事务账本 | 消费扣款、节点额度、贡献值、准备金、job complete 同事务；失败不扣；幂等 | `mindone-coordinator/src/services/jobs.rs` | PostgreSQL settlement integration | 规划 |
| 哈希链 | 唯一 ID、时间、前后余额、请求 ID、前哈希、自身哈希；只追加 | `mindone-accounting/src/ledger.rs`, migrations | `ledger_tests::detects_tamper` | 规划 |
| 准备金 | 仅四种允许用途；独立释放账项；不得透支；流入/流出/余额可查 | `mindone-coordinator/src/services/reserve.rs` | `reserve_integration::*` | 规划 |

## 8. 节点策略

| 命令 | 参数与行为 | 计划实现 | 自动化验证 | 状态 |
|---|---|---|---|---|
| `node policy show` | 显示拒绝标签和最大并发 | `commands/node.rs` | `policy_tests::show` | 规划 |
| `node policy set` | `--reject-tags`、`--max-concurrent`；领取前与执行前生效 | `commands/node.rs`, `worker.rs` | `policy_tests::preclaim_and_preexecute` | 规划 |
| `node threshold show` | 显示 GPU 温度与显存保留，能力不可用时明确 | `commands/node.rs` | `threshold_tests::show_capability` | 规划 |
| `node threshold set` | `--gpu-temp-limit`、`--vram-reserve`；超温暂停、滞回恢复 | `commands/node.rs`, `worker.rs` | `threshold_tests::pause_and_recover` | 规划 |
| `node optimize` | 基于真实 TPS/TTFT/错误率/Tier 的确定性建议 | `commands/node.rs` | `optimize_tests::deterministic` | 规划 |
| 策略拒绝 | 实际拒绝请求并返回错误码 50，不扣额度 | CLI、worker、coordinator | policy/accounting integration；场景 B | 规划 |

## 9. 全局配置与诊断

| 命令 | 参数与行为 | 计划实现 | 自动化验证 | 状态 |
|---|---|---|---|---|
| `config set <KEY> <VALUE>` | 白名单 server URL/default engine/log level/data dir/update channel；原子写 | `commands/config.rs`, `mindone-common/src/config.rs` | `config_tests::known_atomic` | 规划 |
| `config get <KEY>` | 读取已知键；未知键报错 | `commands/config.rs` | `config_tests::get_unknown` | 规划 |
| `config list` | 列出非敏感配置；不显示系统凭证 | `commands/config.rs` | `config_tests::never_lists_secret` | 规划 |
| 敏感配置拒绝 | Token、password、secret、私钥、DB URL 等禁止保存 | `mindone-common/src/config.rs` | `config_tests::rejects_sensitive` | 规划 |
| `doctor` | OS/arch、依赖、目录、Keychain、DNS/网络、server、engine、model、port、sandbox、GPU、cloudflared；server 模式才查 DB | `commands/doctor.rs` | `doctor_tests::*`; 本机 smoke | 规划 |
| `MINDONE_HOME` | 支持隔离数据目录，供双用户 E2E | `mindone-common/src/dirs.rs` | `dirs_tests::isolated_home` | 规划 |

## 10. 稳定退出码

| 码 | 含义 | 计划实现 | 自动化验证 | 状态 |
|---:|---|---|---|---|
| 0 | 成功 | `mindone-common/src/error.rs` | `exit_code_tests::success` | 规划 |
| 1 | 通用错误 | 同上 | `exit_code_tests::generic` | 规划 |
| 10 | 认证/系统凭证库失败 | 同上 | `exit_code_tests::auth` | 规划 |
| 20 | 引擎安装/沙盒初始化失败 | 同上 | `exit_code_tests::engine` | 规划 |
| 21 | 模型安全校验失败 | 同上 | `exit_code_tests::model` | 规划 |
| 30 | 远程证明失败 | 同上 | `exit_code_tests::attestation` | 规划 |
| 31 | 明确请求更高能力后发生信任降级警告 | 同上 | `exit_code_tests::downgrade` | 规划 |
| 40 | 可用额度不足 | 同上 | `exit_code_tests::quota` | 规划 |
| 50 | 节点策略拒绝 | 同上 | `exit_code_tests::policy` | 规划 |

## 11. 规范业务场景

| 场景 | 预期 | 计划实现 | 自动化验证 | 状态 |
|---|---|---|---|---|
| A：荣誉账单 | base 1.00，High/Standard deduction 1.50，quota 1.20，points 1.80，reserve 0.30 | accounting + `quota receipt` | `receipt_tests::spec_scenario_a` | 规划 |
| B：硬件保护 | 75°C、保留 4GB、拒绝 nsfw/heavy-math、最大并发 2，实际影响领取/执行 | policy + worker | `policy_e2e::spec_scenario_b` | 规划 |

## 12. 完成时总体验收

| 验收 | 证据 | 状态 |
|---|---|---|
| fmt、clippy、workspace tests | 本地命令与 CI | 规划 |
| PostgreSQL migrations 和 API 集成 | Compose + 集成测试 | 规划 |
| 两个隔离 Home 的真实 GGUF E2E | `scripts/e2e-test.sh` 日志 | 规划 |
| Cloudflare 五项公网安全测试 | HTTPS 与端口检查 | 规划 |
| 安装、版本、帮助、doctor、卸载 | 干净临时目录测试 | 规划 |
| GitHub Actions、分支推送和 PR | GitHub 状态链接 | 规划 |
| 静态扫描零违规项 | `rg` 与 secret scan | 规划 |

