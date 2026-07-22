# MindOne 命令行接口 (CLI) 规范文档

**文档版本**：v1.0.0 MVP / Release Draft
**对齐白皮书**：MindOne 技术白皮书 v1.0.0
**草案日期**：2026年7月17日

> 本文是 CLI 的目标规范草案，不是正式发布或当前全量验收证明。实际命令、限制和测试证据以 `mindone --help`、`README.md` 与 `docs/CLI_COMPLIANCE.md` 为准。邮箱登录仍使用标准 Ed25519 Device Flow：浏览器只授权用户手工输入的终端 12 位代码，不接收 bearer；CLI 必须签名 poll 后才取得会话。password reset 尚未实现，也不存在失败后绕过设备证明的 Web 登录回退。

---

## 1. 概述

MindOne CLI (`mindone`) 是 MindOne 纯公益算力共享网络的核心开源控制中枢。基于 Rust 语言编写，旨在为开发者与节点运营者提供高性能、跨平台、极致安全的底层命令行交互能力。

本文档记录 MindOne v1.0.0 CLI 的目标接口，并说明它与白皮书中的 **双轨制经济模型**、**强化型本地沙盒**、**二维信任体系**及体验设计的映射。某项设计写入本文不等于对应平台或外部门禁已经通过。

## 2. 核心设计理念与架构映射

在查阅具体命令前，需明确 MindOne CLI 的底层设计原则及其与 v1.0.0 白皮书的映射关系：

1. **零环境变量污染 (Zero-Env Pollution)**：所有推理引擎均安装并运行在 CLI 管理的本地隔离目录中。CLI 通过绝对路径或内部沙盒机制调用引擎， **绝不修改用户的系统 `PATH`**。
2. **默认强制安全隔离 (Default-Enforced Isolation)**：启动推理时，CLI 默认启用强化型沙盒（Namespaces, seccomp-bpf, Landlock）。 **强制校验模型格式**，全面拒绝 `pickle`，仅允许 `safetensors`，并在请求结束后执行 Best-Effort 显存覆写。
3. **双轨制数据透明展示 (Dual-Track Transparency)**：CLI 在额度与统计模块中，严格区分“可用额度 (Spendable Quota)”与“贡献值 (Contribution Points)”，并提供拆解到小数点后两位的“荣誉账单”，满足极客的心理成就感。
4. **节点绝对掌控权 (Node Absolute Control)**：提供细粒度的节点策略配置，赋予节点主“路由否决权”，将被动共享转化为主动的资源优化。

---

## 3. 完整命令参考 (Command Reference)

以下命令树展示了 `mindone` 的完整结构。每个子命令的说明模拟了终端 `--help` 的输出，并附带了架构实现备注。

### 3.1 根命令 (`mindone`)

```text
MindOne CLI v1.0.0 (Open Source Client)
Decentralized AI Compute & Model Sharing Network (Public Welfare)

Usage: mindone [COMMAND]

Commands:
  auth      Manage identity, OS-level keypairs, and remote attestation
  model     Manage local models (Enforces safetensors & schema validation)
  engine    Manage isolated inference engines (Zero-env installation)
  serve     Run local inference services (Default hardened sandbox enforced)
  share     Publish models, report hardware profiles, and establish trust
  quota     Manage dual-track economy (Spendable Quota & Contribution Points)
  node      Manage node policies, routing veto, and hardware thresholds
  config    Manage global CLI configurations
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### 3.2 身份与认证 (`mindone auth`)

*架构备注：所有认证提供者均采用绑定 Ed25519 设备密钥的 OAuth 2.0 Device Flow，私钥存入 OS 级安全凭证库。邮箱模式的同源浏览器页要求用户手工输入自己终端显示的 12 位用户码，只授权 pending flow，不返回 bearer；CLI 签名 poll 后才取得会话。password reset 尚未实现。TEE 远程证明只有在真实硬件与 verifier 完整通过时才能获得相应信任等级。*

```text
Manage identity, authentication, and hardware attestation.

Usage: mindone auth <COMMAND>

Commands:
  login         Log in via OAuth 2.0 Device Flow (Auto-launches browser)
  logout        Revoke tokens and wipe local keypairs from OS vault
  status        Display UID, Trust Level (Standard/Enhanced), and Key fingerprint
  attest        Trigger TEE Remote Attestation to upgrade to Enhanced Trust
  help          Print this message or the help of the given subcommand(s)
```

### 3.3 模型管理 (`mindone model`)

*架构备注：严格遵循白皮书 3.1 节，强制拦截并拒绝 `pickle` 格式，仅允许 `safetensors`。加载前自动进行 Hash 校验与 Schema 验证。*

```text
Manage locally downloaded open-source AI models.
Security: Enforces safetensors format and strict schema validation.

Usage: mindone model <COMMAND>

Commands:
  list      List all locally downloaded models and disk usage
  download  Download a model (Auto-validates safetensors & hash)
  delete    Delete a local model
  verify    Manually trigger Hash and Schema verification for a local model
  help      Print this message or the help of the given subcommand(s)

Download Options:
      --platform <PLATFORM>  [possible values: huggingface, modelscope]
      --repo <REPO>          Repository name (e.g., meta-llama/Llama-3-8B-Instruct)
      --branch <BRANCH>      Branch name [default: main]
```

### 3.4 推理引擎管理 (`mindone engine`)

```text
Manage isolated inference engines.
Installed in local sandbox directory, NO system PATH modification required.

Usage: mindone engine <COMMAND>

Commands:
  list         List available and installed engines
  install      Download and install engine into local isolated directory
  detect       Probe hardware to generate Node Hardware Profile
  set-default  Set the default inference engine
  help         Print this message or the help of the given subcommand(s)

Install Options:
      --name <NAME>        [possible values: vllm, llama.cpp, ollama, tensorrt-llm]
      --version <VERSION>  [default: latest]
```

### 3.5 本地部署与服务 (`mindone serve`)

*架构备注：启动时自动应用跨平台信任矩阵（如 Linux 使用 Landlock，macOS 使用 Seatbelt）。注入 Standard Inference Profile (seccomp-bpf)。*

```text
Run local inference services inside the hardened sandbox.
Sandbox profile is automatically selected based on OS trust matrix.

Usage: mindone serve <COMMAND>

Commands:
  run      Start local inference service (Sandbox enforced)
  stop     Gracefully stop the service
  status   Display TPS, VRAM usage, and current Sandbox Trust Level
  help     Print this message or the help of the given subcommand(s)

Run Options:
      --model <MODEL>      Name or path of the model
      --engine <ENGINE>    Specify engine (overrides default)
      --port <PORT>        Local listening port [default: 8080]
      --config <FILE>      Path to advanced YAML configuration
```

### 3.6 共享与网络 (`mindone share`)

*架构备注：发布共享时，上报硬件画像。若为 Enhanced 节点，需绑定 TEE 加载权重并上报 `model_weights_hash` 以通过服务端 Hidden Benchmark 校验。*

```text
Publish models to the MindOne network.
Reports hardware profile and model weights hash for anti-cheat verification.

Usage: mindone share <COMMAND>

Commands:
  publish     Publish local model to the network
  unpublish   Remove model from the network
  stats       Display sharing stats (Requests, Uptime, Trust Level)
  help        Print this message or the help of the given subcommand(s)

Publish Options:
      --alias <ALIAS>  Custom alias for your node
      --tags <TAGS>    Comma-separated tags for routing (e.g., code,math)
```

### 3.7 贡献额度与双轨制经济 (`mindone quota`)

*架构备注：完美支撑白皮书第 6 章。清晰区分“可用额度”与“贡献值”，并提供“荣誉账单”查询功能，满足心理学驱动的体验设计。*

```text
Manage the dual-track economy: Spendable Quota & Contribution Points.

Usage: mindone quota <COMMAND>

Commands:
  balance     Display Spendable Quota, Contribution Points, and current Tier
  history     Display transaction history with detailed "Honor Receipts"
  receipt     Show the detailed breakdown of a specific contribution receipt
  use         Start local OpenAI-compatible proxy to consume quota
  help        Print this message or the help of the given subcommand(s)

Use Options:
      --model <MODEL>  Target virtual model name (or auto-routing)
      --port <PORT>    Local proxy port [default: 9090]
```

### 3.8 节点策略与路由否决 (`mindone node`)

*架构备注：支撑白皮书 7.2 节“目标梯度与掌控感”。赋予节点主绝对的路由否决权，将被动共享转化为主动优化。*

```text
Manage node policies, routing veto, and hardware thresholds.
Gives node operators absolute control over resource allocation.

Usage: mindone node <COMMAND>

Commands:
  policy      View or set routing veto policies (e.g., reject specific tags)
  threshold   Set hardware safety thresholds (e.g., GPU temp limit, VRAM reserve)
  optimize    Get AI-driven suggestions to improve Tier (e.g., "Increase TPS by 2% to reach High Tier")
  help        Print this message or the help of the given subcommand(s)

Policy Options:
      --reject-tags <TAGS>  Comma-separated tags to reject (e.g., nsfw,heavy-math)
      --max-concurrent <N>  Max concurrent requests allowed

Threshold Options:
      --gpu-temp-limit <C>  Pause sharing if GPU temp exceeds this (Celsius)
      --vram-reserve <GB>   Reserve VRAM for host system
```

### 3.9 全局配置 (`mindone config`)

```text
Manage global CLI configurations.

Usage: mindone config <COMMAND>

Commands:
  set   Set a global configuration key-value pair
  get   Get a global configuration value
  list  List all current configurations
  help  Print this message or the help of the given subcommand(s)
```

---

## 4. 核心业务场景示例 (CLI 交互演示)

### 场景 A：查看“荣誉账单”（心理学体验设计）

节点主完成一次高质量推理后，查看收益明细：

```bash
$ mindone quota receipt --id tx_8f7a9b2c

==================================================
          MINDONE HONOR RECEIPT (荣誉账单)
==================================================
Transaction ID : tx_8f7a9b2c
Model          : Llama-3-70B-Instruct (High Tier)
Trust Level    : Standard Trusted (x1.0)

[ Cost Breakdown ]
- Base Compute Cost      : 1.00
- Performance Premium    : +0.50 (High Tier x1.5)
-------------------------
= User Deduction         : 1.50

[ Your Rewards ]
- Spendable Quota (x0.8) : 1.20  (Available for your own use)
- Contribution Points    : 1.80  (x1.2 Honor Multiplier)
==================================================
Network Reserve Fund absorbed: 0.30
Thank you for powering the open-source AI ecosystem!
```

### 场景 B：设置路由否决权与硬件保护

节点主希望在玩游戏时保留 GPU 性能，并拒绝特定类型的任务：

```bash
$ mindone node threshold set --gpu-temp-limit 75 --vram-reserve 4.0
Success: Node will pause sharing if GPU temp > 75°C or VRAM usage > (Total - 4GB).

$ mindone node policy set --reject-tags nsfw,heavy-math --max-concurrent 2
Success: Routing veto updated. Rejecting tags: [nsfw, heavy-math]. Max concurrent: 2.
```

---

## 5. 退出码与错误处理 (Exit Codes)

为便于自动化运维与脚本集成，CLI 严格遵循 POSIX 规范并扩展了业务错误码：

- `0`: 成功 (Success)
- `1`: 通用错误 (Generic Error)
- `10`: 认证失败或 OS 凭证库不可用 (Auth/Keychain Failed)
- `20`: 引擎安装或沙盒初始化失败 (Sandbox Init Failed)
- `21`: **模型安全校验失败** (Model Validation Failed - e.g., detected pickle format)
- `30`: **远程证明失败**，节点未被服务端信任 (Remote Attestation Failed)
- `31`: **信任降级警告** (Trust Downgraded - e.g., OS kernel too old for Landlock)
- `40`: 可用额度不足 (Insufficient Spendable Quota)
- `50`: 节点策略拦截 (Request rejected by Node Policy/Veto)

---

## 6. 结语

MindOne CLI v1.0.0 不仅仅是一个命令行工具，它是 MindOne 纯公益算力共享网络理念的代码化呈现。通过强制的安全沙盒、严谨的模型校验、透明的双轨制荣誉账单，以及赋予节点主绝对掌控权的策略配置，CLI 在底层确保了网络的安全、公平与极客精神的传承。

配合受控核心服务端的全局调度与反作弊机制，MindOne 正在让全球每一张闲置的显卡，都在这个透明、安全的网络中，闪耀出属于它们的光芒。
