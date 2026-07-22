# MindOne CLI v1.0.0 完整可用 MVP 总任务

你正在 Codex 桌面版的目标模式中工作。请完整实现 MindOne，而不是制作演示、代码骨架、空壳命令或不可运行的半成品。

仓库：

```text
https://github.com/beluga383/MindOne
```

规范文件：

```text
docs/specs/mindone_1.0.0.md
docs/specs/mindone_cli_1.0.0.md
```

开始前必须完整阅读这两份文件，并创建：

```text
docs/CLI_COMPLIANCE.md
```

该文件需要逐项列出第二份 CLI 规范中的每个命令、参数、行为、错误码和业务场景，标记对应实现文件与自动化测试。任务完成时，不允许存在未完成项。

---

# 一、最终目标

完成一套可以真实安装、登录、下载模型、安装推理引擎、运行本地推理、发布节点、承接网络请求、结算额度、查看贡献记录和多人协作开发的 MindOne MVP。

最终系统必须包含：

```text
1. MindOne 简体中文 CLI
2. MindOne 协调服务器
3. PostgreSQL 数据库及迁移
4. 真实账号登录
5. 节点注册与心跳
6. 模型发布与取消发布
7. 任务创建、领取、执行、返回和失败重试
8. 两阶段模型与节点调度
9. 可用额度、贡献值和网络准备金账本
10. OpenAI 兼容本地调用代理
11. llama.cpp 引擎管理
12. 模型安全验证
13. 节点资源保护与路由否决
14. Cloudflare Tunnel 公网 API
15. 安装、卸载、升级和 GitHub Release
16. 单元测试、集成测试和真实端到端测试
17. Git 多人协作说明
```

不允许只实现 CLI 本地界面而缺少服务端，也不允许通过固定返回值假装服务器、额度、共享、认证或推理已经工作。

---

# 二、执行规则

1. 检查当前仓库和 Git 状态。
2. 拉取远程最新代码，不覆盖用户未提交的修改。
3. 从最新主分支创建：

```text
codex/complete-cli-mvp-v1
```

4. 不允许直接重写 `main`，不允许 force push。
5. 先提交实施计划到：

```text
docs/IMPLEMENTATION_PLAN.md
```

6. 随后持续编码、运行测试、修复错误，直到所有验收条件通过。
7. 不要仅告诉用户“下一步该做什么”；除必须由用户亲自批准的登录、验证码、系统权限和 Cloudflare 保存操作外，其余工作全部自己完成。
8. 每完成一个独立模块就创建一次清晰的 Git commit。
9. 所有源代码、终端帮助、状态、错误和安装说明默认使用简体中文。
10. 代码标识符、协议字段、日志结构和 API 路径可以使用英文。
11. 普通错误不得使用 `panic!`。
12. 不允许遗留影响功能的 `TODO`、`unimplemented!()`、假数据或占位接口。
13. 不得伪造测试结果、命令输出或安全能力。
14. 不得修改域名 Nameserver、删除现有 Cloudflare 配置、创建付费服务或进行购买。
15. 不得把数据库密码、OAuth Secret、Token、私钥或 Cloudflare Token提交进 Git。

---

# 三、现实边界与规范冲突处理

## 3.1 模型格式

CLI 规范同时要求支持 `llama.cpp`，又要求只允许 `safetensors`。`llama.cpp` 实际运行 GGUF，因此采用以下可执行规则：

```text
允许登记和验证：
- .gguf
- .safetensors

llama.cpp 可以运行：
- .gguf

其他兼容引擎可以运行：
- .safetensors

强制拒绝：
- .pkl
- .pickle
- .pt
- .pth
- 其他依赖任意代码反序列化的模型格式
```

将这个决定写入：

```text
docs/adr/0001-model-formats.md
```

不得通过修改文件扩展名绕过验证。必须检查文件头、结构、大小、SHA-256 和安全限制。

## 3.2 TEE 与远程证明

不得在没有真实硬件支持时假装 Enhanced Trusted。

`mindone auth attest` 必须完整实现：

```text
1. 检测当前平台和可用证明提供者。
2. 支持提供者接口和证明报告验证流程。
3. 验证 nonce、防重放、时间戳、策略哈希、运行时哈希和模型哈希。
4. 不支持的设备必须明确返回“此设备不支持 Enhanced 远程证明”。
5. 返回退出码 30，而不是伪造成功。
6. macOS 默认只能获得 Standard-Limited。
7. Windows 默认为 Experimental。
8. 支持的 Linux TEE 环境才允许升级 Enhanced。
```

硬件不存在时正确拒绝，是完整行为，不得使用软件随机值伪装硬件证明。

## 3.3 沙盒能力

根据实际平台启用真实可用的最高隔离等级：

```text
Linux 5.13+：
Namespaces + seccomp-bpf + Landlock

较旧 Linux：
Namespaces + seccomp-bpf + AppArmor 检测与降级

macOS：
Seatbelt/App Sandbox 能力检测与受限运行
标记 Standard-Limited

Windows：
Job Objects + 可用的 AppContainer
无法启用时标记 Experimental
```

CLI 状态必须显示实际启用的机制，禁止显示不存在的安全能力。

---

# 四、技术架构

使用 Rust stable 和 Cargo workspace。

建议结构可以调整，但职责必须完整：

```text
MindOne/
├── AGENTS.md
├── Cargo.toml
├── Cargo.lock
├── crates/
│   ├── mindone-cli/
│   ├── mindone-coordinator/
│   ├── mindone-protocol/
│   ├── mindone-common/
│   ├── mindone-engine/
│   ├── mindone-sandbox/
│   └── mindone-accounting/
├── migrations/
├── deploy/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── cloudflared/
├── scripts/
│   ├── install.sh
│   ├── install.ps1
│   ├── uninstall.sh
│   └── e2e-test.sh
├── docs/
│   ├── specs/
│   ├── adr/
│   ├── IMPLEMENTATION_PLAN.md
│   ├── CLI_COMPLIANCE.md
│   ├── API.md
│   ├── INSTALL.md
│   ├── OPERATIONS.md
│   ├── SECURITY.md
│   └── COLLABORATION.md
└── .github/workflows/
    ├── ci.yml
    ├── release.yml
    └── security.yml
```

推荐使用：

```text
clap
tokio
axum
reqwest
serde
serde_json
toml
sqlx
postgres
uuid
sha2
keyring
thiserror
tracing
tracing-subscriber
sysinfo
time
jsonwebtoken
rustls
tower
tower-http
```

约束：

```text
- 所有网络连接使用 TLS。
- 数据库金额不得使用浮点数。
- 可用额度和贡献值使用整数最小单位，例如 microquota。
- 数据库结算必须使用事务。
- 用户端不得自行决定或修改余额。
- CLI 不得持有数据库凭证。
- CLI 只能通过协调服务器 API 操作账户。
```

---

# 五、完整 CLI 命令

程序名称：

```text
mindone
```

根帮助必须为简体中文，并包含：

```text
auth
model
engine
serve
share
quota
node
config
doctor
help
```

全局参数至少包含：

```text
-h, --help
-V, --version
--json
--quiet
--verbose
```

## 5.1 身份认证

完整实现：

```text
mindone auth login
mindone auth logout
mindone auth status
mindone auth attest
```

要求：

```text
- 使用 OAuth 2.0 Device Flow。
- 优先采用 GitHub OAuth Device Flow。
- login 显示验证码和验证地址，并自动打开浏览器。
- 凭证存入 macOS Keychain、Windows Credential Manager 或 Linux Secret Service。
- 不允许把明文 Token 写入 config.toml。
- logout 撤销会话并清除本地凭证和密钥。
- status 显示用户、UID、信任等级、密钥指纹、登录时间和服务器地址。
- attest 按前文真实能力执行。
```

需要建立本地设备密钥对，并完成服务端绑定、轮换和撤销。

如果 GitHub OAuth App 尚未创建：

```text
1. 使用 Computer Use 打开 Safari。
2. 进入用户已经登录的 GitHub 设置。
3. 创建 MindOne OAuth App。
4. 启用 Device Flow。
5. 对保存、权限或敏感操作请求用户确认。
6. 将 Client ID 写入非敏感配置。
7. Client Secret 仅写入本机安全 Secret 或服务器环境变量。
```

## 5.2 模型管理

完整实现：

```text
mindone model list
mindone model download
mindone model delete
mindone model verify
```

`download` 参数：

```text
--platform <huggingface|modelscope>
--repo <REPO>
--branch <BRANCH>
--name <NAME>
```

要求：

```text
- 支持续传、进度显示、临时文件和原子重命名。
- 防止路径穿越。
- 下载后验证 SHA-256、文件头、格式和结构。
- 支持可信清单和用户提供的 checksum。
- 拒绝 Pickle 风险格式。
- list 显示名称、格式、大小、路径、哈希、验证状态和兼容引擎。
- delete 要求确认，并清理登记记录。
- verify 可重复执行，并在文件改变后标记失效。
```

## 5.3 推理引擎

完整实现：

```text
mindone engine list
mindone engine install
mindone engine detect
mindone engine set-default
```

`install` 参数：

```text
--name <vllm|llama.cpp|ollama|tensorrt-llm>
--version <VERSION>
```

要求：

```text
- MVP 至少真实运行 llama.cpp。
- 其他引擎必须具有完整的能力检测和安装适配器。
- 不支持的平台必须返回明确原因，不能假装安装成功。
- 引擎安装进 MindOne 独立目录。
- 禁止修改系统 PATH。
- 下载对应架构的发行文件并校验 checksum。
- detect 检测 OS、架构、CPU、RAM、GPU、显存、Metal/CUDA 和可用后端。
- set-default 验证引擎确实已安装。
```

本地目录遵循系统规范，示例：

```text
~/.mindone/
├── config.toml
├── models/
├── engines/
├── runtime/
├── logs/
└── cache/
```

## 5.4 本地服务

完整实现：

```text
mindone serve run
mindone serve stop
mindone serve status
```

参数：

```text
--model <MODEL>
--engine <ENGINE>
--port <PORT>
--config <FILE>
```

要求：

```text
- 默认监听 127.0.0.1，禁止默认监听 0.0.0.0。
- 自动应用平台可用沙盒。
- 使用绝对路径启动引擎。
- 不修改 PATH。
- 保存 PID、启动时间、端口、模型、引擎、日志和沙盒状态。
- 启动后执行真实健康检查。
- 拒绝重复启动。
- status 必须检查真实进程，不只读取状态文件。
- 显示 TPS、内存/显存、模型、端口、进程状态和信任等级。
- stop 先优雅退出，超时后再终止。
- 请求结束后对可控 KV Cache 和主机缓冲区执行 Best-Effort 清理。
- 日志轮转，避免无限增长。
```

## 5.5 网络共享

完整实现：

```text
mindone share publish
mindone share unpublish
mindone share stats
```

`publish` 参数：

```text
--model <MODEL>
--alias <ALIAS>
--tags <TAGS>
```

要求：

```text
- 注册节点和硬件画像。
- 发布模型实例及 model_weights_hash。
- 启动持续心跳。
- 从服务端领取真实任务。
- 在本地执行任务并上传加密传输的结果。
- 失败时上传明确错误分类。
- 支持任务超时、租约、重试和节点断线恢复。
- unpublish 停止领取新任务，等待已有任务结束，再取消发布。
- stats 显示请求数、成功率、运行时间、TTFT、TPS、失败数、Tier、Trust 和收益。
```

节点不需要公网端口。任务通信采用节点主动连接协调服务器的出站 HTTPS 长轮询或安全 WebSocket。

不得将 `llama-server` 直接暴露到互联网。

## 5.6 双轨经济

完整实现：

```text
mindone quota balance
mindone quota history
mindone quota receipt
mindone quota use
```

`use` 参数：

```text
--model <MODEL>
--port <PORT>
```

要求：

```text
- balance 显示可用额度、贡献值、节点等级和准备金相关统计。
- history 支持分页、时间过滤和 JSON。
- receipt 输出完整“荣誉账单”。
- use 在本机启动 OpenAI 兼容代理，默认监听 127.0.0.1:9090。
```

至少支持：

```text
GET  /v1/models
POST /v1/chat/completions
POST /v1/completions
```

如果底层暂时不能流式生成，应返回明确不支持；能够支持时实现 SSE 流式输出。

经济公式严格按照白皮书：

```text
Deduct_user = C_base × M_perf
Quota_node = Deduct_user × 0.8 × Trust
Points_node = Deduct_user × 1.2 × Trust
Reserve = Deduct_user - Quota_node
```

要求：

```text
- 高级表现倍率 1.5
- 中级表现倍率 1.0
- 低级表现倍率 0.7
- Enhanced 信任 1.1
- Standard 信任 1.0
- Unverified 信任 0.5
- 使用整数定点计算
- 所有账本只追加，禁止原地覆盖历史
- 每笔账变拥有唯一 ID、时间、前后余额、请求 ID 和哈希链
- 结算、准备金和任务完成处于同一数据库事务
- 失败任务不得错误扣款
- 重试费用和准备金使用必须可审计
```

解决白皮书准备金回流未定义的问题：

```text
- 准备金只能用于验证、失败重算、带宽补贴和高峰保障。
- 每次释放必须生成独立账本项。
- 任意时刻总释放不得突破准备金余额。
- 输出准备金流入、流出和余额。
- 在 docs/adr 中记录规则。
```

## 5.7 节点策略

完整实现：

```text
mindone node policy
mindone node threshold
mindone node optimize
```

支持：

```text
mindone node policy show
mindone node policy set \
  --reject-tags <TAGS> \
  --max-concurrent <N>

mindone node threshold show
mindone node threshold set \
  --gpu-temp-limit <C> \
  --vram-reserve <GB>

mindone node optimize
```

要求：

```text
- 策略在领取任务前和执行前都要检查。
- 拒绝标签、最大并发、GPU 温度和显存保留必须真正生效。
- 超过温度阈值自动暂停领取任务。
- 恢复后自动重新上线。
- optimize 根据真实 TPS、TTFT、错误率和当前 Tier 给出可复现建议。
- 不得使用随机文字假装智能优化。
```

## 5.8 全局配置

完整实现：

```text
mindone config set
mindone config get
mindone config list
```

要求：

```text
- 支持服务器地址、默认引擎、日志级别、数据目录、更新通道等配置。
- 配置使用原子写入。
- 对未知配置键给出错误。
- 敏感值禁止通过 config 命令保存。
```

## 5.9 环境诊断

实现：

```text
mindone doctor
```

检查：

```text
- 系统与架构
- Rust/运行依赖
- 数据目录权限
- Keychain
- 网络和 DNS
- 协调服务器健康状态
- 引擎安装
- 模型验证
- 端口占用
- 沙盒能力
- GPU/Metal/CUDA
- cloudflared 状态
- 数据库仅在服务端模式检查
```

每一项显示通过、警告或失败，并返回合理退出码。

---

# 六、退出码

严格实现：

```text
0  成功
1  通用错误
10 认证失败或系统凭证库不可用
20 引擎安装或沙盒初始化失败
21 模型安全校验失败
30 远程证明失败
31 信任等级降级警告
40 可用额度不足
50 节点策略拒绝请求
```

可以增加业务错误码，但不得改变以上含义。

`--json` 输出必须包含稳定字段：

```json
{
  "ok": false,
  "code": 21,
  "error": {
    "type": "model_validation_failed",
    "message": "检测到不安全的模型格式"
  }
}
```

---

# 七、协调服务器

使用 Axum 或同等 Rust Web 框架，真实实现：

```text
GET  /health
GET  /ready

POST /v1/auth/device/start
POST /v1/auth/device/poll
POST /v1/auth/refresh
POST /v1/auth/logout

POST /v1/nodes/register
POST /v1/nodes/{node_id}/heartbeat
GET  /v1/nodes/{node_id}/stats

POST   /v1/models/publish
DELETE /v1/models/{model_instance_id}
GET    /v1/models

POST /v1/jobs
GET  /v1/jobs/{job_id}
POST /v1/jobs/claim
POST /v1/jobs/{job_id}/renew
POST /v1/jobs/{job_id}/result
POST /v1/jobs/{job_id}/fail

GET /v1/quota/balance
GET /v1/quota/history
GET /v1/quota/receipts/{receipt_id}

GET /v1/reserve
```

至少建立：

```text
users
sessions
device_keys
nodes
node_policies
node_metrics
models
model_instances
jobs
job_attempts
quota_accounts
quota_ledger
contribution_ledger
reserve_ledger
attestation_reports
heartbeats
```

要求：

```text
- SQL migrations 可重复执行。
- 使用 PostgreSQL 事务。
- 任务领取使用租约和行锁，防止重复领取。
- 幂等键避免重复提交和重复结算。
- Token 哈希存储。
- 访问 Token 短期有效，支持刷新和撤销。
- 设置请求大小限制、超时、速率限制和结构化日志。
- 不记录 Prompt 和 Response 明文。
- 健康检查不泄露 Secret。
```

---

# 八、调度与模型评价

实现白皮书中的两阶段调度。

第一阶段选择模型：

```text
质量
意图匹配
成本
可用状态
上下文长度
```

第二阶段选择节点：

```text
信任等级
健康度
网络延迟
容量
当前并发
策略限制
近期错误率
```

质量融合需要修复权重不归一问题，使用：

```text
Q = (1 - beta) × BenchmarkNormalized
  + beta × GlickoNormalized
```

其中：

```text
beta = n / (n + k)
```

Tier 不能只依赖强制 Top/Bottom 比例。采用：

```text
绝对性能门槛为主
同模型相对排名为辅
滞回区间防止频繁跳级
最小样本数防止冷启动误判
```

将最终算法、参数和原因写进 ADR，并编写确定性测试。

---

# 九、Cloudflare 和域名

用户会打开并登录 Cloudflare Dashboard 的 Safari 页面。

需要使用 Computer Use 操作 Safari，只处理与本任务相关的 Cloudflare 页面。

流程：

```text
1. 检查本机协调服务器监听端口，建议使用 8787。
2. 检查是否已有 Cloudflare Tunnel。
3. 没有则创建名为 mindone-coordinator 的 Tunnel。
4. 使用终端安装并启动 cloudflared connector。
5. 在 Cloudflare Tunnel 的 Routes 中选择 Add route。
6. 选择 Published application。
7. 从用户 Cloudflare UI 中已有域名里选择合适域名。
8. 优先创建 api.<现有域名>。
9. Service URL 指向 http://localhost:8787。
10. 不要暴露 PostgreSQL、llama-server 或本地管理端口。
11. 保存前让用户确认域名和路由。
12. 保存后测试 https://api.<域名>/health。
13. 将最终 API 地址写入 MindOne 配置和 docs/OPERATIONS.md。
```

不得：

```text
- 修改 Nameserver
- 删除现有 DNS 记录
- 开启付费功能
- 暴露数据库
- 暴露用户本地推理端口
- 绕过 Cloudflare 登录或安全验证
```

如果 Safari 或系统弹出账号、验证码、系统权限或敏感确认，暂停并让用户亲自完成；完成后继续任务，不要因此结束整个开发。

---

# 十、GitHub 与自动发布

仓库远程地址：

```text
https://github.com/beluga383/MindOne
```

完成以下 GitHub Actions：

```text
ci.yml
- cargo fmt --check
- cargo clippy --workspace --all-targets -- -D warnings
- cargo test --workspace
- 数据库迁移测试
- API 集成测试
- Linux、macOS、Windows 构建

release.yml
- 根据 v* tag 构建发布文件
- macOS arm64
- macOS x86_64
- Linux x86_64
- Linux aarch64
- Windows x86_64
- 生成 SHA-256
- 生成压缩包
- 创建 GitHub Release

security.yml
- cargo audit
- Secret 扫描
- 依赖检查
```

如果无法提供 Apple 或 Windows 代码签名证书，不得伪造签名。请明确标记当前发行物未签名，并在文档中说明正式公测前需要哪些开发者证书。

---

# 十一、安装与升级

提供真实可运行的安装方式。

macOS/Linux：

```bash
curl -fsSL https://raw.githubusercontent.com/beluga383/MindOne/main/scripts/install.sh | sh
```

Windows PowerShell：

```powershell
irm https://raw.githubusercontent.com/beluga383/MindOne/main/scripts/install.ps1 | iex
```

同时支持：

```bash
cargo install --git https://github.com/beluga383/MindOne mindone-cli
```

要求：

```text
- 自动识别系统与 CPU 架构。
- 下载正确的 Release 产物。
- 校验 SHA-256。
- 安装 mindone 可执行文件。
- 不覆盖不相关文件。
- 支持 --version。
- 支持卸载。
- 支持检查更新。
- 安装失败时清理临时文件。
```

安装脚本不得要求用户关闭系统安全机制，也不得指示用户绕过来源验证。

---

# 十二、测试要求

必须自己实际运行测试，不能只编写测试文件。

## 12.1 单元测试

覆盖：

```text
- 所有 clap 命令解析
- 简体中文帮助
- 配置读写
- 密钥存储抽象
- SHA-256
- GGUF 文件头验证
- safetensors 结构验证
- 危险格式拒绝
- 退出码
- 定点额度计算
- 哈希链账本
- Tier 算法
- 路由评分
- 节点策略
- 阈值判断
```

## 12.2 集成测试

覆盖：

```text
- PostgreSQL migrations
- 用户认证
- 节点注册和心跳
- 模型发布和取消发布
- 任务领取租约
- 重复领取保护
- 任务完成结算
- 失败任务不扣款
- 准备金流入和释放
- 余额不足
- 路由否决
- API Token 撤销
```

## 12.3 真实端到端测试

使用两个隔离的 `MINDONE_HOME` 目录，在同一台机器模拟：

```text
消费者 A
贡献节点 B
```

必须实际完成：

```text
1. 启动 PostgreSQL。
2. 运行数据库迁移。
3. 启动协调服务器。
4. 完成账号登录。
5. 安装或检测 llama.cpp。
6. 下载一个许可证允许测试的小型 GGUF 模型。
7. 验证模型哈希和格式。
8. 启动本地推理服务。
9. 发布节点和模型。
10. 确认心跳在线。
11. 消费者启动 mindone quota use。
12. 使用 curl 调用本机 OpenAI 兼容接口。
13. 由贡献节点真实生成返回内容。
14. 检查消费者额度被扣除。
15. 检查贡献节点可用额度和贡献值增加。
16. 检查网络准备金增加。
17. 查询 history 和 receipt。
18. 取消发布。
19. 停止服务。
20. 注销登录。
```

调用示例：

```bash
curl http://127.0.0.1:9090/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "auto",
    "messages": [
      {"role": "user", "content": "只回复：MindOne 已连接"}
    ]
  }'
```

必须验证返回来自真实模型推理，而不是硬编码字符串或 Mock。

Mock 只允许用于单元和部分集成测试，最终 E2E 不得使用 Mock 推理结果。

## 12.4 公网测试

完成 Cloudflare 路由后实际测试：

```text
- HTTPS /health
- 未认证访问受保护 API 被拒绝
- 正确 Token 可以访问
- 数据库端口无法从公网访问
- llama-server 端口无法从公网访问
```

## 12.5 发布安装测试

在临时目录或干净用户环境中：

```text
- 运行 install.sh
- mindone --version
- mindone --help
- mindone doctor
- 运行卸载
- 验证未残留错误文件
```

---

# 十三、完成门槛

以下项目全部通过才允许声明完成：

```text
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
docker compose up 后服务健康
真实 GGUF 推理成功
消费者到节点的完整网络任务成功
经济账本结算正确
Cloudflare 公网健康检查成功
安装脚本在本机成功
CLI_COMPLIANCE.md 没有未完成项
GitHub Actions 全部通过
Git 工作区干净
分支已推送到 origin
```

执行以下代码检查：

```text
- 搜索 TODO
- 搜索 FIXME
- 搜索 unimplemented!
- 搜索生产代码中的 panic!
- 搜索硬编码 Secret
- 搜索假余额、假推理结果和固定成功响应
```

发现任何影响功能的内容就继续修复。

---

# 十四、最终提交与汇报

完成后：

```text
1. 提交所有代码。
2. 推送 codex/complete-cli-mvp-v1。
3. 创建 Pull Request 到 main。
4. PR 中写清架构、测试、安全限制和迁移方式。
5. 不自动合并，交给用户审查。
```

最终回复必须使用简体中文，并包含以下内容。

## 14.1 做了什么

逐模块说明：

```text
CLI
协调服务器
数据库
认证
模型
引擎
推理
共享
调度
经济系统
沙盒
Cloudflare
安装
GitHub Actions
```

## 14.2 实现了什么

逐项对应 `mindone_cli_1.0.0.md`，不能只写模糊总结。

## 14.3 实际测试结果

列出：

```text
- 实际执行的命令
- 每项测试通过数量
- E2E 使用的模型
- 实际推理响应
- Cloudflare HTTPS 测试结果
- GitHub Actions 链接或状态
```

不得编造没有运行的结果。

## 14.4 本机安装和调用指令

给出从零开始的完整命令，包括：

```text
安装
登录
检测硬件
安装引擎
下载模型
验证模型
启动服务
发布节点
查看统计
启动额度代理
curl 调用
查看余额
查看荣誉账单
停止和卸载
```

## 14.5 已知限制

只允许列出真实硬件或外部账号造成的限制，例如：

```text
当前 Mac 不具备目标 TEE
缺少 Apple 代码签名证书
某引擎不支持当前平台
```

不得把本应实现的核心功能放进“已知限制”。

## 14.6 告诉其他人如何参与 Git

创建并完善：

```text
docs/COLLABORATION.md
CONTRIBUTING.md
```

最终回复也需要给出简明流程：

```bash
git clone https://github.com/beluga383/MindOne.git
cd MindOne
git switch main
git pull
git switch -c feature/功能名称

# 修改并测试

git add .
git commit -m "feat: 功能说明"
git push -u origin feature/功能名称
```

然后说明：

```text
- 在 GitHub 创建 Pull Request。
- 不要直接向 main 推送。
- 合并前必须通过 CI。
- 每个人使用独立分支。
- 提交信息遵循 Conventional Commits。
- 大模型文件、Token、数据库和本地配置不得提交。
```

---

# 十五、最后原则

你不能为了快速结束而降低目标。

遇到错误时：

```text
定位原因 → 修改实现 → 重新测试 → 记录结果
```

不要只报告错误并停止。

只有需要用户亲自完成的验证码、账号批准、系统权限、安全确认或 Cloudflare 保存操作，才能暂停并请求用户操作。用户完成后立即继续。

除真实硬件能力外，不接受“以后实现”“留到下一版”“当前只是 MVP”作为缺少 CLI 规范功能的理由。

现在开始检查仓库、阅读两份规范、创建实施计划，然后持续实现，直到所有完成门槛通过。
