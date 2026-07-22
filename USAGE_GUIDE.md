# MindOne 实际使用指南

本指南介绍如何真实使用 MindOne：下载模型、安装推理引擎、运行本地推理、以及使用网络算力。

## 前提条件

- macOS (arm64/x86_64) 或 Linux (x86_64/aarch64)
- 网络连接（用于下载模型和引擎）
- 至少 8GB 可用磁盘空间（模型文件较大）

## 快速开始

### 步骤 0: 构建并安装 CLI

```bash
cd /Users/beluga/Documents/MindOne

# 构建 release 版本
cargo +1.88 build --locked --release -p mindone-cli

# 二进制位置
CLI=./target/release/mindone

# 可选：安装到系统路径
sudo cp ./target/release/mindone /usr/local/bin/mindone
```

### 步骤 1: 检查环境

```bash
# 探测硬件能力（CPU、内存、GPU、后端）
$CLI engine detect
```

**预期输出**：显示你的操作系统、CPU、内存、GPU 和可用的推理后端（Metal/CUDA/CPU）。

### 步骤 2: 安装推理引擎

```bash
# 安装 llama.cpp（推荐，从 GitHub Releases 下载官方审计版本 b10064）
$CLI engine install --name llama.cpp

# 查看已安装引擎
$CLI engine list

# 设置默认引擎
$CLI engine set-default llama.cpp
```

**说明**：
- `llama.cpp` 会下载官方审计版本（b10064），支持 GGUF 模型
- 引擎安装在 MindOne 隔离目录，不影响系统
- 下载会验证 SHA-256 校验和

**引擎边界**：
- `llama.cpp` - 当前唯一接入 `serve run` / `share publish` 的受管推理适配器，支持 GGUF（推荐）
- `ollama` - 可安装并验证官方发行物，但当前不能设为默认服务引擎
- `vllm` / `tensorrt-llm` - 只在满足精确 Linux/CUDA/容器能力时安装受管适配资产；当前没有 `serve run` 适配器

`engine list` 会如实区分“已安装”和“可作为默认受管服务”。不要把安装成功写成已经能承接 MindOne 推理。

### 步骤 3: 下载模型

```bash
# 从 HuggingFace 下载 GGUF 模型（推荐小模型测试）
$CLI model download \
  --platform huggingface \
  --repo "Qwen/Qwen2.5-0.5B-Instruct-GGUF" \
  --file "qwen2.5-0.5b-instruct-q4_k_m.gguf" \
  --name qwen-0.5b

# 或从 ModelScope 下载（国内更快）
# 注意：ModelScope 仓库分支通常是 master，需要指定 --branch master
$CLI model download \
  --platform modelscope \
  --repo "Qwen/Qwen2.5-0.5B-Instruct-GGUF" \
  --branch master \
  --file "qwen2.5-0.5b-instruct-q4_k_m.gguf" \
  --name qwen-0.5b

# 查看已下载模型
$CLI model list

# 验证模型完整性
$CLI model verify qwen-0.5b
```

**说明**：
- 支持 HuggingFace 和 ModelScope 两个平台
- 支持 GGUF 和 safetensors 格式
- 下载必须有可信 SHA-256：优先使用平台受信清单；清单缺失时必须显式提供 `--sha256 <64位小写hex>`，否则失败关闭
- 支持断点续传和进度显示

**推荐测试模型**（体积小，下载快）：
| 模型 | 大小 | 用途 |
|------|------|------|
| Qwen2.5-0.5B-Instruct-GGUF | ~400MB | 测试对话 |
| Qwen2.5-1.5B-Instruct-GGUF | ~1GB | 轻量应用 |
| Llama-3.2-1B-Instruct-GGUF | ~800MB | 通用测试 |

### 步骤 4: 本地运行推理服务

```bash
# 启动本地推理服务（在隔离沙盒中）注意是 serve run 子命令
$CLI serve run --model qwen-0.5b --engine llama.cpp --port 8080

# 查看服务状态
$CLI serve status

# 停止服务
$CLI serve stop
```

> **平台说明（macOS）**：受管推理服务运行在 Seatbelt 沙盒中，沙盒出于安全隔离会拒绝
> GPU/Metal 设备访问，因此 macOS 上受管 llama.cpp 固定以**纯 CPU** 运行（自动注入
> `--device none`、`--n-gpu-layers 0`、`--no-kv-offload` 和 `--no-op-offload`）。其他平台
> 可在 serve 配置中显式设置 `cpu_only: true` 使用同一受管策略。不要在高级参数中重复或
> 覆盖这些开关；管理器会拒绝冲突，并清除 `LLAMA_ARG_DEVICE`、`LLAMA_ARG_N_GPU_LAYERS`、
> `LLAMA_ARG_KV_OFFLOAD`、`LLAMA_ARG_NO_KV_OFFLOAD`、`LLAMA_ARG_NO_OP_OFFLOAD`，防止父进程
> 环境重新启用 GPU/offload。实际速度取决于 CPU、模型、量化和上下文长度，应以本机实测为准。

**测试推理**（另开一个终端）：

```bash
# OpenAI 兼容的聊天补全接口
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen-0.5b",
    "messages": [
      {"role": "user", "content": "你好，请介绍一下自己"}
    ]
  }'
```

## 使用网络算力（需要账户）

### 步骤 5: 注册和登录

```bash
# 先设置受支持的非敏感协调服务器 origin，再登录
$CLI config set server.url https://api.holarchic.cn

# CLI 启动 Ed25519 Device Flow，并可打开同源浏览器页面
$CLI auth login

# 查看登录状态
$CLI auth status
```

**登录流程**：

1. CLI 在终端显示同源 `/auth/login` 地址和随机 12 位 `user_code`；地址不携带 query 或 fragment。
2. 仔细核对浏览器 origin 与终端地址完全一致，再手工输入终端中的 `user_code`。不要使用邮件、聊天或陌生网页给出的代码；这是防钓鱼边界。
3. 在浏览器登录已验证邮箱账户；首次注册时先通过验证邮件完成邮箱验证。浏览器只授权这次待处理 Device Flow，不接收或保存 bearer token。
4. CLI 继续轮询 `/v1/auth/device/poll`，并以本机 Ed25519 私钥签名证明设备持有；只有最终签名轮询成功后，访问令牌、刷新令牌和设备私钥才写入系统凭证库。

密码重置流程尚未实现。忘记密码时不能依赖未公开的 reset URL，应联系部署方按受审流程处理。

### 步骤 6: 查看积分

```bash
# 查看积分余额和贡献值
$CLI quota balance
```

**输出说明**：
- **可用积分**：可用于调用网络算力
- **贡献值**：作为节点贡献算力获得的积分
- **网络准备金**：系统预留积分

### 步骤 7: 使用网络算力调用

MindOne 通过本地 OpenAI 兼容代理使用网络算力（自动路由到贡献节点并消耗积分）：

```bash
# 启动本地额度代理（默认监听 127.0.0.1:9090）
# model=auto 表示由网络自动路由到合适的贡献节点
$CLI quota use --model auto --port 9090
```

**调用推理**（另开一个终端）：

```bash
# 向本地代理发请求，代理会通过网络路由到贡献节点并扣积分
curl http://127.0.0.1:9090/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "auto",
    "messages": [
      {"role": "user", "content": "你好"}
    ]
  }'
```

**说明**：
- `quota use` 在本地启动代理，无需手动管理 token
- 代理自动使用已登录的凭证进行认证
- 请求通过网络路由到贡献节点；金额按任务创建时冻结的授权输入/最大输出上界与服务端物理参考 profile 计算，实际 token 只做越界校验，不按较小实际用量降价
- 调用地址是本地代理（127.0.0.1:9090），不是直接访问远程

### 步骤 8: 贡献算力赚取积分

```bash
# 先启动本地推理服务
$CLI serve run --model qwen-0.5b --engine llama.cpp --port 8080

# 将本地模型发布到网络，承接推理任务赚取积分
$CLI share publish --model qwen-0.5b

# 查看贡献统计（请求数、成功率、收益）
$CLI share stats

# 停止贡献（排空当前任务后取消发布）
$CLI share unpublish
```

`share publish` 会持久化当前生效的 `runtime/node-policy.json`。活动 worker 每次领取前和执行前都会重新读取；文件缺失、损坏、是符号链接、不是普通文件或内容无效时会以策略错误失败关闭，不会退回默认允许策略。遇到这类错误时先停止共享，再通过 `node policy set` / `node threshold set` 或重新发布生成受控策略文件，不要手工软链接替换。

部分推理模型可能只返回 `reasoning_content` 而没有用户可见 `content`。MindOne 会把这种 chat 视为本地执行失败并释放任务，不会上传一个确定无效的成功结果；协调器仍保留 HTTP 400 校验兜底，worker 会用固定脱敏失败收口租约，不把远端正文写入日志。

## 图形界面（TUI）

直接运行 `mindone`（无参数）启动终端图形界面：

```bash
$CLI
# 或
mindone
```

**TUI 功能**：

- 新版工作台由 `SPACE` 分类、`ACTION` 动作、`OVERVIEW` 操作说明、`ACTIVITY` 执行结果和 `COMMAND` 参数编辑组成；宽屏与紧凑终端会自适应，10 类动作精确覆盖 CLI 的 40 个公开叶子命令
- `Tab` / `Shift-Tab` 在分类、动作、命令编辑区切换焦点，`↑/↓` 选择，`Enter` 进入编辑或执行；分类区也可按 `1-9` 快速选择
- 在编辑区补齐完整参数后，可执行登录、下载、安装、服务、共享、额度、节点策略、配置和诊断等全部公开 CLI 能力
- 非编辑区按 `M` 打开可过滤的 65 模型选择器，`R` 根据本机 RAM/显存生成推荐，`D` 生成首选模型的一键自动部署命令；模型选择和部署仍经过普通命令解析与安全确认
- 单引号、双引号和反斜杠只用于安全分词，命令不经过 shell；变量、管道、重定向和命令替换不会被展开或执行，内部 `__worker` 也会拒绝
- 认证、写入及启动/停止等生命周期动作必须二次确认；执行期间回到普通终端，结束后恢复 TUI，并在结果区保留原始 `exit_code`

`PgUp/PgDn` 可滚动结果，`Esc` 返回上一级，非编辑区按 `q` 退出。管道、重定向或 CI 等非交互环境不会进入 raw 模式：裸 `mindone` 显示帮助，显式 `mindone ui` 返回需要交互式终端的错误。

## 常见问题

### 引擎安装失败

```bash
# 检查网络连接
curl -I https://github.com

# 查看详细错误
RUST_LOG=debug $CLI engine install --name llama.cpp
```

### 模型下载慢

- HuggingFace 慢：改用 ModelScope 平台（`--platform modelscope`）
- 使用镜像：设置 `HF_ENDPOINT` 环境变量

### 推理服务启动失败

```bash
# 检查模型是否已下载并验证
$CLI model list
$CLI model verify <模型名>

# 检查引擎是否已安装
$CLI engine list

# 查看详细日志
RUST_LOG=debug $CLI serve run --model <模型名> --engine llama.cpp
```

### 内存不足

- 选择更小的量化模型（q4_k_m 而非 q8_0）
- 选择更小参数的模型（0.5B 而非 7B）

## 目录结构

MindOne 数据存储位置：

```
~/.config/mindone/          # 非敏感配置（平台实际路径可能不同）
~/.local/share/mindone/     # 数据目录
├── models/                 # 下载的模型
├── engines/                # 安装的引擎
│   └── llama.cpp/
│       └── b10064/
└── runtime/                # 运行时状态
```

Token、refresh challenge、Ed25519 设备私钥和证明密钥不在上述目录以明文文件保存，而是按 `MINDONE_HOME` 派生隔离命名空间后写入操作系统凭证库（macOS Keychain、Linux Secret Service 或相应平台后端）。`config.toml` 不保存敏感凭证。

## 完整示例：从零到推理

```bash
#!/bin/bash
# 完整的本地推理设置流程

CLI=./target/release/mindone

echo "=== 1. 检查环境 ==="
$CLI engine detect

echo "=== 2. 安装引擎 ==="
$CLI engine install --name llama.cpp
$CLI engine set-default llama.cpp

echo "=== 3. 下载模型 ==="
$CLI model download \
  --platform huggingface \
  --repo "Qwen/Qwen2.5-0.5B-Instruct-GGUF" \
  --file "qwen2.5-0.5b-instruct-q4_k_m.gguf" \
  --name qwen-test

echo "=== 4. 验证模型 ==="
$CLI model verify qwen-test

echo "=== 5. 启动推理服务 ==="
echo "运行: $CLI serve run --model qwen-test --engine llama.cpp --port 8080"
echo "然后测试:"
echo 'curl http://localhost:8080/v1/chat/completions -H "Content-Type: application/json" -d "{\"model\":\"qwen-test\",\"messages\":[{\"role\":\"user\",\"content\":\"你好\"}]}"'
```

---

**注意**：模型下载和引擎安装需要真实网络连接，会从 HuggingFace/ModelScope/GitHub 下载文件。首次使用建议选择小模型测试。
