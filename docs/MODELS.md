# 模型目录与一键部署

MindOne 的静态目录只声明允许用户选择的 Hugging Face 仓库 ID，不冒充仓库在线、许可已接受、文件完整或本机能够运行。每次探测/下载都会在用户设备上实时读取 HF 清单；完整下载以清单 LFS SHA-256 校验整文件并进行 GGUF/safetensors 结构验证。协调服务器不代下载模型权重，也不消耗部署方模型流量。

## 用户流程

```bash
mindone model catalog
mindone model recommend
mindone model probe Qwen/Qwen3-0.6B --deployment --metadata-only
mindone model probe Qwen/Qwen3-0.6B --deployment
mindone model deploy Qwen/Qwen3-0.6B
mindone model deploy auto
mindone model deploy <模型ID> --replace
mindone model deploy <另一个模型ID> --port 8081
mindone serve status --port 8081
mindone serve stop --port 8081
mindone model list
mindone model delete <本地模型> --yes
```

`model probe --deployment --metadata-only` 只读取 HF 文件树、大小和 LFS SHA-256，不请求权重内容；去掉 `--metadata-only` 后最多读取所选主 GGUF 的 64 KiB 并主动断开，同样不创建模型文件、`.part` 或登记。正式 `model deploy` 接受单文件 GGUF，或名称严格符合 `-00001-of-000NN.gguf`、数量完整且每片都有可信 LFS SHA-256/大小的分片 GGUF。下载时每片分别续传、校验 SHA-256 和 GGUF 结构，并核对内部 `split.no` / `split.count`；全部通过后才把整个 bundle 原子登记。缺片、重片、错序、辅助 `mmproj`/`imatrix`/MTP 文件或 safetensors 分片都不能冒充主权重。

部署前的内存门槛按“全部 GGUF 分片总和 + 2 GiB”计算，不得超过可用设备内存的 70%。超出预算会在下载权重前明确拒绝。登记记录绑定每片文件名、大小、SHA-256 与 split 元数据；启动时再次验证整个 bundle，沙盒只授予这些精确路径，删除时也只移除无额外文件的完整 bundle 目录。

同一用户可以按端口同时运行多个本地受管实例：默认端口 `8080` 保留兼容状态文件，其他端口使用独立状态、日志和运行目录。`--replace` 只停止并替换同一端口上的实例，不影响其他端口；`serve status/stop --port` 精确管理指定端口。`share publish --port <端口>` 可以选择其中任一健康实例，并把实际端口写入共享状态供 worker 与 attestation 每次复验；省略时兼容默认 `8080`。本地当前仍只有一份活动 share worker/状态，因此选择不同端口不会冒充多份共享容量，也不会自动同时发布多个实例。

目录里的每一项都能从 CLI/TUI 一键发起用户端 HF 探测或部署，但“一键”不等于无条件成功：仓库不存在、许可未接受、需要登录、缺少可信完整 GGUF、模型超出可用内存或当前受审计 llama.cpp 不兼容时会明确拒绝。MindOne 不会为了显示成功而改下分片 safetensors、跳过哈希或写入假状态。发布前可运行 `scripts/audit-hf-model-catalog.sh` 对全部 65 项做实时纯元数据审计；这项外部状态检查不进入离线确定性测试门禁。

2026-07-22 的实时审计中，低并发全目录运行解析成功 61 项，另外 4 项被 HF `429` 限流；随后逐项重试也全部解析成功，合计 65/65 均找到了带大小和 LFS SHA-256 的完整主 GGUF 清单。2026-07-23 的当前 `main` 又只对 Qwen3-0.6B 重跑用户端部署路径：解析到 `unsloth/Qwen3-0.6B-GGUF` 的 `Qwen3-0.6B-Q4_K_M.gguf`（396,705,472 bytes），真实 Range 读取恰好 65,536 bytes 后中止，`persisted=false`。公开 Linux E2E 对同一小模型完成整包下载、验证、启动和真实业务链；没有下载第二个模型。这些证据不代表 65 个模型均已下载，也不代表超大模型能在当前机器运行。

视觉/多模态条目当前只自动选择文本主 GGUF；投影器会被明确排除，现有 OpenAI 兼容入口也尚未承诺图像或音频输入。因此它们可以作为文本模型进入同一下载/部署流程，但不能据此宣称完整视觉或语音能力已经实现。

## Hugging Face 登录仓库

需要鉴权的仓库可以在**用户自己的终端进程**中设置 `HF_TOKEN`。Token 只作为本次 HF HTTPS 请求的 Bearer 凭据，不写入 MindOne 配置、模型登记或日志；ModelScope 请求不会携带它。用户仍须先在 Hugging Face 接受相应许可并拥有访问权。

macOS/Linux 可从隐藏输入临时设置，完成后立即清除：

```bash
read -rs HF_TOKEN && export HF_TOKEN
mindone model deploy <模型ID>
unset HF_TOKEN
```

Windows PowerShell 可从安全提示读入当前进程，完成后删除环境变量：

```powershell
$secure = Read-Host "HF Token" -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try { $env:HF_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
mindone model deploy <模型ID>
Remove-Item Env:HF_TOKEN
```

不要把 Token 直接写在命令行参数、脚本、配置或仓库文件中。

## 官方目标目录（65）

### Qwen

- `Qwen/Qwen3.6-27B`
- `Qwen/Qwen3.6-35B-A3B`
- `Qwen/Qwen3.5-0.8B`
- `Qwen/Qwen3.5-2B`
- `Qwen/Qwen3.5-4B`
- `Qwen/Qwen3.5-9B`
- `Qwen/Qwen3.5-27B`
- `Qwen/Qwen3.5-35B-A3B`
- `Qwen/Qwen3.5-122B-A10B`
- `Qwen/Qwen3.5-397B-A17B`
- `Qwen/Qwen3-0.6B`
- `Qwen/Qwen3-1.7B`
- `Qwen/Qwen3-4B`
- `Qwen/Qwen3-8B`
- `Qwen/Qwen3-14B`
- `Qwen/Qwen3-32B`
- `Qwen/Qwen3-30B-A3B`
- `Qwen/Qwen3-235B-A22B`
- `Qwen/Qwen3-4B-Instruct-2507`
- `Qwen/Qwen3-4B-Thinking-2507`
- `Qwen/Qwen3-30B-A3B-Instruct-2507`
- `Qwen/Qwen3-30B-A3B-Thinking-2507`
- `Qwen/Qwen3-235B-A22B-Instruct-2507`
- `Qwen/Qwen3-235B-A22B-Thinking-2507`
- `Qwen/Qwen2.5-0.5B-Instruct`
- `Qwen/Qwen2.5-1.5B-Instruct`
- `Qwen/Qwen2.5-7B-Instruct`
- `Qwen/Qwen2.5-14B-Instruct`
- `Qwen/Qwen2.5-32B-Instruct`
- `Qwen/Qwen2.5-Coder-0.5B-Instruct`
- `Qwen/Qwen2.5-Coder-1.5B-Instruct`
- `Qwen/Qwen2.5-Coder-3B-Instruct`
- `Qwen/Qwen2.5-Coder-7B-Instruct`
- `Qwen/Qwen2.5-Coder-14B-Instruct`
- `Qwen/Qwen2.5-Coder-32B-Instruct`

### Gemma

- `google/gemma-4-E2B-it`
- `google/gemma-4-E4B-it`
- `google/gemma-4-12B-it`
- `google/gemma-4-26B-A4B-it`
- `google/gemma-4-31B-it`

### DeepSeek

- `deepseek-ai/DeepSeek-V4-Flash`
- `deepseek-ai/DeepSeek-V4-Pro`
- `deepseek-ai/DeepSeek-V3.2-Exp`
- `deepseek-ai/DeepSeek-V3.2-Speciale`
- `deepseek-ai/DeepSeek-R1`
- `deepseek-ai/DeepSeek-R1-0528`
- `deepseek-ai/DeepSeek-R1-0528-Qwen3-8B`

### GLM

- `zai-org/GLM-4.5-Air`
- `zai-org/GLM-4.5`
- `zai-org/GLM-4.7-Flash`
- `zai-org/GLM-4.7`
- `zai-org/GLM-5`
- `zai-org/GLM-5.1`
- `zai-org/GLM-5.2`

### Mistral

- `mistralai/Ministral-3-8B-Instruct-2512`
- `mistralai/Mistral-Small-3.1-24B-Instruct-2503`
- `mistralai/Mistral-Small-4-119B-2603`
- `mistralai/Mistral-7B-Instruct-v0.3`

### Microsoft / IBM / AllenAI

- `microsoft/Phi-4-reasoning-vision-15B`
- `microsoft/Phi-4-multimodal-instruct`
- `ibm-granite/granite-4.1-8b`
- `ibm-granite/granite-3.2-8b-instruct`
- `allenai/Olmo-3-7B-Instruct`
- `allenai/Olmo-3.1-32B-Instruct-DPO`
- `allenai/Olmo-3.1-32B-Think`
