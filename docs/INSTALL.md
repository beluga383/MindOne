# 安装、升级与本地调用

## 1. 安装 CLI

正式 SemVer 标签（例如 `v1.0.0`）创建 GitHub 稳定 Release 并进入 `/releases/latest/download`；带 `-rc.1` 等预发布后缀的标签不会进入稳定通道。版本通道不代表平台原生签名状态：Apple/Windows 代码签名取决于发行 Secret，macOS notarization 尚未接入，必须以发行页的 `SIGNING_STATUS.txt` 和包内 `CODE_SIGNING.txt` 为准。

macOS/Linux：

```bash
curl -fsSL https://raw.githubusercontent.com/beluga383/MindOne/main/scripts/install.sh \
  | sh -s -- --launch
```

`--launch` 在安装和 SHA-256 自检成功后直接进入 TUI；在 CI、管道或其他非交互终端中安全降级为执行真实 `mindone --help`，不会进入 raw mode。安装器默认向当前用户实际使用的 zsh/bash/POSIX sh/fish 配置写入带固定边界的受管 PATH 块，因此新终端可直接输入裸 `mindone`。脚本无法反向修改已经运行它的父 shell，所以本次终端用 `--launch` 直接进入；受控环境可传 `--no-modify-path` 或设置 `MINDONE_INSTALL_NO_MODIFY_PATH=1` 完全关闭配置修改。

指定版本或安装目录：

```bash
curl -fsSL https://raw.githubusercontent.com/beluga383/MindOne/main/scripts/install.sh \
  | sh -s -- --version v1.0.2 --install-dir "$HOME/.local/bin"
```

Windows PowerShell：

```powershell
$installer = [scriptblock]::Create((irm https://raw.githubusercontent.com/beluga383/MindOne/main/scripts/install.ps1))
& $installer -Launch
mindone --version
```

`-Launch` 与 Unix 的 `--launch` 含义相同；Windows CI 环境不会误入交互 TUI。安装器默认只把安装目录加入当前用户 PATH，并同步当前 PowerShell 进程，不修改系统 PATH；安装和默认卸载不会重排或规范化其他 PATH 项，原有空项、空格和尾分隔符也会原样保留。`-NoModifyPath` 或 `MINDONE_INSTALL_NO_MODIFY_PATH=1` 可关闭。

从源码安装：

```bash
cargo install --locked --git https://github.com/beluga383/MindOne --tag v1.0.2 mindone-cli
```

已经从 GitHub clone 并进入仓库根目录后，macOS/Linux 可用一行完成源码安装、让当前终端立即找到命令并启动 TUI：

```bash
cargo install --locked --path crates/mindone-cli --root "$HOME/.local" && export PATH="$HOME/.local/bin:$PATH" && mindone
```

Windows PowerShell（x86_64）对应的一行命令：

```powershell
cargo install --locked --path crates/mindone-cli --root "$env:LOCALAPPDATA\MindOne"; if ($LASTEXITCODE -eq 0) { $env:Path = "$env:LOCALAPPDATA\MindOne\bin;$env:Path"; mindone }
```

这两条命令只修改当前终端的 PATH，不持久改写用户或系统配置。源码安装需要预先安装仓库声明的 Rust 1.88 工具链；普通最终用户优先使用上面的发行包安装器，不需要 Rust。

`git clone` 本身不可能安全地修改父终端的 PATH，也不会自动执行仓库脚本；因此“clone 后不做任何安装就直接输入 mindone”不是 Git 能提供的合同。上面的单行源码安装，或发行包安装器加当前会话 PATH，才是可复现边界。安装完成后裸 `mindone` 会直接进入 TUI。

2026-07-22 已在仓库外隔离安装根真实执行上述 `cargo install`：最小 PATH 下 `mindone --version` 成功，非交互裸 `mindone` 显示中文帮助并退出 0，真实 PTY 中裸 `mindone` 进入新版工作台并由 `q` 正常退出。v1.0.2 发布后又从公开 latest 资产安装 `aarch64-apple-darwin` 到隔离目录，版本、中文帮助和真实 80×24 PTY 裸 `mindone` 渲染/退出均为 0。Windows/Linux 的原生构建和安装卸载由对应 Actions runner 验证；Windows 交互 TUI、Credential Manager、Job Object 生命周期和真实模型启动仍由用户真机验收。

本地已构建二进制装入 PATH（例如把当前工作树的 release 二进制放进已在 PATH 的 `~/.cargo/bin`）：

```bash
cargo build --release -p mindone-cli --bin mindone
install -m 0755 target/release/mindone "$HOME/.cargo/bin/mindone"
mindone --version
```

安装器识别 OS/CPU、下载匹配的 GitHub Release、验证 SHA-256 并原子安装 `mindone`。默认只修改当前用户的受管 shell PATH 块或用户 PATH，不修改系统 PATH；`--launch` / `-Launch` 让单条远程命令在当前交互终端安装后直接进入 TUI，新终端则可直接输入裸 `mindone`。当前发行矩阵支持 macOS Apple Silicon/Intel、Linux arm64/x86_64 和 Windows x86_64；Windows ARM 尚无 MindOne 正式发行包，会明确拒绝而不是下载错误架构。

### 终端图形界面（TUI）

在交互式终端中直接输入 `mindone`（或 `mindone ui`）打开新版终端工作台。顶部展示账户、信任级别和协调器，主体为 Space、Action、Overview、Activity 四层信息区，底部保留不会经过 shell 的命令预览与参数编辑。10 类动作精确覆盖 CLI 的 40 个公开叶子命令，并在 68×20 以上终端自动适配紧凑或宽屏布局。

- `M`：打开 65 个模型的选择器；本机推荐置顶，可直接输入厂商或模型名过滤，`Enter` 后进入自动下载部署与二次确认。
- `R`：立即生成前 5 个本机模型推荐。
- `D`：选择推荐首项并进入自动部署确认。
- `?`：打开界内帮助；`1-9` 和 `0` 分别选择 10 个 Space。
- `Tab` / `Shift-Tab` / `←` / `→` 切换区域，`↑/↓` 选择，`PgUp/PgDn` 滚动结果，`Esc` 返回，非编辑区按 `q` 退出。

安装后的一键模型流程（下载发生在用户设备，不经过协调服务器）：

```bash
mindone model recommend
mindone model probe Qwen/Qwen3-0.6B --deployment --metadata-only
mindone model probe Qwen/Qwen3-0.6B --deployment
mindone model deploy auto
```

Windows x86_64、macOS 和 Linux 使用同一 `mindone model deploy` 命令；平台差异由受管引擎安装器处理。目录解析支持单文件或完整规范分片 GGUF，正式下载逐片校验并原子登记；`--metadata-only` 可先只验证 HF 清单，普通 probe 仍最多读取 64 KiB。日常本机审计只对 Qwen3-0.6B 做 64 KiB 有界下载探测；公开 Linux E2E 则对同一小模型完成整包下载、验证、llama.cpp 安装/健康启动、真实推理和清理，没有下载第二个模型。macOS Metal 探测优先解析 `system_profiler -json` 的稳定 family 标识，并兼容旧版文本标签；2026-07-23 已在 macOS 26 / Apple M4 上确认 `spdisplays_metal4` 被识别为 `metal` 后端，不再误报 CPU。ARM64 Linux 的既有原生 CLI/strict Clippy/release/安装闭环仍有效；当前修正版又在无网络、源码只读的 Rust 1.88 arm64 容器中通过 workspace check、CLI/TUI 测试、release 版本/裸入口和真实 PTY 启停。Linux x86_64 release 也已在 amd64 Debian 用户态执行版本、中文帮助、推荐、API 信息并完成安装/重装/卸载/purge。Windows x86_64 MSVC 已完成全 workspace check、严格 Clippy、实际 PE release 交叉构建，并由原生 Windows Runner 通过编译、静态 CRT `dumpbin`、安装、裸命令、更新和安全卸载门禁。Windows 交互 TUI、Credential Manager、Job Object 生命周期和真实模型启动仍须用户真机验证，不能从编译/安装门禁外推。完整目录与格式/内存拒绝边界见 [模型文档](MODELS.md)。

选中动作后可在编辑区补齐完整参数，所以登录、模型、引擎、服务、共享、额度、节点、配置与诊断能力都不必退出 TUI。单引号、双引号和反斜杠只用于安全分词，输入不经过 shell，变量、管道、重定向和命令替换不会被展开或执行；隐藏的内部 `__worker` 会被拒绝。认证、写入及启动/停止等生命周期动作执行前需要二次确认。执行期间界面会暂离备用屏幕和 raw 模式，由普通终端承载命令交互与输出，结束后自动恢复，并保留该命令的原始 `exit_code`。带子命令直接调用（如 `mindone doctor`）仍按普通 CLI 处理；非交互环境下裸 `mindone` 显示帮助，`mindone ui` 返回“需要交互式终端”错误。

每个发行包都包含 `CODE_SIGNING.txt`，GitHub Release 还包含聚合的 `SIGNING_STATUS.txt`。只有实际配置相应发行 Secret 时才会生成并验证 Apple Developer ID 或 Windows Authenticode 签名；macOS notarization 仍未接入。安装器严格验证发行清单中的 SHA-256；Release 另附通过 GitHub OIDC 生成的 Sigstore bundle 和 provenance，供高保证环境独立验证。不要关闭系统安全功能，也不要把“稳定通道”误解为平台原生签名已经存在。

安装器按 SemVer 比较版本。默认拒绝降级；确需回退时，Unix 使用 `--allow-downgrade`，Windows 使用 `-AllowDowngrade`。显式版本示例：

```bash
curl -fsSL https://raw.githubusercontent.com/beluga383/MindOne/main/scripts/install.sh \
  | sh -s -- --version v1.0.2 --allow-downgrade
```

```powershell
$installer = [scriptblock]::Create((irm https://raw.githubusercontent.com/beluga383/MindOne/main/scripts/install.ps1))
& $installer -Version v1.0.2 -AllowDowngrade
```

Windows 当前的本地沙盒能力只声明为 `Experimental`：在尚未建立真实 AppContainer supervisor 时，`mindone doctor --json` 会明确报告沙盒检查失败，不会把 Job Object 或探测结果冒充为 `Standard`。需要真实 allow/deny 隔离保障时，请使用通过 CI 实测的 Linux 四层沙盒或 macOS Seatbelt 环境。

`mindone doctor` 的退出决策是：任一检查失败返回 `1`；无失败、但实际沙盒能力只达到 `Standard-Limited` 或 `Experimental` 而产生“沙盒能力”警告时返回 `31`；其他普通警告不影响成功退出码 `0`。`--json` 在降级时输出 `ok=false` 和 `code=31`，但仍保留完整 `data.checks` / `data.summary`；普通 human 输出仍显示完整诊断，`--quiet` 只抑制输出、不改变退出码。注意：`auth attest` 明确请求升级但证明失败仍使用专用退出码 `30`，不会改为 `31`。

## 2. 初始化与登录

全新配置默认使用官方专用 API origin `https://api.holarchic.cn`；该子域用于避免覆盖 `holarchic.cn` 的现有官网。独立 Tunnel、DNS、目标 origin、production connector 与 live v39 已接通，`/health`、`/ready` 的 MindOne 1.0.2 身份和 `CF-Ray` 已验收；匿名受保护接口返回 401。已有 `config.toml` 始终保留其原值，不会在升级时被覆盖；曾配置根域的客户端应显式执行 `mindone config set server.url https://api.holarchic.cn`。本地开发才改为 loopback：

```bash
mindone --version
mindone doctor
mindone auth login
mindone auth status
# 仅本地开发：mindone config set server.url http://127.0.0.1:8787
```

Token 和设备私钥进入系统凭证库，不会写进配置文件。

### 官网域名、端口与路径映射

公网只需要一个 API hostname：`api.holarchic.cn`。Cloudflare Tunnel 的 Public
Hostname 不要填写 path 过滤，整个 hostname 统一转发到 Compose 内部 origin
`http://coordinator:8787`；这样 `/v1/*`、健康检查和可选的同源邮箱登录页面不会因
漏配路径而出现一部分可用、一部分 404。`holarchic.cn` 根域继续由官网使用，不要把
整个根域改指向 Coordinator。

| 对外地址或本机端口 | 转发目标 | 用途与边界 |
|---|---|---|
| `https://api.holarchic.cn/health` | `coordinator:8787/health` | 进程存活；不能代替 ready |
| `https://api.holarchic.cn/ready` | `coordinator:8787/ready` | 数据库与运行门禁就绪 |
| `https://api.holarchic.cn/v1/*` | `coordinator:8787/v1/*` | CLI、节点、额度、API Key 和 OpenAI 推理 |
| `https://api.holarchic.cn/auth/*` | `coordinator:8787/auth/*` | 仅 email provider 挂载注册/登录/验证页；GitHub Device Flow 仍去 GitHub |
| `127.0.0.1:18787` | 容器 `8787` | 无 Tunnel 的本机维护模式；公网 overlay 会移除此映射 |
| PostgreSQL `5432` | 不做公网或宿主映射 | 只在 Compose internal `backend` 网络并使用 TLS |
| 本地 `8080`/其他 `model deploy --port` | 不做公网映射 | 用户设备上的受管模型服务，只绑定 loopback |
| 本地 `9090`/其他 `quota use --port` | 不做公网映射 | 用户设备上的本地兼容代理，只绑定 loopback |

远程 SDK 的唯一 Base URL 是 `https://api.holarchic.cn/v1`，再提供用户自己的
`mok_...` API Key 和 `/v1/models` 返回的模型名即可；不需要也不允许直连任意贡献端
的 8080、动态 backend 端口或数据库。关键后缀是 `/v1/models`、
`/v1/chat/completions` 与 `/v1/completions`。

## 3. 检测硬件并安装引擎

```bash
mindone engine detect
mindone engine list
mindone engine install --name llama.cpp
mindone engine set-default llama.cpp
```

四个引擎都不从 PATH 导入现有程序，也不修改 PATH：

- `llama.cpp` 下载 ggml-org 官方 release，验证 GitHub 资产 SHA-256 后安全解压、原子登记。
- `ollama` 下载 Ollama 官方 release。macOS 使用官方 universal `ollama-darwin.tgz`；
  Linux x86_64/aarch64 与 Windows x86_64/aarch64 使用各自官方资产。安装器只接受 GitHub
  API 的 `sha256:` digest 或同一 release 的 `sha256sum.txt`，安全解压后必须真实执行
  `ollama --version` 且版本与 release 一致，之后才写入完整目录哈希清单。
- `vllm` 和 `tensorrt-llm` 的受管适配器只支持能够查询 NVIDIA driver/CUDA driver 的
  Linux x86_64 主机，并要求本机固定 `/var/run/docker.sock` 以及固定绝对路径的 Docker
  Engine。安装器先由对应官方 GitHub release 得到版本，再解析官方 OCI 镜像的原生
  `linux/amd64` SHA-256 descriptor；拒绝非 TLS registry 和未纳入校验链的 mirror，按
  digest 拉取、复核 `RepoDigests`、实际执行 GPU 容器入口的版本/帮助探测，然后把完整
  Docker image bundle、固定 digest 元数据与绝对路径 launcher 原子写入 MindOne 引擎目录。
  受管 bundle 和 launcher 都进入完整文件哈希清单；不会把 PATH 中的 Python 命令、单个
  wheel 或 Docker 命令冒充完整安装。

不满足上述 OS、架构、CUDA/driver 或本地容器运行时条件时，`engine detect/list/install`
会给出具体拒绝原因。v1 的真实模型推理与 `serve` 验收硬门槛仍是 `llama.cpp`；成功安装
Ollama/vLLM/TensorRT-LLM 只表示其官方依赖闭包和入口通过 `detect/list/install` 健康验证。
v1 的 `serve` 不启动这三个 adapter，且不会通过其 OCI launcher 绕过模型格式与运行沙盒检查。
省略 `--version` 时，`llama.cpp` 固定安装当前唯一完成受管日志、slot erase 与生命周期
审计的 `b10064`；其他引擎仍解析 `latest`。显式安装更新的 llama.cpp 只表示发行资产和
完整目录校验通过，在完成独立运行时审计前不会遮蔽或替代 `b10064` 的受管 serve 路径。

因此 `engine set-default` 和 `config set engine.default` 只接受已安装、完整性校验通过且
当前 `serve` 能实际启动的 `llama.cpp`；其他三个引擎即使安装成功，也会以引擎/沙盒错误
明确拒绝成为默认值，不会留下下一次 `serve run` 必然失败的配置。

## 4. 下载、验证并启动模型

下载器会先读取平台仓库清单。仓库只有一个受支持的 GGUF/safetensors artifact 时，
`--platform`、`--repo`、`--branch` 和 `--name` 就能完成标准旅程；有多个候选时必须用
`--file` 精确选择。Hugging Face 使用 LFS SHA-256，ModelScope 使用官方仓库文件清单的
`Sha256`；所选文件没有平台可信 SHA-256 时必须显式传 `--sha256`，否则失败关闭。显式
`--file` 与 `--sha256` 的兼容旅程不依赖清单可用性，但实际 artifact 仍必须通过 HTTPS、
SHA-256、文件头与结构验证：

```bash
mindone model download \
  --platform huggingface \
  --repo ggml-org/Qwen3-0.6B-GGUF \
  --branch main \
  --file Qwen3-0.6B-Q4_0.gguf \
  --name qwen3-0.6b \
  --sha256 <发布页的SHA-256>

mindone model verify qwen3-0.6b
mindone model list
mindone serve run --model qwen3-0.6b --engine llama.cpp --port 8080
mindone serve status --port 8080
mindone model deploy auto --port 8081
mindone serve status --port 8081
```

默认只监听 `127.0.0.1`。

需要许可或登录的 Hugging Face 仓库使用用户终端中的临时 `HF_TOKEN`；MindOne 只把它发送给 HF，不保存或记录。安全输入示例和清除步骤见 [模型文档](MODELS.md)。

`model deploy` 自动选择主 GGUF，并排除 `mmproj`、`imatrix`、MTP 等辅助文件。对于规范分片，只有全部文件的清单 SHA-256、大小、实际 GGUF 结构和内部 split 元数据一致时才登记；任何一片失败都会使部署失败关闭。服务健康等待按完整模型大小从 60 秒起递增，每 GiB 增加 15 秒并封顶 30 分钟，避免大型模型尚在真实加载时被固定 30 秒误判；进程失败仍会拒绝。视觉/多模态模型当前仍是文本主 GGUF 部署路径，不代表图像或音频输入已经开放。

受管 CPU-only 不是把 `--device` 写进高级参数。macOS Seatbelt 路径会自动生效；其他平台可在 serve 配置中设置 `cpu_only: true`。管理器固定注入 `--device none`、`--n-gpu-layers 0`、`--no-kv-offload` 和 `--no-op-offload`，拒绝高级配置覆盖，并清除 `LLAMA_ARG_DEVICE`、`LLAMA_ARG_N_GPU_LAYERS`、`LLAMA_ARG_KV_OFFLOAD`、`LLAMA_ARG_NO_KV_OFFLOAD`、`LLAMA_ARG_NO_OP_OFFLOAD`。若启动日志提示 CPU-only 参数冲突，应删除相应 `additional_args` 或父进程环境覆盖，而不是放宽管理器检查。

受管 llama.cpp 固定四个隔离 slot 并显式启用统一 KV 缓存：slot 0 只供本机代理，slot 1..3 只供贡献任务。这样单个本机、standard 或 fast 请求不会因为固定四槽被静态缩小为四分之一上下文。`--parallel`、`--kv-unified`、slot 端点和 prompt cache 均为管理器控制项，不能在高级配置或 `LLAMA_*` 环境中覆盖。

## 5. 发布贡献节点

```bash
mindone node policy set --reject-tags nsfw,heavy-math --max-concurrent 1
mindone node threshold set --gpu-temp-limit 75 --vram-reserve 4
mindone share publish --model qwen3-0.6b --port 8080 --alias my-node --tags code,math
mindone share stats
```

`--max-concurrent` 可设为 `1..=3`；示例中的 `1` 是节点主主动收紧，而不是实现上限。`share publish --port` 选择该端口上已经健康运行且模型一致的受管实例；省略时使用 `8080`。节点通过出站连接心跳和领取任务，不开放 llama-server 公网端口。standard/fast 只使用整台空闲贡献端，slow 才会在该真实上限内装箱。

## 6. 消费额度与 OpenAI 兼容调用

```bash
mindone quota balance
mindone quota use --model auto --port 9090
```

另一个终端：

```bash
curl http://127.0.0.1:9090/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model":"auto",
    "messages":[{"role":"user","content":"只回复：MindOne 已连接"}]
  }'

mindone quota history
mindone quota receipt --id <receipt-id>
```

## 7. 停止与注销

```bash
mindone share unpublish
mindone serve stop --port 8081
mindone serve stop --port 8080
mindone auth logout
```

## 8. 检查更新与卸载

```bash
curl -fsSL https://raw.githubusercontent.com/beluga383/MindOne/main/scripts/install.sh \
  | sh -s -- --check

curl -fsSL https://raw.githubusercontent.com/beluga383/MindOne/main/scripts/uninstall.sh \
  | sh -s -- --yes
```

Windows PowerShell：

```powershell
$installer = [scriptblock]::Create((irm https://raw.githubusercontent.com/beluga383/MindOne/main/scripts/install.ps1))
$uninstaller = [scriptblock]::Create((irm https://raw.githubusercontent.com/beluga383/MindOne/main/scripts/uninstall.ps1))
& $installer -Check
& $uninstaller
```

Unix 卸载器的交互确认只从 `/dev/tty` 读取，不会把管道中的脚本文本当作回答；在无控制终端的管道或自动化中必须显式传入 `--yes`，否则会在删除前拒绝执行。

卸载器会先通过已验证的 CLI 解析实际生效的 `data_dir` 和配置控制目录，并按记录的 PID/启动身份安全停止服务。默认删除自己安装的可执行文件，并移除安装器带固定边界的 Unix PATH 块或与安装目录精确匹配的 Windows 用户 PATH 项；Unix `--keep-path` / Windows `-KeepPath` 可显式保留。实际数据、控制配置和账户状态仍默认保留。只有显式传入 Unix 的 `--purge-data` 或 Windows 的 `-PurgeData` 才会递归删除经过所有权检查的实际数据目录；自定义 `data_dir` 与配置控制目录分离时，两处路径都会在确认中明确列出并一并清理。

## 9. 本地烟测（Unix）

### 开发 Compose smoke

`scripts/mvp-dev-smoke.sh` 编排开发 Compose 的迁移、健康、鉴权路由和可选 CLI 检查。脚本默认生成一次性开发凭据；调用者需要覆盖时，Secret 只接受 `MINDONE_DEV_POSTGRES_PASSWORD` 和 `MINDONE_DEV_STANDARD_DATA_KEY` 两个专用环境变量，不接受 Secret 命令行参数，也不会在拒绝错误中回显原值。所有临时诊断材料都位于仓库外由 `mktemp` 创建的 `0700` 目录，并在正常退出或信号退出时清理。CLI 子流程只使用该目录下的隔离 `MINDONE_HOME`，不会读取真实用户会话或改写默认配置。

`sh scripts/mvp-dev-smoke-contract-test.sh` 已在本机通过，并作为 CI 的安全合同测试运行。它用本地命令替身验证专用环境变量注入、CLI Home 隔离、仓库内 `TMPDIR` 拒绝、目录与文件权限、退出清理以及 `.dockerignore` 的凭据兜底规则，不连接 Docker 或网络。因此这项合同测试不能写成完整开发 Compose/Docker smoke 已经重跑；本轮尚未取得后者的新证据。

### 本地发行包 smoke

在 macOS 或 Linux 的仓库根目录先构建真实的 release CLI，再运行本地发行包烟测。限制并发可降低构建时的峰值内存：

```bash
CARGO_INCREMENTAL=0 cargo build --locked --release --package mindone-cli --jobs 1
sh scripts/release-archive-smoke.sh \
  "$(pwd -P)/target/release/mindone"
```

烟测脚本本身不会运行 Cargo。传入文件必须是受支持目标（macOS arm64/x86_64 或 Linux x86_64/aarch64）上的可执行普通文件、不能是符号链接，并且 `mindone --version` 必须满足单行 SemVer 合同。脚本会用该真实二进制、仓库 `LICENSE` 和明确标为 `unsigned-local-smoke` 的 `CODE_SIGNING.txt` 组装当前平台归档与 SHA-256 清单，再通过仅监听 `127.0.0.1` 的临时服务驱动真实 `scripts/install.sh`。它依次验收归档下载和校验、安装后二进制内容及中文帮助、同版本 `--check`、同版本重装、默认卸载保留数据、再次安装，以及 `--purge-data` 删除数据但不越界删除隔离 HOME。

`mindone --json doctor` 会执行真实的本机检查，因此退出码可以是 `0`、`1` 或 `31`。烟测不会要求当前机器所有检查都通过，但会要求 JSON 的 `code`、`ok`、检查计数和 `data.summary` 决策与实际退出码严格一致：存在失败时为 `1`，无失败但存在信任降级时为 `31`，两者都不存在时为 `0`；其他退出码一律失败。

整个流程的写入和删除范围只在脚本创建并规范化后的 `mktemp` 目录内，不读写默认安装目录或默认 MindOne 数据目录。安装器的 loopback HTTP 例外只在该隔离测试子进程中显式启用，不能作为跨主机或生产环境绕过 HTTPS 的方式。这个烟测证明的是当前 Unix 主机上的本地归档/安装闭环，不证明 GitHub Release 上传、远程 TLS、GitHub Actions、Windows PowerShell、平台代码签名、macOS notarization 或真实模型推理端到端可用。

### 真实模型 E2E

`scripts/e2e-test.sh` 会构建真实 CLI/Coordinator，创建独立 PostgreSQL、两个 `MINDONE_HOME` 和测试凭证库，安装官方 llama.cpp b10064，并下载校验 Qwen3-0.6B-Q4_0 GGUF。不要使用正在运行的 production 端口；示例显式选择另一组 loopback 端口：

```bash
MINDONE_E2E_POSTGRES_PORT=55439 \
MINDONE_E2E_COORDINATOR_PORT=18892 \
MINDONE_E2E_LLAMA_PORT=18082 \
MINDONE_E2E_PROXY_PORT=19092 \
MINDONE_E2E_PROFILE=debug \
MINDONE_E2E_CARGO_JOBS=1 \
MINDONE_E2E_CPU_ONLY=1 \
CARGO_NET_OFFLINE=true \
sh scripts/e2e-test.sh
```

无桌面 Linux runner 没有 DBus Secret Service 时，可以把这一轮测试包在独立内核 keyring session 内，并显式选择真实 keyutils 凭证库：

```bash
keyctl session -- sh -c '
  export MINDONE_LINUX_CREDENTIAL_STORE=keyutils
  export MINDONE_E2E_LLAMA_PORT=18082
  sh scripts/e2e-test.sh
'
```

`keyutils` 不把 Token 或设备私钥落盘，但该 session 在重启或内核回收后不会保留登录，适合无桌面的临时 runner。Linux 桌面默认仍使用 Secret Service；macOS 和 Windows 不读取这个 Linux 专用选项。

2026-07-22 当前 macOS arm64 工作树已用上述隔离配置通过：真实非流式 chat/completions、两个端点的 SSE 动态增量、连续游标及数据库故障恢复、Standard AEAD/HMAC 静态存储、公开 canary 收口、领取后策略复核失败且零结算、三轨唯一结算、Regulated `stream:true` 拒绝、Prompt/Response 日志扫描和清理均得到验证。该运行使用 debug 二进制、`local-development` 和 CPU-only Seatbelt；它不证明 release/签名产物、email SMTP/浏览器、公网 TLS、production 升级、GPU/其他平台、真实 private catalog 多实例仲裁或 SNP/TDX Regulated 硬件可用。

2026-07-23 当前四槽版本另用 `18082` 完成 Qwen3-0.6B-Q4_0 整包下载、SHA-256/结构验证、b10064 启动和 `/health`；随后旧脚本因 `serve status` 漏传端口而在默认 `8080` 误报未运行。脚本已把 status、publish、stop、日志审计和清理全部绑定 `MINDONE_E2E_LLAMA_PORT`，`share publish` 也会持久化并复验所选端口；修复后的公开 Linux E2E 已继续完成双账号 Standard job、chat/completions、两类 SSE、结算、策略拒绝零结算及最终清理。

## 10. 数据目录

默认数据位于平台规范目录；开发和 E2E 可显式隔离：

```bash
MINDONE_HOME=/绝对路径/consumer mindone auth status
```

`MINDONE_HOME` 必须是绝对路径。模型、引擎、日志、runtime 状态和配置不会提交到 Git。
