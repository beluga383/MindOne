# 参与 MindOne 开发

感谢你为公益算力网络贡献代码、测试或文档。

## 开发流程

```bash
git clone https://github.com/beluga383/MindOne.git
cd MindOne
git switch main
git pull --ff-only
git switch -c feature/功能名称

# 修改并测试
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

git add .
git commit -m "feat: 功能说明"
git push -u origin feature/功能名称
```

然后在 GitHub 创建 Pull Request：

- 不直接向 `main` 推送，不 force push 共享分支。
- 每个人使用独立分支；需要协作时通过 PR 或明确的共享分支进行。
- 合并前必须通过 CI、代码审查和相关集成测试。
- 提交信息遵循 Conventional Commits，例如 `feat:`、`fix:`、`docs:`、`test:`、`refactor:`。
- 一个提交只处理一个清晰主题；行为变化必须同时更新测试和文档。

## 本地依赖

- Rust stable（以 `rust-toolchain.toml` 为准）
- Docker 与 Docker Compose
- PostgreSQL 集成测试使用 `deploy/docker-compose.dev.yml`
- 真实推理 E2E 需要官方 llama.cpp 和许可证允许的小型 GGUF

数据库测试仅在显式提供 `DATABASE_URL` 时连接真实 PostgreSQL。`scripts/e2e-test.sh` 本身就是非 mock 的真实 E2E：它会构建 CLI/协调器、启动隔离 PostgreSQL、安装官方 llama.cpp、下载并验证 GGUF，再以两个隔离 `MINDONE_HOME` 完成推理和结算。脚本不读取 `MINDONE_E2E_REAL` 或 `MINDONE_TEST_MODEL`；直接运行即可使用脚本内的默认模型：

```bash
./scripts/e2e-test.sh
```

需要覆盖默认值时，只使用脚本实际读取的变量：

```bash
MINDONE_E2E_PROFILE=debug \
MINDONE_E2E_MODEL_REPO=ggml-org/Qwen3-0.6B-GGUF \
MINDONE_E2E_MODEL_FILE=Qwen3-0.6B-Q4_0.gguf \
MINDONE_E2E_MODEL_BRANCH=main \
MINDONE_E2E_MODEL_NAME=qwen3-e2e \
MINDONE_E2E_KEEP_TMP=1 \
./scripts/e2e-test.sh
```

固定自定义模型时可额外把 `MINDONE_E2E_MODEL_SHA256` 设置为该文件实际的 64 位小写 SHA-256。端口和数据库镜像还可由 `MINDONE_E2E_POSTGRES_IMAGE`、`MINDONE_E2E_POSTGRES_PORT`、`MINDONE_E2E_COORDINATOR_PORT`、`MINDONE_E2E_LLAMA_PORT`、`MINDONE_E2E_PROXY_PORT` 覆盖。E2E 成功只证明 Standard 本地真实推理与结算闭环；它不覆盖公网 Cloudflare 路由或真实 SNP/TDX Regulated 硬件。

## 安全要求

绝不提交：

- OAuth Secret、Token、数据库密码、Cloudflare Token、私钥
- `config.toml`、`.env`、本地数据库或日志
- GGUF、safetensors 或其他大模型文件
- 真实 Prompt/Response 样本，除非内容是专门构造且不含个人数据的测试向量

新增网络请求必须说明 TLS/loopback 边界；新增模型格式必须先通过安全评审；新增账本写入必须处于事务、只追加、幂等且有哈希链测试。

## 代码规则

- 用户可见文本默认简体中文；协议字段和 API 路径使用稳定英文。
- 普通错误返回 `Result`，生产代码不得使用 `panic!`、`todo!`、`unimplemented!`。
- 不得用固定成功响应、假余额、假证明或状态文件冒充真实进程。
- 平台能力不可用时明确拒绝或降级，不伪造安全机制。
- CLI 不直接连接数据库。

## 报告安全问题

请不要在公开 Issue 中粘贴可利用细节或 Secret。优先使用 GitHub 仓库的 Private vulnerability reporting；见 [docs/SECURITY.md](docs/SECURITY.md)。
