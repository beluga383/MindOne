# Git 多人协作

## 分支模型

- `main` 始终保持可发布，不接受直接推送。
- 功能分支使用 `feature/<名称>`，修复使用 `fix/<名称>`，文档使用 `docs/<名称>`。
- Codex 自动实现分支使用 `codex/<名称>`。
- 一项功能一个分支；不要在同一分支混入无关格式化或大规模重构。

## 标准流程

```bash
git clone https://github.com/beluga383/MindOne.git
cd MindOne
git switch main
git pull --ff-only
git switch -c feature/功能名称

# 编码、测试

git add crates/相关模块 docs/相关文档
git commit -m "feat(scope): 功能说明"
git push -u origin feature/功能名称
```

在 GitHub 向 `main` 创建 Pull Request，不自动合并。PR 需要写清：

- 解决的问题和架构选择
- 用户可见行为与兼容性
- 实际执行的测试和输出摘要
- 数据库迁移、部署或回滚方式
- 安全边界和未签名发行物说明

## 避免冲突

- 开始前在 Issue/PR 中声明模块所有权。
- 公共协议先提交 DTO/ADR，再让 CLI 和服务器分别接入。
- 数据库 migration 文件一经进入共享分支不修改序号；新变化追加下一 migration。
- 不提交格式化整个仓库的混杂改动。
- 更新分支优先 `git fetch origin` 后 rebase 自己未共享的功能分支；已多人共享的分支通过 merge 协调，不重写他人历史。

## 合并门槛

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

涉及数据库还需真实 PostgreSQL integration；涉及引擎还需目标平台 smoke；涉及任务闭环还需真实 GGUF E2E。所有 CI 通过、审查意见解决后才合并。

## 禁止提交

大模型、Token、私钥、数据库、`.env`、本地配置、日志和用户 Prompt/Response 均不得进入 Git。发现误提交 Secret 时，立即撤销/轮换 Secret，并按 GitHub 安全流程清除历史；只删除最新文件不等于完成处置。
