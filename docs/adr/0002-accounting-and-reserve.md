# ADR 0002：定点结算、基础成本与准备金

- 状态：已接受
- 日期：2026-07-17

## 决策

### 金额与舍入

- 1 quota = 1,000,000 microquota。
- 数据库和协议中的可消费金额、贡献值与准备金都使用有符号 64 位整数。
- 乘法使用 128 位中间值和 checked arithmetic。
- 用户扣费向上取整；节点可用额度与贡献值向下取整；准备金是扣费减节点额度。

这种非对称舍入保证任何最小单位下都不会因舍入产生负准备金或可用额度增发。

### 基础成本

`server_reference_upper_bound_v1` 不采用节点上报的实际 token、GPU 时间或显存。
协调器为精确模型权重绑定一条只追加 `billing_profiles` 记录，固化参考硬件类别、
最大输入/输出、固定 GPU 微秒、每 1,000 token 的参考 GPU 微秒、参考显存 MiB、
三项整数费率、证据哈希和绝对有效期。profile 全量内容由数据库生成并校验指纹；
发布者、节点和任务结果都不能选择或修改费率。

对协调器授权的输入上界 `I` 和最大输出 `O`：

```text
T = I + O
G = fixed_gpu_time_us + ceil(T * gpu_time_us_per_1k_tokens / 1000)
V = G * reference_vram_mib

C_token = ceil(T * token_rate_micro_per_1k / 1000)
C_gpu   = ceil(G * gpu_rate_micro_per_second / 1,000,000)
C_vram  = ceil(V * vram_rate_micro_per_gib_second / (1024 * 1,000,000))
C_base  = C_token + C_gpu + C_vram
```

每个分项独立向上取整；中间值使用 128 位 checked arithmetic，最终值必须能安全
落入有符号 64 位整数。创建任务时的准备金就是上述授权上界报价。节点 telemetry
只进入风险、Tier 与反作弊审计，改变节点上报的 actual token、GPU 时间或显存不能
改变任何金额。

迁移 `0032` 先冻结 profile、快照形状与 legacy allowlist。迁移前行诚实标记为
`legacy_token_v1` 且物理分项保持 NULL；同一发布内 writer 切换期间的新行只能保持
版本和全量快照均为 NULL，不能靠默认值或事后更新伪造 legacy/v1。writer 全部接入
后由下一迁移禁止 transitional NULL。不得为缺失 profile 发明默认物理费率。

创建任务时按物理参考上界、High 表现倍率和 Enhanced 信任上界预留额度；失败任务
释放全部预留且不扣费。

### 双轨公式

```text
Deduct_user = ceil(C_base * M_perf)
Quota_node  = floor(Deduct_user * 0.8 * Trust)
Points_node = floor(Deduct_user * 1.2 * Trust)
Reserve     = Deduct_user - Quota_node
```

表现倍率为 High 1.5、Medium 1.0、Low 0.7；结算信任桶为 Enhanced 1.1、Standard 1.0、Unverified 0.5。

执行能力和结算信任分离：`Standard-Limited` 映射 Standard，`Experimental` 映射 Unverified。前者不允许 Sensitive/Regulated 数据，后者只允许 Public 测试数据。

公开透明度报告也保持这两条价值轨道分离：按 receipt 的 `node_user_id` 聚合贡献账户，分别公开窗口内 `node_quota_micro` 可消费额度奖励与 `contribution_micro` 不可消费贡献积分的总额、最小值、中位数、P90 和最大值，绝不把二者相加。由于 receipt 只能确定账户归属，报告使用 `contributing_accounts`，不能把它描述为物理节点数。两条轨道共用 5 个贡献账户的最小样本阈值；阈值以下同时抑制全部统计值，避免一条轨道泄露另一条轨道所保护的小样本。

### 账本和事务

- quota、contribution、reserve ledger 只追加，由数据库触发器拒绝 UPDATE/DELETE。
- 每项包含唯一 ID、请求/任务 ID、前后余额、幂等键、前哈希、自身哈希和服务端时间。
- 三条链的权威 head 与 entry count 存在被同一事务锁定的账户行中，新增账项的数据库触发器要求 `prev_hash` 恰好等于当前 head、账项终值等于账户终值，再原子推进 head。不得按 `created_at` 或 UUID 排序猜测链头；PostgreSQL `now()` 是 transaction-start 时间，长事务可能在较晚提交时留下更早时间戳。
- 迁移 `0024` 从全零 genesis 顺序回放每个既有链，核对唯一 successor、完整可达性、逐项余额连续和最终账户余额；任何分叉、断链、循环、孤立记录或余额不符都会拒绝启动，不能静默选一个“看起来最新”的分支。
- job 成功、消费者扣款、节点额度、贡献值、准备金流入和 receipt 必须在同一 PostgreSQL 事务提交。
- 重复 result 使用相同幂等键返回原 receipt；不同键冲突，不重复结算。
- 本地开发初始额度只在显式启用 local-development auth 时发放，且写入独立 `bootstrap_grant` 账项；生产默认余额为零。
- production 不在注册时自动发放额度，也不提供 HTTP admin 赠额路由。首批供应只能由持有服务器数据库环境的运维者执行 `mindone-coordinator quota-grant`：单笔正数不超过 `1,000,000,000,000` microquota，账户锁、余额更新、`operator_grant` quota 账项和只追加 `operator_quota_grants` 审计必须在同一事务提交；审计绑定用户、运维者、理由、金额、幂等键和 ledger。
- 运营赠额是双轨任务结算公式之外的显式外生启动供给，不生成 job、receipt、节点贡献或准备金记录。因此不能声称系统全局永不增发；可验证的保证是每次外生供给均受上限、幂等冲突和只追加审计约束，任务结算本身仍遵守 `Reserve = Deduct_user - Quota_node`。

Standard 任务的实际 Token 和结果仍由承接节点上报，只作为受限风险信号，不参与
`C_base`。receipt、`settlement_hash` 和哈希链用于协调器内事务一致性、幂等与篡改
审计，不是远端执行、Token 用量或输出正确性的密码学证明。

### 准备金释放

准备金只允许以下用途：

- 结果验证
- 失败重算
- 带宽补贴
- 高峰保障

释放只能由持有完整服务器环境和数据库访问权的运维者执行 `mindone-coordinator reserve-release`，不提供 HTTP admin 路由。命令必须包含用途、金额、审计引用、operator、8 到 512 字符理由和全局幂等键；每次生成独立 reserve ledger，并在同一事务写入只追加 `operator_reserve_releases`。迁移 `0021` 的数据库触发器核对用途、金额、reference、幂等键、ledger hash 与准备金账户终值，并拒绝 UPDATE/DELETE。事务内锁定准备金账户，余额不足即拒绝，永不透支；完全相同的重试返回原记录，同键变更冲突。

### 动态贡献标签

节点统计使用版本 `node-honor-v1` 从权威 receipts、jobs 和 job_attempts 实时聚合：

- 贡献 percentile 是所有累计贡献大于零节点的确定性 midrank；cohort 少于 5 个节点时抑制为未知。
- 下一里程碑从 1 quota（`1,000,000` microquota）开始按十倍递增，并且严格大于当前累计贡献。
- 连续零故障天数按 UTC 日历日计算；每天必须至少有一个终态 attempt 且没有 failed/expired，缺失日或失败日都会打断。今天有终态时从今天起算，否则从昨天起算；完全没有终态样本时返回未知。

这些值不读取客户端状态文件，也不允许客户端自报。

## 后果

- 白皮书示例精确得到 1.50 / 1.20 / 1.80 / 0.30。
- 节点不能在结果提交时自行指定费率或通过上报 telemetry 改变金额；Standard
  节点的用量上报仍不是密码学可验证事实。
- 物理资源成本通过不可变、可审计的服务端参考 profile 校准，实时指标只用于 Tier、
  路由和反作弊审计。
