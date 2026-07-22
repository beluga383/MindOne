# ADR 0003：质量融合、两阶段路由与 Tier

- 状态：已接受
- 日期：2026-07-17
- 最近修订：2026-07-19（`contribution-routing-v1`）

## 质量融合

对同一模型和领域，先把 benchmark 与 Glicko-2 映射到 `[0,1]`：

```text
beta = n / (n + k)
Q = (1 - beta) * BenchmarkNormalized + beta * GlickoNormalized
```

`n` 是有效盲测样本数，`k` 是版本化冷启动常量。两个权重之和始终为 1；输入非有限或越界时拒绝。

v1 参数与状态定义：

- `k = 20`。
- Glicko-2 初始状态为 rating `1500`、RD `350`、volatility `0.06`；`tau = 0.5`，求根误差 `1e-6`，最多迭代 `1000` 次，超限 fail-closed。
- `GlickoNormalized = clamp((rating - 1000) / 1000, 0, 1)`。
- 只有通过服务器侧 `quality-record` 导入的独立可信 benchmark/canary evidence 才进入按样本数加权的客观分流；canary 通过记 `1`、失败记 `0`，且不增加 Glicko 盲测样本数。ordinary jobs wire 上的 public canary 和 private hidden challenge 都是在线实例审计，不属于这个全局质量输入；private hidden 的 `corroborated` 仲裁也不会更新 canonical benchmark、Glicko 或 Tier。
- 盲测结果只能是 win、draw、loss，并使用真正的 Glicko-2 rating-period 更新；实现以论文示例 `1500/200/0.06 -> 1464.06/151.52/0.059996` 作为 golden test。

## 评分权限与审计

模型发布者不是评分权威。公共 `POST /v1/models/publish` 为兼容保留 `benchmark_normalized`、`glicko_normalized` 与 `evaluation_samples`，但三者必须为 `0`；非零请求明确拒绝。迁移 `0008` 把旧版可能来自客户端的质量值重置为中性冷启动状态，避免继承自评分。

生产唯一入口是服务器侧 `mindone-coordinator quality-record`，没有允许客户端直接写分数的 HTTP 路由。命令不接受裸分数：独立 evaluator 必须签署短期 `mindone-quality-evidence-v1` statement，协调器用 pinned Ed25519 公钥验证签名，并重新计算真实 artifact SHA-256。原始评分构造与事务函数保持 crate-private，不能被外部调用绕过 evidence。每次更新执行以下单一事务：

1. 验证 manifest/短期时效、evaluator 公钥签名和 artifact commitment；
2. 用受限 ASCII 幂等键串行化并校验包含签名、operator 与理由的请求指纹；
3. 锁定同名的全部已启用模型；
4. 严格验证分数、样本、对手 rating/RD 与小写证据 SHA-256；
5. 更新服务端状态，为同名、已启用 cohort 的每个成员重新计算融合分、相对 percentile 与 Tier；
6. 原子追加 `model_quality_events` 与 `quality_evidence_audits`；若目标事件改变任一 cohort 成员的 Tier，再追加绑定源质量事件、cohort commitment 与 percentile 的 `model_tier_transition_events`。迁移 `0021`/`0025` 的触发器核对绑定并拒绝 UPDATE/DELETE。

审计表不保存隐藏 Prompt、模型响应或 logits 明文，只保存数值、签名 statement、artifact/行为 commitment、公钥指纹和 operator/evaluator 归属；真实 artifact 与 private catalog 由独立 evaluator 和部署方按其保留策略管理。不存在 `/v1/evaluations/*` 公共路由：协调器用 CSPRNG 抽样把挑战混入普通 `POST /v1/jobs/claim`，worker 继续走相同的 `/renew`、`/result` 和 `/fail`。这些公共 wire 字段没有 kind、score、passed 或专用 token；result/fail 只返回与普通任务同形的最小 ACK。

在线挑战分为两个明确口径：public canary 使用仓库内有限模板与随机参数，只产生 exact-instance 风险信号；private hidden 优先从仓库外部署目录读取短期 `mindone-private-evaluation-catalog-v1`，验证 pinned evaluator Ed25519 签名、时效和边界后选择与目标权重匹配的全局一次性 entry。private entry 的 Prompt、`utf8-trim-v1` 行为 SHA-256、固定推理 seed 与输出上限受签名保护；challenge binding 进一步覆盖 catalog/entry/evaluator commitment、`model_id + model_instance_id + node_id + job_id`、模型权重、随机 nonce、Prompt/行为 commitment、授权 Token 和初始租约时效。Prompt hash 与行为 hash 的数据库唯一约束阻止 catalog 轮换后重新消费。catalog 未配置、缺失、无效、过期、权重不匹配或耗尽时只能签发 public canary，不能把 fallback 冒充 private hidden。

private 正确/错误结果、主动 `/fail` 与沉默超时都会原子追加跨实例真实性仲裁。仲裁按模型权重、evaluator key fingerprint 和 case family 隔离，只以不同 `model_instance_id` 的最新观察形成 `pending`、`corroborated` 或 `disputed` 快照；事件拒绝 UPDATE/DELETE。public/private 信号还共同驱动 exact-instance 的隔离与恢复状态，但在线分数和仲裁 verdict 都不更新 canonical benchmark、Glicko 或 Tier，也不产生消费者扣费、贡献值、准备金变动或 receipt。

这一隐蔽性只覆盖执行前与提交 wire 没有专用标签，不承诺 Prompt 语义、领取时序、流量分布或完成后不可分类。真实零结算可以暴露类别；实现不得通过伪造消费者、余额、贡献值或账本来隐藏这个事实。部署期签名 catalog、行为指纹和跨实例仲裁是软件风险证据，不会把不可信 Standard worker 变成可信硬件；`corroborated` 不是 TEE、硬件签名或可验证计算证明。仓库提供实现与显式 Compose overlay，也不等于 live production 已启用：2026-07-18 已验证的 production 仍在 migration 26 且没有挂载 catalog，必须迁移到 28、挂载真实签名 catalog 并完成 PostgreSQL/真实模型验收后再改变部署声明。

## Phase 1：模型选择

先硬过滤不可用模型和上下文长度不足模型，再计算：

```text
score_model = (0.50 * quality
             + 0.30 * intent_match
             - 0.20 * normalized_cost) / 1.00
```

同分时按稳定模型 ID 升序，确保结果可复现。

## Phase 2：节点选择

先过滤：模型不匹配、策略拒绝、熔断、达到并发上限、信任/健康低于门槛、延迟超限。其余节点计算：

```text
score_node = 0.25 * trust
           + 0.20 * health
           + 0.15 * normalized_coordinator_rtt
           + 0.15 * capacity
           + 0.15 * available_load
           + 0.10 * reliability
```

Standard 与 Regulated 使用同一组 `25/20/15/15/15/10` 权重；Regulated 已硬过滤为 Enhanced 节点，因此其 trust 项固定为 `1_000_000`。定点分值尺度为 `1_000_000`。网络项只读取最新节点指标的 `coordinator_rtt_ms`，即 worker 用单调时钟观测到的协调器请求往返时延；本地模型首 Token TTFT 不是网络 RTT，绝不参与 Phase 2 网络项。具体规则固定为：

```text
coordinator_rtt_ms = None        -> 网络项 0，节点仍可参与
1 <= coordinator_rtt_ms <= 1000 -> 1_000_000 - coordinator_rtt_ms * 1000
coordinator_rtt_ms > 1000        -> 过滤该已报告节点
```

缺失 RTT 表示未知，不表示实测 0ms；给未知值零分而不是伪造中性延迟，可让尚未形成上一周期观测的节点参与冷启动，同时避免获得网络加分。数据库约束拒绝非正的已报告值，路由层仍以 `1..=1000` 白名单边界过滤。该 RTT 是节点报告的运行信号，不是硬件证明；路由同时使用服务端健康、信任、容量和可靠性信号，不能仅凭 RTT 提升信任等级。

其他输入归一化到 `[0,1]`；`available_load = 1 - current/max`，`reliability = 1 - recent_error_rate`。同分按节点 ID 升序。首选节点熔断后按同一确定性排序选择备用节点。

### 网络拥堵贡献优先：`contribution-routing-v1`

贡献优先只是 Phase 2 的受限近同分决胜器，不是资格、信任或容量信号。Standard 与 Regulated 必须先执行既有的安全、节点策略、温度、VRAM、协调器 RTT、实例隔离、证明、模型状态与容量硬过滤；贡献不能恢复任何已被过滤的节点，也不能改变 Regulated 的模型质量与成本 Phase 1。ordinary job 的候选 SQL 才应用本规则，public canary 与 private hidden evaluation 在此前已进入独立领取流，因此不应用贡献排序。

唯一贡献输入是服务端最终 `receipts.contribution_micro`。该字段已固化创建期和调用图反作弊权重，路由不得再乘权，也不得改读账户余额、节点自报值或估算值。按 receipt 对应已结算 job 的 `leased_to_node_id` 归属到实际物理节点，只累计 `receipt.created_at` 最近 30 天的非负值；同一 owner 的其他节点不能继承该值。

cohort 只包含完成全部硬过滤后的唯一物理节点，同一节点的多个实例不重复计数。按 `contribution_micro` 升序确定性计算 midrank percentile，定点范围为 `0..=1_000_000`：

```text
percentile_ppm = (2 * lower_count + tied_count - 1) * 1_000_000
                 / (2 * (cohort_size - 1))
```

整数除法向下取整；相同贡献得到完全相同的 percentile。`cohort_size < 5` 时不应用贡献优先。

拥堵只由协调器数据库证明：`ready_demand > server_counted_free_slots`。ready job 必须满足 claim 的状态、`available_at` 与剩余尝试次数合同，并与当前请求属于同一模型和大小写不敏感、去重且顺序无关的标签集合；Standard 还要求相同 confidentiality。Regulated prepare 在选路前没有持久化自身，所以只计算数据库中已经存在的同一合格模型/标签 ready backlog；并发但尚未落库的 prepare 不计数，绝不能用进程内请求数补造。`server_counted_free_slots` 对合格物理节点去重后求和，以策略 `max_concurrent` 减去服务端计数的有效租约、已绑定 Regulated ready job、未过期 prepared route 与 leased hidden evaluation，并饱和到零；`node_metrics.current_concurrent` 可继续参与既有保守硬过滤和基础负载分，但绝不进入拥堵空闲槽位口径。

非拥堵时贡献 key 全部为 `NULL`，排序逐项保持原有基础分、节点 ID、实例 ID 合同。拥堵时也只有满足下式的候选获得贡献 percentile 排序 key：

```text
candidate_base_score * 100 >= best_base_score * 98
```

即基础分位于最佳分 2% 相对窗口内。该窗口内先按 contribution percentile 降序，再按基础分降序和稳定 ID；窗口外仍按基础分与稳定 ID 排序，最高贡献也不能跨过 2% 边界。Regulated 的最佳基础节点分按当前模型分别计算，并始终把模型质量降序与成本升序放在贡献 key 之前。

## Tier

默认策略：

| 参数 | 值 |
|---|---:|
| 最小有效样本 | 20 |
| High 进入 | 0.80 |
| High 保持 | 0.72 |
| Low 进入 | 0.35 |
| Low 保持 | 0.42 |
| 相对排名辅助边距 | 0.03 |
| High 辅助 percentile | >= 0.80 |
| Low 辅助 percentile | <= 0.20 |

- 样本不足一律 Medium，避免冷启动误判。
- 绝对门槛优先；相对排名只在绝对门槛 0.03 范围内辅助。
- 进入/退出门槛形成滞回，避免频繁跳级。
- 相对 percentile 在同名、已启用模型组内按确定性 midrank 计算；只有一个候选时取 `0.5`。任一成员质量变化都会在同一行锁事务内重算全组，避免 peer Tier 因事件顺序而过期。
- 参数由配置版本标识，变更必须有迁移、回放与确定性测试。

## optimize

优化建议只由真实成功请求产生的引擎 TPS、首 Token TTFT 实测、错误率、样本量和当前权威 Tier 经过固定规则生成；相同输入必须得到相同 code、优先级、证据和建议，不调用随机模型生成话术。TTFT 由 worker 用单调时钟记录从本地 HTTP 请求开始到首个非空生成 delta 到达；无此观测时保留未知，绝不用 prompt timing 补造。

v1 使用版本标识 `local-observed-best-v1`：worker 只把同一受管 worker/模型真实成功请求中观测到的最高引擎 TPS 与最低首 Token TTFT 实测作为恢复基线，错误率目标为零，最小样本沿用本 ADR 的 20。基线更新是单调且确定的，不使用“临时提升 2%”或随机文案。该目标只表示恢复本机在当前采集口径下已经观测到的表现，不承诺 Tier 晋升；Tier 仍由上文服务端质量融合、样本量和 percentile 策略决定。

若没有正数引擎 TPS、首 Token TTFT 实测、权威 Tier 或真实服务端指标，CLI 必须明确拒绝生成建议。未来若改用服务端或同模型 cohort 目标，必须发布新版本、说明统计口径和隐私阈值，并保留可回放的确定性测试。
