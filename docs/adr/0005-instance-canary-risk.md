# ADR 0005：有限 canary 的精确实例风险隔离

- 状态：已接受
- 日期：2026-07-18

## 背景

v1 会把服务端生成的算术和字符串挑战混入 ordinary jobs wire。模板虽然带有 CSPRNG 参数，但源码公开、数量有限，而且任务完成后的零经济结算是真实可观察事实。它不能证明某个权重实际执行，也不能承担 canonical 模型的 benchmark、Glicko 或 Tier 更新。

完全忽略失败信号同样不可取：重复错答、worker failure 或故意让租约过期至少说明精确实例存在运行风险，需要可审计的路由保护和运维告警。

## 决策

- 信号只绑定 `node_id + model_instance_id + model_id`；不更新共享 canonical 模型质量、Tier、奖励或结算。
- 每个 result、显式 fail 和 lease expiry 与挑战终态在同一 PostgreSQL 事务更新 `model_instance_canary_state`，并向 `model_instance_canary_events` 追加事件；同一事务也尝试把没有剩余租约的 `draining` 实例收口为 `unpublished`。事件表拒绝 UPDATE/DELETE。
- result/fail 提交事务在锁定 challenge 后再次判断 `lease_expires_at <= now()`，不能只依赖事务外预检。协调器生命周期还运行固定 5 秒、每批最多 128 条的全局 expiry sweep；`FOR UPDATE SKIP LOCKED` 让多个副本安全分摊，节点停止 claim 或被强制停止也不会阻止终态收口。
- 连续 3 个失败信号把该精确实例隔离。新的 Standard 与 Regulated 消费者路由、prepared Regulated route 消费、模型列表和节点最佳 Tier 查询都失败关闭地排除它。
- 隔离不会改写已完成结算或伪造消费者、receipt、余额和任务。已经执行中的普通 Standard 租约不被追溯取消。
- 隔离实例仍可通过相同 `/v1/jobs/claim`、`/renew`、`/result`、`/fail` wire 接受 canary；连续 2 个正确结果解除隔离。失败会打断恢复连续数。
- 隔离和恢复阈值是 v1 固定策略，状态转换使用行锁，幂等重放不会重复计数。
- ordinary claim 在 canary gate 后对精确 `model_instances` 行取得共享锁并最终复核 `published`，与并发 unpublish 建立明确先后关系，禁止候选读取后把任务租给已经取消发布的实例。

## 明确不保证

该机制只提供有限 canary 的有界风险处置，不是模型真实性、权重执行、Token 精确性或输出正确性的密码学证明。更强的真实性评价需要部署期私有的一次性题库、独立可信 evaluator、跨实例仲裁、策略版本和回放证据；在这些边界实现前，不得把在线 Standard canary 聚合进 canonical 质量或 Tier。
