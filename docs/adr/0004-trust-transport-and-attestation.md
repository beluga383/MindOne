# ADR 0004：信任、传输与远程证明边界

- 状态：已接受
- 日期：2026-07-17

## 平台执行等级

- Linux 只有当前启动计划实际组合应用 Namespaces、seccomp-bpf 与 Landlock 后才是 Standard；降级路径只报告实际应用的子集，不能把内核支持或能力探测冒充已应用。
- macOS 只有当前进程实际应用 Seatbelt/App Sandbox 或继承受限容器时才报告对应机制，最高仍为 Standard-Limited；无法应用时不报告该机制。
- 当前官方 Windows 启动路径只在监督进程实际创建并持续持有 Job Object 时报告该机制，等级仍为 Experimental；未应用时报告空集合。Job Object 只提供进程生命周期约束，不宣称文件系统或网络沙箱，当前官方路径也不宣称 AppContainer/Hyper-V。
- 协调器由客户端上报的机制计算 Standard/Standard-Limited；即使使用官方客户端，这仍是客户端对本次启动状态的观测自报，不是服务器独立观测或远程证明，不能抵抗主机 root 或篡改客户端。
- Enhanced 只来自受支持 Linux TEE 的硬件证书链与证明报告，软件随机值永不升级信任。

## 远程证明验证

证明必须绑定：一次性 nonce、服务器时间窗、sandbox policy hash、runtime binary hash、model weights hash、TEE 临时公钥和厂商证书链。

服务器依次验证结构、challenge 有效期与一次性消费状态、REPORTDATA 全字段绑定、策略/运行时哈希 allowlist、TEE measurement、证书链、TCB/collateral 时效和硬件签名。任一步失败都不升级。当前设备没有受支持 provider 时，`mindone auth attest` 明确报告不支持并退出 30。

## Regulated E2EE 数据面

Regulated 请求先准备一次性固定 route。消费者本机使用固定 verifier 复验原始厂商 evidence、REPORTDATA、measurement 与 allowlist，再用一次性 X25519 私钥、HKDF-SHA-256 和 ChaCha20-Poly1305 生成版本化 envelope。AAD 由 direction、route、report、模型实例和模型权重哈希确定性生成，不由发送方自由提供。协调服务器只调度和保存 opaque envelope，不持有解密密钥。

普通 worker 不解密 Regulated payload；只有同一报告绑定的 TEE runtime adapter 能使用不透明 `key_handle` 完成解密、推理和结果回封。route 重放、固定节点或报告失效、证据/密钥来源错配、全零密钥材料、AAD/方向/模型绑定错误、verifier 或 adapter 缺失均失败关闭，释放 reservation 且不扣费，不迁移节点，也不降级为 Standard。

Standard/Standard-Limited 无法防止物理节点 root 读取进程内存，CLI 和文档必须明确该边界。

## 当前实施状态

已实现带认证的一次性 challenge/submit 证明控制面、固定外部 verifier、REPORTDATA 全字段绑定、服务端 allowlist、有期限的节点信任升级，以及上述 Regulated 客户端加密、固定路由、TEE adapter 推理和结果解密数据面。CLI 只接受 SNP extended report 或 TDX Quote；Regulated TEE 私钥不导出，凭证库只保存 adapter 返回的不透明 `key_handle`。消费者的一次性会话私钥仅在本地请求生命周期内使用并零化。

实现存在不等于硬件部署已经验收。仓库内确定性密码学测试和 PostgreSQL 集成测试覆盖绑定、篡改、重放、过期、错误节点、容量与幂等，但不能替代目标 SNP/TDX guest、固件、证书 collateral、厂商 verifier 和 TEE adapter 的真实端到端验证。Linux/macOS 的真实沙箱 allow/deny 测试同样是 `#[ignore]` 且必须分别显式设置 `MINDONE_REAL_LINUX_SANDBOX_TEST=1` / `MINDONE_REAL_SEATBELT_TEST=1` 才执行；普通 workspace test 不会证明这些平台机制。没有这些条件时 Regulated 保持失败关闭。

Standard 仍使用 Base64/Base64URL JSON；字段名 `encrypted_payload` / `result_ciphertext` 不使其成为密文。Standard receipt、结算哈希和哈希链也不是节点执行、Token 用量或输出正确性的密码学证明。

## 传输

- 所有跨主机连接必须 HTTPS/WSS，并由 rustls 校验证书和主机名。
- HTTP 例外只允许权限受限的 loopback 开发，或同一 Docker 主机上不发布端口、仅连接协调器与专用 cloudflared 的 internal connector 网络；跨主机时没有该例外。
- Cloudflare 公网终止 TLS 后，专用 connector 通过 internal 网络连接 `http://coordinator:8787`。协调器只信任 connector 固定 IP；所有宿主机进程共享的 Docker 网关不是 connector 身份。示例配置不证明公网 hostname 已启用。
- 生产 PostgreSQL 即使在同主机 internal bridge 也启用专用 CA 的 `verify-full`，服务端明确拒绝明文 TCP。不得公开 PostgreSQL、llama-server 或 quota proxy。
- URL 验证拒绝非 loopback HTTP、userinfo、降级重定向和明文 Secret 参数。
