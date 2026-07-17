# ADR 0001：模型格式与安全验证

- 状态：已接受
- 日期：2026-07-17

## 背景

CLI 规范要求只允许 safetensors，同时又要求 v1.0.0 真实支持 `llama.cpp`。
`llama.cpp` 的原生权重格式是 GGUF；只允许 safetensors 会使真实 MVP 无法运行。

## 决策

MindOne 允许登记和验证两类模型：

- `.gguf`：仅交给兼容的 `llama.cpp` 类引擎执行。
- `.safetensors`：仅交给声明并验证兼容性的引擎执行。

强制拒绝 `.pkl`、`.pickle`、`.pt`、`.pth`，以及其他依赖任意代码反序列化的格式。

验证不依赖扩展名作为安全证明：

1. 先检查规范化路径、普通文件类型、大小上限和符号链接边界。
2. 计算完整文件 SHA-256。
3. GGUF 检查 `GGUF` magic、版本、张量/元数据计数与所有长度/偏移边界。
4. safetensors 检查 8 字节 header 长度、JSON 对象、dtype、shape、data offsets、越界和重叠。
5. 扩展名与实际结构不一致时拒绝，不允许通过改名绕过。
6. registry 记录文件大小、修改时间和哈希；任一变化都会使旧验证失效。
7. 下载只有在可信 manifest checksum 或用户提供 checksum 验证成功、结构验证通过后才原子登记。

所有模型安全失败映射为退出码 21，并提供稳定 JSON 错误类型 `model_validation_failed`。

## 后果

- v1.0.0 能用 GGUF 完成真实 llama.cpp E2E，同时保持对危险反序列化格式的硬拒绝。
- 引擎适配器必须显式声明支持格式，不能把 safetensors 传给 llama.cpp。
- 格式解析器需要防整数溢出、恶意长度、截断和资源耗尽。

