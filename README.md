# DEC! - 高性能文件加密工具

[![许可证：MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org/)

## ⚠️ WARNING / 警告
```
EN: PRE-RELEASE SOFTWARE - USE AT YOUR OWN RISK
This is a testing branch of DEC!. The software is currently in active development and has not undergone a formal security audit.

- Data Loss Risk: Future updates may change the file format, making files encrypted with older versions unreadable.

- Security: Do not use this for highly sensitive data yet.

- Stability: Breaking changes to the CLI and internal logic can occur at any time without notice.
```

```
ZH: 预发布软件 - 使用风险自担
这是 DEC! 的 开发测试分支。本项目目前处于活跃开发阶段，且尚未经过正式的安全审计。

- 数据丢失风险：后续更新可能会更改文件格式，导致旧版本加密的文件无法被新版本解密。

- 安全性：现阶段请勿将其用于存储极度敏感的数据。

- 稳定性：命令行参数及内部逻辑可能会在不经预告的情况下发生破坏性变更。
```

DEC! 是一款用 Rust 编写的高性能文件加密工具，它利用并行处理能力，在提供强大安全性的同时，也实现了卓越的性能。

## 功能特性

- 🔒 **军用级加密**：采用 Argon2id 密钥派生的 AES-256-GCM 加密

- ⚡ **并行处理**：充分利用所有 CPU 核心，实现最佳性能

- 📈 **实时进度跟踪**：可视化进度条，显示吞吐量指标

- 💾 **内存高效**：支持可配置缓冲区大小的文件流传输

- 🖥️ **跨平台**：支持 Windows、macOS 和 Linux 系统

## 技术细节

### 加密设计

DEC!实现稳健的加密架构：

1. **密钥派生**：

- 使用 Argon2id（密码哈希竞赛的获胜者），具体参数如下：

- 内存占用：256 MiB

- 3 次迭代

- 2 路并行

2. **加密**：

- AES-GCM 对单个 块 进行 加/解密

- 每次操作使用唯一的盐值（16 字节）

- 每次操作使用的 Nonce 来自 (base_iv + chunk_index)，保证不复用

- 每一个块都有自己的 校验码（保证密码输入错误的用户体验，以及获取文件篡改的具体位置）

3. **文件格式**：

```

[魔数][版本][盐值][初始化向量][块大小][块#1: 数据+校验][块#2: 数据+校验]...

```

### 并行处理架构

DEC!通过智能并行化实现卓越性能：

- **自适应线程**：自动检测 CPU 核心数

- **基于块的处理**：将数据分割成块进行并行处理

- **基于阈值的回退**：对小文件（<16KB）使用单线程处理，以最大限度地减少开销

### 安全特性

- **前向保密**：每次操作使用新的盐值和初始化向量 (IV)

- **篡改检测**：GCM 验证可防止篡改攻击

- **内存**安全性：应用与依赖 **均使用 Rust 编写**，运行时零崩溃

- **密码安全**：安全的密码输入方式，不会回显到终端


## 性能

DEC! 专为高性能加密而设计：

- **缓冲区大小**：自定义 的数据块，实现最佳 I/O 性能

- **并行阈值**：文件大于 16KB 时自动切换到并行模式

- **内存使用**：内存占用恒定（根据 CPU核心数 与 块大小），不受文件大小影响

- **AES-NI 硬件加密**：在支持 AES-NI 指令集的设备上获得最佳体验

在现代硬件上的典型性能：

- 小文件（<1MB）：受 I/O 限制，而非 CPU 限制

- 大文件（100MB+）：充分利用所有 CPU 核心

- 超大文件（1GB+）：持续吞吐量达数百 MB/s (M4 Max: 400MB/s)

## 与其他方案的比较

| 工具      | 算法                     | 并行性 | 语言   | 性能 |
|---------|------------------------|-----|------|----|
| DEC!    | AES-256-GCM + Argon2id | ✅ 是 | Rust | 优秀 |
| GPG     | AES-128/256            | ❌ 否 | C    | 良好 |
| OpenSSL | 多种                     | ❌ 否 | C    | 一般 |
| 7-Zip   | AES-256                | ❌ 否 | C++  | 一般 |