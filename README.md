# dec-cryptor

## 项目概述

这是一个基于 Rust 的文件加密/解密工具，名为“DEC!”，它使用行业标准的加密算法提供安全的对称加密。该工具支持单线程和并行处理模式，以提高处理大型文件的性能。

### 实测
> 平台：M4 Max (14C)

**加密/解密**
- 500MB: 1.6s
- 2GB: 6.2s


## 主要特性

- 使用 AES-256 进行 CTR 模式的对称加密/解密

- 基于密码的密钥派生，使用 Argon2id

- 支持使用 Rayon 进行并行处理，以提高性能

- 使用 HMAC-SHA256 进行身份验证，以确保数据完整性

- 通过可视化进度条跟踪进度

- 安全生成随机盐值和初始化向量 (IV)

## 架构

代码库采用模块化结构，主要组件如下：

1. `main.rs` - 入口点，控制台I/O，模块调度

2. `args.rs` - 解析参数

3. `encryptor.rs` - 核心加密逻辑和文件处理

4. `decryptor.rs` - 核心解密逻辑和文件处理

5. `crypto_utils.rs` - 加密常量和实用函数

6. `key_derivation.rs` - 使用 Argon2 和 HKDF 进行密钥派生

7. `hmac_validator.rs` - HMAC 计算和验证

8. `parallel_handler.rs` - 并行处理实现AES-CTR

9. `progress_utils.rs` - 进度跟踪和计时工具

10. `lib.rs` - 封装模块，方便 `tests/integration_tests.rs` 集合测试

### 依赖项

- `rpassword` - 安全密码输入

- `ring` - 用于生成随机数的加密原语

- `aes` 和 `ctr` - AES-256-CTR 加密实现

- `argon2` - Argon2id 密钥派生

- `hmac` 和 `sha2` - HMAC-SHA256 实现

- `hkdf` - HKDF 密钥派生

- `rayon` - 并行处理

- `tempfile` - 创建临时文件，方便测试

## 开发相关
- `test.bat` & `test.sh` 
- - 执行 `cargo test --release -- --nocapture`


- `create_file.lua`
- - 生成 **目标大小** 测试文件


- `manual_test.lua`
- - 手动创建测试文件，编译，调用加密解密，清理文件

## 加密设计

1. **密钥派生**：

- 密码 → Argon2id（带盐值）→ 主密钥（32 字节）

- 主密钥 → HKDF-SHA256 → 加密密钥（32 字节）+ HMAC 密钥（32 字节）

2. **加密**：

- 使用随机生成的 IV 的 AES-256-CTR 模式

- 支持大型文件的并行处理

3. **认证**：

- 对密文计算 HMAC-SHA256

- 存储在加密文件末尾，用于验证

4. **文件格式**：

- 魔数（“DEC!”）

- 版本字节

- 盐值（16 字节）

- IV（16 字节）

- 加密数据

- HMAC（32 字节）

## 并行处理

该工具实现了并行 AES-CTR 处理具体步骤：

1. 将数据分割成块

2. 使用 `StreamCipherSeek` 将每个并行工作线程定位到正确的密钥流偏移量

3. 使用 Rayon 并行处理数据块

4. 确保输出结果与单线程处理结果完全一致
