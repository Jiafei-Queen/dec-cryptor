# DEC! – High‑Performance File Encryption Tool
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust 2024](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org/)

DEC! is a high‑performance file encryption utility written in Rust. It leverages parallel processing to deliver strong security without sacrificing speed.

## Features

- 🔒 **Military‑grade encryption** – Argon2id key derivation + AES‑256‑GCM
- ⚡ **Parallel processing** – Utilises all CPU cores for peak performance
- 📈 **Real‑time progress tracking** – Visual progress bars with throughput metrics
- 💾 **Memory‑efficient** – Configurable buffer sizes for streaming I/O
- 🖥️ **Cross‑platform** – Works on Windows, macOS, and Linux

## Technical Details

### Encryption Design

DEC! implements a robust encryption pipeline:

1. **Key Derivation**
    - Argon2id (winner of the Password Hashing Competition)
    - Parameters: 256 MiB memory, 3 iterations, 2‑way parallelism

2. **Encryption**
    - AES‑GCM operates on individual blocks
    - Each operation uses a unique 16‑byte salt
    - Nonce derived from `(base_iv + chunk_index)` to guarantee uniqueness
    - Every block has its own authentication tag (ensures tamper detection and a better user experience when the wrong password is supplied)

3. **File Format**
   ```text
   [MAGIC][VERSION][SALT][INITIAL_VECTOR][BLOCK_SIZE][BLOCK#1: DATA+TAG][BLOCK#2: DATA+TAG]...
   ```

### Parallel Processing Architecture

DEC! achieves excellent performance with intelligent parallelism:

- **Adaptive threads** – Auto‑detects the number of CPU cores
- **Chunk‑based processing** – Splits data into blocks for concurrent handling
- **Threshold fallback** – Files smaller than 16 KB are processed single‑threaded to minimise overhead

### Security Features

- **Forward secrecy** – New salt and IV for every operation
- **Tamper detection** – GCM authentication tag protects against modifications
- **Memory safety** – Entire codebase and dependencies are written in Rust, ensuring no crashes
- **Secure password input** – Passwords are entered without echoing to the terminal

## Performance

DEC! is tuned for high throughput:

- **Buffer size** – Customisable block size for optimal I/O performance
- **Parallel threshold** – Switches to parallel mode for files larger than 16 KB
- **Memory usage** – Constant, scaled only by the number of CPU cores and block size; independent of file size
- **AES‑NI acceleration** – Leverages hardware AES‑NI instructions when available

Typical benchmarks on modern hardware:

| Hardware | Encryption | Decryption |
| -------- |----------|----------|
| M4 Max MiBP | 843 MiB/s | 882 MiB/s |
| i5-10400F + nvme | 575 MiB/s | 585MiB/s  |


## Comparison With Other Tools

| Tool | Algorithm | Parallelism | Language | Performance |
|------|-----------|-------------|----------|-------------|
| **DEC!** | AES‑256‑GCM + Argon2id | ✅ | Rust | Excellent |
| GPG | AES‑128/256 | ❌ | C | Good |
| OpenSSL | Multiple | ❌ | C | Average |
| 7‑Zip | AES‑256 | ❌ | C++ | Average |

--- 

Feel free to clone, build, and experiment! 🚀
