# DEC! – High‑Performance File Encryption Tool
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust 2024](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org/)

DEC! is a high‑performance file encryption utility written in Rust. It leverages parallel processing to deliver strong security without sacrificing speed.

## Features

- 🔒 **Military‑grade encryption** – Argon2id key derivation + AES‑256‑GCM
- ⚡ **Parallel processing** – Three‑stage read/encrypt/write pipeline for high throughput
- 📈 **Terminal-friendly progress output** – Progress is rendered on `stderr`, so `stdout` remains pipe-safe
- 🔁 **Unix-style streaming support** – Read from `stdin` and write to `stdout`
- 💾 **Chunked file processing** – Configurable buffer sizes for file I/O
- 🖥️ **Cross‑platform** – Works on Windows, macOS, and Linux

## Build

```bash
cargo build --release
```

The binary will be available at:

```text
./target/release/dec
```

## Usage

### Basic file encryption

```bash
dec -e secret.txt -p Password123
```

This writes the encrypted output to `secret.txt.decx`.

### Basic file decryption

```bash
dec -d secret.txt.decx -p Password123
```

If the input ends with `.decx`, DEC! strips that suffix for the default output path.

### Custom output path

```bash
dec -e archive.tar -p Password123 -o archive.bundle
dec -d archive.bundle -p Password123 -o archive.tar
```

### Skip overwrite confirmation

```bash
dec -e secret.txt -p Password123 -q
```

`-q` only skips confirmation prompts. It does not disable progress output.

### Stream plaintext from stdin to stdout

```bash
cat secret.txt | dec -e - -p Password123 --stdout > secret.txt.decx
```

You can also use the short form:

```bash
cat secret.txt | dec -e - -p Password123 -c > secret.txt.decx
```

### Stream ciphertext back to plaintext

```bash
cat secret.txt.decx | dec -d - -p Password123 --stdout > secret.txt
```

### Output behaviour

- Progress output is written to `stderr`
- Encrypted or decrypted stream data is written to `stdout` only when `--stdout` / `-c` is used
- DEC! refuses to write stream data directly to an interactive terminal; redirect or pipe `stdout`

## CLI Summary

```text
dec -e <input> [-p PASSWORD] [-o OUTPUT] [-q]
dec -d <input> [-p PASSWORD] [-o OUTPUT] [-q]
dec -e - [-p PASSWORD] --stdout
dec -d - [-p PASSWORD] --stdout
```

## Technical Details

### Encryption Design

DEC! implements a robust encryption pipeline:

1. **Key Derivation**
    - Argon2id (winner of the Password Hashing Competition)
    - Parameters: 256 MiB memory, 3 iterations, 2‑way parallelism

2. **Encryption**
    - AES‑GCM operates on individual blocks
    - Each operation uses a unique 16‑byte salt
    - Nonce derived from `base_iv` with the chunk index XORed into the low 4 bytes, guaranteeing uniqueness per chunk
    - Every block has its own authentication tag (ensures tamper detection and a better user experience when the wrong password is supplied)

3. **File Format**
   ```text
   [MAGIC][VERSION][SALT][INITIAL_VECTOR][BLOCK_SIZE][BLOCK#1: DATA+TAG][BLOCK#2: DATA+TAG]...
   ```

### Parallel Processing Architecture

DEC! achieves excellent throughput with a three‑stage bounded pipeline (`reader → encryptor/decryptor → writer`). Each stage runs in its own thread, with `PIPELINE_DEPTH = 16` slots per channel — natural back‑pressure caps memory regardless of file size.

- **Pipeline depth** – 16 in‑flight chunks per channel; per‑chunk AES‑GCM work keeps the CPU busy while the next read / write is in flight.
- **Chunk‑based processing** – Splits data into 1 MiB blocks; per‑chunk index is XORed into the low 4 bytes of the IV to derive a unique AES‑GCM nonce.
- **Single encryptor / decryptor worker (hardware AES path)** – On machines with hardware AES (x86 AES‑NI / aarch64 FEAT_AES) a single worker already saturates the AES pipeline, so parallelism comes from overlapping I/O with one CPU worker, not from fanning the cipher across cores.
- **Adaptive parallelism (software‑AES path)** – When `aes_hardware_available()` reports no hardware AES (e.g. older x86, small ARM cores), the encryptor / decryptor stage switches to a batched rayon `par_iter` (batch size 8): chunks accumulate until the batch is full, then AES is computed in parallel and re‑emitted in index order. This trades a small batching latency for near‑linear multi‑core AES speed‑up on software‑AES machines. On hardware‑AES machines this branch is dead code, so the cost is a single branch in the hot path.
- **Threshold fallback** – Files smaller than `PARALLEL_THRESHOLD` (1 MiB) take the single‑threaded path: Argon2 KDF (~270 ms) already dominates small‑file latency, so the three `thread::spawn` / `join` round‑trips (~50‑100 µs) bring no benefit.
- **Memory envelope** – Peak ≈ `3 × (PIPELINE_DEPTH + 1) × CHUNK_SIZE ≈ 51 MiB`, **independent of file size** (the rayon path adds at most one extra batch = 8 MiB of in‑flight data, still bounded).

### Security Features

- **Forward secrecy** – New salt and IV for every operation
- **Tamper detection** – GCM authentication tag protects against modifications
- **Memory safety** – Entire codebase and dependencies are written in Rust, ensuring no crashes
- **Secure password input** – Passwords are entered without echoing to the terminal

## Performance

DEC! is tuned for high throughput:

- **Chunk size** – 1 MiB blocks for the encryption pipeline; per‑block AES‑GCM work keeps AES‑NI saturated while the next read / write is in flight.
- **I/O buffer** – 256 KiB `BufReader` / `BufWriter` capacity per stream.
- **Parallel threshold** – Switches to the three‑stage pipeline at 1 MiB (`PARALLEL_THRESHOLD`).
- **Memory usage** – Peak ≈ 51 MiB (`3 × (PIPELINE_DEPTH + 1) × CHUNK_SIZE`); **independent of file size**.
- **AES‑NI acceleration** – Leverages hardware AES‑NI instructions when available.

Typical benchmarks on modern hardware:

| Hardware | Encryption | Decryption |
| -------- |----------|----------|
| M4 Max MBP (release build) | ~1380 MiB/s | ~1360 MiB/s |
| i5-10400F + nvme | 575 MiB/s | 585 MiB/s |

Numbers are measured with the project's `tests/perf_threshold.rs` probe, 500 MiB pseudo‑random payload, median of three runs; CLI throughput at smaller file sizes includes ~270 ms of Argon2 KDF and is therefore lower. Both the hardware‑AES and software‑AES paths share the same pipeline envelope; on machines without AES‑NI the soft‑AES path takes the rayon batched branch and recovers multi‑core throughput.

## Testing

Run the normal test suite with:

```bash
cargo test
```

The repository also keeps a heavy performance-oriented integration test that is ignored by default:

```bash
cargo test -- --ignored
```

Current automated coverage includes:

- Argument parsing and default output-path behaviour
- File-based encrypt/decrypt round-trips
- `stdin`/`stdout` streaming round-trips
- `stderr` progress separation from `stdout` ciphertext/plaintext
- Failure paths such as invalid ciphertext and wrong passwords

## Comparison With Other Tools

| Tool | Algorithm | Parallelism | Language | Performance |
|------|-----------|-------------|----------|-------------|
| **DEC!** | AES‑256‑GCM + Argon2id | ✅ | Rust | Excellent |
| GPG | AES‑128/256 | ❌ | C | Good |
| OpenSSL | Multiple | ❌ | C | Average |
| 7‑Zip | AES‑256 | ❌ | C++ | Average |

--- 

Feel free to clone, build, and experiment! 🚀
