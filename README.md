# DEC! - High-Performance File Encryption Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org/)

DEC! is a high-performance file encryption tool written in Rust that provides strong security with excellent performance through parallel processing capabilities.

## Features

- 🔒 **Military-Grade Encryption**: AES-256-CTR with Argon2id key derivation
- ⚡ **Parallel Processing**: Utilizes all CPU cores for maximum performance
- 🛡️ **Integrity Protection**: HMAC-SHA256 validation to detect tampering
- 📈 **Real-time Progress Tracking**: Visual progress bar with throughput metrics
- 💾 **Memory Efficient**: Streams files with configurable buffer sizes
- 🖥️ **Cross-platform**: Works on Windows, macOS, and Linux

## Technical Details

### Cryptographic Design

DEC! implements a robust cryptographic architecture:

1. **Key Derivation**:
   - Uses Argon2id (winner of the Password Hashing Competition) with:
     - 65,536 KiB memory usage
     - 3 iterations
     - 4-way parallelism
   - HKDF-SHA256 for expanding the master key into separate encryption and HMAC keys

2. **Encryption**:
   - AES-256 in CTR mode (no padding required)
   - Unique salt (16 bytes) and IV (16 bytes) for each operation
   - Authenticated encryption with HMAC-SHA256

3. **File Format**:
   ```
   [Magic Number][Version][Salt][IV][Encrypted Data][HMAC]
   ```

### Parallel Processing Architecture

DEC! achieves remarkable performance through intelligent parallelization:

- **Adaptive Threading**: Automatically detects CPU core count
- **Chunk-based Processing**: Splits data into chunks for parallel processing
- **CTR Mode Compatibility**: Uses stream cipher seeking to maintain cryptographic consistency
- **Threshold-based Fallback**: Uses single-threaded processing for small files (<16KB) to minimize overhead

Test Environment:
- Device: MacBook Pro (M4 Max) 
- Test Command: ` cargo test --release --test integration_test -- --nocapture`

Performance benchmarks on a 500MB file:
- Encryption: ~320 MB/s
- Decryption: ~325 MB/s
- Utilizes all available CPU cores efficiently

### Security Features

- **Forward Secrecy**: New salt and IV for every operation
- **Tamper Detection**: HMAC validation prevents modification attacks
- **Memory Safety**: Written in Rust with zero runtime crashes
- **Password Security**: Secure password input that doesn't echo to terminal

## Installation

### Prerequisites

- Rust 1.65 or higher

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/dec.git
cd dec

# Build in release mode (recommended for performance)
cargo build --release

# The executable will be in target/release/dec
```

### Installing via Cargo

```bash
cargo install dec
```

## Usage

### Basic Commands

```bash
# Encrypt a file
dec -e input_file.txt

# Decrypt a file
dec -d encrypted_file.decx

# Specify output file name
dec -e input.tar -o encrypted_archive

# Specify password (otherwise prompted)
dec -d secret.doc.decx -p mysecretpassword

# Quiet mode (skip overwrite confirmation)
dec -e confidential.pdf -q
```

### Command Line Options

```
Operations:
  -e, --encrypt     Encrypt a file
  -d, --decrypt     Decrypt a file

Options:
  -o, --output      Set output file name
  -p, --password    Set password (not recommended for security)
  -q, --quiet       Skip overwrite confirmation

Others:
  -v, --version     Show version information
```

### Examples

```bash
# Encrypt a document
dec -e confidential.docx

# Encrypt with custom output name
dec --encrypt backup.tar.gz -o secure_backup.enc

# Decrypt with explicit password
dec --decrypt secure_file.decx --password myspecialpass --output original.tar.gz

# Batch processing (bash script example)
for file in *.txt; do
  dec -e "$file"
done
```

## Performance

DEC! is designed for high-performance encryption:

- **Buffer Size**: 256KB chunks for optimal I/O
- **Parallel Threshold**: Automatically switches to parallel mode for files >16KB
- **Memory Usage**: Constant memory footprint regardless of file size
- **CPU Utilization**: Near 100% usage on all cores during processing

Typical performance on modern hardware:
- Small files (<1MB): Limited by I/O rather than CPU
- Large files (100MB+): Fully utilizes all CPU cores
- Very large files (1GB+): Sustained throughput of hundreds of MB/s

## Comparison with Alternatives

| Tool | Algorithm | Parallel | Language | Performance |
|------|-----------|----------|----------|-------------|
| DEC! | AES-256-CTR + Argon2id | ✅ Yes | Rust | Excellent |
| GPG | AES-128/256 | ❌ No | C | Good |
| OpenSSL | Various | ❌ No | C | Fair |
| 7-Zip | AES-256 | ❌ No | C++ | Fair |

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Setup

```bash
# Run tests
cargo test

# Run with specific optimizations
cargo test --release

# Check code formatting
cargo fmt

# Run clippy for code quality checks
cargo clippy
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Rust Crypto](https://github.com/RustCrypto) for excellent cryptographic primitives
- [Rayon](https://github.com/rayon-rs/rayon) for seamless parallel processing
- [Argon2](https://github.com/P-H-C/phc-winner-argon2) for secure key derivation

## Support

For issues, feature requests, or questions:
1. Check existing [issues](https://github.com/yourusername/dec/issues)
2. Create a new issue with detailed information
3. Include version information and steps to reproduce problems