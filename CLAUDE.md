# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust-based file encryption/decryption tool called "DEC!" that provides secure symmetric encryption using industry-standard cryptographic algorithms. The tool supports both single-threaded and parallel processing modes to improve performance when handling large files.

## Architecture

The codebase follows a modular structure with the following main components:

1. `src/main.rs` - Entry point, console I/O, module coordination
2. `src/args.rs` - Command-line argument parsing
3. `src/encryptor.rs` - Core encryption logic and file processing
4. `src/decryptor.rs` - Core decryption logic and file processing
5. `src/crypto_utils.rs` - Cryptographic constants and utility functions
6. `src/key_derivation.rs` - Key derivation using Argon2 and HKDF
7. `src/hmac_validator.rs` - HMAC calculation and verification
8. `src/parallel_handler.rs` - Parallel processing implementation for AES-CTR
9. `src/progress_utils.rs` - Progress tracking and timing utilities
10. `src/lib.rs` - Module exports for integration testing

## Cryptographic Design

1. **Key Derivation**:
   - Password → Argon2id (with salt) → Master Key (32 bytes)
   - Master Key → HKDF-SHA256 → Encryption Key (32 bytes) + HMAC Key (32 bytes)

2. **Encryption**:
   - AES-256-CTR mode with randomly generated IV
   - Support for parallel processing of large files

3. **Authentication**:
   - HMAC-SHA256 calculated on ciphertext
   - Stored at the end of encrypted file for verification

4. **File Format**:
   - Magic number ("DEC!")
   - Version byte
   - Salt (16 bytes)
   - IV (16 bytes)
   - Encrypted data
   - HMAC (32 bytes)

## Common Development Commands

### Building
```bash
# Build in debug mode
cargo build

# Build in release mode
cargo build --release
```

### Testing
```bash
# Run unit tests
cargo test

# Run unit tests with output
cargo test -- --nocapture

# Run tests in release mode
cargo test --release -- --nocapture

# Run integration tests
cargo test --test integration_test
```

### Running the Application
```bash
# Encrypt a file
cargo run --release -- -e input_file.txt

# Decrypt a file
cargo run --release -- -d input_file.txt.decx

# Encrypt with specific output and password
cargo run --release -- -e input_file.txt -o output.decx -p mypassword

# Decrypt with specific output and password
cargo run --release -- -d input_file.decx -o output.txt -p mypassword
```

### Manual Testing
```bash
# Create test files and run encryption/decryption tests
lua manual_test.lua 500MB

# Create a specific size test file
lua create_file.lua 2GB
```

## Dependencies

- `rpassword` - Secure password input
- `ring` - Cryptographic primitives for random number generation
- `aes` and `ctr` - AES-256-CTR encryption implementation
- `argon2` - Argon2id key derivation
- `hmac` and `sha2` - HMAC-SHA256 implementation
- `hkdf` - HKDF key derivation
- `rayon` - Parallel processing
- `tempfile` - Temporary file creation for testing

## Parallel Processing

The tool implements parallel AES-CTR processing with these steps:
1. Split data into chunks
2. Use `StreamCipherSeek` to position each parallel worker thread to the correct keystream offset
3. Process data chunks in parallel using Rayon
4. Ensure output results are identical to single-threaded processing

The parallel processing is automatically enabled based on available CPU cores and only used for data larger than 16KB to avoid overhead on small files.