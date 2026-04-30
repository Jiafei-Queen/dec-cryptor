# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a high-performance file encryption/decryption tool written in Rust called "dec". It provides secure AES-256-CTR encryption with HMAC validation and parallel processing capabilities.

## Architecture Overview

The application follows a modular architecture with these key components:

1. **Main Entry Point** (`src/main.rs`): Handles command-line argument parsing and user interaction
2. **Core Cryptographic Modules**:
   - `src/encryptor.rs`: Implements file encryption with AES-256-CTR
   - `src/decryptor.rs`: Implements file decryption and format validation
   - `src/key_derivation.rs`: Handles Argon2id key derivation and HKDF key expansion
   - `src/hmac_validator.rs`: Provides HMAC-SHA256 validation for integrity checking
3. **Utility Modules**:
   - `src/crypto_utils.rs`: Constants and helper functions for cryptographic operations
   - `src/parallel_handler.rs`: Parallel processing implementation using Rayon
   - `src/progress_utils.rs`: Progress bar and timing utilities
   - `src/args.rs`: Command-line argument parsing

## Key Features

- **Strong Cryptography**: AES-256-CTR encryption with Argon2id key derivation and HMAC-SHA256 integrity validation
- **Parallel Processing**: Utilizes all CPU cores for faster encryption/decryption of large files
- **Memory Efficient**: Streams data with configurable buffer sizes (256KB by default)
- **Progress Tracking**: Real-time progress bar with throughput metrics
- **Secure Defaults**: Automatic salt and IV generation, version tagging

## Common Development Tasks

### Building the Project
```bash
cargo build          # Build in debug mode
cargo build --release # Build in release mode (recommended for performance)
```

### Running Tests
```bash
cargo test           # Run all tests
cargo test --release # Run tests in release mode for better performance
```

### Running the Application
```bash
# Encrypt a file
cargo run -- -e input_file.txt

# Decrypt a file
cargo run -- -d input_file.txt.decx

# Encrypt with custom output and password
cargo run -- -e input_file.txt -o encrypted_output.decx -p mypassword

# Decrypt with custom output
cargo run -- -d encrypted_file.decx -o decrypted_output.txt
```

### Performance Testing
The integration tests include a 500MB performance benchmark:
```bash
cargo test --release -- --nocapture
```

### Linting and Formatting
```bash
cargo fmt           # Format code
cargo clippy -- -D warnings  # Lint, treat warnings as errors
```

### Running a Single Test
```bash
cargo test <test_name>          # Run test matching name
cargo test --test <test_file>   # Run tests in a specific integration test file
```

## Code Structure Guidelines

1. **Cryptographic Flow**:
   - Encryption: Generate salt/IV → Derive keys with Argon2 → Encrypt with AES-CTR → Calculate HMAC → Write file
   - Decryption: Read header → Derive keys → Verify HMAC → Decrypt → Write file

2. **Parallel Processing**:
   - Uses Rayon for automatic workload distribution
   - Falls back to single-threaded for small files (<16KB)
   - Maintains cryptographic consistency through CTR seek operations

3. **Error Handling**:
   - Comprehensive error messages for user-facing operations
   - Graceful degradation for non-critical failures

4. **Security Considerations**:
   - Never store passwords in memory longer than necessary
   - All keys are derived per-operation, no key reuse
   - HMAC validation prevents tampering and incorrect passwords

## Dependencies

- `aes`, `ctr`: AES-256-CTR encryption
- `argon2`: Memory-hard key derivation
- `hmac`, `sha2`: Integrity validation
- `hkdf`: Key expansion
- `rayon`: Parallel processing
- `rpassword`: Secure password input
- `rand`: Cryptographically secure random number generation

## Version Compatibility

The current version (2.5.0) maintains backward compatibility with previous 2.x versions but uses an updated file format that is not compatible with 1.x versions.