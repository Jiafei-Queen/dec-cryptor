# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust-based encryption/decryption tool called "DEC!" that provides file encryption and decryption using AES-256-GCM with PBKDF2 key derivation. The application supports large file processing with progress tracking and handles files with extensions like .tar and .txt.

## Codebase Structure

- `src/main.rs` - Entry point with command-line interface handling
- `src/encryptor.rs` - File encryption implementation using AES-256-GCM
- `src/decryptor.rs` - File decryption implementation with version checking
- `src/crypto_utils.rs` - Cryptographic utilities for key derivation, salt/IV generation
- `src/progress_utils.rs` - Progress tracking and timing utilities
- `Cargo.toml` - Project dependencies (rpassword, ring)

## Development Commands

### Building
```bash
cargo build
cargo build --release
```

### Running
```bash
# Encrypt a file
cargo run -- --enc <input_file> <output_file>

# Decrypt a file
cargo run -- --dec <input_file> <output_file>

# Show version
cargo run -- -v
```

### Testing
Currently, there are no specific test commands defined in the codebase. Tests would need to be added manually.

## Architecture Notes

1. **Encryption Process**:
   - Uses PBKDF2 with 1,000,000 iterations to derive a 256-bit key from password
   - Generates random 16-byte salt and 12-byte IV
   - Uses AES-256-GCM for authenticated encryption
   - Stores magic number "DEC!", version byte, salt, and IV in file header

2. **File Format**:
   - Magic number: "DEC!" (4 bytes)
   - Version: 0x01 (1 byte)
   - Salt: 16 bytes
   - IV: 12 bytes
   - Encrypted data: rest of file

3. **Progress Tracking**:
   - Real-time progress bar with ANSI color codes
   - Unit conversion (B/KB/MB/GB) based on file size
   - Duration timing with formatted output

4. **Security Considerations**:
   - Passwords are not stored, only used for key derivation
   - Uses cryptographically secure random number generation
   - Authenticated encryption provides both confidentiality and integrity