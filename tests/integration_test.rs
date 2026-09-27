// tests/integration_test.rs
#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use tempfile::NamedTempFile;

    #[test]
    #[ignore = "performance coverage only; too heavy for normal test runs"]
    fn test_encrypt_decrypt_speed_and_consistency() {
        // 创建测试数据
        let test_data: Vec<u8> = (0..1024 * 1024 * 500).map(|i| (i % 256) as u8).collect(); // 500MB测试数据
        let password = "Password123!".to_string();

        // 创建临时文件
        let mut input_file = NamedTempFile::new().expect("Failed to create temp file");
        input_file.write_all(&test_data).expect("Failed to write test data");
        let input_path = input_file.path().to_str().unwrap().to_string();

        let encrypted_file = NamedTempFile::new().expect("Failed to create temp file");
        let encrypted_path = encrypted_file.path().to_str().unwrap().to_string();

        let decrypted_file = NamedTempFile::new().expect("Failed to create temp file");
        let decrypted_path = decrypted_file.path().to_str().unwrap().to_string();

        // 测试加密速度
        let start_time = std::time::Instant::now();

        let encrypt_result = dec_cryptor::encryptor::encrypt_with_mode(
            &input_path,
            &encrypted_path,
            &password
        );

        assert!(encrypt_result.is_ok(), "Encryption failed: {:?}", encrypt_result.err());

        let encrypt_duration = start_time.elapsed();
        println!("Encryption time for 500MB data: {:?}", encrypt_duration);

        // 测试解密速度
        let start_time = std::time::Instant::now();

        let decrypt_result = dec_cryptor::decryptor::decrypt_with_mode(
            &encrypted_path,
            &decrypted_path,
            &password
        );

        assert!(decrypt_result.is_ok(), "Decryption failed: {:?}", decrypt_result.err());

        let decrypt_duration = start_time.elapsed();
        println!("Decryption time for 500MB data: {:?}", decrypt_duration);

        // 验证内容一致性
        let decrypted_data = std::fs::read(&decrypted_path).expect("Failed to read decrypted file");
        assert_eq!(test_data.len(), decrypted_data.len(), "File sizes don't match");
        assert_eq!(test_data, decrypted_data, "File contents don't match");

        // 验证版本检查
        let version_check = dec_cryptor::decryptor::check_version(&encrypted_path);
        assert!(version_check.is_ok(), "Version check failed: {:?}", version_check.err());

        println!("Performance test completed successfully!");
        println!("Encryption speed: {:.2} MB/s", 500.0 / encrypt_duration.as_secs_f64());
        println!("Decryption speed: {:.2} MB/s", 500.0 / decrypt_duration.as_secs_f64());
    }

    #[test]
    fn test_encrypt_decrypt_via_stdio() {
        let test_data = b"stdin/stdout roundtrip test payload".to_vec();

        let encrypt_output = run_dec_with_stdin(
            ["-e", "-", "-q", "-p", "Password123!", "--stdout"],
            &test_data,
        );

        assert!(encrypt_output.status.success(), "Encrypt process failed");
        assert!(!encrypt_output.stdout.is_empty(), "Encrypt stdout should contain ciphertext");
        // 管道输入 → 进度静默（无 spinner / 无进度条），stderr 应仅含错误信息，
        // 正常加密成功时 stderr 为空。
        assert!(
            encrypt_output.stderr.is_empty(),
            "Encrypt stderr should be empty for pipe stdin (no progress), got: {:?}",
            String::from_utf8_lossy(&encrypt_output.stderr)
        );

        let decrypt_output = run_dec_with_stdin(
            ["-d", "-", "-q", "-p", "Password123!", "--stdout"],
            &encrypt_output.stdout,
        );

        assert!(decrypt_output.status.success(), "Decrypt process failed");
        assert_eq!(decrypt_output.stdout, test_data, "Roundtrip payload mismatch");
        // 管道输入 → 进度静默；正常解密成功时 stderr 为空。
        assert!(
            decrypt_output.stderr.is_empty(),
            "Decrypt stderr should be empty for pipe stdin (no progress), got: {:?}",
            String::from_utf8_lossy(&decrypt_output.stderr)
        );
    }

    #[test]
    fn test_encrypt_to_stdout_keeps_header_out_of_stderr() {
        let input = b"stream separation check";
        let output = run_dec_with_stdin(
            ["-e", "-", "-q", "-p", "Password123!", "--stdout"],
            input,
        );

        assert!(output.status.success(), "Encrypt process failed");
        assert!(output.stdout.starts_with(b"DEC!"), "Ciphertext header missing from stdout");
        // 管道输入 → 进度静默；stdout 顶部仍是 37 字节 header（"DEC!"），
        // 但 stderr 不应该出现任何进度文本或 spinner / 进度条标记。
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.is_empty(),
            "Encrypt stderr should be empty for pipe stdin, got: {:?}",
            stderr
        );
        assert!(!stderr.contains("refusing to write stream data"), "Unexpected terminal refusal");
    }

    #[test]
    fn test_encrypt_stdin_to_file_and_decrypt_file_to_stdout() {
        let input = b"stdin to file and back";
        let mut input_file = NamedTempFile::new().expect("Failed to create input temp file");
        input_file.write_all(input).expect("Failed to write input");
        let output_file = NamedTempFile::new().expect("Failed to create output temp file");

        let encrypt_status = Command::new(dec_bin())
            .args([
                "-e",
                input_file.path().to_str().unwrap(),
                "-q",
                "-p",
                "Password123!",
                "-o",
                output_file.path().to_str().unwrap(),
            ])
            .status()
            .expect("Failed to run file encryption");
        assert!(encrypt_status.success(), "File encryption failed");

        let decrypt_output = Command::new(dec_bin())
            .args([
                "-d",
                output_file.path().to_str().unwrap(),
                "-q",
                "-p",
                "Password123!",
                "--stdout",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("Failed to run file decryption");

        assert!(decrypt_output.status.success(), "File decryption failed");
        assert_eq!(decrypt_output.stdout, input, "Decrypted stdout mismatch");
        assert!(!decrypt_output.stderr.is_empty(), "Expected progress output on stderr");
    }

    #[test]
    fn test_decrypt_with_wrong_password_fails() {
        let input = b"wrong password coverage";
        let encrypted = run_dec_with_stdin(
            ["-e", "-", "-q", "-p", "Password123!", "--stdout"],
            input,
        );
        assert!(encrypted.status.success(), "Encryption failed unexpectedly");

        let output = run_dec_with_stdin(
            ["-d", "-", "-q", "-p", "wrong-password", "--stdout"],
            &encrypted.stdout,
        );

        assert!(!output.status.success(), "Wrong-password decrypt should fail");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("decryption failed"), "Expected decrypt error on stderr");
    }

    #[test]
    fn test_decrypt_stdin_invalid_ciphertext_fails() {
        let output = run_dec_with_stdin(
            ["-d", "-", "-q", "-p", "Password123!", "--stdout"],
            b"not-a-valid-dec-stream",
        );

        assert!(!output.status.success(), "Invalid ciphertext should fail");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("decryption failed"), "Expected decrypt failure on stderr");
        assert!(output.stdout.is_empty(), "Invalid decrypt should not produce plaintext");
    }

    #[test]
    fn test_encrypt_stdout_matches_file_decrypt_roundtrip() {
        let input = b"stdout ciphertext can be decrypted from file";
        let encrypted = run_dec_with_stdin(
            ["-e", "-", "-q", "-p", "Password123!", "--stdout"],
            input,
        );
        assert!(encrypted.status.success(), "Encryption failed unexpectedly");

        let cipher_file = NamedTempFile::new().expect("Failed to create cipher temp file");
        fs::write(cipher_file.path(), &encrypted.stdout).expect("Failed to persist ciphertext");

        let plain_file = NamedTempFile::new().expect("Failed to create plaintext temp file");
        let decrypt_status = Command::new(dec_bin())
            .args([
                "-d",
                cipher_file.path().to_str().unwrap(),
                "-q",
                "-p",
                "Password123!",
                "-o",
                plain_file.path().to_str().unwrap(),
            ])
            .status()
            .expect("Failed to decrypt ciphertext file");
        assert!(decrypt_status.success(), "Decrypting stdout ciphertext file failed");

        let decrypted = fs::read(plain_file.path()).expect("Failed to read decrypted file");
        assert_eq!(decrypted, input, "Roundtrip via stdout ciphertext file mismatch");
    }

    fn dec_bin() -> &'static str {
        env!("CARGO_BIN_EXE_dec")
    }

    /// 跑一个 `dec` 子进程，把 `stdin_data` 写完，并收集全部输出。
    ///
    /// **stdin 必须由独立线程写**：父进程若先 `write_all` 再 `wait_with_output`，
    /// 只要输入超过 peek(1 MiB + 1 B) + 流水线缓冲量，子进程就会因为 stdout
    /// 管道背压而停止读 stdin，父进程随即阻塞在写 stdin 上 —— 互等。
    /// （4 MiB 的用例曾把整个 `cargo test` 挂到超时。）
    fn run_dec_with_stdin<const N: usize>(args: [&str; N], stdin_data: &[u8]) -> std::process::Output {
        let mut child = Command::new(dec_bin())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn dec process");

        let mut stdin = child.stdin.take().expect("Missing child stdin");
        let data = stdin_data.to_vec();
        let feeder = std::thread::spawn(move || {
            // 子进程提前失败（例如错口令）会关掉 stdin，EPIPE 属预期结果。
            let _ = stdin.write_all(&data);
        });

        let output = child
            .wait_with_output()
            .expect("Failed to wait for child process");
        feeder.join().expect("stdin feeder thread panicked");
        output
    }

    // ────────────────────────────────────────────────────────────────────────
    // 流式 stdin 路径回归测试（修复 OOM / 落盘后的核心场景）
    // ────────────────────────────────────────────────────────────────────────

    /// 1 MiB 是 PARALLEL_THRESHOLD 阈值；用 2 MiB 输入走并行流水线分支。
    #[test]
    fn test_stdin_roundtrip_large_uses_parallel_path() {
        let mut payload = Vec::with_capacity(2 * 1024 * 1024);
        for i in 0u32..(2 * 1024 * 1024) {
            payload.push((i.wrapping_mul(2654435761) ^ (i >> 8)) as u8);
        }

        let encrypted = run_dec_with_stdin(
            ["-e", "-", "-q", "-p", "Password123!", "--stdout"],
            &payload,
        );
        assert!(encrypted.status.success(), "Encrypt failed");
        // 管道输入 → 静默；stderr 应该为空
        assert!(encrypted.stderr.is_empty(), "Pipe stdin should not emit progress to stderr");

        let decrypted = run_dec_with_stdin(
            ["-d", "-", "-q", "-p", "Password123!", "--stdout"],
            &encrypted.stdout,
        );
        assert!(decrypted.status.success(), "Decrypt failed");
        assert!(decrypted.stderr.is_empty(), "Pipe stdin should not emit progress to stderr");
        assert_eq!(decrypted.stdout, payload, "Large stdin roundtrip mismatch");
    }

    /// 256 KiB 远低于 PARALLEL_THRESHOLD，强制走串行路径（encrypt_stdin_to_stdout 的
    /// peek 阶段不会攒满阈值，直接走 encrypt_serial）。
    #[test]
    fn test_stdin_roundtrip_small_uses_serial_path() {
        let payload: Vec<u8> = (0..(256 * 1024) as u32)
            .map(|i| (i.wrapping_mul(31) ^ (i >> 16)) as u8)
            .collect();

        let encrypted = run_dec_with_stdin(
            ["-e", "-", "-q", "-p", "Password123!", "--stdout"],
            &payload,
        );
        assert!(encrypted.status.success(), "Small stdin encrypt failed");
        assert!(encrypted.stderr.is_empty(), "Pipe stdin should not emit progress");

        let decrypted = run_dec_with_stdin(
            ["-d", "-", "-q", "-p", "Password123!", "--stdout"],
            &encrypted.stdout,
        );
        assert!(decrypted.status.success(), "Small stdin decrypt failed");
        assert_eq!(decrypted.stdout, payload, "Small stdin roundtrip mismatch");
    }

    /// 空 stdin 加密：payload 为 0 字节，但 v4 仍必须写出 EOF 帧 ——
    /// stdout = 37 B header + 20 B EOF 帧；解密回空明文（文件模式同样成立，
    /// 这正是"用 payload 长度为 0 判空"那个旧误报被移除后的行为）。
    #[test]
    fn test_stdin_empty_encrypt_emits_header_and_eof_frame() {
        let output = run_dec_with_stdin(
            ["-e", "-", "-q", "-p", "Password123!", "--stdout"],
            &[],
        );

        assert!(output.status.success(), "Empty stdin encrypt should succeed");
        assert_eq!(
            output.stdout.len(),
            37 + 20,
            "Empty stdin must produce header (37 B) + EOF frame (20 B), got {} bytes",
            output.stdout.len()
        );
        assert!(output.stdout.starts_with(b"DEC!"), "Header magic missing");
        assert_eq!(output.stdout[4], 0x04, "expected the v4 version marker");

        // 管道模式
        let decrypted = run_dec_with_stdin(
            ["-d", "-", "-q", "-p", "Password123!", "--stdout"],
            &output.stdout,
        );
        assert!(decrypted.status.success(), "Empty stream must decrypt, not error");
        assert!(decrypted.stdout.is_empty(), "Empty plaintext expected");

        // 文件模式：v4 之前这里会因为 payload 长度为 0 被误判为格式错误
        let cipher_file = NamedTempFile::new().expect("Failed to create temp file");
        fs::write(cipher_file.path(), &output.stdout).unwrap();
        let plain_file = NamedTempFile::new().expect("Failed to create temp file");
        let status = Command::new(dec_bin())
            .args([
                "-d",
                cipher_file.path().to_str().unwrap(),
                "-q",
                "-p",
                "Password123!",
                "-o",
                plain_file.path().to_str().unwrap(),
            ])
            .status()
            .expect("Failed to run dec");
        assert!(status.success(), "Empty stream must decrypt in file mode too");
        assert_eq!(fs::read(plain_file.path()).unwrap().len(), 0);
    }

    /// 空 stdin 解密：`read_exact(&mut [0u8; 37])` 立刻报 UnexpectedEof；
    /// 退出码非 0、stdout 为空、stderr 含错误信息。
    #[test]
    fn test_stdin_empty_decrypt_fails_cleanly() {
        let output = run_dec_with_stdin(
            ["-d", "-", "-q", "-p", "Password123!", "--stdout"],
            &[],
        );

        assert!(!output.status.success(), "Empty stdin decrypt must fail");
        assert!(output.stdout.is_empty(), "Empty decrypt should produce no plaintext");
        let stderr = String::from_utf8_lossy(&output.stderr);
        // 应有错误信息（"decryption failed" 是 main.rs 通用包装文案）
        assert!(
            !stderr.is_empty(),
            "Empty decrypt should emit an error message on stderr"
        );
    }

    /// 错口令大输入解密：第一个 GCM tag 校验失败即终止流水线，
    /// stdout 不会出现 PARALLEL_THRESHOLD 以上的明文数据。
    /// 这是修复后"错口令快速失败"的关键回归用例。
    #[test]
    fn test_stdin_wrong_password_fails_fast_with_no_plaintext_dump() {
        // 4 MiB 随机数据 → 走并行流水线；错口令应在第一个 chunk 终止
        let payload: Vec<u8> = (0u32..(4 * 1024 * 1024))
            .map(|i| (i ^ 0x5a).wrapping_mul(2654435761) as u8)
            .collect();

        let encrypted = run_dec_with_stdin(
            ["-e", "-", "-q", "-p", "correct-password", "--stdout"],
            &payload,
        );
        assert!(encrypted.status.success(), "Encrypt phase should succeed");

        let decrypt = run_dec_with_stdin(
            ["-d", "-", "-q", "-p", "wrong-password", "--stdout"],
            &encrypted.stdout,
        );

        assert!(!decrypt.status.success(), "Wrong-password decrypt must fail");
        // 关键回归：错口令时不会有 4 MiB 明文"喷"出来
        assert!(
            decrypt.stdout.len() < 2 * 1024 * 1024,
            "Wrong-password decrypt leaked too much plaintext: {} bytes",
            decrypt.stdout.len()
        );
        let stderr = String::from_utf8_lossy(&decrypt.stderr);
        assert!(
            stderr.contains("decryption failed"),
            "Expected decrypt error on stderr, got: {:?}",
            stderr
        );
    }

    /// 错口令小输入解密：同样不应有大量 stdout 输出。
    #[test]
    fn test_stdin_wrong_password_small_input_no_dump() {
        let payload = b"a few bytes that should not leak".to_vec();

        let encrypted = run_dec_with_stdin(
            ["-e", "-", "-q", "-p", "correct-password", "--stdout"],
            &payload,
        );
        assert!(encrypted.status.success());

        let decrypt = run_dec_with_stdin(
            ["-d", "-", "-q", "-p", "wrong-password", "--stdout"],
            &encrypted.stdout,
        );

        assert!(!decrypt.status.success());
        // 小输入只有一个 chunk；错口令时 stdout 应为空（第一个 chunk 还没出 writer 就失败）
        assert!(
            decrypt.stdout.is_empty(),
            "Wrong-password decrypt should not write any plaintext, got {} bytes",
            decrypt.stdout.len()
        );
    }

    /// 边界值：刚好 PARALLEL_THRESHOLD 字节 (1 MiB) 的输入应走串行；
    /// 再多 1 字节则走并行。两条路径都要 round-trip 一致。
    #[test]
    fn test_stdin_roundtrip_exactly_at_threshold_boundary() {
        // 恰好 1 MiB：buf.len() == THRESHOLD → use_parallel == false → 串行
        let payload_at: Vec<u8> = (0..(1024 * 1024) as u32).map(|i| i as u8).collect();
        let enc = run_dec_with_stdin(
            ["-e", "-", "-q", "-p", "Password123!", "--stdout"],
            &payload_at,
        );
        assert!(enc.status.success());
        let dec = run_dec_with_stdin(
            ["-d", "-", "-q", "-p", "Password123!", "--stdout"],
            &enc.stdout,
        );
        assert!(dec.status.success());
        assert_eq!(dec.stdout, payload_at);

        // 1 MiB + 1 字节：buf.len() > THRESHOLD → use_parallel == true → 并行
        let mut payload_over = payload_at.clone();
        payload_over.push(0xAB);
        let enc2 = run_dec_with_stdin(
            ["-e", "-", "-q", "-p", "Password123!", "--stdout"],
            &payload_over,
        );
        assert!(enc2.status.success());
        let dec2 = run_dec_with_stdin(
            ["-d", "-", "-q", "-p", "Password123!", "--stdout"],
            &enc2.stdout,
        );
        assert!(dec2.status.success());
        assert_eq!(dec2.stdout, payload_over);
    }

    /// `-` 输入 + `-o FILE`：以前 `-o` 被静默忽略（密文/明文照旧写 stdout），
    /// 现在必须落到文件、stdout 保持干净。
    #[test]
    fn test_stdin_input_respects_output_file() {
        let payload = b"stdin payload routed into a real file".to_vec();

        let cipher_file = NamedTempFile::new().expect("Failed to create cipher temp file");
        let cipher_path = cipher_file.path().to_str().unwrap().to_string();
        let encrypted = run_dec_with_stdin(
            ["-e", "-", "-q", "-p", "Password123!", "-o", &cipher_path],
            &payload,
        );
        assert!(
            encrypted.status.success(),
            "Encrypt failed: {:?}",
            String::from_utf8_lossy(&encrypted.stderr)
        );
        assert!(encrypted.stdout.is_empty(), "ciphertext must not be written to stdout");
        let cipher = fs::read(&cipher_path).expect("encrypted output file must exist");
        assert!(cipher.starts_with(b"DEC!"), "output file must hold a DEC! stream");

        let plain_file = NamedTempFile::new().expect("Failed to create plain temp file");
        let plain_path = plain_file.path().to_str().unwrap().to_string();
        let decrypted = run_dec_with_stdin(
            ["-d", "-", "-q", "-p", "Password123!", "-o", &plain_path],
            &cipher,
        );
        assert!(
            decrypted.status.success(),
            "Decrypt failed: {:?}",
            String::from_utf8_lossy(&decrypted.stderr)
        );
        assert!(decrypted.stdout.is_empty(), "plaintext must not be written to stdout");
        assert_eq!(fs::read(&plain_path).expect("plaintext file must exist"), payload);
    }

    /// `-` 输入且不给 `-o` 时默认写 stdout，而不是推出 `-.decx` / `-.out` 假文件名。
    #[test]
    fn test_stdin_input_defaults_to_stdout() {
        let payload = b"default stdout routing for stdin".to_vec();

        let encrypted = run_dec_with_stdin(["-e", "-", "-q", "-p", "Password123!"], &payload);
        assert!(
            encrypted.status.success(),
            "Encrypt failed: {:?}",
            String::from_utf8_lossy(&encrypted.stderr)
        );
        assert!(encrypted.stdout.starts_with(b"DEC!"), "ciphertext must go to stdout");

        let decrypted = run_dec_with_stdin(["-d", "-", "-q", "-p", "Password123!"], &encrypted.stdout);
        assert!(
            decrypted.status.success(),
            "Decrypt failed: {:?}",
            String::from_utf8_lossy(&decrypted.stderr)
        );
        assert_eq!(decrypted.stdout, payload);

        let cwd = std::env::current_dir().expect("cwd");
        assert!(!cwd.join("-.decx").exists(), "must not create a literal `-.decx` file");
        assert!(!cwd.join("-.out").exists(), "must not create a literal `-.out` file");
    }

    /// `-` 输入 + 目标文件已存在：不能弹 y/n 提示 —— 提示读的就是 stdin，
    /// 会把 payload 当成回答吃掉（静默丢数据）。必须直接拒绝并要求 `-q`。
    #[test]
    fn test_stdin_input_refuses_existing_output_without_quiet() {
        let payload = b"payload that must not be eaten by a prompt".to_vec();
        let existing = NamedTempFile::new().expect("Failed to create output temp file");
        fs::write(existing.path(), b"keep me").unwrap();
        let path = existing.path().to_str().unwrap().to_string();

        let output = run_dec_with_stdin(["-e", "-", "-p", "Password123!", "-o", &path], &payload);

        assert!(!output.status.success(), "must refuse instead of prompting on stdin");
        assert!(output.stdout.is_empty(), "nothing may be written to stdout");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("already") && stderr.contains("EXISTS"),
            "got stderr: {:?}",
            stderr
        );
        assert!(
            stderr.contains("-q"),
            "refusal must tell the user how to overwrite, got: {:?}",
            stderr
        );
        assert_eq!(
            fs::read(&path).expect("existing output file"),
            b"keep me",
            "existing file must stay untouched"
        );
    }

    /// 覆盖确认遇到 stdin EOF 时必须按"取消"退出，而不是无限重问（曾经会死循环）。
    #[test]
    fn test_overwrite_prompt_cancels_on_eof() {
        let input_file = NamedTempFile::new().expect("Failed to create input temp file");
        fs::write(input_file.path(), b"some plaintext").unwrap();
        let existing = NamedTempFile::new().expect("Failed to create output temp file");
        fs::write(existing.path(), b"keep me").unwrap();

        let output = Command::new(dec_bin())
            .args([
                "-e",
                input_file.path().to_str().unwrap(),
                "-p",
                "Password123!",
                "-o",
                existing.path().to_str().unwrap(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("Failed to run dec");

        assert!(output.status.success(), "EOF must cancel the overwrite, not hang");
        assert_eq!(
            fs::read(existing.path()).expect("existing output file"),
            b"keep me",
            "existing file must stay untouched"
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // v4 完整性：EOF 帧必须存在、位置正确、且后面没有多余字节
    // ────────────────────────────────────────────────────────────────────────

    /// 把 v4 密文切成 `(header, 数据帧列表, EOF 帧)`，供截断类用例构造变体。
    fn split_stream(stream: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>, Vec<u8>) {
        assert!(stream.len() > 37, "stream shorter than its header");
        let header = stream[..37].to_vec();
        let mut data = Vec::new();
        let mut eof = Vec::new();
        let mut offset = 37;
        while offset + 4 <= stream.len() {
            let block_len =
                u32::from_le_bytes(stream[offset..offset + 4].try_into().unwrap()) as usize;
            let frame_len = if block_len == 0 { 4 + 16 } else { 4 + block_len };
            let frame = stream[offset..offset + frame_len].to_vec();
            offset += frame_len;
            if block_len == 0 {
                eof = frame;
                break;
            }
            data.push(frame);
        }
        assert!(!eof.is_empty(), "stream must carry the v4 EOF frame");
        assert_eq!(offset, stream.len(), "frame parse must consume the whole stream");
        (header, data, eof)
    }

    /// P1 回归：v3 下"按帧边界截断"会 exit 0 并静默输出残缺明文；
    /// v4 下这些变体在**文件模式与管道模式都必须报错**。
    #[test]
    fn test_v4_rejects_truncated_and_tampered_streams() {
        let payload: Vec<u8> = (0..(3 * 1024 * 1024) as u32)
            .map(|i| (i ^ 0x33).wrapping_mul(2654435761) as u8)
            .collect();
        let encrypted = run_dec_with_stdin(
            ["-e", "-", "-q", "-p", "Password123!", "--stdout"],
            &payload,
        );
        assert!(encrypted.status.success(), "Encrypt failed");

        let (header, data, eof) = split_stream(&encrypted.stdout);
        assert!(data.len() >= 2, "expected several data frames, got {}", data.len());
        let all_data = data.concat();
        let without_last_data = data[..data.len() - 1].concat();

        fn join(parts: &[&[u8]]) -> Vec<u8> {
            parts.concat()
        }
        let variants: Vec<(&str, Vec<u8>)> = vec![
            // 整帧边界截断：丢掉最后一个数据帧（连同 EOF 帧）—— v3 的静默场景
            (
                "drop last data frame + marker",
                join(&[header.as_slice(), without_last_data.as_slice()]),
            ),
            // 只丢最后一个数据帧，保留 EOF 帧：标记与下标错位
            (
                "drop last data frame, keep marker",
                join(&[header.as_slice(), without_last_data.as_slice(), eof.as_slice()]),
            ),
            // 只丢 EOF 帧
            ("drop marker", join(&[header.as_slice(), all_data.as_slice()])),
            // 只剩 header
            ("header only", header.clone()),
            // EOF 帧被砍掉一半
            (
                "half marker",
                join(&[header.as_slice(), all_data.as_slice(), &eof[..9]]),
            ),
            // EOF 帧被搬到最前：只留标记、丢掉全部数据
            ("marker moved to front", join(&[header.as_slice(), eof.as_slice()])),
            // 合法流之后追加垃圾
            (
                "trailing garbage",
                join(&[encrypted.stdout.as_slice(), b"junk".as_slice()]),
            ),
        ];

        for (label, bytes) in variants {
            let pipe = run_dec_with_stdin(
                ["-d", "-", "-q", "-p", "Password123!", "--stdout"],
                &bytes,
            );
            assert!(
                !pipe.status.success(),
                "{label}: pipe mode must fail, got a successful exit"
            );

            let cipher_file = NamedTempFile::new().expect("Failed to create temp file");
            fs::write(cipher_file.path(), &bytes).unwrap();
            let plain_file = NamedTempFile::new().expect("Failed to create temp file");
            let file_mode = Command::new(dec_bin())
                .args([
                    "-d",
                    cipher_file.path().to_str().unwrap(),
                    "-q",
                    "-p",
                    "Password123!",
                    "-o",
                    plain_file.path().to_str().unwrap(),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("Failed to run dec");
            assert!(
                !file_mode.status.success(),
                "{label}: file mode must fail, got a successful exit"
            );
        }
    }

    /// v3 及更早的密文没有 EOF 帧，无法检测截断 —— 必须直接拒绝。
    #[test]
    fn test_v3_ciphertext_is_rejected() {
        let encrypted = run_dec_with_stdin(
            ["-e", "-", "-q", "-p", "Password123!", "--stdout"],
            b"legacy version check",
        );
        assert!(encrypted.status.success(), "Encrypt failed");
        let mut legacy = encrypted.stdout.clone();
        assert_eq!(legacy[4], 0x04, "fresh output must be v4");
        legacy[4] = 0x03;

        let pipe = run_dec_with_stdin(
            ["-d", "-", "-q", "-p", "Password123!", "--stdout"],
            &legacy,
        );
        assert!(!pipe.status.success(), "v3 stream must be rejected");
        let stderr = String::from_utf8_lossy(&pipe.stderr);
        assert!(stderr.contains("version"), "got stderr: {:?}", stderr);

        let cipher_file = NamedTempFile::new().expect("Failed to create temp file");
        fs::write(cipher_file.path(), &legacy).unwrap();
        let file_mode = Command::new(dec_bin())
            .args([
                "-d",
                cipher_file.path().to_str().unwrap(),
                "-q",
                "-p",
                "Password123!",
                "--stdout",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("Failed to run dec");
        assert!(!file_mode.status.success(), "v3 file must be rejected");
        assert!(
            String::from_utf8_lossy(&file_mode.stderr).contains("version"),
            "expected a version error"
        );
    }
}
