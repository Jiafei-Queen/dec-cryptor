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
        let dec_bin = dec_bin();

        let mut encrypt_child = Command::new(dec_bin)
            .args(["-e", "-", "-q", "-p", "Password123!", "--stdout"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn encrypt process");

        encrypt_child
            .stdin
            .as_mut()
            .expect("Missing encrypt stdin")
            .write_all(&test_data)
            .expect("Failed to write encrypt stdin");

        let encrypt_output = encrypt_child
            .wait_with_output()
            .expect("Failed to wait for encrypt process");

        assert!(encrypt_output.status.success(), "Encrypt process failed");
        assert!(!encrypt_output.stdout.is_empty(), "Encrypt stdout should contain ciphertext");
        assert!(!encrypt_output.stderr.is_empty(), "Encrypt stderr should contain progress");

        let mut decrypt_child = Command::new(dec_bin)
            .args(["-d", "-", "-q", "-p", "Password123!", "--stdout"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn decrypt process");

        decrypt_child
            .stdin
            .as_mut()
            .expect("Missing decrypt stdin")
            .write_all(&encrypt_output.stdout)
            .expect("Failed to write decrypt stdin");

        let decrypt_output = decrypt_child
            .wait_with_output()
            .expect("Failed to wait for decrypt process");

        assert!(decrypt_output.status.success(), "Decrypt process failed");
        assert_eq!(decrypt_output.stdout, test_data, "Roundtrip payload mismatch");
        assert!(!decrypt_output.stderr.is_empty(), "Decrypt stderr should contain progress");
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
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("DEC!"), "Expected progress text on stderr");
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

        let mut decrypt_child = Command::new(dec_bin())
            .args(["-d", "-", "-q", "-p", "wrong-password", "--stdout"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn decrypt process");

        decrypt_child
            .stdin
            .as_mut()
            .expect("Missing decrypt stdin")
            .write_all(&encrypted.stdout)
            .expect("Failed to write decrypt stdin");

        let output = decrypt_child
            .wait_with_output()
            .expect("Failed to wait for decrypt process");

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

    fn run_dec_with_stdin<const N: usize>(args: [&str; N], stdin_data: &[u8]) -> std::process::Output {
        let mut child = Command::new(dec_bin())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn dec process");

        child
            .stdin
            .as_mut()
            .expect("Missing child stdin")
            .write_all(stdin_data)
            .expect("Failed to write child stdin");

        child
            .wait_with_output()
            .expect("Failed to wait for child process")
    }
}
