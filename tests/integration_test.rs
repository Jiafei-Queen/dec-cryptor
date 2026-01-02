// tests/integration_test.rs
#[cfg(test)]
mod tests {
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
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

        let encrypt_result = dec::encryptor::encrypt_with_mode(
            &input_path,
            &encrypted_path,
            &password
        );

        assert!(encrypt_result.is_ok(), "Encryption failed: {:?}", encrypt_result.err());

        let encrypt_duration = start_time.elapsed();
        println!("Encryption time for 500MB data: {:?}", encrypt_duration);

        // 测试解密速度
        let start_time = std::time::Instant::now();

        let decrypt_result = dec::decryptor::decrypt_with_mode(
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
        let version_check = dec::decryptor::check_version(&encrypted_path);
        assert!(version_check.is_ok(), "Version check failed: {:?}", version_check.err());

        println!("Performance test completed successfully!");
        println!("Encryption speed: {:.2} MB/s", 500.0 / encrypt_duration.as_secs_f64());
        println!("Decryption speed: {:.2} MB/s", 500.0 / decrypt_duration.as_secs_f64());
    }
}