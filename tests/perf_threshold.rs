// tests/perf_threshold.rs
//
// 量化 serial vs parallel 在不同文件大小下的差异，帮助决定 PARALLEL_THRESHOLD 合理值。
// 跑法: cargo test --release --test perf_threshold -- --nocapture --include-ignored
#[cfg(test)]
mod tests {
    use dec_cryptor::decryptor::decrypt_with_mode;
    use dec_cryptor::encryptor::encrypt_with_mode;
    use std::time::Instant;
    use tempfile::NamedTempFile;

    fn measure(label: &str, data: &[u8]) {
        let password = "Password123!";
        let mut input = NamedTempFile::new().unwrap();
        std::io::Write::write_all(input.as_file_mut(), data).unwrap();
        let in_path = input.path().to_str().unwrap().to_string();

        let enc_file = NamedTempFile::new().unwrap();
        let enc_path = enc_file.path().to_str().unwrap().to_string();

        let dec_file = NamedTempFile::new().unwrap();
        let dec_path = dec_file.path().to_str().unwrap().to_string();

        let t0 = Instant::now();
        encrypt_with_mode(&in_path, &enc_path, password).unwrap();
        let enc_ms = t0.elapsed().as_secs_f64() * 1000.0;

        let t1 = Instant::now();
        decrypt_with_mode(&enc_path, &dec_path, password).unwrap();
        let dec_ms = t1.elapsed().as_secs_f64() * 1000.0;

        // 验证 roundtrip 正确
        let decrypted = std::fs::read(&dec_path).unwrap();
        assert_eq!(data.len(), decrypted.len(), "{}: size mismatch", label);
        assert_eq!(data, &decrypted[..], "{}: content mismatch", label);

        println!(
            "[{:<8}]  size={:>7} B  enc={:>7.1} ms  dec={:>7.1} ms  total={:>7.1} ms",
            label,
            data.len(),
            enc_ms,
            dec_ms,
            enc_ms + dec_ms
        );
    }

    #[test]
    #[ignore = "performance probe"]
    fn probe_threshold_sizes() {
        // 覆盖从远低于到远高于当前阈值 (16 KiB) 的范围
        let sizes: &[(&str, usize)] = &[
            ("1KiB",     1024),
            ("8KiB",     8 * 1024),
            ("16KiB",   16 * 1024),    // 当前阈值
            ("64KiB",   64 * 1024),
            ("256KiB", 256 * 1024),
            ("1MiB",    1024 * 1024),  // = CHUNK_SIZE
            ("4MiB",    4 * 1024 * 1024),
            ("16MiB",  16 * 1024 * 1024),
            ("64MiB",  64 * 1024 * 1024),
            ("128MiB",128 * 1024 * 1024),
            ("256MiB",256 * 1024 * 1024),
            ("500MiB",500 * 1024 * 1024),
        ];
        for (label, size) in sizes {
            // 用伪随机填充避免压缩
            let data: Vec<u8> = (0..*size).map(|i| (i % 251) as u8).collect();
            measure(label, &data);
        }
    }
}
