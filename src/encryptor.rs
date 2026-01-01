use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::Path;
use aes::Aes256;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use crate::crypto_utils::*;
use crate::progress_utils::*;
use crate::key_derivation;
use crate::hmac_validator::HmacValidator;

type Aes256Ctr = Ctr128BE<Aes256>;

pub fn encrypt_with_mode(input_file_path: &str, output_file_path: &str, password: &str, parts: usize) -> Result<(), Box<dyn std::error::Error>> {
    let input_path = Path::new(input_file_path);
    let output_path = Path::new(output_file_path);
    let buffer_size = std::cmp::max(256 * 1024, (if parts == 0 { 1 } else { parts }) * 2 * 1024 * 1024);

    // 检查输入文件是否存在
    if !input_path.exists() || !input_path.is_file() {
        return Err(format!("输入文件不存在: {}", input_file_path).into());
    }
    
    // 启动计时器
    let start_time = start_timer();
    
    // 生成盐和IV
    let salt = generate_salt();
    let iv = generate_iv();
    
    // 使用Argon2派生主密钥
    let master_key = key_derivation::derive_master_key(password.as_bytes(), &salt)?;
    
    // 使用HKDF派生加密密钥和HMAC密钥
    let (encryption_key, hmac_key) = key_derivation::derive_encryption_and_hmac_keys(&master_key)?;
    
    // 创建输出文件（放大写缓冲）
    let mut output_file = File::create(output_path)?;
    let mut writer = BufWriter::with_capacity(buffer_size, &mut output_file);
    
    // 写入魔数
    writer.write_all(MAGIC_NUMBER.as_bytes())?;
    
    // 写入版本字节
    writer.write_all(&[VERSION_SIGN])?;
    
    // 写入盐
    writer.write_all(&salt)?;
    
    // 写入IV
    writer.write_all(&iv)?;
    
    // 创建HMAC计算器
    let mut hmac = HmacValidator::new(&hmac_key)?;
    
    // 打开输入文件（放大读缓冲）
    let input_file = File::open(input_path)?;
    let mut reader = BufReader::with_capacity(buffer_size, input_file);
    let file_size = input_path.metadata()?.len();
    
    // 流式加密数据
    let mut buffer = vec![0u8; buffer_size];
    let mut total_read: u64 = 0;
    let ap = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let parallel_parts = if parts == 0 { ap.max(1) } else { parts.max(1).min(ap) };

    // 单流加密器（仅在 parts==1 时使用）
    let mut single_cipher = if parallel_parts == 1 {
        Some(Aes256Ctr::new(encryption_key.as_slice().into(), iv.as_slice().into()))
    } else { None };
    
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 { break; }
        let chunk = &mut buffer[..bytes_read];

        if parallel_parts == 1 {
            // 使用CTR模式加密数据
            if let Some(cipher) = &mut single_cipher { cipher.apply_keystream(chunk); }
        } else {
            // 并行处理：根据绝对偏移计算子流位置
            crate::parallel_handler::ctr_apply_in_parts(
                encryption_key.as_slice(),
                iv.as_slice(),
                chunk,
                total_read as usize,
                parallel_parts,
            ).map_err(|e| format!("parallel encrypt error: {}", e))?;
        }

        // 更新HMAC（对密文计算）
        hmac.update(chunk);
        // 写入加密后的数据
        writer.write_all(chunk)?;

        total_read += bytes_read as u64;
        update_progress(total_read, file_size);
    }
    
    // 获取并写入HMAC
    let hmac_code = hmac.finalize();
    writer.write_all(&hmac_code)?;
    writer.flush()?;
    
    // 显示完成状态
    let duration = start_time.elapsed();
    update_progress(file_size, file_size);
    println!("\u{001B}[0mDEC!: 加密完成，耗时: {}", format_duration(duration));
    
    Ok(())
}