use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter, Seek, SeekFrom};
use std::path::Path;
use aes::Aes256;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use crate::crypto_utils::*;
use crate::progress_utils::*;
use crate::key_derivation;
use crate::hmac_validator::HmacValidator;

type Aes256Ctr = Ctr128BE<Aes256>;

pub fn check_version(input_file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let input_path = Path::new(input_file_path);
    
    // 打开文件并读取文件头信息
    let mut file = File::open(input_path)?;
    let mut magic_number_bytes = vec![0u8; MAGIC_NUMBER.len()];
    file.read_exact(&mut magic_number_bytes)?;
    
    // 验证魔数
    if magic_number_bytes != MAGIC_NUMBER.as_bytes() {
        return Err("无效的加密文件格式".into());
    }
    
    // 读取版本字节
    let mut version = [0u8; 1];
    file.read_exact(&mut version)?;
    if version[0] != VERSION_SIGN {
        return Err(format!("不支持的文件版本: {}", version[0]).into());
    }
    
    Ok(())
}

pub fn decrypt_with_mode(input_file_path: &str, output_file_path: &str, password: &str, parts: usize) -> Result<(), Box<dyn std::error::Error>> {
    let input_path = Path::new(input_file_path);
    let output_path = Path::new(output_file_path);
    
    if !input_path.exists() || !input_path.is_file() {
        return Err(format!("输入文件不存在: {}", input_file_path).into());
    }
    
    // 启动计时器
    let start_time = start_timer();
    
    // 读取文件头信息（使用缓冲读）
    let mut file = BufReader::with_capacity(BUFFER_SIZE, File::open(input_path)?);
    
    // 跳过魔数和版本字节
    file.seek(SeekFrom::Start((MAGIC_NUMBER.len() + 1) as u64))?;
    
    // 读取盐和IV
    let mut salt = vec![0u8; SALT_LENGTH];
    file.read_exact(&mut salt)?;
    let mut iv = vec![0u8; IV_LENGTH];
    file.read_exact(&mut iv)?;
    
    println!("DEC!: 正在派生密钥..");
    
    // 使用Argon2派生主密钥
    let master_key = key_derivation::derive_master_key(password.as_bytes(), &salt)?;
    
    // 使用HKDF派生加密密钥和HMAC密钥
    let (encryption_key, hmac_key) = key_derivation::derive_encryption_and_hmac_keys(&master_key)?;
    
    // 计算文件总长度和文件头长度
    let total_file_length = input_path.metadata()?.len();
    let header_length = (MAGIC_NUMBER.len() + 1 + SALT_LENGTH + IV_LENGTH) as u64;
    let hmac_length = 32u64; // HMAC-SHA256的长度
    let encrypted_data_length = total_file_length - header_length - hmac_length;
    
    // 创建输出文件（放大写缓冲）
    let mut output_file = File::create(output_path)?;
    let mut writer = BufWriter::with_capacity(BUFFER_SIZE, &mut output_file);
    
    // parts 模式：仅当 parts==1 时持有单流解密器；否则使用并行处理
    let parallel_parts = match parts { 2 => 2, 4 => 4, 8 => 8, _ => 1 };
    let mut single_cipher = if parallel_parts == 1 {
        Some(Aes256Ctr::new(encryption_key.as_slice().into(), iv.as_slice().into()))
    } else { None };
    
    // 创建HMAC计算器
    let mut hmac = HmacValidator::new(&hmac_key)?;
    
    // 流式解密数据
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut total_read = 0;
    
    while total_read < encrypted_data_length {
        let bytes_to_read = std::cmp::min(BUFFER_SIZE as u64, encrypted_data_length - total_read) as usize;
        let bytes_read = file.read(&mut buffer[..bytes_to_read])?;
        
        if bytes_read == 0 {
            break;
        }
        
        let chunk = &mut buffer[..bytes_read];
        
        // 更新HMAC（对密文计算）
        hmac.update(chunk);

        if parallel_parts == 1 {
            if let Some(cipher) = &mut single_cipher { cipher.apply_keystream(chunk); }
        } else {
            crate::parallel_handler::ctr_apply_in_parts(
                encryption_key.as_slice(),
                iv.as_slice(),
                chunk,
                total_read as usize,
                parallel_parts,
            ).map_err(|e| format!("parallel decrypt error: {}", e))?;
        }
        
        // 写入解密后的数据
        writer.write_all(chunk)?;
        
        total_read += bytes_read as u64;
        
        // 更新进度显示
        update_progress(total_read, encrypted_data_length);
    }
    
    // 读取存储的HMAC
    let mut stored_hmac = vec![0u8; hmac_length as usize];
    file.read_exact(&mut stored_hmac)?;
    
    // 验证HMAC
    hmac.verify(&stored_hmac)?;
    
    writer.flush()?;
    
    // 显示进度完成
    let duration = start_time.elapsed();
    update_progress(encrypted_data_length, encrypted_data_length);
    println!("DEC!: 解密完成，耗时: {}", format_duration(duration));
    
    Ok(())
}
