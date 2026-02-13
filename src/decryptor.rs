use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter, Seek, SeekFrom};
use std::path::Path;
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use generic_array::GenericArray;
use crate::crypto_utils::*;
use crate::progress_utils::*;
use crate::key_derivation;
use rayon::prelude::*;

pub fn check_version(input_file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let input_path = Path::new(input_file_path);

    // 打开文件并读取文件头信息
    let mut file = File::open(input_path)?;
    let mut magic_number_bytes = vec![0u8; MAGIC_NUMBER.len()];
    file.read_exact(&mut magic_number_bytes)?;

    // 验证魔数
    if magic_number_bytes != MAGIC_NUMBER.as_bytes() {
        return Err("Invalid encrypted file format".into());
    }

    // 读取版本字节
    let mut version = [0u8; 1];
    file.read_exact(&mut version)?;
    if version[0] != VERSION_SIGN {
        return Err(format!("Unsupported file version: {}", version[0]).into());
    }

    Ok(())
}

pub fn decrypt_with_mode(input_file_path: &str, output_path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let input_path = Path::new(input_file_path);
    let start_time = std::time::Instant::now();
    let mut file = BufReader::new(File::open(input_path)?);

    // 1. 解析 Header
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    file.seek(SeekFrom::Current(1))?; // Skip version

    let mut salt = [0u8; SALT_LENGTH];
    file.read_exact(&mut salt)?;
    let mut iv = [0u8; IV_LENGTH];
    file.read_exact(&mut iv)?;

    let mut cs_buf = [0u8; 4];
    file.read_exact(&mut cs_buf)?;
    let chunk_size = u32::from_le_bytes(cs_buf) as usize;

    let encryption_key = key_derivation::derive_key(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&encryption_key));

    let mut output_file = BufWriter::with_capacity(BUFFER_SIZE, File::create(output_path)?);
    let file_size = input_path.metadata()?.len();

    let mut chunk_index: u64 = 0;
    let mut current_pos = file.stream_position()?;

    // 分批处理：平衡并行度和内存压力
    while current_pos < file_size {
        let mut batch = Vec::new();
        for _ in 0..64 {
            if current_pos >= file_size { break; }

            let mut len_buf = [0u8; 4];
            if file.read_exact(&mut len_buf).is_err() { break; }
            let block_len = u32::from_le_bytes(len_buf) as usize;

            let mut ciphertext = vec![0u8; block_len];
            file.read_exact(&mut ciphertext)?;

            batch.push((chunk_index, ciphertext));
            current_pos += 4 + block_len as u64;
            chunk_index += 1;
        }

        // 并行解密
        let results: Result<Vec<Vec<u8>>, String> = batch
            .into_par_iter()
            .map(|(idx, data)| {
                let nonce = generate_nonce_for_chunk(&iv, idx);
                cipher.decrypt(&nonce, data.as_slice())
                    .map_err(|e| format!("Block {} decryption failed (wrong password?): {}", idx, e))
            })
            .collect();

        // 顺序写入
        for plaintext in results? {
            output_file.write_all(&plaintext)?;
        }
        update_progress(current_pos, file_size);
    }

    output_file.flush()?;
    println!("\u{001B}[0mDEC!: Done in {:?}", start_time.elapsed());
    Ok(())
}