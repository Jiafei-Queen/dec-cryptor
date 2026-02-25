use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter, Seek, SeekFrom};
use std::path::Path;
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use generic_array::GenericArray;
use rayon::prelude::*;
use crate::crypto_utils::*;
use crate::progress_utils::*;
use crate::key_derivation;

/// 解密单个数据块
fn decrypt_chunk(cipher: &Aes256Gcm, iv: &[u8], chunk_index: u64, ciphertext: &[u8]) 
    -> Result<Vec<u8>, String> {
    let nonce = generate_nonce_for_chunk(iv, chunk_index);
    cipher.decrypt(&nonce, ciphertext)
        .map_err(|e| format!("Block {} decryption failed (wrong password?): {}", chunk_index, e))
}

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

/// 并行解密大文件
fn decrypt_parallel(
    file: &mut BufReader<File>,
    output_file: &mut BufWriter<&mut File>,
    cipher: &Aes256Gcm,
    iv: &[u8],
    file_size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut all_chunks: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut chunk_index: u64 = 0;
    let mut current_pos = file.stream_position()?;

    // 读取所有块
    while current_pos < file_size {
        let mut len_buf = [0u8; 4];
        if file.read_exact(&mut len_buf).is_err() { break; }
        let block_len = u32::from_le_bytes(len_buf) as usize;

        let mut ciphertext = vec![0u8; block_len];
        file.read_exact(&mut ciphertext)?;

        all_chunks.push((chunk_index, ciphertext));
        current_pos += 4 + block_len as u64;
        chunk_index += 1;
    }

    // 并行解密所有块
    let results: Result<Vec<(u64, Vec<u8>)>, String> = all_chunks
        .into_par_iter()
        .map(|(idx, data)| {
            decrypt_chunk(cipher, iv, idx, &data)
                .map(|plaintext| (idx, plaintext))
        })
        .collect();

    // 按顺序写入结果（保持原始顺序）
    let mut sorted_results = results?;
    sorted_results.sort_by_key(|(idx, _)| *idx);
    
    let total_chunks = sorted_results.len() as u64;
    for (i, (_idx, plaintext)) in sorted_results.into_iter().enumerate() {
        output_file.write_all(&plaintext)?;
        update_progress((i as u64 + 1) * CHUNK_SIZE as u64, file_size.min(total_chunks * CHUNK_SIZE as u64));
    }

    Ok(())
}

/// 串行解密小文件
fn decrypt_serial(
    file: &mut BufReader<File>,
    output_file: &mut BufWriter<&mut File>,
    cipher: &Aes256Gcm,
    iv: &[u8],
    file_size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut chunk_index: u64 = 0;
    let mut current_pos = file.stream_position()?;

    while current_pos < file_size {
        let mut len_buf = [0u8; 4];
        if file.read_exact(&mut len_buf).is_err() { break; }
        let block_len = u32::from_le_bytes(len_buf) as usize;

        let mut ciphertext = vec![0u8; block_len];
        file.read_exact(&mut ciphertext)?;

        let plaintext = decrypt_chunk(cipher, iv, chunk_index, &ciphertext)?;
        output_file.write_all(&plaintext)?;

        current_pos += 4 + block_len as u64;
        chunk_index += 1;
        update_progress(current_pos, file_size);
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
    let _chunk_size = u32::from_le_bytes(cs_buf) as usize;

    let encryption_key = key_derivation::derive_key(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&encryption_key));

    let mut output_file = File::create(output_path)?;
    let mut writer = BufWriter::with_capacity(BUFFER_SIZE, &mut output_file);
    let file_size = input_path.metadata()?.len();

    // 根据文件大小选择并行或串行模式
    if file_size > PARALLEL_THRESHOLD as u64 {
        decrypt_parallel(&mut file, &mut writer, &cipher, &iv, file_size)?;
    } else {
        decrypt_serial(&mut file, &mut writer, &cipher, &iv, file_size)?;
    }

    writer.flush()?;
    println!("\u{001B}[0mDEC!: Done in {:?}", start_time.elapsed());
    Ok(())
}
