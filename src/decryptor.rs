use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::Path;
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use generic_array::GenericArray;
use rayon::prelude::*;
use tempfile::NamedTempFile;
use crate::crypto_utils::*;
use crate::progress_utils::*;
use crate::key_derivation;

/// 解密单个数据块
fn decrypt_chunk(cipher: &Aes256Gcm, iv: &[u8], chunk_index: u64, ciphertext: &[u8]) 
    -> Result<Vec<u8>, String> {
    let nonce = generate_nonce_for_chunk(iv, chunk_index);
    cipher.decrypt(&nonce, ciphertext)
        .map_err(|e| format!("Block #{} decryption failed (wrong password?): {}", chunk_index, e))
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
    file: &mut dyn Read,
    output_file: &mut dyn Write,
    cipher: &Aes256Gcm,
    iv: &[u8],
    encrypted_size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut all_chunks: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut chunk_index: u64 = 0;
    let mut encrypted_read: u64 = 0;

    // 读取所有块
    while encrypted_read < encrypted_size {
        let mut len_buf = [0u8; 4];
        if file.read_exact(&mut len_buf).is_err() { break; }
        let block_len = u32::from_le_bytes(len_buf) as usize;

        let mut ciphertext = vec![0u8; block_len];
        file.read_exact(&mut ciphertext)?;

        all_chunks.push((chunk_index, ciphertext));
        encrypted_read += 4 + block_len as u64;
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
        update_progress((i as u64 + 1) * CHUNK_SIZE as u64, encrypted_size.min(total_chunks * CHUNK_SIZE as u64));
    }

    Ok(())
}

/// 串行解密小文件
fn decrypt_serial(
    file: &mut dyn Read,
    output_file: &mut dyn Write,
    cipher: &Aes256Gcm,
    iv: &[u8],
    encrypted_size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut chunk_index: u64 = 0;
    let mut encrypted_read: u64 = 0;

    while encrypted_read < encrypted_size {
        let mut len_buf = [0u8; 4];
        if file.read_exact(&mut len_buf).is_err() { break; }
        let block_len = u32::from_le_bytes(len_buf) as usize;

        let mut ciphertext = vec![0u8; block_len];
        file.read_exact(&mut ciphertext)?;

        let plaintext = decrypt_chunk(cipher, iv, chunk_index, &ciphertext)?;
        output_file.write_all(&plaintext)?;

        encrypted_read += 4 + block_len as u64;
        chunk_index += 1;
        update_progress(encrypted_read, encrypted_size);
    }

    Ok(())
}

fn read_stdin_to_temp_with_progress() -> Result<(NamedTempFile, u64), Box<dyn std::error::Error>> {
    let mut temp = NamedTempFile::new()?;
    let mut stdin = std::io::stdin();
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut total_read = 0u64;

    loop {
        let bytes_read = stdin.read(&mut buffer)?;
        if bytes_read == 0 { break; }

        temp.write_all(&buffer[..bytes_read])?;
        total_read += bytes_read as u64;
        update_stream_progress(total_read);
    }

    temp.as_file_mut().flush()?;
    clear_progress_line();
    Ok((temp, total_read))
}

pub fn decrypt_with_mode(input_file_path: &str, output_path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    reset_progress();
    let mut stdin_temp_file: Option<NamedTempFile> = None;
    let (mut file, file_size): (Box<dyn Read>, u64) = if input_file_path == "-" {
        let (temp, copied) = read_stdin_to_temp_with_progress()?;
        let reopened = temp.reopen()?;
        stdin_temp_file = Some(temp);
        reset_progress();
        (Box::new(BufReader::with_capacity(BUFFER_SIZE, reopened)), copied)
    } else {
        let input_path = Path::new(input_file_path);
        let file = File::open(input_path)?;
        let file_size = input_path.metadata()?.len();
        (Box::new(BufReader::with_capacity(BUFFER_SIZE, file)), file_size)
    };

    // 1. 解析 Header
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    if magic != MAGIC_NUMBER.as_bytes() {
        return Err("Invalid encrypted file format".into());
    }

    let mut version = [0u8; 1];
    file.read_exact(&mut version)?;
    if version[0] != VERSION_SIGN {
        return Err(format!("Unsupported file version: {}", version[0]).into());
    }

    let mut salt = [0u8; SALT_LENGTH];
    file.read_exact(&mut salt)?;
    let mut iv = [0u8; IV_LENGTH];
    file.read_exact(&mut iv)?;

    let mut cs_buf = [0u8; 4];
    file.read_exact(&mut cs_buf)?;
    let _chunk_size = u32::from_le_bytes(cs_buf) as usize;

    let encryption_key = key_derivation::derive_key(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&encryption_key));

    let mut writer: Box<dyn Write> = if output_path == "-" {
        Box::new(BufWriter::with_capacity(BUFFER_SIZE, std::io::stdout()))
    } else {
        Box::new(BufWriter::with_capacity(BUFFER_SIZE, File::create(output_path)?))
    };
    let encrypted_size = file_size.saturating_sub((MAGIC_NUMBER.len() + 1 + SALT_LENGTH + IV_LENGTH + 4) as u64);
    if encrypted_size == 0 {
        return Err("Invalid encrypted file format".into());
    }

    // 根据文件大小选择并行或串行模式
    if encrypted_size > PARALLEL_THRESHOLD as u64 {
        decrypt_parallel(&mut file, &mut writer, &cipher, &iv, encrypted_size)?;
    } else {
        decrypt_serial(&mut file, &mut writer, &cipher, &iv, encrypted_size)?;
    }

    writer.flush()?;
    drop(stdin_temp_file);
    Ok(())
}
