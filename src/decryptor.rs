use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::Path;
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use rayon::prelude::*;
use tempfile::NamedTempFile;
use crate::crypto_utils::*;
use crate::progress_utils::*;
use crate::key_derivation;

fn decrypt_chunk(cipher: &Aes256Gcm, iv: &[u8], chunk_index: u64, ciphertext: &[u8])
    -> Result<Vec<u8>, String> {
    let nonce = generate_nonce_for_chunk(iv, chunk_index);
    cipher.decrypt(&nonce, ciphertext)
        .map_err(|e| format!("Block #{} decryption failed (wrong password?): {}", chunk_index, e))
}

fn decrypt_parallel(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    cipher: &Aes256Gcm,
    iv: &[u8],
    encrypted_size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut all_chunks: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut chunk_index: u64 = 0;
    let mut encrypted_read: u64 = 0;

    while encrypted_read < encrypted_size {
        let mut len_buf = [0u8; 4];
        if reader.read_exact(&mut len_buf).is_err() { break; }
        let block_len = u32::from_le_bytes(len_buf) as usize;

        let mut ciphertext = vec![0u8; block_len];
        reader.read_exact(&mut ciphertext)?;

        all_chunks.push((chunk_index, ciphertext));
        encrypted_read += 4 + block_len as u64;
        chunk_index += 1;
    }

    let results: Result<Vec<(u64, Vec<u8>)>, String> = all_chunks
        .into_par_iter()
        .map(|(idx, data)| {
            decrypt_chunk(cipher, iv, idx, &data)
                .map(|plaintext| (idx, plaintext))
        })
        .collect();

    let mut sorted_results = results?;
    sorted_results.sort_by_key(|(idx, _)| *idx);

    let total_chunks = sorted_results.len() as u64;
    for (i, (_idx, plaintext)) in sorted_results.into_iter().enumerate() {
        writer.write_all(&plaintext)?;
        update_progress((i as u64 + 1) * CHUNK_SIZE as u64, encrypted_size.min(total_chunks * CHUNK_SIZE as u64));
    }

    Ok(())
}

fn decrypt_serial(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    cipher: &Aes256Gcm,
    iv: &[u8],
    encrypted_size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut chunk_index: u64 = 0;
    let mut encrypted_read: u64 = 0;

    while encrypted_read < encrypted_size {
        let mut len_buf = [0u8; 4];
        if reader.read_exact(&mut len_buf).is_err() { break; }
        let block_len = u32::from_le_bytes(len_buf) as usize;

        let mut ciphertext = vec![0u8; block_len];
        reader.read_exact(&mut ciphertext)?;

        let plaintext = decrypt_chunk(cipher, iv, chunk_index, &ciphertext)?;
        writer.write_all(&plaintext)?;

        encrypted_read += 4 + block_len as u64;
        chunk_index += 1;
        update_progress(encrypted_read, encrypted_size);
    }

    Ok(())
}

/// 基于流的解密核心 —— 根据数据量自动选择并行/串行模式
pub fn decrypt_stream(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    cipher: &Aes256Gcm,
    iv: &[u8],
    encrypted_size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    if encrypted_size > PARALLEL_THRESHOLD as u64 {
        decrypt_parallel(reader, writer, cipher, iv, encrypted_size)
    } else {
        decrypt_serial(reader, writer, cipher, iv, encrypted_size)
    }
}

/// 从任意 Reader 解析加密文件头，返回 (salt, iv, chunk_size)
pub fn parse_header<R: Read>(reader: &mut R) -> Result<(Vec<u8>, Vec<u8>, usize), Box<dyn std::error::Error>> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != MAGIC_NUMBER.as_bytes() {
        return Err("Invalid encrypted file format".into());
    }

    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;
    if version[0] != VERSION_SIGN {
        return Err(format!("Unsupported file version: {}", version[0]).into());
    }

    let mut salt = vec![0u8; SALT_LENGTH];
    reader.read_exact(&mut salt)?;
    let mut iv = vec![0u8; IV_LENGTH];
    reader.read_exact(&mut iv)?;

    let mut cs_buf = [0u8; 4];
    reader.read_exact(&mut cs_buf)?;
    let chunk_size = u32::from_le_bytes(cs_buf) as usize;

    Ok((salt, iv, chunk_size))
}

/// 检查文件版本（快速验证，无需完整解密）
pub fn check_version(input_file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(Path::new(input_file_path))?;
    parse_header(&mut file)?;
    Ok(())
}

/// 文件解密封装 —— 从加密文件读取，解密写入文件
pub fn decrypt_file(input_path: &str, output_path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    reset_progress();
    let src = Path::new(input_path);
    let file = File::open(src)?;
    let file_size = src.metadata()?.len();
    let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);

    let (salt, iv, _chunk_size) = parse_header(&mut reader)?;
    let encryption_key = key_derivation::derive_key(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&encryption_key)?;

    let encrypted_size = file_size.saturating_sub(HEADER_SIZE as u64);
    if encrypted_size == 0 {
        return Err("Invalid encrypted file format".into());
    }

    let mut writer = BufWriter::with_capacity(BUFFER_SIZE, File::create(Path::new(output_path))?);

    decrypt_stream(&mut reader, &mut writer, &cipher, &iv, encrypted_size)?;
    writer.flush()?;
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

/// 标准输入→标准输出解密封装
pub fn decrypt_stdin_to_stdout(password: &str) -> Result<(), Box<dyn std::error::Error>> {
    reset_progress();
    let (temp, copied) = read_stdin_to_temp_with_progress()?;
    let file = temp.reopen()?;
    let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);

    let (salt, iv, _chunk_size) = parse_header(&mut reader)?;
    let encryption_key = key_derivation::derive_key(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&encryption_key)?;

    let encrypted_size = copied.saturating_sub(HEADER_SIZE as u64);
    if encrypted_size == 0 {
        return Err("Invalid encrypted file format".into());
    }

    let mut writer = BufWriter::with_capacity(BUFFER_SIZE, std::io::stdout());

    decrypt_stream(&mut reader, &mut writer, &cipher, &iv, encrypted_size)?;
    writer.flush()?;
    drop(temp);
    Ok(())
}

/// 统一入口 —— 根据输入输出路径自动路由
pub fn decrypt_with_mode(input_path: &str, output_path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    if input_path == "-" {
        decrypt_stdin_to_stdout(password)
    } else if output_path == "-" {
        reset_progress();
        let src = Path::new(input_path);
        let file = File::open(src)?;
        let file_size = src.metadata()?.len();
        let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);

        let (salt, iv, _chunk_size) = parse_header(&mut reader)?;
        let encryption_key = key_derivation::derive_key(password.as_bytes(), &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&encryption_key)?;

        let encrypted_size = file_size.saturating_sub(HEADER_SIZE as u64);
        if encrypted_size == 0 {
            return Err("Invalid encrypted file format".into());
        }

        let mut writer = BufWriter::with_capacity(BUFFER_SIZE, std::io::stdout());

        decrypt_stream(&mut reader, &mut writer, &cipher, &iv, encrypted_size)?;
        writer.flush()?;
        Ok(())
    } else {
        decrypt_file(input_path, output_path, password)
    }
}
