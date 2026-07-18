use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter, Cursor};
use std::path::Path;
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use generic_array::GenericArray;
use rayon::prelude::*;
use crate::crypto_utils::*;
use crate::progress_utils::*;
use crate::key_derivation;

fn encrypt_chunk(cipher: &Aes256Gcm, iv: &[u8], chunk_index: u64, data: &[u8])
    -> Result<Vec<u8>, String> {
    let nonce = generate_nonce_for_chunk(iv, chunk_index);
    cipher.encrypt(&nonce, data)
        .map_err(|e| format!("Encryption failed: {}", e))
}

fn encrypt_parallel(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    cipher: &Aes256Gcm,
    iv: &[u8],
    file_size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut all_chunks: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut chunk_index: u64 = 0;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 { break; }

        let data = buffer[..bytes_read].to_vec();
        all_chunks.push((chunk_index, data));
        chunk_index += 1;
    }

    let encrypted_chunks: Result<Vec<(u64, Vec<u8>)>, String> = all_chunks
        .into_par_iter()
        .map(|(idx, data)| {
            encrypt_chunk(cipher, iv, idx, &data)
                .map(|ciphertext| (idx, ciphertext))
        })
        .collect();

    for (idx, ciphertext) in encrypted_chunks? {
        writer.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
        writer.write_all(&ciphertext)?;
        update_progress(((idx + 1) * CHUNK_SIZE as u64).min(file_size), file_size);
    }

    Ok(())
}

fn encrypt_serial(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    cipher: &Aes256Gcm,
    iv: &[u8],
    file_size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut total_read: u64 = 0;
    let mut chunk_index: u64 = 0;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 { break; }

        let data = &buffer[..bytes_read];
        let ciphertext = encrypt_chunk(cipher, iv, chunk_index, data)?;

        writer.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
        writer.write_all(&ciphertext)?;

        total_read += bytes_read as u64;
        chunk_index += 1;
        update_progress(total_read, file_size);
    }

    Ok(())
}

/// 基于流的加密核心 —— 根据数据量自动选择并行/串行模式
pub fn encrypt_stream(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    cipher: &Aes256Gcm,
    iv: &[u8],
    file_size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    if file_size > PARALLEL_THRESHOLD as u64 {
        encrypt_parallel(reader, writer, cipher, iv, file_size)
    } else {
        encrypt_serial(reader, writer, cipher, iv, file_size)
    }
}

fn write_header(writer: &mut dyn Write, salt: &[u8], iv: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    writer.write_all(MAGIC_NUMBER.as_bytes())?;
    writer.write_all(&[VERSION_SIGN])?;
    writer.write_all(salt)?;
    writer.write_all(iv)?;
    writer.write_all(&(CHUNK_SIZE as u32).to_le_bytes())?;
    Ok(())
}

/// 文件加密封装 —— 从文件读取，加密写入文件
pub fn encrypt_file(input_path: &str, output_path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    reset_progress();
    let salt = generate_salt();
    let iv = generate_iv();
    let encryption_key = key_derivation::derive_key(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&encryption_key));

    let src = Path::new(input_path);
    let file = File::open(src)?;
    let file_size = src.metadata()?.len();
    let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);

    let mut writer = BufWriter::with_capacity(BUFFER_SIZE, File::create(Path::new(output_path))?);

    write_header(&mut writer, &salt, &iv)?;
    encrypt_stream(&mut reader, &mut writer, &cipher, &iv, file_size)?;
    writer.flush()?;
    Ok(())
}

fn read_stdin_all() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    let mut stdin = std::io::stdin();
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut total_read = 0u64;

    loop {
        let bytes_read = stdin.read(&mut buffer)?;
        if bytes_read == 0 { break; }

        input.extend_from_slice(&buffer[..bytes_read]);
        total_read += bytes_read as u64;
        update_stream_progress(total_read);
    }

    clear_progress_line();
    Ok(input)
}

/// 标准输入→标准输出加密封装
pub fn encrypt_stdin_to_stdout(password: &str) -> Result<(), Box<dyn std::error::Error>> {
    reset_progress();
    let input = read_stdin_all()?;
    let file_size = input.len() as u64;

    let salt = generate_salt();
    let iv = generate_iv();
    let encryption_key = key_derivation::derive_key(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&encryption_key));

    let mut reader = BufReader::with_capacity(BUFFER_SIZE, Cursor::new(input));
    let mut writer = BufWriter::with_capacity(BUFFER_SIZE, std::io::stdout());

    write_header(&mut writer, &salt, &iv)?;
    encrypt_stream(&mut reader, &mut writer, &cipher, &iv, file_size)?;
    writer.flush()?;
    Ok(())
}

/// 统一入口 —— 根据输入输出路径自动路由
pub fn encrypt_with_mode(input_path: &str, output_path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    if input_path == "-" {
        return encrypt_stdin_to_stdout(password);
    }
    if output_path == "-" {
        reset_progress();
        let salt = generate_salt();
        let iv = generate_iv();
        let encryption_key = key_derivation::derive_key(password.as_bytes(), &salt)?;
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&encryption_key));

        let src = Path::new(input_path);
        let file = File::open(src)?;
        let file_size = src.metadata()?.len();
        let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
        let mut writer = BufWriter::with_capacity(BUFFER_SIZE, std::io::stdout());

        write_header(&mut writer, &salt, &iv)?;
        encrypt_stream(&mut reader, &mut writer, &cipher, &iv, file_size)?;
        writer.flush()?;
        return Ok(());
    }
    encrypt_file(input_path, output_path, password)
}
