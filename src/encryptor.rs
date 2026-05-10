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

/// 加密单个数据块
fn encrypt_chunk(cipher: &Aes256Gcm, iv: &[u8], chunk_index: u64, data: &[u8]) 
    -> Result<Vec<u8>, String> {
    let nonce = generate_nonce_for_chunk(iv, chunk_index);
    cipher.encrypt(&nonce, data)
        .map_err(|e| format!("Encryption failed: {}", e))
}

/// 并行加密大文件
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

    // 读取所有块
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 { break; }
        
        let data = buffer[..bytes_read].to_vec();
        all_chunks.push((chunk_index, data));
        chunk_index += 1;
    }

    // 并行加密所有块
    let encrypted_chunks: Result<Vec<(u64, Vec<u8>)>, String> = all_chunks
        .into_par_iter()
        .map(|(idx, data)| {
            encrypt_chunk(cipher, iv, idx, &data)
                .map(|ciphertext| (idx, ciphertext))
        })
        .collect();

    // 按顺序写入结果
    for (idx, ciphertext) in encrypted_chunks? {
        writer.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
        writer.write_all(&ciphertext)?;
        update_progress(((idx + 1) * CHUNK_SIZE as u64).min(file_size), file_size);
    }

    Ok(())
}

/// 串行加密小文件
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

fn read_stdin_with_progress() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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

pub fn encrypt_with_mode(input_file_path: &str, output_file_path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    reset_progress();
    let salt = generate_salt();
    let iv = generate_iv();
    let encryption_key = key_derivation::derive_key(password.as_bytes(), &salt)?;

    let mut writer: Box<dyn Write> = if output_file_path == "-" {
        Box::new(BufWriter::with_capacity(BUFFER_SIZE, std::io::stdout()))
    } else {
        let output_path = Path::new(output_file_path);
        Box::new(BufWriter::with_capacity(BUFFER_SIZE, File::create(output_path)?))
    };

    // 写入文件头
    writer.write_all(MAGIC_NUMBER.as_bytes())?;
    writer.write_all(&[VERSION_SIGN])?;
    writer.write_all(&salt)?;
    writer.write_all(&iv)?;
    writer.write_all(&(CHUNK_SIZE as u32).to_le_bytes())?;

    let (mut reader, file_size): (Box<dyn Read>, u64) = if input_file_path == "-" {
        let input = read_stdin_with_progress()?;
        let size = input.len() as u64;
        reset_progress();
        (Box::new(BufReader::with_capacity(BUFFER_SIZE, Cursor::new(input))), size)
    } else {
        let input_path = Path::new(input_file_path);
        let file = File::open(input_path)?;
        let file_size = input_path.metadata()?.len();
        (Box::new(BufReader::with_capacity(BUFFER_SIZE, file)), file_size)
    };

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&encryption_key));

    // 根据文件大小选择并行或串行模式
    if file_size > PARALLEL_THRESHOLD as u64 {
        encrypt_parallel(&mut reader, &mut writer, &cipher, &iv, file_size)?;
    } else {
        encrypt_serial(&mut reader, &mut writer, &cipher, &iv, file_size)?;
    }

    writer.flush()?;
    Ok(())
}
