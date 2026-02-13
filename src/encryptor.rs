use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::Path;
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use generic_array::GenericArray;
use crate::crypto_utils::*;
use crate::progress_utils::*;
use crate::key_derivation;

pub fn encrypt_with_mode(input_file_path: &str, output_file_path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let input_path = Path::new(input_file_path);
    let output_path = Path::new(output_file_path);

    let start_time = std::time::Instant::now();
    let salt = generate_salt();
    let iv = generate_iv();
    let encryption_key = key_derivation::derive_key(password.as_bytes(), &salt)?;

    let mut output_file = File::create(output_path)?;
    let mut writer = BufWriter::with_capacity(BUFFER_SIZE, &mut output_file);

    // 写入文件头
    writer.write_all(MAGIC_NUMBER.as_bytes())?;
    writer.write_all(&[VERSION_SIGN])?;
    writer.write_all(&salt)?;
    writer.write_all(&iv)?;

    // 使用常量或从 Cell 获取
    let current_chunk_size = CHUNK_SIZE.load(std::sync::atomic::Ordering::Relaxed);
    writer.write_all(&(current_chunk_size as u32).to_le_bytes())?;

    let file = File::open(input_path)?;
    let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
    let file_size = input_path.metadata()?.len();

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&encryption_key));

    let mut buffer = vec![0u8; current_chunk_size];
    let mut total_read: u64 = 0;
    let mut chunk_index: u64 = 0;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 { break; }

        let data = &buffer[..bytes_read];
        let nonce = generate_nonce_for_chunk(&iv, chunk_index);

        // 加密并附加 Tag
        let ciphertext = cipher.encrypt(&nonce, data)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        writer.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
        writer.write_all(&ciphertext)?;

        total_read += bytes_read as u64;
        chunk_index += 1;
        update_progress(total_read, file_size);
    }

    writer.flush()?;
    println!("\u{001B}[0mENC!: Done in {:?}", start_time.elapsed());
    Ok(())
}

