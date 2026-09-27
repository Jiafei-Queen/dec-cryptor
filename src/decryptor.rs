use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use tempfile::NamedTempFile;

use crate::crypto_utils::*;
use crate::progress_utils::*;
use crate::key_derivation;

/// 流水线每个阶段的在途 chunk 数量。
/// 内存峰值 ≈ 3 × (PIPELINE_DEPTH + 1) × CHUNK_SIZE ≈ 51 MiB（K=16, chunk=1 MiB），
/// 与文件大小无关 —— 这是相对于原 "读全文件再并行" 方案的核心改进。
const PIPELINE_DEPTH: usize = 16;

fn decrypt_chunk(cipher: &Aes256Gcm, iv: &[u8], chunk_index: u64, ciphertext: &[u8])
    -> Result<Vec<u8>, String> {
    let nonce = generate_nonce_for_chunk(iv, chunk_index);
    cipher.decrypt(&nonce, ciphertext)
        .map_err(|e| format!("Block #{} decryption failed (wrong password?): {}", chunk_index, e))
}

fn decrypt_serial<R, W>(
    mut reader: R,
    mut writer: W,
    cipher: &Aes256Gcm,
    iv: &[u8],
    encrypted_size: u64,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: Read,
    W: Write,
{
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

    let _ = writer.flush();
    finish_progress_line();
    Ok(())
}

/// 有界三阶段流水线：
///
/// ```text
///   Reader thread ── in_channel ──► Decryptor thread ── out_channel ──► Writer thread
/// ```
///
/// - 每个 channel 容量受限 → 天然背压，避免任一阶段堆积无界内存。
/// - Writer 端维护 `BTreeMap<u64, _>` 窗口，保证输出按 idx 严格递增。
/// - 错误 / 取消信号通过共享 `Arc<AtomicBool>` + `Arc<Mutex<Option<String>>>` 传播。
/// - 三个 thread 启动后主线程 `join` 等待；任一阶段出错都会让其他阶段提前退出。
///
/// 内存峰值与文件大小**无关**：`3 × (PIPELINE_DEPTH + 1) × CHUNK_SIZE`。
fn decrypt_parallel<R, W>(
    mut reader: R,
    mut writer: W,
    cipher: Arc<Aes256Gcm>,
    iv: Arc<Vec<u8>>,
    encrypted_size: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    type Item = (u64, Vec<u8>);

    let (in_tx, in_rx) = mpsc::sync_channel::<Item>(PIPELINE_DEPTH);
    let (out_tx, out_rx) = mpsc::sync_channel::<Item>(PIPELINE_DEPTH);

    // 错误通过共享 Muted<Option<String>> 传播。
    // 取消通过 channel close 自然传递：reader 完成 → drop in_tx → decryptor
    // 收到 Err → drop out_tx → writer 收到 Err。这样保证 writer 在 break 前
    // 已经把 out_channel 里的所有 chunk 都消费掉。
    let error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    // ── Reader thread: 读取 [len:4][ciphertext] 帧 ──
    let err_r = Arc::clone(&error);
    let reader_handle = thread::spawn(move || {
        let mut chunk_index: u64 = 0;
        let mut encrypted_read: u64 = 0;
        while encrypted_read < encrypted_size {
            let mut len_buf = [0u8; 4];
            // EOF（剩余不到 4 字节）视为正常流结束
            if reader.read_exact(&mut len_buf).is_err() { break; }
            let block_len = u32::from_le_bytes(len_buf) as usize;
            encrypted_read += 4;

            let mut ciphertext = vec![0u8; block_len];
            if reader.read_exact(&mut ciphertext).is_err() {
                *err_r.lock().unwrap() =
                    Some("unexpected EOF inside ciphertext block".into());
                break;
            }
            encrypted_read += block_len as u64;

            // 阻塞 send；如果下游死了直接退出（错误已被 err_e/d/w 记录）
            if in_tx.send((chunk_index, ciphertext)).is_err() { break; }
            chunk_index += 1;
        }
        drop(in_tx);
    });

    // ── Decryptor thread (单 worker) ──
    let err_e = Arc::clone(&error);
    let decryptor_handle = thread::spawn(move || {
        // 通过 in_rx.recv() 返回 Err 自然退出（reader drop in_tx 后）
        while let Ok((idx, ciphertext)) = in_rx.recv() {
            match decrypt_chunk(&cipher, &iv, idx, &ciphertext) {
                Ok(plaintext) => {
                    if out_tx.send((idx, plaintext)).is_err() {
                        *err_e.lock().unwrap() =
                            Some("downstream closed unexpectedly".into());
                        break;
                    }
                }
                Err(e) => {
                    *err_e.lock().unwrap() = Some(e);
                    break;
                }
            }
        }
        drop(out_tx);
    });

    // ── Writer thread ──
    let err_w = Arc::clone(&error);
    let writer_handle = thread::spawn(move || {
        let mut next_idx: u64 = 0;
        let mut window: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut plaintext_written: u64 = 0;
        let mut write_failed = false;

        // 通过 out_rx.recv() 返回 Err 自然退出（decryptor drop out_tx 后）
        // —— 这保证 out_channel 中的所有 chunk 都被消费完毕，**不丢任何数据**。
        while let Ok((idx, plaintext)) = out_rx.recv() {
            window.insert(idx, plaintext);
            while let Some(pt) = window.remove(&next_idx) {
                if writer.write_all(&pt).is_err() {
                    *err_w.lock().unwrap() = Some("write failed".into());
                    write_failed = true;
                    break;
                }
                plaintext_written += pt.len() as u64;
                // plaintext 总字节 ≈ encrypted_size - 16×chunk_count，
                // 分母用 encrypted_size 让进度条最后自然收敛到 100%。
                update_progress(plaintext_written.min(encrypted_size), encrypted_size);
                next_idx += 1;
            }
            if write_failed { break; }
        }
        let _ = writer.flush();
        finish_progress_line();
    });

    reader_handle.join().unwrap();
    decryptor_handle.join().unwrap();
    writer_handle.join().unwrap();

    if let Some(e) = error.lock().unwrap().take() {
        return Err(e.into());
    }
    Ok(())
}

/// 基于流的解密核心 —— 根据数据量自动选择并行/串行模式。
///
/// 并行模式现在通过有界流水线实现，**内存峰值与文件大小无关**。
///
/// 边界 `R/W: Read/Write + Send + 'static`：流水线阶段需要把 reader/writer
/// move 进独立线程，因此 caller 必须传 owned reader/writer（如 `BufReader<File>`、
/// `BufWriter<File>`、`BufWriter<Stdout>` 等），不能传 `&mut dyn Read`。
pub fn decrypt_stream<R, W>(
    reader: R,
    writer: W,
    cipher: &Aes256Gcm,
    iv: &[u8],
    encrypted_size: u64,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    if encrypted_size > PARALLEL_THRESHOLD as u64 {
        decrypt_parallel(
            reader,
            writer,
            Arc::new(cipher.clone()),
            Arc::new(iv.to_vec()),
            encrypted_size,
        )
        .map_err(|e| -> Box<dyn std::error::Error> { e })
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
    let mut file = File::open(src)?;
    let file_size = src.metadata()?.len();

    let (salt, iv, _chunk_size) = parse_header(&mut file)?;
    let encryption_key = key_derivation::derive_key(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&encryption_key)?;

    let encrypted_size = file_size.saturating_sub(HEADER_SIZE as u64);
    if encrypted_size == 0 {
        return Err("Invalid encrypted file format".into());
    }

    // parse_header 已读完 37 字节，file 当前位置正好是 payload 起点
    let reader = BufReader::with_capacity(BUFFER_SIZE, file);
    let writer = BufWriter::with_capacity(BUFFER_SIZE, File::create(Path::new(output_path))?);
    decrypt_stream(reader, writer, &cipher, &iv, encrypted_size)?;
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
    let mut file = temp.reopen()?;

    let (salt, iv, _chunk_size) = parse_header(&mut file)?;
    let encryption_key = key_derivation::derive_key(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&encryption_key)?;

    let encrypted_size = copied.saturating_sub(HEADER_SIZE as u64);
    if encrypted_size == 0 {
        return Err("Invalid encrypted file format".into());
    }

    let reader = BufReader::with_capacity(BUFFER_SIZE, file);
    let writer = BufWriter::with_capacity(BUFFER_SIZE, std::io::stdout());
    decrypt_stream(reader, writer, &cipher, &iv, encrypted_size)?;
    drop(temp);
    Ok(())
}

/// 统一入口 —— 根据输入输出路径自动路由
pub fn decrypt_with_mode(input_path: &str, output_path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    if input_path == "-" {
        return decrypt_stdin_to_stdout(password);
    }
    if output_path == "-" {
        reset_progress();
        let src = Path::new(input_path);
        let mut file = File::open(src)?;
        let file_size = src.metadata()?.len();

        let (salt, iv, _chunk_size) = parse_header(&mut file)?;
        let encryption_key = key_derivation::derive_key(password.as_bytes(), &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&encryption_key)?;

        let encrypted_size = file_size.saturating_sub(HEADER_SIZE as u64);
        if encrypted_size == 0 {
            return Err("Invalid encrypted file format".into());
        }

        let reader = BufReader::with_capacity(BUFFER_SIZE, file);
        let writer = BufWriter::with_capacity(BUFFER_SIZE, std::io::stdout());
        decrypt_stream(reader, writer, &cipher, &iv, encrypted_size)?;
        return Ok(());
    }
    decrypt_file(input_path, output_path, password)
}