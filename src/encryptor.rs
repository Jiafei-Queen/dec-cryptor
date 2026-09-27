use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor, Read, Write};
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;

use crate::crypto_utils::*;
use crate::progress_utils::*;
use crate::key_derivation;

/// 流水线每个阶段的在途 chunk 数量。
/// 内存峰值 ≈ 3 × (PIPELINE_DEPTH + 1) × CHUNK_SIZE ≈ 51 MiB（K=16, chunk=1 MiB），
/// 与文件大小无关 —— 这是相对于原 "读全文件再并行" 方案的核心改进。
const PIPELINE_DEPTH: usize = 16;

fn encrypt_chunk(cipher: &Aes256Gcm, iv: &[u8], chunk_index: u64, data: &[u8])
    -> Result<Vec<u8>, String> {
    let nonce = generate_nonce_for_chunk(iv, chunk_index);
    cipher.encrypt(&nonce, data)
        .map_err(|e| format!("Encryption failed: {}", e))
}

fn encrypt_serial<R, W>(
    mut reader: R,
    mut writer: W,
    cipher: &Aes256Gcm,
    iv: &[u8],
    file_size: u64,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: Read,
    W: Write,
{
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

    let _ = writer.flush();
    finish_progress_line();
    Ok(())
}

/// 有界三阶段流水线：
///
/// ```text
///   Reader thread ── in_channel ──► Encryptor thread ── out_channel ──► Writer thread
/// ```
///
/// - 每个 channel 容量受限 → 天然背压，避免任一阶段堆积无界内存。
/// - Writer 端维护 `BTreeMap<u64, _>` 窗口，保证输出按 idx 严格递增
///   （解密端才能正确解析每块的长度前缀）。
/// - 错误通过共享 `Arc<Mutex<Option<String>>>` 传播；取消通过 channel close
///   自然传递，保证 writer 在退出前一定把 out_channel 里的所有 chunk 都消费掉。
/// - 三个 thread 启动后主线程 `join` 等待；任一阶段出错都会让其他阶段通过
///   channel close 提前退出。
///
/// 内存峰值与文件大小**无关**：`3 × (PIPELINE_DEPTH + 1) × CHUNK_SIZE`。
fn encrypt_parallel<R, W>(
    mut reader: R,
    mut writer: W,
    cipher: Arc<Aes256Gcm>,
    iv: Arc<Vec<u8>>,
    file_size: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    type Item = (u64, Vec<u8>);

    let (in_tx, in_rx) = mpsc::sync_channel::<Item>(PIPELINE_DEPTH);
    let (out_tx, out_rx) = mpsc::sync_channel::<Item>(PIPELINE_DEPTH);

    // 取消通过 channel close 自然传递：reader 完成 → drop in_tx → encryptor
    // 收到 Err → drop out_tx → writer 收到 Err。这样保证 writer 在 break 前
    // 已经把 out_channel 里的所有 chunk 都消费掉，**不丢任何数据**。
    let error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    // ── Reader thread ──
    let err_r = Arc::clone(&error);
    let reader_handle = thread::spawn(move || {
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut idx: u64 = 0;
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = buffer[..n].to_vec();
                    if in_tx.send((idx, chunk)).is_err() { break; }
                    idx += 1;
                }
                Err(e) => {
                    *err_r.lock().unwrap() = Some(e.to_string());
                    break;
                }
            }
        }
        drop(in_tx); // 关闭 in_channel，触发 encryptor 退出
    });

    // ── Encryptor thread ──
    // 单 worker —— `std::sync::mpsc::Receiver` 不可克隆、不支持多消费者；
    // 若需要多 worker 加密请改用 crossbeam-channel（trade-off：多一个依赖）。
    let err_e = Arc::clone(&error);
    let encryptor_handle = thread::spawn(move || {
        // 通过 in_rx.recv() 返回 Err 自然退出（reader drop in_tx 后）
        while let Ok((idx, plaintext)) = in_rx.recv() {
            match encrypt_chunk(&cipher, &iv, idx, &plaintext) {
                Ok(ciphertext) => {
                    if out_tx.send((idx, ciphertext)).is_err() {
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
        drop(out_tx); // 关闭 out_channel，触发 writer 退出
    });

    // ── Writer thread ──
    let err_w = Arc::clone(&error);
    let writer_handle = thread::spawn(move || {
        let mut next_idx: u64 = 0;
        let mut window: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut total_written: u64 = 0;
        let mut write_failed = false;

        // 通过 out_rx.recv() 返回 Err 自然退出（encryptor drop out_tx 后）
        // —— 这保证 out_channel 中的所有 chunk 都被消费完毕，**不丢任何数据**。
        while let Ok((idx, ciphertext)) = out_rx.recv() {
            window.insert(idx, ciphertext);
            // 连续段立即 flush（乱序到达时窗口里只会有少数几个 idx）
            while let Some(ct) = window.remove(&next_idx) {
                let len_bytes = (ct.len() as u32).to_le_bytes();
                if writer.write_all(&len_bytes).is_err()
                    || writer.write_all(&ct).is_err()
                {
                    *err_w.lock().unwrap() = Some("write failed".into());
                    write_failed = true;
                    break;
                }
                total_written += 4 + ct.len() as u64;
                update_progress(total_written.min(file_size), file_size);
                next_idx += 1;
            }
            if write_failed { break; }
        }
        let _ = writer.flush();
        finish_progress_line();
    });

    reader_handle.join().unwrap();
    encryptor_handle.join().unwrap();
    writer_handle.join().unwrap();

    if let Some(e) = error.lock().unwrap().take() {
        return Err(e.into());
    }
    Ok(())
}

/// 基于流的加密核心 —— 根据数据量自动选择并行/串行模式。
///
/// 并行模式现在通过有界流水线实现，**内存峰值与文件大小无关**；
/// 因此阈值保留低值，以便中等文件也能享受流水线（read/compute/write 三阶段并行）收益。
///
/// 边界 `R/W: Read/Write + Send + 'static`：流水线阶段需要把 reader/writer
/// move 进独立线程，因此 caller 必须传 owned reader/writer（如 `BufReader<File>`、
/// `BufWriter<File>`、`BufWriter<Stdout>` 等），不能传 `&mut dyn Read`。
pub fn encrypt_stream<R, W>(
    reader: R,
    writer: W,
    cipher: &Aes256Gcm,
    iv: &[u8],
    file_size: u64,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    if file_size > PARALLEL_THRESHOLD as u64 {
        // 流水线阶段要求 owned + Send + 'static，故把 cipher/iv 升级到 Arc
        encrypt_parallel(
            reader,
            writer,
            Arc::new(cipher.clone()),
            Arc::new(iv.to_vec()),
            file_size,
        )
        .map_err(|e| -> Box<dyn std::error::Error> { e })
    } else {
        encrypt_serial(reader, writer, cipher, iv, file_size)
    }
}

/// 构造文件头 37 字节：`"DEC!"` + version + salt(16) + iv(12) + chunk_size(4, LE)
fn build_header(salt: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_SIZE);
    header.extend_from_slice(MAGIC_NUMBER.as_bytes());
    header.push(VERSION_SIGN);
    header.extend_from_slice(salt);
    header.extend_from_slice(iv);
    header.extend_from_slice(&(CHUNK_SIZE as u32).to_le_bytes());
    header
}

/// 文件加密封装 —— 从文件读取，加密写入文件
pub fn encrypt_file(input_path: &str, output_path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    reset_progress();
    let salt = generate_salt();
    let iv = generate_iv();
    let encryption_key = key_derivation::derive_key(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&encryption_key)?;

    let src = Path::new(input_path);
    let file = File::open(src)?;
    let file_size = src.metadata()?.len();

    let mut output_file = File::create(Path::new(output_path))?;
    output_file.write_all(&build_header(&salt, &iv))?;

    let reader = BufReader::with_capacity(BUFFER_SIZE, file);
    let writer = BufWriter::with_capacity(BUFFER_SIZE, output_file);
    encrypt_stream(reader, writer, &cipher, &iv, file_size)?;
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
    let cipher = Aes256Gcm::new_from_slice(&encryption_key)?;

    let mut stdout = std::io::stdout();
    stdout.write_all(&build_header(&salt, &iv))?;
    stdout.flush()?;

    let reader = BufReader::with_capacity(BUFFER_SIZE, Cursor::new(input));
    let writer = BufWriter::with_capacity(BUFFER_SIZE, stdout);
    encrypt_stream(reader, writer, &cipher, &iv, file_size)?;
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
        let cipher = Aes256Gcm::new_from_slice(&encryption_key)?;

        let src = Path::new(input_path);
        let file = File::open(src)?;
        let file_size = src.metadata()?.len();

        let mut stdout = std::io::stdout();
        stdout.write_all(&build_header(&salt, &iv))?;
        stdout.flush()?;

        let reader = BufReader::with_capacity(BUFFER_SIZE, file);
        let writer = BufWriter::with_capacity(BUFFER_SIZE, stdout);
        encrypt_stream(reader, writer, &cipher, &iv, file_size)?;
        return Ok(());
    }
    encrypt_file(input_path, output_path, password)
}