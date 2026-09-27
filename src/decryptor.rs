use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor, IsTerminal, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use parking_lot::Mutex;
use std::sync::Arc;
use std::thread;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use rayon::prelude::*;

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

/// 读入一个 v4 EOF 帧的 tag 部分（长度前缀 `0` 之后的 16 字节）。
fn read_eof_tag<R: Read>(reader: &mut R) -> Result<[u8; GCM_TAG_LENGTH], String> {
    let mut tag = [0u8; GCM_TAG_LENGTH];
    reader.read_exact(&mut tag)
        .map_err(|_| ERR_TRUNCATED_EOF.to_string())?;
    Ok(tag)
}

/// 校验 EOF 帧的 tag：载荷为空，且 nonce 索引与流内位置一致。
///
/// tag 由 `[0u32]` 帧携带、索引绑定位置 —— 前移/复制/搬移标记都会在这里失败。
fn verify_eof_tag(cipher: &Aes256Gcm, iv: &[u8], chunk_count: u64, tag: &[u8])
    -> Result<(), String> {
    cipher
        .decrypt(&generate_nonce_for_chunk(iv, chunk_count), tag)
        .map(|_| ())
        .map_err(|_| ERR_BAD_EOF.to_string())
}

/// EOF 帧之后流必须立刻结束：多出任何字节都说明密文被拼接或篡改。
fn check_no_trailing_bytes<R: Read>(reader: &mut R) -> Result<(), String> {
    let mut probe = [0u8; 1];
    loop {
        match reader.read(&mut probe) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(ERR_TRAILING_DATA.to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
}

const ERR_TRUNCATED_EOF: &str =
    "truncated end-of-stream marker (ciphertext is shorter than its EOF frame)";
const ERR_BAD_EOF: &str =
    "invalid end-of-stream marker (stream truncated, reordered or tampered with)";
const ERR_MISSING_EOF: &str =
    "ciphertext ended without the v4 end-of-stream marker (truncated stream)";
const ERR_TRAILING_DATA: &str = "trailing data after end-of-stream marker";

fn decrypt_serial<R, W>(
    mut reader: R,
    mut writer: W,
    cipher: &Aes256Gcm,
    iv: &[u8],
    encrypted_size: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: Read,
    W: Write,
{
    let mut chunk_index: u64 = 0;
    let mut encrypted_read: u64 = 0;
    let mut saw_eof = false;

    // `Some(n)` 时读到 n 字节为止（按 [len:4][ciphertext] 帧推进）；
    // `None` 时读到 EOF 为止（stdin 流模式）。
    loop {
        if let Some(n) = encrypted_size {
            if encrypted_read >= n { break; }
        }
        let mut len_buf = [0u8; 4];
        if reader.read_exact(&mut len_buf).is_err() { break; }
        let block_len = u32::from_le_bytes(len_buf) as usize;

        // v4：`len == 0` 的帧是 EOF 标记，后跟空载荷的 16 B GCM tag。
        if block_len == 0 {
            let tag = read_eof_tag(&mut reader)?;
            verify_eof_tag(cipher, iv, chunk_index, &tag)?;
            saw_eof = true;
            break;
        }

        let mut ciphertext = vec![0u8; block_len];
        reader.read_exact(&mut ciphertext)?;

        let plaintext = decrypt_chunk(cipher, iv, chunk_index, &ciphertext)?;
        writer.write_all(&plaintext)?;

        if encrypted_size.is_some() {
            encrypted_read += 4 + block_len as u64;
        }
        chunk_index += 1;
        // 进度：file_size == 0（unknown）由 update_progress 内部走 spinner 分支
        update_progress(encrypted_read, encrypted_size.unwrap_or(0));
    }

    if !saw_eof {
        return Err(ERR_MISSING_EOF.into());
    }
    check_no_trailing_bytes(&mut reader)?;

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
/// - 错误 / 取消信号通过共享 `Arc<Mutex<Option<String>>>` 传播；channel close
///   自然传递，保证 writer 退出前把 out_channel 里的所有 chunk 都消费掉。
/// - 三个 thread 启动后主线程 `join` 等待；任一阶段出错都会让其他阶段提前退出。
/// - **v4 完整性**：reader 必须读到 EOF 帧（`len == 0`）才算成功；tag 由解密
///   阶段校验（nonce 索引绑定位置），EOF 帧之后不允许再有字节。三者缺一即报错，
///   因此"尾部按帧边界截断"（v3 下会静默输出残缺明文）不再可能通过。
///
/// `chunk_parallel`：与 `encrypt_parallel` 同义。
/// - `false`（默认，硬件 AES）：单 worker 算 AES。
/// - `true`（软 AES）：批量 + rayon par_iter + 按 idx 排序发送。
///
/// 内存峰值与文件大小**无关**：`3 × (PIPELINE_DEPTH + 1) × CHUNK_SIZE`。
pub(crate) fn decrypt_parallel<R, W>(
    mut reader: R,
    mut writer: W,
    cipher: Arc<Aes256Gcm>,
    iv: Arc<Vec<u8>>,
    encrypted_size: u64,
    chunk_parallel: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    type Item = (u64, Vec<u8>);

    let (in_tx, in_rx) = mpsc::sync_channel::<Item>(PIPELINE_DEPTH);
    let (out_tx, out_rx) = mpsc::sync_channel::<Item>(PIPELINE_DEPTH);

    // 错误通过共享 Mutex<Option<String>> 传播。
    // 取消通过 channel close 自然传递：reader 完成 → drop in_tx → decryptor
    // 收到 Err → drop out_tx → writer 收到 Err。这样保证 writer 在 break 前
    // 已经把 out_channel 里的所有 chunk 都消费掉。
    let error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    // `saw_eof`：reader 是否读到了 v4 EOF 帧。等三个线程 join 之后统一判定，
    // 避免"reader 因下游死亡而提前退出"与"流被截断"互相掩盖。
    let saw_eof = Arc::new(AtomicBool::new(false));

    // ── Reader thread: 读取 [len:4][ciphertext] 帧 ──
    // `encrypted_size == 0` 表示未知长度（stdin 流模式），读到 EOF 帧为止。
    // 已知长度时读满 `encrypted_size` 字节即退出；两种情况下都必须见过 EOF 帧，
    // 否则报"密文被截断"（v4 的核心完整性保证）。
    let err_r = Arc::clone(&error);
    let eof_r = Arc::clone(&saw_eof);
    let reader_handle = thread::spawn(move || {
        let mut chunk_index: u64 = 0;
        let mut encrypted_read: u64 = 0;
        let mut saw_eof = false;
        loop {
            // 已知长度且已读满 → 退出（若没读到 EOF 帧，收尾会报截断）
            if encrypted_size > 0 && encrypted_read >= encrypted_size { break; }

            let mut len_buf = [0u8; 4];
            // 帧边界处的 EOF：可能正常结束，也可能是尾帧被砍掉，收尾统一判定
            if reader.read_exact(&mut len_buf).is_err() { break; }
            let block_len = u32::from_le_bytes(len_buf) as usize;
            if encrypted_size > 0 { encrypted_read += 4; }

            // v4：`len == 0` 的帧是 EOF 标记，后跟空载荷的 16 B GCM tag。
            // tag 交给解密阶段校验（nonce 索引绑定位置）。
            if block_len == 0 {
                match read_eof_tag(&mut reader) {
                    Ok(tag) => {
                        if in_tx.send((chunk_index, tag.to_vec())).is_err() { break; }
                        saw_eof = true;
                        if let Err(e) = check_no_trailing_bytes(&mut reader) {
                            *err_r.lock() = Some(e);
                        }
                    }
                    Err(e) => *err_r.lock() = Some(e),
                }
                break;
            }

            let mut ciphertext = vec![0u8; block_len];
            if reader.read_exact(&mut ciphertext).is_err() {
                *err_r.lock() =
                    Some("unexpected EOF inside ciphertext block".into());
                break;
            }
            if encrypted_size > 0 { encrypted_read += block_len as u64; }

            // 阻塞 send；如果下游死了直接退出（错误已被 err_e/d/w 记录）
            if in_tx.send((chunk_index, ciphertext)).is_err() { break; }
            chunk_index += 1;
        }
        if saw_eof { eof_r.store(true, Ordering::Relaxed); }
        drop(in_tx);
    });

    // ── Decryptor thread ──
    // 单 worker 串行算 AES（chunk_parallel = false）；或
    // 批量并发算 AES（chunk_parallel = true，仅在没有硬件 AES 的机器上）。
    // 与 encrypt_parallel 同形的 batch strategy：积累 BATCH_SIZE 个密文块后
    // 用 rayon 并行解密，再按 idx 排序写回 out_tx。
    const BATCH_SIZE: usize = 8;
    let err_e = Arc::clone(&error);
    let err_e2 = Arc::clone(&error);
    let decryptor_handle = thread::spawn(move || {
        if !chunk_parallel {
            // 单线程路径
            while let Ok((idx, ciphertext)) = in_rx.recv() {
                match decrypt_chunk(&cipher, &iv, idx, &ciphertext) {
                    Ok(plaintext) => {
                        if out_tx.send((idx, plaintext)).is_err() {
                            *err_e.lock() =
                                Some("downstream closed unexpectedly".into());
                            break;
                        }
                    }
                    Err(e) => {
                        *err_e.lock() = Some(e);
                        break;
                    }
                }
            }
        } else {
            // 多线程路径：批量 + rayon par_iter + 按 idx 排序发送
            use std::collections::VecDeque;
            let mut pending: VecDeque<(u64, Vec<u8>)> = VecDeque::with_capacity(BATCH_SIZE);
            let mut drain_err: bool = false;

            loop {
                while pending.len() < BATCH_SIZE {
                    match in_rx.recv() {
                        Ok(item) => pending.push_back(item),
                        Err(_) => {
                            drain_err = true;
                            break;
                        }
                    }
                }

                if pending.is_empty() {
                    break;
                }

                let batch: Vec<(u64, Vec<u8>)> = pending.drain(..).collect();
                let cipher_ref = &cipher;
                let iv_ref = &iv;
                let mut results: Vec<(u64, Result<Vec<u8>, String>)> = batch
                    .par_iter()
                    .map(|(idx, ciphertext)| {
                        (*idx, decrypt_chunk(cipher_ref, iv_ref, *idx, ciphertext))
                    })
                    .collect();
                results.sort_by_key(|(idx, _)| *idx);

                for (idx, r) in results {
                    match r {
                        Ok(plaintext) => {
                            if out_tx.send((idx, plaintext)).is_err() {
                                *err_e2.lock() =
                                    Some("downstream closed unexpectedly".into());
                                break;
                            }
                        }
                        Err(e) => {
                            *err_e2.lock() = Some(e);
                            break;
                        }
                    }
                }

                if drain_err || err_e2.lock().is_some() {
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
                    *err_w.lock() = Some("write failed".into());
                    write_failed = true;
                    break;
                }
                plaintext_written += pt.len() as u64;
                // plaintext 总字节 ≈ encrypted_size - 16×chunk_count，
                // 分母用 encrypted_size 让进度条最后自然收敛到 100%。
                // 未知长度（encrypted_size == 0）由 update_progress 走 spinner 分支，
                // 这里不再 `.min(encrypted_size)` 截断（否则会把所有数都压成 0）。
                update_progress(plaintext_written, encrypted_size);
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

    if let Some(e) = error.lock().take() {
        return Err(e.into());
    }
    if !saw_eof.load(Ordering::Relaxed) {
        return Err(ERR_MISSING_EOF.into());
    }
    Ok(())
}

/// 基于流的解密核心 —— 根据数据量与硬件能力自动选择并行模式。
///
/// 并行模式现在通过有界流水线实现，**内存峰值与文件大小无关**；
/// AES 计算是否在解密阶段内部多线程并行，由运行时硬件能力决定
/// （详见 `encrypt_stream` 的 doc 注释；语义完全对称）。
///
/// `encrypted_size: Option<u64>`：
/// - `Some(n)`：已知密文长度 n 字节（payload 部分，不含 header）；按阈值分流。
/// - `None`：未知长度（stdin 流模式）；**强制走并行流水线**，pipeline 读到 EOF 为止。
///   `chunk_parallel = false`（保守：未知长度场景不应叠加 rayon batch）。
///
/// 边界 `R/W: Read/Write + Send + 'static`：流水线阶段需要把 reader/writer
/// move 进独立线程，因此 caller 必须传 owned reader/writer（如 `BufReader<File>`、
/// `BufWriter<File>`、`BufWriter<Stdout>` 等），不能传 `&mut dyn Read`。
pub fn decrypt_stream<R, W>(
    reader: R,
    writer: W,
    cipher: &Aes256Gcm,
    iv: &[u8],
    encrypted_size: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let use_parallel = match encrypted_size {
        Some(n) => n > PARALLEL_THRESHOLD as u64,
        None => true,
    };

    if use_parallel {
        // 未知长度时强制单 worker：
        //   1) 硬 AES 单核已饱和，开 rayon 反而拖慢；
        //   2) 未知 size 通常是交互/管道场景，开销敏感。
        let chunk_parallel = encrypted_size.is_some() && !aes_hardware_available();
        let size_u64 = encrypted_size.unwrap_or(0);
        decrypt_parallel(
            reader,
            writer,
            Arc::new(cipher.clone()),
            Arc::new(iv.to_vec()),
            size_u64,
            chunk_parallel,
        )
        .map_err(|e| -> Box<dyn std::error::Error> { e })
    } else {
        decrypt_serial(reader, writer, cipher, iv, encrypted_size)
    }
}

/// 从任意 Reader 解析加密文件头，返回 (salt, iv, chunk_size)
///
/// 只接受当前版本（v4）。v1–v3 没有认证过的 EOF 帧，无法检测密文被截断，
/// 因此**直接拒绝**，要求用新版本重新加密。
pub fn parse_header<R: Read>(reader: &mut R) -> Result<(Vec<u8>, Vec<u8>, usize), Box<dyn std::error::Error>> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != MAGIC_NUMBER.as_bytes() {
        return Err("Invalid encrypted file format".into());
    }

    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;
    if version[0] != VERSION_SIGN {
        if version[0] == LEGACY_VERSION_SIGN {
            return Err(format!(
                "Unsupported file version: {} (v4 is required; streams written by v3 or earlier \
                 carry no end-of-stream marker and cannot be verified — re-encrypt the input)",
                version[0]
            )
            .into());
        }
        return Err(format!(
            "Unsupported file version: {} (this build reads v{})",
            version[0], VERSION_SIGN
        )
        .into());
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

    // parse_header 已读完 37 字节，file 当前位置正好是 payload 起点。
    // 长度只用于进度条与预读边界：完整性由 v4 EOF 帧保证，
    // 所以这里不再用"payload 长度为 0"判空（空明文在 v4 里也有 EOF 帧）。
    let encrypted_size = file_size.saturating_sub(HEADER_SIZE as u64);
    let reader = BufReader::with_capacity(BUFFER_SIZE, file);
    let writer = BufWriter::with_capacity(BUFFER_SIZE, File::create(Path::new(output_path))?);
    decrypt_stream(reader, writer, &cipher, &iv, Some(encrypted_size))?;
    Ok(())
}

/// 标准输入 → 任意 Writer 的解密内核。
///
/// 流式策略与 `encrypt_stdin_to_writer` 对称：
/// 1. stdin 是 TTY → 保留进度；管道 → 静默。
/// 2. 先 `read_exact` 抽 37 字节 header（必须先于 peek，否则 peek 会吞掉 payload）。
/// 3. peek `PARALLEL_THRESHOLD + 1` 字节 payload，决定走串行（小）还是并行（大）。
/// 4. 大输入把 peek 攒下的字节 + 剩余 stdin 串成 `Cursor::chain(Stdin)` 喂给并行流水线；
///    pipeline 读到 EOF 为止（错口令时第一个 GCM tag 校验失败立刻终止）。
///
/// **安全优势**：与原"先落盘 NamedTempFile 再 reopen"相比，明文**不再短暂存在
/// /tmp 上**，杜绝了多用户系统上的窗口期明文泄漏。
///
/// **资源优势**：不再有"先把所有 stdin 写到磁盘"的全量落盘步骤；磁盘耗尽 / tmpfs
/// 受限等环境不再影响解密路径。
///
/// 解密不需要 [`FullRead`]：帧驱动 + `read_exact` 本身就补齐短读，且帧长由
/// 加密侧决定，这里不能改变边界。
pub fn decrypt_stdin_to_writer<W>(writer: W, password: &str) -> Result<(), Box<dyn std::error::Error>>
where
    W: Write + Send + 'static,
{
    reset_progress();
    let interactive = std::io::stdin().is_terminal();
    set_progress_enabled(interactive);

    // Phase 1: 抽 37 字节 header —— 这一步必须在 peek 之前，
    // 因为 peek 会吞掉后续 payload 字节，header 字节会与 payload 混在一起。
    let mut header = [0u8; HEADER_SIZE];
    std::io::stdin().read_exact(&mut header)?;
    let (salt, iv, _chunk_size) = {
        let mut cursor = std::io::Cursor::new(&header[..]);
        parse_header(&mut cursor)?
    };

    // Phase 2: KDF
    let encryption_key = key_derivation::derive_key(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&encryption_key)?;

    // Phase 3: peek payload 前 PARALLEL_THRESHOLD + 1 字节
    let peek_limit = (PARALLEL_THRESHOLD + 1) as u64;
    let mut buf: Vec<u8> = Vec::with_capacity(peek_limit as usize);
    {
        let stdin = std::io::stdin();
        let mut take = (&stdin).take(peek_limit);
        take.read_to_end(&mut buf)?;
        // drop `stdin` —— 内部共享 buffer 已前进 `buf.len()` 字节
    }
    let use_parallel = buf.len() > PARALLEL_THRESHOLD;

    // 与加密侧对称：两条路径都统一包 BufWriter。
    let writer = BufWriter::with_capacity(BUFFER_SIZE, writer);

    // Phase 4: dispatch —— payload 起点（header 已被消费，stream 直接是 payload）
    if use_parallel {
        let chained = std::io::Cursor::new(buf).chain(std::io::stdin());
        let reader = BufReader::with_capacity(BUFFER_SIZE, chained);
        decrypt_stream(reader, writer, &cipher, &iv, None)
    } else {
        // 小输入：buf ≤ PARALLEL_THRESHOLD；size 已知 → 阈值分流走串行
        let buf_len = buf.len() as u64;
        decrypt_stream(Cursor::new(buf), writer, &cipher, &iv, Some(buf_len))
    }
}

/// 标准输入 → 标准输出解密封装
pub fn decrypt_stdin_to_stdout(password: &str) -> Result<(), Box<dyn std::error::Error>> {
    decrypt_stdin_to_writer(std::io::stdout(), password)
}

/// 标准输入 → 文件解密封装（`-d - -o <file>`）
pub fn decrypt_stdin_to_file(output_path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    decrypt_stdin_to_writer(File::create(Path::new(output_path))?, password)
}

/// 统一入口 —— 根据输入输出路径自动路由
pub fn decrypt_with_mode(input_path: &str, output_path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    if input_path == "-" {
        // stdin 是流：输出要么是 stdout，要么是 `-o` 指定的文件。
        return if output_path == "-" {
            decrypt_stdin_to_stdout(password)
        } else {
            decrypt_stdin_to_file(output_path, password)
        };
    }
    if output_path == "-" {
        reset_progress();
        let src = Path::new(input_path);
        let mut file = File::open(src)?;
        let file_size = src.metadata()?.len();

        let (salt, iv, _chunk_size) = parse_header(&mut file)?;
        let encryption_key = key_derivation::derive_key(password.as_bytes(), &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&encryption_key)?;

        // 完整性靠 v4 EOF 帧校验，长度只作进度条/边界用途。
        let encrypted_size = file_size.saturating_sub(HEADER_SIZE as u64);
        let reader = BufReader::with_capacity(BUFFER_SIZE, file);
        let writer = BufWriter::with_capacity(BUFFER_SIZE, std::io::stdout());
        decrypt_stream(reader, writer, &cipher, &iv, Some(encrypted_size))?;
        return Ok(());
    }
    decrypt_file(input_path, output_path, password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryptor::{encrypt_serial, encrypt_parallel};

    /// 测试用 Write：通过 Arc<Mutex<Vec<u8>>> 跨线程捕获输出。
    struct SharedWrite(Arc<Mutex<Vec<u8>>>);
    impl Write for SharedWrite {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    fn shared_write() -> (SharedWrite, Arc<Mutex<Vec<u8>>>) {
        let v = Arc::new(Mutex::new(Vec::new()));
        (SharedWrite(Arc::clone(&v)), v)
    }

    fn make_cipher(password: &[u8], salt: &[u8], _iv: &[u8]) -> Aes256Gcm {
        let key = key_derivation::derive_key(password, salt).unwrap();
        Aes256Gcm::new_from_slice(&key).unwrap()
    }

    /// 显式走 decrypt_parallel(chunk_parallel=true) 解密一份"硬 AES 加密过的"密文，
    /// 验证两种内部走向的密文格式完全等价（即加密侧怎么走向，解密侧都能正确解密）。
    #[test]
    fn test_chunk_parallel_decrypt_hard_aes_ciphertext() {
        let plaintext: Vec<u8> = (0..(2 * CHUNK_SIZE) as u32)
            .map(|i| (i ^ 0x5a) as u8)
            .collect();

        let mut input = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(input.as_file_mut(), &plaintext).unwrap();
        input.as_file_mut().flush().unwrap();

        let salt = generate_salt();
        let iv = generate_iv();
        let cipher = make_cipher(b"test-pass", &salt, &iv);

        // 加密走硬 AES（chunk_parallel = false）路径
        let (enc_w, enc_captured) = shared_write();
        encrypt_parallel(
            BufReader::with_capacity(BUFFER_SIZE, input.reopen().unwrap()),
            enc_w,
            Arc::new(cipher.clone()),
            Arc::new(iv.clone()),
            plaintext.len() as u64,
            false,
        )
        .unwrap();
        let enc_out = enc_captured.lock().clone();

        // 解密走 chunk_parallel = true 路径
        let mut dec_input = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(dec_input.as_file_mut(), &crate::encryptor::build_header(&salt, &iv)).unwrap();
        std::io::Write::write_all(dec_input.as_file_mut(), &enc_out).unwrap();
        dec_input.as_file_mut().flush().unwrap();

        let (w, captured) = shared_write();
        let mut dec_file = dec_input.reopen().unwrap();
        crate::decryptor::parse_header(&mut dec_file).unwrap();
        decrypt_parallel(
            BufReader::with_capacity(BUFFER_SIZE, dec_file),
            w,
            Arc::new(cipher.clone()),
            Arc::new(iv.clone()),
            enc_out.len() as u64,
            true,
        )
        .unwrap();
        let dec_out = captured.lock().clone();

        assert_eq!(dec_out, plaintext, "decrypt_parallel(chunk_parallel=true) must accept hard-AES-encrypted ciphertext");
    }

    /// encrypt_serial（小文件路径）→ decrypt_parallel(chunk_parallel=true) roundtrip。
    #[test]
    fn test_serial_cipher_chunk_parallel_decrypt_roundtrip() {
        let plaintext: Vec<u8> = (0..(PARALLEL_THRESHOLD / 2) as u32)
            .map(|i| (i.wrapping_mul(31) ^ (i >> 16)) as u8)
            .collect();

        let mut input = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(input.as_file_mut(), &plaintext).unwrap();
        input.as_file_mut().flush().unwrap();

        let salt = generate_salt();
        let iv = generate_iv();
        let cipher = make_cipher(b"test-pass", &salt, &iv);

        let mut enc_out: Vec<u8> = Vec::new();
        encrypt_serial(
            BufReader::with_capacity(BUFFER_SIZE, input.reopen().unwrap()),
            &mut enc_out,
            &cipher,
            &iv,
            Some(plaintext.len() as u64),
        )
        .unwrap();

        let mut dec_input = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(dec_input.as_file_mut(), &crate::encryptor::build_header(&salt, &iv)).unwrap();
        std::io::Write::write_all(dec_input.as_file_mut(), &enc_out).unwrap();
        dec_input.as_file_mut().flush().unwrap();

        let (w, captured) = shared_write();
        let mut dec_file = dec_input.reopen().unwrap();
        crate::decryptor::parse_header(&mut dec_file).unwrap();
        decrypt_parallel(
            BufReader::with_capacity(BUFFER_SIZE, dec_file),
            w,
            Arc::new(cipher.clone()),
            Arc::new(iv.clone()),
            enc_out.len() as u64,
            true,
        )
        .unwrap();
        let dec_out = captured.lock().clone();

        assert_eq!(dec_out, plaintext);
    }
}