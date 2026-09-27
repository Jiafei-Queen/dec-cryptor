use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor, IsTerminal, Read, Write};
use std::path::Path;
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

/// 把底层 reader 的短读合并成"填满调用方 buffer，或到达 EOF"。
///
/// 流水线的 chunk 边界等于 `read` 的返回长度，而 `Stdin` / 管道会把一次
/// `read` 截成任意长度（实测 1 B ~ 64 KiB）。若原样透传短读，一个 3 MiB 的
/// stdin 会退化成几十个碎片帧（每帧白付 4 B 长度前缀 + 16 B GCM tag），
/// 且与 header 里声明的 `CHUNK_SIZE` 不符。这里在加密侧合并一次，
/// 使帧长稳定为 `CHUNK_SIZE`（最后一帧除外）。
///
/// 解密侧不需要它：解密按 `[len:4]` 帧推进，`read_exact` 本身就会补齐短读。
struct FullRead<R>(R);

impl<R: Read> Read for FullRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut filled = 0;
        while filled < buf.len() {
            match self.0.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(filled)
    }
}

fn encrypt_chunk(cipher: &Aes256Gcm, iv: &[u8], chunk_index: u64, data: &[u8])
    -> Result<Vec<u8>, String> {
    let nonce = generate_nonce_for_chunk(iv, chunk_index);
    cipher.encrypt(&nonce, data)
        .map_err(|e| format!("Encryption failed: {}", e))
}

pub(crate) fn encrypt_serial<R, W>(
    mut reader: R,
    mut writer: W,
    cipher: &Aes256Gcm,
    iv: &[u8],
    file_size: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: Read,
    W: Write,
{
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut total_read: u64 = 0;
    let mut chunk_index: u64 = 0;
    // `Some(n)` 时读到 n 字节为止；`None` 时读到 EOF 为止（stdin 流模式）。
    let size_limit: Option<u64> = file_size;

    loop {
        if let Some(n) = size_limit {
            if total_read >= n { break; }
        }
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 { break; }

        let data = &buffer[..bytes_read];
        let ciphertext = encrypt_chunk(cipher, iv, chunk_index, data)?;

        writer.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
        writer.write_all(&ciphertext)?;

        total_read += bytes_read as u64;
        chunk_index += 1;
        // 进度更新：file_size 由 update_progress 内部按 `0 == 未知` 约定处理。
        update_progress(total_read, size_limit.unwrap_or(0));
    }

    write_eof_frame(&mut writer, cipher, iv, chunk_index)?;

    let _ = writer.flush();
    finish_progress_line();
    Ok(())
}

/// 计算 v4 EOF 帧的 tag：空载荷，nonce 索引 = `chunk_count`（数据帧数量）。
///
/// nonce 索引把标记绑定在流内的位置上：攻击者把它前移、复制或搬走都会让 tag 校验失败。
fn eof_tag(cipher: &Aes256Gcm, iv: &[u8], chunk_count: u64) -> Result<Vec<u8>, String> {
    encrypt_chunk(cipher, iv, chunk_count, &[])
}

/// 写出 v4 的 EOF 帧：`[0u32][空载荷的 GCM tag]`。
///
/// 载荷长度为 0 的**数据帧**不存在（加密端 `read` 返回 0 即终止），
/// 所以 `len == 0` 在帧语法里无歧义。
fn write_eof_frame<W: Write>(
    writer: &mut W,
    cipher: &Aes256Gcm,
    iv: &[u8],
    chunk_count: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let tag = eof_tag(cipher, iv, chunk_count)?;
    writer.write_all(&0u32.to_le_bytes())?;
    writer.write_all(&tag)?;
    Ok(())
}

/// 有界三阶段流水线：
///
/// ```text
///   Reader thread ── in_channel ──► Encryptor thread ── out_channel ──► Writer thread
/// ```
///
/// - 每个 channel 容量受限 → 天然背压，避免任一阶段堆积无界内存。
/// - Encryptor 阶段维护 `BTreeMap<u64, _>` 窗口（仅当 `chunk_parallel = true`
///   时，因为 rayon 回调乱序返回），保证输出按 idx 严格递增
///   （解密端才能正确解析每块的长度前缀）。
/// - 错误通过共享 `Arc<Mutex<Option<String>>>` 传播；取消通过 channel close
///   自然传递，保证 writer 在退出前一定把 out_channel 里的所有 chunk 都消费掉。
/// - 三个 thread 启动后主线程 `join` 等待；任一阶段出错都会让其他阶段通过
///   channel close 提前退出。
/// - 输入正常读完后追加 v4 **EOF 帧**（`[0u32][空载荷 tag]`，nonce 索引 =
///   数据帧数量），它是流完整性的唯一依据；出错时不写，解密端会报截断。
///
/// `chunk_parallel`：
/// - `false`（默认）：encryptor 阶段单线程串行算 AES。本机有硬件 AES-NI 时
///   已经是吞吐上限，再开多 worker 也只是浪费 CPU 且拖累 cache。
/// - `true`：encryptor 阶段把每块 AES 任务 `spawn` 到 rayon global pool，
///   多核并行算 AES。仅在没有硬件 AES 的机器上有意义（软 AES 是瓶颈时
///   多核能接近线性提速）；有硬件 AES 时反而会拖慢。
///
/// 内存峰值与文件大小**无关**：`3 × (PIPELINE_DEPTH + 1) × CHUNK_SIZE`。
pub(crate) fn encrypt_parallel<R, W>(
    mut reader: R,
    mut writer: W,
    cipher: Arc<Aes256Gcm>,
    iv: Arc<Vec<u8>>,
    file_size: u64,
    chunk_parallel: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    // `file_size == 0` 表示未知长度（stdin 流模式）；内部按"读到 EOF 为止"工作。
    // 该约定见 `progress_utils::update_progress` 与 `decrypt_parallel` 注释。
    type Item = (u64, Vec<u8>);
    /// out_channel 的元素：`(idx, ciphertext, is_eof)`。`is_eof == true` 时
    /// `ciphertext` 是空载荷的 GCM tag，长度前缀按 v4 语法写 `0`。
    type OutItem = (u64, Vec<u8>, bool);

    let (in_tx, in_rx) = mpsc::sync_channel::<Item>(PIPELINE_DEPTH);
    let (out_tx, out_rx) = mpsc::sync_channel::<OutItem>(PIPELINE_DEPTH);

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
                    *err_r.lock() = Some(e.to_string());
                    break;
                }
            }
        }
        drop(in_tx); // 关闭 in_channel，触发 encryptor 退出
    });

    // ── Encryptor thread ──
    // 单 worker 串行算 AES（chunk_parallel = false）；或
    // 批量并发算 AES（chunk_parallel = true，仅在没有硬件 AES 的机器上）。
    // `std::sync::mpsc::Receiver` 不可克隆、不支持多消费者，所以 chunk_parallel
    // 模式下我们采用 batch strategy：累积一批明文到 BATCH_SIZE 后用 rayon 并行加密，
    // 再按 idx 顺序写回 out_tx。内存峰值额外增加 BATCH_SIZE × CHUNK_SIZE。
    const BATCH_SIZE: usize = 8;
    let err_e = Arc::clone(&error);
    let err_e2 = Arc::clone(&error);
    let encryptor_handle = thread::spawn(move || {
        if !chunk_parallel {
            // 单线程路径：每次来一块就加密一块
            let mut next_idx: u64 = 0;
            let mut failed = false;
            while let Ok((idx, plaintext)) = in_rx.recv() {
                match encrypt_chunk(&cipher, &iv, idx, &plaintext) {
                    Ok(ciphertext) => {
                        if out_tx.send((idx, ciphertext, false)).is_err() {
                            *err_e.lock() =
                                Some("downstream closed unexpectedly".into());
                            failed = true;
                            break;
                        }
                        next_idx = idx + 1;
                    }
                    Err(e) => {
                        *err_e.lock() = Some(e);
                        failed = true;
                        break;
                    }
                }
            }
            if !failed && err_e.lock().is_none() {
                // 只有"输入正常读完、且没有任何阶段报错"才写 EOF 帧。
                // reader 中途出错时 in_channel 也会关闭，单看 channel close 会误判为
                // "读完"，从而给残缺密文盖上一个合法标记 —— 那正是 v4 要防的静默截断。
                match eof_tag(&cipher, &iv, next_idx) {
                    Ok(tag) => {
                        let _ = out_tx.send((next_idx, tag, true));
                    }
                    Err(e) => {
                        *err_e.lock() = Some(e);
                    }
                }
            }
        } else {
            // 多线程路径：批量 + rayon par_iter + 按 idx 排序发送
            use std::collections::VecDeque;
            let mut pending: VecDeque<(u64, Vec<u8>)> = VecDeque::with_capacity(BATCH_SIZE);
            let mut drain_err: bool = false;
            let mut next_idx: u64 = 0;
            let mut failed = false;

            loop {
                // 收集一批：BATCH_SIZE 个，或读完了
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

                // 把这一批拿出来算 AES。rayon par_iter 在 software-AES 上才能
                // 带来提速；hardware-AES 单核已是吞吐上限，这条路径不会被走到。
                let batch: Vec<(u64, Vec<u8>)> = pending.drain(..).collect();
                let cipher_ref = &cipher;
                let iv_ref = &iv;
                let mut results: Vec<(u64, Result<Vec<u8>, String>)> = batch
                    .par_iter()
                    .map(|(idx, plaintext)| {
                        (*idx, encrypt_chunk(cipher_ref, iv_ref, *idx, plaintext))
                    })
                    .collect();
                // 按 idx 排序，保证下游 writer / decryptor 按输入顺序拿到 chunk
                results.sort_by_key(|(idx, _)| *idx);

                for (idx, r) in results {
                    match r {
                        Ok(ciphertext) => {
                            if out_tx.send((idx, ciphertext, false)).is_err() {
                                *err_e2.lock() =
                                    Some("downstream closed unexpectedly".into());
                                failed = true;
                                break;
                            }
                            next_idx = idx + 1;
                        }
                        Err(e) => {
                            *err_e2.lock() = Some(e);
                            failed = true;
                            break;
                        }
                    }
                }

                if failed || (drain_err && pending.is_empty()) {
                    break;
                }
            }

            if !failed && drain_err && err_e2.lock().is_none() {
                // 同上：in_channel 关闭 + 全程无错，才追加 EOF 帧。
                match eof_tag(&cipher, &iv, next_idx) {
                    Ok(tag) => {
                        let _ = out_tx.send((next_idx, tag, true));
                    }
                    Err(e) => {
                        *err_e2.lock() = Some(e);
                    }
                }
            }
        }
        drop(out_tx); // 关闭 out_channel，触发 writer 退出
    });

    // ── Writer thread ──
    let err_w = Arc::clone(&error);
    let writer_handle = thread::spawn(move || {
        let mut next_idx: u64 = 0;
        let mut window: BTreeMap<u64, (Vec<u8>, bool)> = BTreeMap::new();
        let mut total_written: u64 = 0;
        let mut write_failed = false;

        // 通过 out_rx.recv() 返回 Err 自然退出（encryptor drop out_tx 后）
        // —— 这保证 out_channel 中的所有 chunk 都被消费完毕，**不丢任何数据**。
        while let Ok((idx, ciphertext, is_eof)) = out_rx.recv() {
            window.insert(idx, (ciphertext, is_eof));
            // 连续段立即 flush（乱序到达时窗口里只会有少数几个 idx）
            while let Some((ct, is_eof)) = window.remove(&next_idx) {
                // v4 EOF 帧的长度前缀固定写 0（载荷 0 字节，后面只跟 16 B tag）。
                let block_len = if is_eof { 0 } else { ct.len() as u32 };
                let len_bytes = block_len.to_le_bytes();
                if writer.write_all(&len_bytes).is_err()
                    || writer.write_all(&ct).is_err()
                {
                    *err_w.lock() = Some("write failed".into());
                    write_failed = true;
                    break;
                }
                total_written += 4 + ct.len() as u64;
                // `file_size == 0` 由 update_progress 内部走 spinner 分支
                // （未知长度），因此这里不再 `.min(file_size)` 截断。
                update_progress(total_written, file_size);
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

    if let Some(e) = error.lock().take() {
        return Err(e.into());
    }
    Ok(())
}

/// 基于流的加密核心 —— 根据数据量与硬件能力自动选择并行模式。
///
/// 并行模式现在通过有界流水线实现，**内存峰值与文件大小无关**；
/// 因此阈值保留低值，以便中等文件也能享受流水线（read/compute/write 三阶段并行）收益。
///
/// AES 计算是否在 encryptor 阶段内部多线程并行，由运行时硬件能力决定：
/// - 硬件 AES（x86 AES-NI / aarch64 FEAT_AES）：单 worker 已经把单核 AES 管线
///   喂满，开多 worker 反而拖慢 cache + 增加 rayon 调度开销。`chunk_parallel = false`。
/// - 软件 AES（小核、旧 CPU）：单 worker 算一个 1 MiB chunk 是几十 ms 的活，
///   多核并行能接近线性提速。`chunk_parallel = true`。
///
/// `file_size: Option<u64>`：
/// - `Some(n)`：已知输入长度 n 字节；按 `n > PARALLEL_THRESHOLD` 阈值分流。
/// - `None`：未知长度（stdin 流模式）；**强制走并行流水线**，pipeline 容量天然有界，
///   不会因为 stdin 多长就吃多少内存。`chunk_parallel = false`（保守：未知长度
///   场景下不应叠加 rayon batch，避免给小输入引入调度开销）。
///
/// 边界 `R/W: Read/Write + Send + 'static`：流水线阶段需要把 reader/writer
/// move 进独立线程，因此 caller 必须传 owned reader/writer（如 `BufReader<File>`、
/// `BufWriter<File>`、`BufWriter<Stdout>` 等），不能传 `&mut dyn Read`。
pub fn encrypt_stream<R, W>(
    reader: R,
    writer: W,
    cipher: &Aes256Gcm,
    iv: &[u8],
    file_size: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    // 阈值分流：
    //   已知长度且 ≤ THRESHOLD → 串行（Argon2 KDF 已主导耗时，开线程白搭）
    //   已知长度且  > THRESHOLD → 并行流水线
    //   未知长度                → 并行流水线（防止 stdin 任意长度撑爆内存）
    let use_parallel = match file_size {
        Some(n) => n > PARALLEL_THRESHOLD as u64,
        None => true,
    };

    if use_parallel {
        // 流水线阶段要求 owned + Send + 'static，故把 cipher/iv 升级到 Arc
        // 未知长度时强制单 worker（chunk_parallel = false）：
        //   1) 硬 AES 单核已饱和，开 rayon 反而拖慢；
        //   2) 未知 size 通常是交互/管道场景，开销敏感。
        let chunk_parallel = file_size.is_some() && !aes_hardware_available();
        // 把 `Option<u64>` 扁平化成 `u64` 传给内部 API；`None` 用 `0` 占位。
        let size_u64 = file_size.unwrap_or(0);
        encrypt_parallel(
            reader,
            writer,
            Arc::new(cipher.clone()),
            Arc::new(iv.to_vec()),
            size_u64,
            chunk_parallel,
        )
        .map_err(|e| -> Box<dyn std::error::Error> { e })
    } else {
        encrypt_serial(reader, writer, cipher, iv, file_size)
    }
}

/// 构造文件头 37 字节：`"DEC!"` + version + salt(16) + iv(12) + chunk_size(4, LE)
///
/// v4 的完整格式是 `header + 数据帧* + EOF 帧`；EOF 帧由 `write_eof_frame`
/// （串行路径）或流水线的 encryptor 阶段追加，解密端缺它即报截断。
pub(crate) fn build_header(salt: &[u8], iv: &[u8]) -> Vec<u8> {
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
    encrypt_stream(reader, writer, &cipher, &iv, Some(file_size))?;
    Ok(())
}

/// 标准输入 → 任意 Writer 的加密内核。
///
/// 流式策略：
/// 1. 若 stdin 是 TTY → 保留进度输出；管道 / 重定向 → **静默**（spinner 反而是噪声）。
/// 2. 先 `take(PARALLEL_THRESHOLD + 1).read_to_end` peek 一下，最多攒 1 MiB + 1 B；
///    超过 PARALLEL_THRESHOLD 即视为"大输入"，把 peek 攒下的字节 + 剩余 stdin
///    串成 `Cursor::chain(Stdin)` 喂给 `encrypt_stream` 的并行流水线；
///    不到 PARALLEL_THRESHOLD 即"小输入"，走串行路径。
/// 3. 并行路径用 [`FullRead`] 合并 stdin 的短读，保证帧长 == `CHUNK_SIZE`；
///    小输入走 `Cursor`（`read` 天然填满请求），不需要额外包装。
///
/// 内存上限：`PARALLEL_THRESHOLD + 1` ≈ 1 MiB + 1 B（peek 阶段），之后流水线
/// 容量固定为 `3 × (PIPELINE_DEPTH + 1) × CHUNK_SIZE` ≈ 51 MiB。
pub fn encrypt_stdin_to_writer<W>(writer: W, password: &str) -> Result<(), Box<dyn std::error::Error>>
where
    W: Write + Send + 'static,
{
    reset_progress();
    // 管道场景下不显示 spinner；TTY 下保留。必须在 peek 之前设置，
    // 否则 peek 阶段那几毫秒会有一闪而过的 spinner。
    let interactive = std::io::stdin().is_terminal();
    set_progress_enabled(interactive);

    // Phase 1: peek — 把 stdin 前 PARALLEL_THRESHOLD + 1 字节抽进 Vec
    //         （再多拿 1 字节只为区分"恰好 1 MiB"与"超过 1 MiB"两种情况）。
    let peek_limit = (PARALLEL_THRESHOLD + 1) as u64;
    let mut buf: Vec<u8> = Vec::with_capacity(peek_limit as usize);
    {
        let stdin = std::io::stdin();
        let mut take = (&stdin).take(peek_limit);
        take.read_to_end(&mut buf)?;
        // drop `stdin` —— 内部共享 buffer 已前进 `buf.len()` 字节
    }
    let use_parallel = buf.len() > PARALLEL_THRESHOLD;

    // Phase 2: KDF + header（沿用既有逻辑）
    let salt = generate_salt();
    let iv = generate_iv();
    let encryption_key = key_derivation::derive_key(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&encryption_key)?;

    // 统一用 BufWriter 包住目标 writer（stdout 或文件），先写 37 字节 header。
    // 串行路径以前直接写 `Stdout`（LineWriter），与并行路径不一致。
    let mut writer = BufWriter::with_capacity(BUFFER_SIZE, writer);
    writer.write_all(&build_header(&salt, &iv))?;
    writer.flush()?;

    // Phase 3: dispatch
    if use_parallel {
        // 把 peek 攒下的 `buf` 与剩余 stdin 拼成一个 Read，喂给并行流水线。
        // 第二次 `stdin()` 拿到的 handle 自动从 `buf.len()` 位置继续读
        // （Stdin 内部共享 buffer，多个 handle 顺序读取位置是连续的）。
        let chained = Cursor::new(buf).chain(std::io::stdin());
        let reader = FullRead(BufReader::with_capacity(BUFFER_SIZE, chained));
        // 未知长度（剩余 stdin 还没读完）。
        encrypt_stream(reader, writer, &cipher, &iv, None)
    } else {
        // 小输入：直接用 buf 喂串行路径；size 已知 → 阈值分流时走串行。
        let buf_len = buf.len() as u64;
        encrypt_stream(Cursor::new(buf), writer, &cipher, &iv, Some(buf_len))
    }
}

/// 标准输入 → 标准输出加密封装
pub fn encrypt_stdin_to_stdout(password: &str) -> Result<(), Box<dyn std::error::Error>> {
    encrypt_stdin_to_writer(std::io::stdout(), password)
}

/// 标准输入 → 文件加密封装（`-e - -o <file>`）
pub fn encrypt_stdin_to_file(output_path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    encrypt_stdin_to_writer(File::create(Path::new(output_path))?, password)
}

/// 统一入口 —— 根据输入输出路径自动路由
pub fn encrypt_with_mode(input_path: &str, output_path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    if input_path == "-" {
        // stdin 是流：输出要么是 stdout，要么是 `-o` 指定的文件。
        return if output_path == "-" {
            encrypt_stdin_to_stdout(password)
        } else {
            encrypt_stdin_to_file(output_path, password)
        };
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
        encrypt_stream(reader, writer, &cipher, &iv, Some(file_size))?;
        return Ok(());
    }
    encrypt_file(input_path, output_path, password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decryptor::decrypt_stream;

    /// 测试用 Write 实现：通过 Arc<Mutex<Vec<u8>>> 跨线程捕获输出，
    /// 这样测试结束后可以读出密文内容。
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

    fn make_cipher(password: &[u8], salt: &[u8], iv: &[u8])
        -> (Aes256Gcm, Vec<u8>, Vec<u8>)
    {
        let key = key_derivation::derive_key(password, salt).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        (cipher, salt.to_vec(), iv.to_vec())
    }

    /// reader 中途报错时，加密端不能写出"看似完整"的密文：否则残缺密文带上合法
    /// EOF 标记后能被静默解密成部分明文 —— 正是 v4 要消灭的那种"假成功"。
    struct FailingReader {
        remaining: usize,
    }

    impl Read for FailingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::Error::other("simulated read failure"));
            }
            let n = buf.len().min(self.remaining);
            self.remaining -= n;
            Ok(n)
        }
    }

    #[test]
    fn test_reader_error_does_not_emit_valid_eof_marker() {
        let salt = generate_salt();
        let iv = generate_iv();
        let (cipher, _, _) = make_cipher(b"test-pass", &salt, &iv);

        let (w, captured) = shared_write();
        let result = encrypt_stream(
            FailingReader { remaining: 2 * CHUNK_SIZE },
            w,
            &cipher,
            &iv,
            None,
        );
        assert!(result.is_err(), "reader failure must be reported");

        let partial = captured.lock().clone();
        assert!(
            !partial.is_empty(),
            "some ciphertext should have been written before the failure"
        );

        let (dw, _) = shared_write();
        let decrypt = decrypt_stream(Cursor::new(partial), dw, &cipher, &iv, None);
        assert!(
            decrypt.is_err(),
            "a stream cut short by a read error must not decrypt as a success"
        );
    }

    /// chunk_parallel = true 加密 → 标准 decrypt_stream 解密，验证密文格式兼容。
    #[test]
    fn test_chunk_parallel_encrypt_decrypt_roundtrip() {
        let plaintext: Vec<u8> = (0..(2 * CHUNK_SIZE) as u32)
            .map(|i| (i.wrapping_mul(2654435761) ^ (i >> 8)) as u8)
            .collect();

        let mut input = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(input.as_file_mut(), &plaintext).unwrap();
        input.as_file_mut().flush().unwrap();

        let salt = generate_salt();
        let iv = generate_iv();
        let (cipher, salt_v, iv_v) = make_cipher(b"test-pass", &salt, &iv);

        let (w, captured) = shared_write();
        encrypt_parallel(
            BufReader::with_capacity(BUFFER_SIZE, input.reopen().unwrap()),
            w,
            Arc::new(cipher.clone()),
            Arc::new(iv.clone()),
            plaintext.len() as u64,
            true, // chunk_parallel
        )
        .unwrap();
        let enc_out = captured.lock().clone();

        // 拼装完整密文（header + body），用标准 decrypt_stream 解密
        let mut full = build_header(&salt_v, &iv_v);
        full.extend_from_slice(&enc_out);

        let mut dec_input = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(dec_input.as_file_mut(), &full).unwrap();
        dec_input.as_file_mut().flush().unwrap();

        // 关键：必须先用 parse_header 消费掉 37 字节 header，
        // 再把同一个 File 交给 BufReader，让 reader 从 header 之后开始读。
        let mut dec_file = dec_input.reopen().unwrap();
        crate::decryptor::parse_header(&mut dec_file).unwrap();

        let (dec_w, dec_captured) = shared_write();
        decrypt_stream(
            BufReader::with_capacity(BUFFER_SIZE, dec_file),
            dec_w,
            &cipher,
            &iv,
            Some(enc_out.len() as u64),
        )
        .unwrap();
        let dec_out = dec_captured.lock().clone();

        assert_eq!(dec_out, plaintext, "chunk_parallel encrypt produces compatible ciphertext");
    }

    /// encrypt_stream 的两次内部走向（threshold 上下）必须产出格式兼容的密文。
    /// 这里走 encrypt_stream 自身，所以加密侧 chunk_parallel 由硬件探测决定；
    /// 解密侧用公开的 decrypt_stream 走对应分支。roundtrip 通过即证明格式兼容。
    #[test]
    fn test_encrypt_stream_roundtrip_large_file() {
        let plaintext: Vec<u8> = (0..(2 * CHUNK_SIZE) as u32)
            .map(|i| i.wrapping_mul(2654435761) as u8)
            .collect();

        let mut input = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(input.as_file_mut(), &plaintext).unwrap();
        input.as_file_mut().flush().unwrap();

        let salt = generate_salt();
        let iv = generate_iv();
        let (cipher, _, _) = make_cipher(b"test-pass", &salt, &iv);

        // 加密走公开 API（chunk_parallel 由硬件决定）
        let (w, captured) = shared_write();
        encrypt_stream(
            BufReader::with_capacity(BUFFER_SIZE, input.reopen().unwrap()),
            w,
            &cipher,
            &iv,
            Some(plaintext.len() as u64),
        )
        .unwrap();
        let enc_out = captured.lock().clone();

        // 解密走公开 API（chunk_parallel 由硬件决定）
        let mut dec_input = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(dec_input.as_file_mut(), &build_header(&salt, &iv)).unwrap();
        std::io::Write::write_all(dec_input.as_file_mut(), &enc_out).unwrap();
        dec_input.as_file_mut().flush().unwrap();

        let mut dec_file = dec_input.reopen().unwrap();
        crate::decryptor::parse_header(&mut dec_file).unwrap();

        let (dec_w, dec_captured) = shared_write();
        decrypt_stream(
            BufReader::with_capacity(BUFFER_SIZE, dec_file),
            dec_w,
            &cipher,
            &iv,
            Some(enc_out.len() as u64),
        )
        .unwrap();
        let dec_out = dec_captured.lock().clone();

        assert_eq!(dec_out, plaintext);
    }
}