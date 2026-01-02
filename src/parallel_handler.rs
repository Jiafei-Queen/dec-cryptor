use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use ctr::Ctr128BE;
use rayon::prelude::*;

// AES-256-CTR 类型别名
pub type Aes256Ctr = Ctr128BE<Aes256>;

// 对于非常小的数据，并行处理的开销可能超过收益，直接单线程处理。
// 这里的 16KB 是一个经验值，可以根据实际情况调整。
const PARALLEL_THRESHOLD: usize = 16 * 1024;

/// 通过将缓冲区拆分为多个片段，并利用 Rayon 的并行迭代器将 AES-CTR 密钥流应用到数据上。
///
/// 会就地修改 `data`。此方式与单流处理产生完全相同的结果，但利用了多核 CPU 加速。
///
/// - key: 32 字节
/// - iv: 16 字节
/// - data: 需要原地转换的字节切片
/// - stream_offset: 在整体流中的绝对字节偏移（用于文件流式处理）
pub fn ctr_apply_in_parts(
    key: &[u8],
    iv: &[u8],
    data: &mut [u8],
    stream_offset: usize
) -> Result<(), String> {
    let total_len = data.len();
    if total_len == 0 {
        return Ok(());
    }

    let num_parts = crate::crypto_utils::get_parts();

    if num_parts <= 1 || total_len < PARALLEL_THRESHOLD {
        // 回退到单线程处理
        let mut cipher = Aes256Ctr::new(key.into(), iv.into());
        cipher.seek(stream_offset as u128);
        cipher.apply_keystream(data);
        return Ok(());
    }

    // 计算每个数据块的大小，使用向上取整，确保覆盖所有数据
    let chunk_size = (total_len + num_parts - 1) / num_parts;

    // 将数据分成多个可变切片
    let mut chunks: Vec<&mut [u8]> = data.chunks_mut(chunk_size).collect();

    // 使用 Rayon 的 `par_iter` 进行并行处理
    chunks.par_iter_mut()
        .enumerate() // 获取块的索引，用于计算偏移量
        .for_each(|(chunk_index, chunk)| {
            // 为每个并行任务（线程）创建一个新的 cipher 实例。
            // 这是必须的，因为 cipher 实例内部有状态，不能在线程间共享。
            let mut cipher = Aes256Ctr::new(key.into(), iv.into());

            // 计算当前块的偏移量
            let offset = stream_offset + chunk_index * chunk_size;

            // 将 cipher 定位到当前块的正确密钥流位置
            cipher.seek(offset as u128);

            // 对当前数据块应用密钥流
            cipher.apply_keystream(chunk);
        });

    Ok(())
}