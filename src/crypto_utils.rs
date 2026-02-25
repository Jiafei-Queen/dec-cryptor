use rand::random;
use aes_gcm::Nonce;

// 常量定义
pub const MAGIC_NUMBER: &str = "DEC!";
pub const VERSION_SIGN: u8 = 0x03;
pub const SALT_LENGTH: usize = 16;
pub const IV_LENGTH: usize = 12;
/// 默认块大小：1MB (用于并行处理)
pub const CHUNK_SIZE: usize = 1024 * 1024;
/// 并行处理阈值：16KB (小于此值使用单线程)
pub const PARALLEL_THRESHOLD: usize = 16 * 1024;
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_MEMORY_KIB: u32 = 256 * 1024;
pub const ARGON2_PARALLELISM: u32 = 2;
pub const MASTER_KEY_LENGTH: usize = 32;
pub const BUFFER_SIZE: usize = 256 * 1024;

/// 获取 CPU 线程数
#[allow(dead_code)]
pub fn get_parts() -> usize {
    std::thread::available_parallelism().map_or(4, |n| n.get())
}

/// 生成随机盐
pub fn generate_salt() -> Vec<u8> {
    let salt: [u8; SALT_LENGTH] = random();
    salt.to_vec()
}

/// 生成随机IV
pub fn generate_iv() -> Vec<u8> {
    let iv: [u8; IV_LENGTH] = random();
    iv.to_vec()
}

pub fn generate_nonce_for_chunk(base_iv: &[u8], index: u64) -> Nonce<generic_array::typenum::U12> {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&base_iv[..12]);
    let index_bytes = index.to_le_bytes();
    // 修改后4字节
    for i in 0..4 {
        nonce_bytes[8 + i] ^= index_bytes[i];
    }
    // 修复点：显式转换回 Nonce 类型
    *Nonce::<generic_array::typenum::U12>::from_slice(&nonce_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        assert_eq!(salt1.len(), SALT_LENGTH);
        assert_eq!(salt2.len(), SALT_LENGTH);
        // 确保两次生成的盐不同（极大概率）
        assert_ne!(salt1, salt2);
    }

    #[test]
    fn test_generate_iv() {
        let iv1 = generate_iv();
        let iv2 = generate_iv();

        assert_eq!(iv1.len(), IV_LENGTH);
        assert_eq!(iv2.len(), IV_LENGTH);
        // 确保两次生成的IV不同（极大概率）
        assert_ne!(iv1, iv2);
    }

    #[test]
    fn test_get_parts() {
        let parts = get_parts();
        // 确保返回的线程数合理（至少1个）
        assert!(parts >= 1);
    }

    #[test]
    fn test_constants() {
        assert_eq!(MAGIC_NUMBER, "DEC!");
        assert_eq!(VERSION_SIGN, 0x03);
        assert_eq!(SALT_LENGTH, 16);
        assert_eq!(IV_LENGTH, 12);
        assert_eq!(MASTER_KEY_LENGTH, 32);
        assert_eq!(CHUNK_SIZE, 1024 * 1024);
        assert_eq!(PARALLEL_THRESHOLD, 16 * 1024);
    }
}