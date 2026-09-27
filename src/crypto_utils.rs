use rand::random;
use aes_gcm::Nonce;
use typenum::consts::U12;

/// Returns true if the running CPU exposes hardware-accelerated AES.
///
/// On x86 / x86_64 we check for the `aes` feature at runtime so the same
/// binary can ship on machines with and without AES-NI.
///
/// On aarch64 the FEAT_AES extension is mandatory from ARMv8.0-A onward,
/// so we trust the target without an extra runtime probe.
///
/// Other architectures fall back to "no hardware AES" and rely on the
/// parallel chunk path (which only matters when software AES is the
/// bottleneck).
pub fn aes_hardware_available() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        is_x86_feature_detected!("aes")
    }
    #[cfg(target_arch = "aarch64")]
    {
        true
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

// 常量定义
pub const MAGIC_NUMBER: &str = "DEC!";
pub const VERSION_SIGN: u8 = 0x03;
pub const SALT_LENGTH: usize = 16;
pub const IV_LENGTH: usize = 12;
/// 默认块大小：1MB (用于并行处理)
pub const CHUNK_SIZE: usize = 1024 * 1024;
/// **< 1 MiB**：单线程路径。Argon2 KDF（~270 ms）已经主导耗时，
/// 3 个 thread 的创建/join 开销（~50-100 µs）毫无收益。
pub const PARALLEL_THRESHOLD: usize = 1024 * 1024;
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_MEMORY_KIB: u32 = 256 * 1024;
pub const ARGON2_PARALLELISM: u32 = 2;
pub const MASTER_KEY_LENGTH: usize = 32;
pub const BUFFER_SIZE: usize = 256 * 1024;
pub const HEADER_SIZE: usize = MAGIC_NUMBER.len() + 1 + SALT_LENGTH + IV_LENGTH + 4; // 37

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

pub fn generate_nonce_for_chunk(base_iv: &[u8], index: u64) -> Nonce<U12> {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&base_iv[..12]);
    let index_bytes = index.to_le_bytes();
    for i in 0..4 {
        nonce_bytes[8 + i] ^= index_bytes[i];
    }
    Nonce::<U12>::from(nonce_bytes)
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
        assert_eq!(PARALLEL_THRESHOLD, 1024 * 1024);
    }

    #[test]
    fn test_aes_hardware_available_matches_target() {
        // The probe must agree with the target arch:
        //   aarch64 -> always true (FEAT_AES mandatory from ARMv8.0-A)
        //   x86/x86_64 -> true iff runtime AES-NI feature is present
        //   anything else -> false
        let result = aes_hardware_available();
        #[cfg(target_arch = "aarch64")]
        assert!(result, "aarch64 must report hardware AES available");
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
        assert!(!result, "non-x86 non-aarch64 targets must report no hardware AES");
        // On x86 we cannot assert either way (depends on the host CPU).
    }
}