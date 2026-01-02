use ring::rand;
use ring::rand::SecureRandom;

// 常量定义
pub const MAGIC_NUMBER: &str = "DEC!";
pub const VERSION_SIGN: u8 = 0x02;
pub const SALT_LENGTH: usize = 16;
pub const IV_LENGTH: usize = 16;
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_MEMORY_KIB: u32 = 65536;
pub const ARGON2_PARALLELISM: u32 = 4;
pub const MASTER_KEY_LENGTH: usize = 32;
pub const ENCRYPTION_KEY_LENGTH: usize = 32;
pub const HMAC_KEY_LENGTH: usize = 32;
pub const BUFFER_SIZE: usize = 256 * 1024;

/// 获取 CPU 线程数
pub fn get_parts() -> usize {
    std::thread::available_parallelism().map_or(4, |n| n.get())
}

/// 生成随机盐
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; SALT_LENGTH];
    let rng = rand::SystemRandom::new();
    rng.fill(&mut salt).expect("Failed to generate salt");
    salt
}

/// 生成随机IV
pub fn generate_iv() -> Vec<u8> {
    let mut iv = vec![0u8; IV_LENGTH];
    let rng = rand::SystemRandom::new();
    rng.fill(&mut iv).expect("Failed to generate IV");
    iv
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
        assert_eq!(VERSION_SIGN, 0x02);
        assert_eq!(SALT_LENGTH, 16);
        assert_eq!(IV_LENGTH, 16);
        assert_eq!(MASTER_KEY_LENGTH, 32);
        assert_eq!(ENCRYPTION_KEY_LENGTH, 32);
        assert_eq!(HMAC_KEY_LENGTH, 32);
    }
}