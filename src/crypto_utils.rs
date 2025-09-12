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
pub const BUFFER_SIZE: usize =  4 * 1024 * 1024; // 4MB 默认块大小

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
