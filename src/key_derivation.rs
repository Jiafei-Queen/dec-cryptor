use argon2::{Algorithm, Argon2, Params, Version};
use crate::crypto_utils::{ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, MASTER_KEY_LENGTH};

/// 从密码和盐派生主密钥
/// 对于 AES-256-GCM，Argon2 直接输出 32 字节密钥，无需 HKDF 扩展
pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(MASTER_KEY_LENGTH),
    ).map_err(|e| format!("Failed to create Argon2 params: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = vec![0u8; MASTER_KEY_LENGTH];

    argon2.hash_password_into(password, salt, &mut key)
        .map_err(|e| format!("Failed to derive key: {}", e))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_utils::{SALT_LENGTH, MASTER_KEY_LENGTH};

    #[test]
    fn test_derive_key() {
        let password = b"test_password";
        let salt = vec![0u8; SALT_LENGTH];

        let result = derive_key(password, &salt);
        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.len(), MASTER_KEY_LENGTH);
    }

    #[test]
    fn test_consistent_key_derivation() {
        let password = b"consistent_test_password";
        let salt = vec![1u8; SALT_LENGTH];

        // 多次调用应该产生相同的结果
        let key1 = derive_key(password, &salt).unwrap();
        let key2 = derive_key(password, &salt).unwrap();

        assert_eq!(key1, key2);
    }
}