use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use crate::crypto_utils::{ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, ENCRYPTION_KEY_LENGTH, HMAC_KEY_LENGTH, MASTER_KEY_LENGTH};

pub fn derive_master_key(password: &[u8], salt: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(MASTER_KEY_LENGTH),
    ).map_err(|e| format!("Failed to create Argon2 params: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut master_key = vec![0u8; MASTER_KEY_LENGTH];

    argon2.hash_password_into(password, salt, &mut master_key)
        .map_err(|e| format!("Failed to derive master key: {}", e))?;

    Ok(master_key)
}

/// 使用HKDF从主密钥派生加密密钥和HMAC密钥
pub fn derive_encryption_and_hmac_keys(master_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let hk = Hkdf::<Sha256>::new(None, master_key);

    // 派生加密密钥
    let mut encryption_key = vec![0u8; ENCRYPTION_KEY_LENGTH];
    hk.expand(b"dec-encryption", &mut encryption_key)
        .map_err(|_| "Failed to derive encryption key")?;

    // 派生HMAC密钥
    let mut hmac_key = vec![0u8; HMAC_KEY_LENGTH];
    hk.expand(b"dec-hmac", &mut hmac_key)
        .map_err(|_| "Failed to derive HMAC key")?;

    Ok((encryption_key, hmac_key))
}
