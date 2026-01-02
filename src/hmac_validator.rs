use hmac::{Hmac, Mac};
use sha2::Sha256;

/// HMAC-SHA256 校验器
pub struct HmacValidator {
    mac: Hmac<Sha256>,
}

impl HmacValidator {
    /// 创建新的HMAC校验器
    pub fn new(hmac_key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let mac = Hmac::<Sha256>::new_from_slice(hmac_key)
            .map_err(|_| "Failed to create HMAC")?;
        Ok(Self { mac })
    }

    /// 更新HMAC计算
    pub fn update(&mut self, data: &[u8]) {
        self.mac.update(data);
    }

    /// 完成HMAC计算并返回结果
    pub fn finalize(self) -> Vec<u8> {
        let result = self.mac.finalize();
        result.into_bytes().to_vec()
    }

    /// 验证HMAC
    pub fn verify(self, stored_hmac: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.mac
            .verify_slice(stored_hmac)
            .map_err(|_| "HMAC验证失败，文件可能已被篡改或密码错误".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_validator_creation() {
        let key = b"test_hmac_key_32_bytes_long_key!";
        let validator = HmacValidator::new(key);
        assert!(validator.is_ok());
    }

    #[test]
    fn test_hmac_validation_success() {
        let key = b"test_hmac_key_32_bytes_long_key!";
        let data = b"test data for hmac validation";

        // 创建HMAC并计算
        let mut validator = HmacValidator::new(key).unwrap();
        validator.update(data);
        let hmac_code = validator.finalize();

        // 验证HMAC
        let mut validator2 = HmacValidator::new(key).unwrap();
        validator2.update(data);
        let result = validator2.verify(&hmac_code);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hmac_validation_failure() {
        let key1 = b"test_hmac_key_32_bytes_long_key!";
        let key2 = b"different_hmac_key_32_bytes_long!";
        let data = b"test data for hmac validation";

        // 用key1创建HMAC
        let mut validator = HmacValidator::new(key1).unwrap();
        validator.update(data);
        let hmac_code = validator.finalize();

        // 用key2验证应该失败
        let mut validator2 = HmacValidator::new(key2).unwrap();
        validator2.update(data);
        let result = validator2.verify(&hmac_code);
        assert!(result.is_err());
    }
}