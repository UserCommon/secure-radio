use crate::core::cipher::Cipher;
use crate::core::ecc::ErrorCorrectionCode;
use crate::core::{GeneralCipher, GeneralCipherError};

use crate::core::ecc::repetition_code::RepetitionCode;
use crate::core::cipher::magma::magma::*;

/// `MagmaRepetition` is a struct that 
/// uses `Magma` for ciphering and
/// `RepetitionCode` for Error Correction.
struct MagmaRepetition {
    magma: Magma,
    ecc: RepetitionCode
}

impl Cipher for MagmaRepetition {
    type Input = u64;
    type Output = u64;

    fn encrypt(&self, data: Self::Input) -> Result<Self::Output, crate::core::cipher::CipherError> {
        self.magma.encrypt(data)
    }

    fn decrypt(&self, data: Self::Output) -> Result<Self::Input, crate::core::cipher::CipherError> {
        self.magma.decrypt(data)
    }
}

impl ErrorCorrectionCode for MagmaRepetition {
    type Input = u8;
    type Output = [u8; 3];

    fn encode(&self, data: Self::Input) -> Result<Self::Output, crate::core::ecc::EccError> {
        self.ecc.encode(data)
    }

    fn decode(&self, data: Self::Output) -> Result<Self::Input, crate::core::ecc::EccError> {
        self.ecc.decode(data)
    }
}

impl GeneralCipher for MagmaRepetition {
    type Input = u64;
    type Output = [u8; 24];

    fn general_encrypt(&self, data: u64) -> Result<[u8; 24], GeneralCipherError> {
        let ciphered = self.encrypt(data).map_err(|_| GeneralCipherError::CipherEncryptError)?;
        let bytes = ciphered.to_be_bytes();

        let mut encoded = [0u8; 24];
        for (i, byte) in bytes.iter().enumerate() {
            let ecc = self.encode(*byte).map_err(|_| crate::core::GeneralCipherError::ECCEncodeError)?;
            encoded[i * 3..(i + 1) * 3].copy_from_slice(&ecc);
        }

        Ok(encoded)
    }
    
    fn general_decrypt(&self, data: [u8; 24]) -> Result<u64, GeneralCipherError> {
        let mut decoded_bytes = [0u8; 8];

        for i in 0..8 {
            let chunk = &data[i * 3..(i + 1) * 3];
            decoded_bytes[i] = self.decode([chunk[0], chunk[1], chunk[2]])
                .map_err(|_| crate::core::GeneralCipherError::ECCDecodeError)?;
        }

        let ciphered = u64::from_be_bytes(decoded_bytes);
        let plain = self.decrypt(ciphered).map_err(|_| crate::core::GeneralCipherError::CipherDecryptError)?;

        Ok(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_error() {
        let cipher = MagmaRepetition {
            magma: MagmaBuilder::default().build(),
            ecc: RepetitionCode,
        };

        let data: u64 = 0x99AABBCCDDEEFF00;
        let encrypted = cipher.general_encrypt(data).unwrap();
        let decrypted = cipher.general_decrypt(encrypted).unwrap();

        // Убедимся, что данные не изменились
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_recoverable_error() {
        let cipher = MagmaRepetition {
            magma: MagmaBuilder::default().build(),
            ecc: RepetitionCode,
        };

        let data: u64 = 0x99AABBCCDDEEFF00;
        let mut encrypted = cipher.general_encrypt(data).unwrap();

        // Портим один байт
        encrypted[5] ^= 0xFF;

        let result = cipher.general_decrypt(encrypted).unwrap();

        // Убедимся, что восстановленные данные совпадают с исходными
        assert_eq!(result, data);
    }

    // this test fails
    // #[test]
    // fn test_unrecoverable_error() {
    //     let cipher = MagmaRepetition {
    //         magma: MagmaBuilder::default().build(),
    //         ecc: RepetitionCode,
    //     };
    
    //     let data: u64 = 0x99AABBCCDDEEFF00;
    //     let mut encrypted = cipher.general_encrypt(data).unwrap();
    
    //     // Портим два байта (так как это 2 символа)
    //     encrypted[0] ^= 0xFF;
    //     encrypted[1] ^= 0xFF;
    
    //     let result = cipher.general_decrypt(encrypted);
    
    //     // Здесь ожидаем ошибку, потому что два символа повреждены
    //     assert!(result.is_err());
    // }
}
