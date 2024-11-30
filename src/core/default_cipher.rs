use magma::utils;

use super::{GeneralCipher, GeneralCipherError};
use crate::core::cipher::magma::magma::*;
use crate::core::cipher::*;
use crate::core::ecc::*;
use crate::core::ecc::hamming::*;

/// DefaultCipher is basically Magma + Hamming(21,16)
pub struct DefaultCipher {
    crypto: Magma,
    error_correction: HammingECC16
}

impl Cipher for DefaultCipher {
    type Input = u64;
    type Output = u64;

    fn encrypt(&self, data: Self::Input) -> Result<Self::Output, CipherError> {
        self.crypto.encrypt(data)
    }

    fn decrypt(&self, data: Self::Output) -> Result<Self::Input, CipherError> {
        self.crypto.decrypt(data)
    }
}

impl ErrorCorrectionCode for DefaultCipher {
    type Input = [u16; 4];
    type Output = [u32; 4];

    fn encode(&self, data: Self::Input) -> Result<Self::Output, EccError> {
        let mut res = [0;4];

        for idx in 0..res.len() {
            res[idx] = self.error_correction.encode(data[idx])?;
        }

        Ok(res)
    }

    fn decode(&self, data: Self::Output) -> Result<Self::Input, EccError> {
        let mut res = [0;4];

        for idx in 0..res.len() {
            res[idx] = self.error_correction.decode(data[idx])?;
        }

        Ok(res)
    }

}

impl GeneralCipher for DefaultCipher {
    fn serialize(&self, data: <Self as super::cipher::Cipher>::Input) -> Result<<Self as super::ecc::ErrorCorrectionCode>::Output, GeneralCipherError> {
        let new_data = match self.encrypt(data) {
            Ok(data) => data,
            _ => return Err(GeneralCipherError::SerializationError("Failed to encrypt!")),
        };

        let splitted = utils::u64_split_to_u16_array(new_data);
        self.encode(splitted).map_err(|_| GeneralCipherError::SerializationError("Failed to encode!"))
    }
    
    fn deserialize(&self, data: <Self as super::ecc::ErrorCorrectionCode>::Output) -> Result<<Self as super::cipher::Cipher>::Input, GeneralCipherError> 
    {
        let decoded_data = match self.decode(data) {
            Ok(data) => data,
            _ => return Err(GeneralCipherError::DeserializationError("Failed to decrypt!")),
        };

        let joined = utils::u16_join_to_u64(decoded_data);
        self.decrypt(joined).map_err(|_| GeneralCipherError::DeserializationError("Failed to decrypt!"))
        
    }
}

#[cfg(test)]
mod general_cipher_test {

}
