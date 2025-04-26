use crate::core::ecc::ErrorCorrectionCode;
use crate::core::{GeneralCipher, GeneralCipherError};
use crate::core::cipher::magma::magma::*;
use crate::core::cipher::*;


/// `MagmaNoecc` - struct which is represents magma without ecc
/// that implements `GeneralCipher` trait
/// No test required because its uses magma cipher which is
/// already has been tested
pub struct MagmaNoecc {
    magma: Magma
}

impl Cipher for MagmaNoecc {
    type Input = u64;
    type Output = u64;

    fn encrypt(&self, data: Self::Input) -> Result<Self::Output, CipherError> {
        self.magma.encrypt(data)    
    }

    fn decrypt(&self, data: Self::Output) -> Result<Self::Input, CipherError> {
        self.magma.decrypt(data)
    }
}

impl ErrorCorrectionCode for MagmaNoecc {
    type Input = ();
    type Output = ();

    fn encode(&self, data: Self::Input) -> Result<Self::Output, crate::core::ecc::EccError> {
        Ok(())
    }

    fn decode(&self, data: Self::Output) -> Result<Self::Input, crate::core::ecc::EccError> {
        Ok(())
    }
}

impl GeneralCipher for MagmaNoecc {
    type Input = u64;
    type Output = [u8; 8];

    fn general_encrypt(&self, data: <Self as GeneralCipher>::Input) -> Result<<Self as GeneralCipher>::Output, GeneralCipherError> {
        self.magma.encrypt(data)
            .map(|d| d.to_be_bytes())
            .map_err(|_| GeneralCipherError::CipherEncryptError)
    }

    fn general_decrypt(&self, data: <Self as GeneralCipher>::Output) -> Result<<Self as GeneralCipher>::Input, GeneralCipherError> {
        let data = u64::from_be_bytes(data);
        self.magma.decrypt(data)
            .map_err(|_| GeneralCipherError::CipherDecryptError)
    }
}

