pub mod cipher;
pub mod default_ciphers;
pub mod ecc;

#[derive(Debug)]
pub enum GeneralCipherError {
    ECCDecodeError,
    ECCEncodeError,
    CipherDecryptError,
    CipherEncryptError,
}

pub trait GeneralCipher: cipher::Cipher + ecc::ErrorCorrectionCode { 
    type Input;
    type Output;

    fn general_encrypt(&self, data: <Self as GeneralCipher>::Input) -> Result<<Self as GeneralCipher>::Output, GeneralCipherError>;
    fn general_decrypt(&self, data: <Self as GeneralCipher>::Output) -> Result<<Self as GeneralCipher>::Input, GeneralCipherError>;
}
