pub mod cipher;
pub mod default_cipher;
pub mod ecc;

#[derive(Debug)]
pub enum GeneralCipherError {
    SerializationError(&'static str),
    DeserializationError(&'static str)
}

pub trait GeneralCipher: cipher::Cipher + ecc::ErrorCorrectionCode {
    fn serialize(&self, data: <Self as cipher::Cipher>::Input) -> Result<<Self as ecc::ErrorCorrectionCode>::Output, GeneralCipherError>;
    fn deserialize(&self, data: <Self as ecc::ErrorCorrectionCode>::Output) -> Result<<Self as cipher::Cipher>::Input, GeneralCipherError>;
}
