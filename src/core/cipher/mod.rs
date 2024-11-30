pub mod magma;

#[derive(Debug)]
pub enum CipherError {
    EncryptError,
    DecryptError
}

pub trait Cipher {
    type Input;
    type Output;

    fn encrypt(&self, data: Self::Input) -> Result<Self::Output, CipherError>;
    fn decrypt(&self, data: Self::Output) -> Result<Self::Input, CipherError>;
}
