use std::io;

#[derive(Debug, Clone)]
pub enum Error {
    DialogClosed,
    IOFailed(io::ErrorKind),
    QrCodeGenerationFailed,
    PngWriteFailed,
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid input")]
    InvalidInput,

    #[error("key derivation failed")]
    KdfError,

    #[error("encryption failed")]
    EncryptError,

    #[error("decryption failed or authentication tag mismatch")]
    DecryptError,
}
