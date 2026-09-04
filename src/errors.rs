use std::io;

#[derive(Debug, Clone)]
pub enum Error {
    DialogClosed,
    IOFailed(io::ErrorKind),
    QrCodeGenerationFailed,
    PngWriteFailed,
}

// Error Definition
#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("invalid input")]
    InvalidInput,
    // #[error("missing input: provide a file with -i or pipe data to stdin")]
    // MissingInput,
    // #[error("missing wordlist: include the file wordlist.txt in the src/ directory")]
    // MissingWordlist,
    // #[error("I/O error: {0}")]
    // IoError(String),
    // #[error("maximum attempts reached")]
    // AttemptsExceeded,
    #[error("key derivation failed")]
    KdfError,
    #[error("encryption failed")]
    EncryptError,
    #[error("decryption failed or authentication tag mismatch")]
    DecryptError,
}
