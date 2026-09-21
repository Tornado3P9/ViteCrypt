// Global Constants
pub const MIN_PASSWORD_LEN: usize = 8; // defining the absolute minimum
pub const GOOD_PASSWORD_LEN: usize = 12; // ok password length, see is_strong_passphrase()
pub const MIN_MNEMONIC_WORDS: usize = 6; // min number of words, see is_mnemonic_passphrase()

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32; // 256-bit key
