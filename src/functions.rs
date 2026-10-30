use crate::Message;
use crate::constants;
use crate::errors::{CryptoError, Error};

use constants::{GOOD_PASSWORD_LEN, KEY_LEN, MIN_MNEMONIC_WORDS, NONCE_LEN, SALT_LEN};

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

// UI
use iced::widget::{TextInput, button, container, text, text_editor, tooltip};
use iced::{Element, Font, Length, Padding};

// Encryption
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::rand_core::RngCore,
    aead::{Aead, KeyInit, OsRng},
};
use argon2::Argon2;
use zeroize::Zeroize;

// QR Code Generation
use image::{ImageBuffer, Luma, imageops::FilterType};
use qrcodegen::{QrCode, QrCodeEcc};
use rqrr;


// -----------------------------------------------------------------------------
// Password-Based Encryption
// -----------------------------------------------------------------------------

/// Derives a fixed-length encryption key from a password and salt using Argon2id.
///
/// The salt must have the configured length and should be generated using a
/// cryptographically secure random-number generator. Argon2id is selected to
/// provide resistance against both GPU-based and side-channel attacks.
///
/// The returned key material should be cleared from memory after use.
fn derive_key_argon2(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], CryptoError> {
    if salt.len() != SALT_LEN {
        return Err(CryptoError::KdfError);
    }

    // Argon2id configuration:
    // - Memory cost: 64 MiB
    // - Time cost: 3 iterations
    // - Parallelism: 1 lane
    //
    // Tune parameters for your platform, e.g.:
    // memory: 256 MiB (262144 KiB) instead of 64 MB (65536 KiB), time (iterations): 6, parallelism: 4 not 1, None
    // Note: memory cost is the most important defense.
    let params = argon2::Params::new(65536, 3, 1, None).map_err(|_| CryptoError::KdfError)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key: [u8; 32] = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| CryptoError::KdfError)?;
    Ok(key)
}

/// Encrypts plaintext using a password-derived AES-256-GCM key.
///
/// The returned blob has the following binary layout:
///
/// ```text
/// salt || nonce || ciphertext
/// ```
///
/// The salt and nonce are stored with the ciphertext because they do not need
/// to remain secret. AES-GCM provides confidentiality and integrity protection.
pub fn encrypt(password: &str, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Generate salt and nonce
    let mut salt: [u8; 16] = [0u8; SALT_LEN];
    let mut nonce_bytes: [u8; 12] = [0u8; NONCE_LEN];
    let mut rng: OsRng = OsRng;

    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_bytes);
    // rng.try_fill_bytes(&mut salt).map_err(|e| CryptoError::IoError(e.to_string()))?;
    // rng.try_fill_bytes(&mut nonce_bytes).map_err(|e| CryptoError::IoError(e.to_string()))?;

    // Derive key
    let key_bytes: [u8; 32] = derive_key_argon2(password, &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ct: Vec<u8> = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptError)?;

    // Construct blob: salt || nonce || ciphertext
    let mut blob: Vec<u8> = Vec::with_capacity(SALT_LEN + NONCE_LEN + ct.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);

    // Zero sensitive local stacks
    // Explicitly clear sensitive key material before returning
    let mut key_bytes_owned: [u8; 32] = key_bytes;
    key_bytes_owned.zeroize();
    salt.zeroize();
    nonce_bytes.zeroize();

    Ok(blob)
}

/// Decrypts an AES-256-GCM ciphertext using a password-derived key.
///
/// The input must contain at least a complete salt and nonce. Authentication
/// failure, including an incorrect password or modified ciphertext, is reported
/// as a decryption error.
pub fn decrypt(password: &str, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < SALT_LEN + NONCE_LEN {
        return Err(CryptoError::InvalidInput);
    }

    // Parse the serialized encryption components from the input blob.
    let salt: &[u8] = &blob[0..SALT_LEN];
    let nonce_bytes: &[u8] = &blob[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ct: &[u8] = &blob[SALT_LEN + NONCE_LEN..];

    // Recreate the encryption key using the stored salt.
    let key_bytes: [u8; 32] = derive_key_argon2(password, salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decryption also verifies the AES-GCM authentication tag.
    let plaintext: Vec<u8> = cipher
        .decrypt(nonce, ct)
        .map_err(|_| CryptoError::DecryptError)?;

    // Clear the temporary key buffer before returning the plaintext.
    let mut key_bytes_owned: [u8; 32] = key_bytes;
    key_bytes_owned.zeroize();

    Ok(plaintext)
}

// -----------------------------------------------------------------------------
// Password Validation
// -----------------------------------------------------------------------------

/// Returns `true` when the password satisfies the configured complexity rules.
///
/// The password must contain at least the minimum required number of bytes and
/// include uppercase characters, lowercase characters, decimal digits, and
/// non-alphanumeric characters.
pub fn is_strong_passphrase(s: &str) -> bool {
    // Check the minimum length before performing character classification.
    if s.len() < GOOD_PASSWORD_LEN {
        return false;
    }
    let has_upper: bool = s.chars().any(|c| c.is_uppercase());
    let has_lower: bool = s.chars().any(|c| c.is_lowercase());
    let has_digit: bool = s.chars().any(|c| c.is_ascii_digit());
    let has_special: bool = s.chars().any(|c| !c.is_alphanumeric());
    has_upper && has_lower && has_digit && has_special
}

/// Returns `true` when the input contains the required number of words.
///
/// Words must be separated by exactly one ASCII space. Leading spaces,
/// trailing spaces, consecutive spaces, and empty input are rejected.
pub fn is_mnemonic_passphrase(s: &str) -> bool {
    if MIN_MNEMONIC_WORDS == 0 {
        return false;
    }

    // Reject empty input and invalid leading or trailing whitespace.
    if s.is_empty() || s.starts_with(' ') || s.ends_with(' ') {
        return false;
    }

    // Reject inputs shorter than the configured minimum format.
    // 6 words of min 5 letters, each separated by one space make: (6*5)+(6-1) = 35
    // let min_len: usize = (MIN_MNEMONIC_WORDS*5)+(MIN_MNEMONIC_WORDS-1);
    if s.len() < 35 {
        return false;
    }

    // Splitting on a literal space allows consecutive spaces to be detected.
    let parts: Vec<&str> = s.split(' ').collect();
    if parts.len() < MIN_MNEMONIC_WORDS {
        return false;
    }

    // Empty segments indicate consecutive spaces.
    if parts.iter().any(|p| p.is_empty()) {
        return false;
    }

    true
}

// -----------------------------------------------------------------------------
// User-Interface Helpers
// -----------------------------------------------------------------------------

/// Creates a password input field with optional secure-text masking.
pub fn password_input_field<F>(
    placeholder: &str,
    value: &str,
    tab_key_id: &str,
    secure_status: bool,
    on_change: F,
) -> TextInput<'static, Message>
where
    F: 'static + Fn(String) -> Message + Clone,
{
    TextInput::new(placeholder, value)
        .width(Length::Fill)
        .padding(Padding::from(10))
        .line_height(text::LineHeight::Relative(1.75))
        // .id(iced::widget::Id::unique())
        // .id(tab_key_id) // If tab_key_id is a String
        // .id(iced::widget::Id::new(tab_id)) // Or use Id::new() explicitly
        .id(tab_key_id.to_string()) // If tab_key_id is a &str (non-static)
        // .id(iced::widget::Id::from(tab_key_id)) // Or use Id::from() explicitly
        .on_input(on_change)
        .secure(secure_status) // in 0.14.0 changed from .password() 0.12.0
}

/// Creates an action button with an optional tooltip.
///
/// The button uses a disabled style when no action is provided. The tooltip
/// label is retained for the `'static` lifetime required by the UI framework.
pub fn action(
    content: Element<'static, Message>,
    label: String,
    on_press: Option<Message>,
) -> Element<'static, Message> {
    let is_disabled: bool = on_press.is_none();
    let label_ref: &str = Box::leak(label.into_boxed_str()); // converts owned String to 'static &str

    tooltip(
        button(container(content).width(30).center_x(30))
            .on_press_maybe(on_press)
            .padding([5, 10])
            .style(if is_disabled {
                button::secondary
            } else {
                button::primary
            }),
        // text(label_ref).size(24),
        label_ref,
        tooltip::Position::Bottom,
        // tooltip::Position::FollowCursor,
    )
    .delay(Duration::from_millis(500)) // default is Duration::ZERO
    .style(container::rounded_box)
    .gap(3) // only works with tooltip::Position::Bottom because of static
    .into()
}

/// Returns the appropriate eye icon for the current password visibility state.
pub fn eye_icon<'a>(visible: bool) -> Element<'a, Message> {
    if visible {
        icon('\u{E804}')
    } else {
        icon('\u{E805}')
    }
}

/// Returns the icon used for creating a new document.
pub fn new_icon<'a>() -> Element<'a, Message> {
    icon('\u{E802}')
}

/// Returns the icon used for opening a document.
pub fn open_icon<'a>() -> Element<'a, Message> {
    icon('\u{F115}')
}

/// Returns the icon used for saving a document.
pub fn save_icon<'a>() -> Element<'a, Message> {
    icon('\u{E803}')
}

/// Returns the icon used for opening/reading a QR code
pub fn qrcode_open_icon<'a>() -> Element<'a, Message> {
    icon('\u{E800}')
}

/// Returns the icon used for saving a QR code
pub fn qrcode_save_icon<'a>() -> Element<'a, Message> {
    icon('\u{E801}')
}

/// Returns the icon used for copying the texteditor content to the clipboard
pub fn copy_icon<'a>() -> Element<'a, Message> {
    icon('\u{F0C5}')
}

/// Returns the icon used for pasting the clipboard content to the texteditor field
pub fn paste_icon<'a>() -> Element<'a, Message> {
    icon('\u{F0EA}')
}

/// Creates a text element using the application's icon font of size 18.
fn icon<'a, Message>(codepoint: char) -> Element<'a, Message> {
    const ICON_FONT: Font = Font::with_name("editor-icons");

    // text(codepoint).font(ICON_FONT).into() // 16 was default
    text(codepoint).font(ICON_FONT).size(18).into()
}

/// Returns the icon used for the texteditor search bar
pub fn lupe_icon<'a>() -> Element<'a, Message> {
    icon_b('\u{E80C}')
}

// fn select_icon<'a>() -> Element<'a, Message> {
//     icon_b('\u{E80E}')
// }

// fn replace_next_icon<'a>() -> Element<'a, Message> {
//     icon_b('\u{E806}')
// }

// fn replace_all_icon<'a>() -> Element<'a, Message> {
//     icon_b('\u{E808}')
// }

/// Creates a text element using the application's icon font but using font size 16.
fn icon_b<'a, Message>(codepoint: char) -> Element<'a, Message> {
    const ICON_FONT: Font = Font::with_name("editor-icons");

    // text(codepoint).font(ICON_FONT).into() // 16 was default
    text(codepoint).font(ICON_FONT).size(16).into()
}

// -----------------------------------------------------------------------------
// Asynchronous File Operations
// -----------------------------------------------------------------------------

/// Opens a file-selection dialog and loads the selected text file.
pub async fn pick_file(title_str: &str) -> Result<(PathBuf, Arc<String>), Error> {
    let handle = rfd::AsyncFileDialog::new()
        .set_title(title_str)
        .pick_file()
        .await
        .ok_or(Error::DialogClosed)?;

    load_file(handle.path().to_owned()).await
}

/// Reads a UTF-8 text file asynchronously.
pub async fn load_file(path: PathBuf) -> Result<(PathBuf, Arc<String>), Error> {
    let contents = tokio::fs::read_to_string(&path)
        .await
        .map(Arc::new)
        .map_err(|error| error.kind())
        .map_err(Error::IOFailed)?;

    Ok((path, contents))
}

/// Saves text to the specified path or prompts the user for a destination path.
pub async fn save_file(path: Option<PathBuf>, text: String) -> Result<PathBuf, Error> {
    let path = if let Some(path) = path {
        path
    } else {
        rfd::AsyncFileDialog::new()
            .set_title("Choose a file name...")
            .save_file()
            .await
            .ok_or(Error::DialogClosed)
            .map(|handle| handle.path().to_owned())?
    };

    tokio::fs::write(&path, text)
        .await
        .map_err(|error| Error::IOFailed(error.kind()))?;

    Ok(path)
}

// -----------------------------------------------------------------------------
// QR-Code Image Operations
// -----------------------------------------------------------------------------

/// Opens a file-selection dialog and decodes the selected QR-code image.
pub async fn pick_qr_image(title_str: &str) -> Result<(PathBuf, Arc<String>), Error> {
    let handle = rfd::AsyncFileDialog::new()
        .set_title(title_str)
        .pick_file()
        .await
        .ok_or(Error::DialogClosed)?;

    load_qr_image(handle.path().to_owned()).await
}

/// Loads an image, converts it to grayscale, and decodes the first detected QR code.
pub async fn load_qr_image(path: PathBuf) -> Result<(PathBuf, Arc<String>), Error> {
    // Read PNG bytes asynchronously
    let bytes: Vec<u8> = tokio::fs::read(&path)
        .await
        .map_err(|e| e.kind())
        .map_err(Error::IOFailed)?;

    // Decode PNG bytes -> DynamicImage -> grayscale (Luma8)
    let img = image::load_from_memory(&bytes)
        .map_err(|_| std::io::ErrorKind::InvalidData)
        .map_err(Error::IOFailed)?
        .to_luma8();

    // Detect and decode with rqrr
    let mut prepared = rqrr::PreparedImage::prepare(img); // Prepare for detection
    let grids = prepared.detect_grids(); // Search for grids, without decoding

    let first = grids
        .get(0)
        .ok_or(io::ErrorKind::InvalidData)
        .map_err(Error::IOFailed)?;

    let (_meta, content) = first
        .decode()
        .map_err(|_| Error::IOFailed(io::ErrorKind::InvalidData))?; // Decode the grid

    // let content = String::from_utf8(content_bytes).map_err(|_| Error::IOFailed(io::ErrorKind::InvalidData))?;

    Ok((path, Arc::new(content)))
}

/// Encodes text into one or more QR-code PNG files.
///
/// If the input exceeds the selected QR-code capacity, it is divided into
/// multiple numbered files. The QR-code error-correction level determines the
/// maximum payload size.
pub async fn save_qr_image(
    text: String,
    ecc: QrCodeEcc,
    args_min_size: usize,
    args_border_width: i32,
    args_scale: i32,
) -> Result<PathBuf, Error> {
    let path: PathBuf = rfd::AsyncFileDialog::new()
        .set_title("Choose a file name...")
        .add_filter("PNG", &["png"])
        .save_file()
        .await
        .ok_or(Error::DialogClosed)
        .map(|handle| handle.path().to_owned())?;

    // let path: PathBuf = path.unwrap_or_else(|| PathBuf::from("qrcode.png"));
    // let path: PathBuf = path.with_extension("png");

    let limit: usize = match ecc {
        QrCodeEcc::Low => 2953,
        QrCodeEcc::Medium => 2331,
        QrCodeEcc::Quartile => 1663,
        QrCodeEcc::High => 1273,
    };

    let mut auto_split: bool = false;
    // If data too big, automatically split data to fit into qrcodes:
    let substrings: Vec<String> = {
        let length: usize = text.len();
        let mut step: usize = limit; // Start with the maximum limit
        let mut substrings: Vec<String> = Vec::new();

        if length <= limit {
            // auto_split = false;
            substrings.push(text.clone());
        } else {
            auto_split = true;

            // Find a divisor between min_length and max_limit (from max_limit down to min_length)
            for i in (args_min_size..=limit).rev() {
                if length % i == 0 {
                    step = i;
                    break;
                }
            }
            // Create substrings
            for j in (0..length).step_by(step) {
                let end: usize = std::cmp::min(j + step, length);
                substrings.push(text[j..end].to_string());
            }
        }

        substrings
    };

    for (index, substring) in substrings.iter().enumerate() {
        let qr: QrCode = QrCode::encode_text(substring, ecc).map_err(|e| {
            eprintln!("Failed to generate QR code: {}", e);
            Error::QrCodeGenerationFailed
        })?;

        let output_file: PathBuf = if auto_split {
            path.with_file_name(format!(
                "{}_{:02}.png",
                path.file_stem().unwrap().to_str().unwrap(),
                index + 1
            ))
        } else {
            // path.clone()
            path.with_file_name(format!(
                "{}.png",
                path.file_stem().unwrap().to_str().unwrap()
            ))
        };

        write_to_png_scaled(&qr, args_border_width, args_scale as u32, &output_file).map_err(
            |e| {
                eprintln!("Error writing PNG: {}", e);
                Error::PngWriteFailed
            },
        )?;
    }

    Ok(path)
}

/// Renders a QR code to a scaled grayscale PNG image.
///
/// A nearest-neighbor filter is used to preserve the sharp edges of QR modules.
fn write_to_png_scaled(
    qr: &QrCode,
    border: i32,
    scale_factor: u32,
    file_path: &Path,
) -> Result<(), String> {
    // Validate rendering parameters before allocating the output image.
    if border < 0 {
        return Err("Border must be non-negative".to_string());
    }
    if scale_factor < 1 {
        return Err("Scale factor must be positive".to_string());
    }

    // Calculate the unscaled image dimensions, including the quiet-zone border.
    let size: i32 = qr.size();
    let img_size: u32 = (size + 2 * border) as u32;
    let mut img: ImageBuffer<Luma<u8>, Vec<u8>> =
        ImageBuffer::from_pixel(img_size, img_size, Luma([255u8]));

    // Render each active QR module as a black pixel.
    for y in 0..size {
        for x in 0..size {
            if qr.get_module(x, y) {
                img.put_pixel((x + border) as u32, (y + border) as u32, Luma([0u8]));
            }
        }
    }

    // Scale the image without smoothing to preserve QR-code readability.
    let scaled_img: ImageBuffer<Luma<u8>, Vec<u8>> = image::imageops::resize(
        &img,
        img_size * scale_factor,
        img_size * scale_factor,
        FilterType::Nearest,
    );

    // Write the final image to disk.
    scaled_img
        .save(file_path)
        .map_err(|e| format!("Failed to save PNG file: {}", e))
}

// -----------------------------------------------------------------------------
// Password and Passphrase Generation
// -----------------------------------------------------------------------------

/// Builds a character set from the requested character categories.
pub fn create_alphabet(
    include_lowercase: bool,
    include_uppercase: bool,
    include_numbers: bool,
    include_special: bool,
) -> String {
    let mut alphabet: String = String::new();

    if include_lowercase {
        alphabet.push_str("abcdefghijklmnopqrstuvwxyz");
    }
    if include_uppercase {
        alphabet.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if include_numbers {
        alphabet.push_str("0123456789");
    }
    if include_special {
        alphabet.push_str("!@#$%^&*()-_=+[]{}|;:',.<>?/\\~`");
    }

    alphabet
}

/// Selects a random character from the supplied character set.
fn get_random_char(charset: &[u8]) -> char {
    let mut rng: OsRng = OsRng;
    let idx: usize = rng.next_u32() as usize % charset.len();
    charset[idx] as char
}

/// Generates a random password with the requested length and character set.
pub fn gen_random_pass(len: i32, charset: &[u8]) -> String {
    let pass: String = (0..len).map(|_| get_random_char(&charset)).collect();

    pass
}

// Load embedded wordlist (one word per line, empty lines are ignored)
pub fn load_wordlist() -> Vec<&'static str> {
    include_str!("wordlist.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

/// Generates a passphrase by selecting words uniformly from the supplied
/// dictionary.
///
/// Rejection sampling is used to avoid modulo bias when converting random
/// values into word-list indices.
pub fn generate_passphrase(wordlist: &[&str], n_words: usize) -> String {
    let mut rng: OsRng = OsRng; // from aes_gcm::aead
    let wl_len: usize = wordlist.len();
    let mut words: Vec<&str> = Vec::with_capacity(n_words);

    for _ in 0..n_words {
        // generate a uniform index in 0..wl_len using rejection sampling to avoid bias
        let idx: usize;
        let range: u128 = wl_len as u128;
        let max: u128 = u128::from(u128::MAX) - (u128::from(u128::MAX) % range);
        loop {
            // fill 16 bytes and interpret as u128
            let mut buf: [u8; 16] = [0u8; 16];
            rng.fill_bytes(&mut buf);
            let v: u128 = u128::from_le_bytes(buf);
            if v < max {
                idx = (v % range) as usize;
                break;
            }
        }
        words.push(wordlist[idx]);
    }

    words.join(" ")
}

pub fn find_in_editor_content(
    content: &text_editor::Content,
    needle: &str,
) -> Option<(text_editor::Position, text_editor::Position)> {
    if needle.is_empty() {
        return None;
    }

    for (line_index, line) in content.lines().enumerate() {
        let text = line.text; // line.text is the line's &str
        if let Some(byte_pos) = text.find(needle) {
            return Some((
                text_editor::Position {
                    line: line_index,
                    column: byte_pos,
                },
                text_editor::Position {
                    line: line_index,
                    column: byte_pos + needle.len(),
                },
            ));
        }
    }

    None
}

pub fn count_non_overlapping(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }

    let mut count = 0;
    let mut start = 0;

    while let Some(pos) = haystack[start..].find(needle) {
        count += 1;
        start += pos + needle.len(); // start += pos + 1; => allow overlaps
        if start > haystack.len() {
            break;
        }
    }

    count
}
