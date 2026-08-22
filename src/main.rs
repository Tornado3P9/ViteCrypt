mod clipboard;

use iced::widget::{
    TextInput, button, column, container, row, space, text,
    text_editor, tooltip, slider, toggler, checkbox,
};
use iced::{
    Element, Font, Length, Padding, Subscription, Task, Theme,
    exit, keyboard,
};

use iced::Alignment::Center;

use smol_str::SmolStr;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

// Encryption Algorithm
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

// Global Constants
const MIN_PASSWORD_LEN: usize = 8; // defining the absolute minimum
const GOOD_PASSWORD_LEN: usize = 12; // ok password length
const MIN_MNEMONIC_WORDS: usize = 6; // min number of words, see is_mnemonic_passphrase()

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32; // 256-bit key

// Error Definition
#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("invalid input")]
    InvalidInput,
    #[error("missing input: provide a file with -i or pipe data to stdin")]
    MissingInput,
    #[error("missing wordlist: include the file wordlist.txt in the src/ directory")]
    MissingWordlist,
    #[error("I/O error: {0}")]
    IoError(String),
    #[error("maximum attempts reached")]
    AttemptsExceeded,
    #[error("key derivation failed")]
    KdfError,
    #[error("encryption failed")]
    EncryptError,
    #[error("decryption failed or authentication tag mismatch")]
    DecryptError,
}

fn derive_key_argon2(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], CryptoError> {
    if salt.len() != SALT_LEN {
        return Err(CryptoError::KdfError);
    }

    // Argon2id parameters (tune for your platform, e.g. memory: 256 MiB (262144 KiB) instead of 64 MB (65536 KiB), time (iterations): 6, parallelism: 4 not 1, None)
    // Note: memory cost is the most important defense.
    let params = argon2::Params::new(65536, 3, 1, None).map_err(|_| CryptoError::KdfError)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key: [u8; 32] = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| CryptoError::KdfError)?;
    Ok(key)
}

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
    // key_bytes and salt will be zeroized when dropped if we explicitly zeroize
    let mut key_bytes_owned: [u8; 32] = key_bytes;
    key_bytes_owned.zeroize();
    salt.zeroize();

    Ok(blob)
}

pub fn decrypt(password: &str, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < SALT_LEN + NONCE_LEN {
        return Err(CryptoError::InvalidInput);
    }

    let salt: &[u8] = &blob[0..SALT_LEN];
    let nonce_bytes: &[u8] = &blob[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ct: &[u8] = &blob[SALT_LEN + NONCE_LEN..];

    let key_bytes: [u8; 32] = derive_key_argon2(password, salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext: Vec<u8> = cipher
        .decrypt(nonce, ct)
        .map_err(|_| CryptoError::DecryptError)?;

    // zeroize key material before returning
    let mut key_bytes_owned: [u8; 32] = key_bytes;
    key_bytes_owned.zeroize();

    Ok(plaintext)
}

/*********Start Texteditor Dropdown Func */
use iced::widget::pick_list;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EditorFunction {
    ReplaceNext,
    ReplaceAll,
    RemoveLineBreaks,
    RemoveSpaces,
}

impl EditorFunction {
    const ALL: &[Self] = &[
        Self::ReplaceNext,
        Self::ReplaceAll,
        Self::RemoveLineBreaks,
        Self::RemoveSpaces,
    ];
}

impl std::fmt::Display for EditorFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::ReplaceNext => "Replace Next",
            Self::ReplaceAll => "Replace All",
            Self::RemoveLineBreaks => "Remove Line Breaks",
            Self::RemoveSpaces => "Remove All Spaces",
        };

        write!(f, "{label}")
    }
}
/*********End Texteditor Dropdown Func */

fn main() -> iced::Result {
    iced::application(Editor::new, Editor::update, Editor::view)
        .subscription(Editor::subscription)
        .title(Editor::title)
        .theme(Editor::theme)
        .settings(iced::Settings {
            id: Some("com.github.tornado3p9.vitecrypt".to_string()),
            ..Default::default()
        })
        .window(iced::window::Settings {
            size: (1280.0, 720.0).into(),
            ..Default::default()
        })
        .default_font(iced::Font::MONOSPACE)
        .font(include_bytes!("../fonts/editor-icons.ttf").as_slice())
        // .font(include_bytes!("../fonts/editor-icons-b.ttf").as_slice()) // multiple fonts possible
        .run()
}

struct Editor {
    path: Option<PathBuf>,
    content: text_editor::Content,
    error: Option<Error>,
    theme: Theme,
    is_dirty: bool,
    search: String,
    replace_with: String,
    find_and_replace_visibility: bool,
    found: usize,
    selected_function: Option<EditorFunction>,

    first: String,
    second: String,
    validation: (String, String),

    is_password_visible: bool,

    is_open: bool,

    passphrase_button: bool,
    mnemonic_button: bool,

    a: bool,
    b: bool,
    c: bool,
    d: bool,

    temp_passphrase: String,
    pass_slider_value: i32,
    mnemonic_slider_value: i32,

    toggler_is_switched: bool,
}

#[derive(Debug, Clone)]
enum Message {
    Edit(text_editor::Action),
    New,
    Open,
    FileOpened(Result<(PathBuf, Arc<String>), Error>),
    Save,
    FileSaved(Result<PathBuf, Error>),
    QRCodeSave,
    QRCodeSaved(Result<PathBuf, Error>),
    QRCodeOPEN,
    QRCodeOPENED(Result<(PathBuf, Arc<String>), Error>),
    Copy,
    Paste,

    SearchChanged(String),
    ReplaceChanged(String),
    FindSelect,
    ToggleRow,
    FunctionSelected(EditorFunction),

    ToggleTheme(bool),

    Encrypt,
    Decrypt,
    ClearAll,
    Exit,

    FirstChanged(String),
    SecondChanged(String),
    TogglePasswordVisibility,

    TabPressed,
    ShiftTabPressed,

    OpenDialog,
    Applied,
    Cancelled,

    PassBtnPressed,
    MnemonicBtnPressed,

    A(bool),
    B(bool),
    C(bool),
    D(bool),

    PassSliderChanged(i32),
    MnemomicSliderChanged(i32),
}

fn is_strong_passphrase(s: &str) -> bool {
    if s.len() < GOOD_PASSWORD_LEN {
        return false;
    }
    let has_upper: bool = s.chars().any(|c| c.is_uppercase());
    let has_lower: bool = s.chars().any(|c| c.is_lowercase());
    let has_digit: bool = s.chars().any(|c| c.is_ascii_digit());
    let has_special: bool = s.chars().any(|c| !c.is_alphanumeric());
    has_upper && has_lower && has_digit && has_special
}

// Returns true if `s` is a mnemonic passphrase consisting of at least `min_words`
// words separated by a single space (no leading/trailing spaces, no consecutive spaces).
fn is_mnemonic_passphrase(s: &str) -> bool {
    if MIN_MNEMONIC_WORDS == 0 {
        return false;
    }
    // Quick rejects: length too short for required words, or leading/trailing space
    if s.is_empty() || s.starts_with(' ') || s.ends_with(' ') {
        return false;
    }
    // 6 words of min 5 letters, each separated by one space make: (6*5)+(6-1) = 35
    // let min_len: usize = (MIN_MNEMONIC_WORDS*5)+(MIN_MNEMONIC_WORDS-1);
    if s.len() < 35 {
        return false;
    }
    // Split on single space and ensure no empty segments (which would indicate consecutive spaces)
    let parts: Vec<&str> = s.split(' ').collect();
    if parts.len() < MIN_MNEMONIC_WORDS {
        return false;
    }
    if parts.iter().any(|p| p.is_empty()) {
        return false;
    }
    // Optionally also check if words are all equal or different
    true
}

// use iced::{button, Background, Color};
// struct SecondaryButton;
// impl button::StyleSheet for SecondaryButton {
//     type Style = ();
//     fn active(&self, _style: &Self::Style) -> button::Appearance {
//         button::Appearance {
//             background: Some(Background::Color(Color::from_rgb8(0xEE,0xEE,0xEE))),
//             border_radius: 4.0,
//             shadow_offset: Default::default(),
//             text_color: Color::BLACK,
//             border_width: 0.0,
//             border_color: Color::TRANSPARENT,
//         }
//     }
//     // hovered/pressed optional overrides...
// }

impl Editor {
    fn new() -> (Self, Task<Message>) {
        (
            Self {
                path: None,
                content: text_editor::Content::new(),
                error: None,
                theme: Theme::Dark,
                is_dirty: true,
                search: String::new(),
                replace_with: String::new(),
                find_and_replace_visibility: false,
                found: 0usize,
                selected_function: None,
                first: String::new(),
                second: String::new(),
                validation: (String::new(), String::new()),
                is_password_visible: false,
                pass_slider_value: 16,
                mnemonic_slider_value: 6,
                is_open: false,
                a: true,
                b: true,
                c: true,
                d: true,
                passphrase_button: true,
                mnemonic_button: false,
                temp_passphrase: "".to_string(),
                toggler_is_switched: false,
            },
            // Task::perform(load_file(default_file()), Message::FileOpened),
            Task::none(), // because of long loading times, removed default_file() and also content: text_editor::Content::new(), already in new()
        )
    }

    fn title(&self) -> String {
        String::from("ViteCrypt")
    }

    fn theme(&self) -> Theme {
        // Theme::Dark
        self.theme.clone()
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Edit(action) => {
                self.is_dirty = self.is_dirty || action.is_edit();
                self.error = None;

                self.content.perform(action);

                Task::none()
            }
            Message::New => {
                self.path = None;
                self.error = None;

                self.content = text_editor::Content::new();
                self.is_dirty = true;

                Task::none()
            }
            Message::Open => Task::perform(pick_file("Choose a text file..."), Message::FileOpened),
            Message::FileOpened(Ok((path, content))) => {
                self.path = Some(path);
                self.error = None;
                // self.content = text_editor::Content::with(&content);
                self.content = text_editor::Content::with_text(&content);
                self.is_dirty = false;

                Task::none()
            }
            Message::FileOpened(Err(error)) => {
                self.error = Some(error);

                Task::none()
            }
            Message::Save => {
                let text: String = self.content.text();

                Task::perform(save_file(self.path.clone(), text), Message::FileSaved)
            }
            Message::FileSaved(Ok(path)) => {
                self.path = Some(path);
                self.error = None;
                self.is_dirty = false;

                Task::none()
            }
            Message::FileSaved(Err(error)) => {
                self.error = Some(error);

                Task::none()
            }
            Message::QRCodeSave => {
                let text: String = self.content.text().to_string();
                let ecc: QrCodeEcc = match "m".to_string().to_lowercase().as_str() {
                    "l" => QrCodeEcc::Low,
                    "m" => QrCodeEcc::Medium,
                    "q" => QrCodeEcc::Quartile,
                    "h" => QrCodeEcc::High,
                    _ => QrCodeEcc::Medium,
                };

                let args_min_size: usize = 500; // example, but no hard value anyway
                let args_border_width: i32 = 4;
                let args_scale: i32 = 10;

                Task::perform(
                    save_qr_image(text, ecc, args_min_size, args_border_width, args_scale),
                    Message::QRCodeSaved,
                )
            }
            Message::QRCodeSaved(Ok(path)) => {
                self.path = Some(path);
                self.error = None;
                self.is_dirty = false;

                Task::none()
            }
            Message::QRCodeSaved(Err(error)) => {
                self.error = Some(error);

                Task::none()
            }
            Message::QRCodeOPEN => Task::perform(
                pick_qr_image("Choose a QRCode PNG image..."),
                Message::QRCodeOPENED,
            ),
            Message::QRCodeOPENED(Ok((_path, content))) => {
                self.path = None;
                self.error = None;

                let current_text: String = self.content.text();
                let combined: String = format!("{}{}", current_text, content); // Append QrCode content after text

                self.content = text_editor::Content::with_text(&combined);
                self.is_dirty = true;

                Task::none()
            }
            Message::QRCodeOPENED(Err(error)) => {
                self.error = Some(error);

                Task::none()
            }
            Message::Copy => {
                self.error = None;

                let text: String = self.content.text().to_string();
                
                let ok: bool = clipboard::set_clipboard_text(&text);
                println!("Set clipboard ok? {}", ok);

                Task::none()
            }
            Message::Paste => {
                self.path = None;
                self.error = None;

                let current_text: String = self.content.text();
                
                if let Some(t) = clipboard::get_clipboard_text() {
                    // println!("Clipboard text: {}", &t);
                    let combined: String = if current_text.is_empty() {
                        t.clone()
                    } else {
                        format!("{}\n{}", current_text, t)
                    }; // Append Clipboard content after text
                    self.content = text_editor::Content::with_text(&combined);
                    self.is_dirty = true;
                }

                Task::none()
            }
            Message::ToggleRow => {
                if self.find_and_replace_visibility {
                    self.find_and_replace_visibility = false;
                } else {
                    self.find_and_replace_visibility = true;
                }
                
                Task::none()
            }
            // Message::ToggleTheme => {
            //     // Version using just a standard button
            //     self.theme = if self.theme == Theme::Light {
            //         Theme::Dark
            //     } else {
            //         Theme::Light
            //     };
            //     Task::none()
            // }
            Message::ToggleTheme(switchstate) => {
                // Version using a switch with two states
                self.toggler_is_switched = switchstate;
                self.theme = if self.toggler_is_switched {
                    Theme::Light
                } else {
                    Theme::Dark
                };
                
                Task::none()
            }
            Message::Encrypt => {
                let text: String = self.content.text();
                let text_as_bytes: &[u8] = text.as_bytes();
                let password1: String = self.first.clone();
                if password1.trim().is_empty() {
                    eprintln!("Error: first password is empty or only contains spaces");
                    return Task::none()
                }
                
                match encrypt(&password1, text_as_bytes) {
                    Ok(encrypted_blob) => {
                        println!("Encryption successful!");

                        let encrypted_base58: String = bs58::encode(encrypted_blob).into_string();
                        // println!("Encrypted data: {:?}", encrypted_base58);

                        self.content = text_editor::Content::with_text(&encrypted_base58);
                        self.is_dirty = true;
                        // // or clear then paste
                        // self.content.perform(text_editor::Action::Edit(text_editor::Edit::Clear));
                        // self.content.perform(text_editor::Action::Edit(text_editor::Edit::Paste(Arc::from(cleartext.into_owned()))));
                    }
                    Err(e) => {
                        eprintln!("Encryption failed: {:?}", e);
                    }
                }

                Task::none()
            }
            Message::Decrypt => {
                let password1: String = self.first.clone();
                if password1.trim().is_empty() {
                    eprintln!("Error: first password is empty or only contains spaces");
                    return Task::none()
                }

                let encrypted_base58: String = self.content.text();
                let encrypted_blob: Vec<u8> = match bs58::decode(encrypted_base58).into_vec() {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Invalid Base58. Failed to decode: {e}");
                        return Task::none()
                    }
                };

                match decrypt(&password1, &encrypted_blob) {
                    Ok(decrypted_cleartext) => {
                        println!("Decryption successful!");
                        // println!("Decrypted data: {}", String::from_utf8_lossy(&decrypted_cleartext));
                        let cleartext: String =
                            String::from_utf8_lossy(&decrypted_cleartext).into_owned();

                        self.content = text_editor::Content::with_text(&cleartext);
                        self.is_dirty = true;
                    }
                    Err(e) => {
                        eprintln!("Decryption failed: {:?}", e);
                    }
                }

                Task::none()
            }
            Message::ClearAll => {
                self.path = None;
                self.error = None;

                self.first.clear();
                self.second.clear();
                self.content = text_editor::Content::new();  // text_editor::Content::with_text("");
                self.is_dirty = true;
                self.search = String::new();
                self.replace_with = String::new();
                self.found = 0usize;

                Task::none()
            }
            Message::Exit => exit(),
            Message::FirstChanged(s) => {
                if s != self.first {
                    self.first = s;
                    self.validation = self.recompute_validation();
                }
                Task::none()
            }
            Message::SecondChanged(s) => {
                if s != self.second {
                    self.second = s;
                    self.validation = self.recompute_validation();
                }
                Task::none()
            }
            Message::TogglePasswordVisibility => {
                self.is_password_visible = !self.is_password_visible;
                Task::none()
            }
            Message::TabPressed => iced::widget::operation::focus_next(),
            Message::ShiftTabPressed => iced::widget::operation::focus_previous(),
            Message::OpenDialog => {
                self.is_open = true;
                Task::none()
            }
            Message::Applied => {
                self.is_open = false;
                self.first = self.temp_passphrase.clone();
                self.second = self.temp_passphrase.clone();
                self.temp_passphrase = "".to_string();
                self.validation = self.recompute_validation();
                Task::none()
            }
            Message::Cancelled => {
                self.is_open = false;
                Task::none()
            }
            Message::PassBtnPressed => {
                if self.mnemonic_button {
                    self.mnemonic_button = false;
                    self.passphrase_button = true;
                }

                if self.a || self.b || self.c || self.d {
                    let new_alphabet: String = create_alphabet(self.a, self.b, self.c, self.d);
                    self.temp_passphrase = gen_random_pass(self.pass_slider_value, &new_alphabet.into_bytes());
                }

                Task::none()
            }
            Message::MnemonicBtnPressed => {
                if self.passphrase_button {
                    self.passphrase_button = false;
                    self.mnemonic_button = true;
                }

                let wordlist: Vec<&str> = load_wordlist();
                // println!("wordlist.len() = {}", wordlist.len()); // Remove before flight!!

                self.temp_passphrase = generate_passphrase(&wordlist, self.mnemonic_slider_value as usize);

                Task::none()
            }
            Message::PassSliderChanged(value) => {
                self.pass_slider_value = value;
                Task::none()
            }
            Message::MnemomicSliderChanged(value) => {
                self.mnemonic_slider_value = value;
                Task::none()
            }
            Message::A(value) => {
                self.a = value;
                Task::none()
            }
            Message::B(value) => {
                self.b = value;
                Task::none()
            }
            Message::C(value) => {
                self.c = value;
                Task::none()
            }
            Message::D(value) => {
                self.d = value;
                Task::none()
            }
            Message::SearchChanged(s) => {
                if s != self.search {
                    self.search = s;
                }
                if self.search.is_empty() {
                    self.found = 0;
                    // println!("No Results"); // remove before flight
                } else {
                    let full_text: String = self.content.text();
                    let result: usize = count_non_overlapping(&full_text, &self.search);
                    // println!("{}", &result); // remove before flight
                    self.found = result;
                }

                Task::none()
            }
            Message::FindSelect => {
                // // Function for highlighting a substring in the editor text
                // println!("Trying to select: \"{}\"", &self.search);

                // // Test Code which works and shows the principle
                // // let start: text_editor::Position = text_editor::Position { line: 0, column: 0 };
                // // let end: text_editor::Position = text_editor::Position { line: 0, column: 5 };
                // let a = text_editor::Position { line: 0, column: 0 };
                // let b = text_editor::Position { line: 0, column: 5 };
                // // normalize: left to right
                // let (start, end) = if (a.line, a.column) <= (b.line, b.column) {
                //     (a, b)
                // } else {
                //     (b, a)
                // };
                // self.content.move_to(text_editor::Cursor {
                //     position: end,
                //     selection: Some(start),
                // });
                
                if let Some((start, end)) = find_in_editor_content(&self.content, &self.search) {
                    self.content.move_to(text_editor::Cursor {
                        position: end,
                        selection: Some(start),
                    });
                }

                // I seem to have to return the selection of text_editor widget via its id as a Task. that works
                iced::widget::operation::focus("input3")
            }
            Message::ReplaceChanged(s) => {
                if s != self.replace_with {
                    self.replace_with = s;
                }
                Task::none()
            }
            Message::FunctionSelected(function) => {
                // self.selected_function = Some(function); // None;
                match function {
                    EditorFunction::ReplaceNext => {
                        // println!("Remove Next selected"); // Remove before flight!!
                        let full_text: String = self.content.text();
                        if self.search.is_empty() {
                            return Task::none() // the program would crash if self.search is empty
                        }
                        self.is_dirty = true;
                        if let Some(pos) = full_text.find(&self.search) {
                            let mut replaced: String = full_text;
                            replaced.replace_range(pos..pos + self.search.len(), &self.replace_with);

                            // Update counter number for substring occurances in text
                            self.found = self.found.saturating_sub(1); //self.found -= 1; but clamp so that not negative

                            // Write modified text back to text_editor
                            self.content = text_editor::Content::with_text(&replaced);
                        }
                        // Without the additional "find" check you could use a oneliner:
                        // self.content = text_editor::Content::with_text(&full_text.replacen(&self.search, &self.replace_with, 1));
                    }
                    EditorFunction::ReplaceAll => {
                        // println!("Remove All selected"); // Remove before flight!!
                        self.is_dirty = true;
                        let full_text: String = self.content.text();
                        let replaced: String = full_text.replace(&self.search, &self.replace_with);
                        self.content = text_editor::Content::with_text(&replaced);
                        self.found = 0;
                        self.find_and_replace_visibility = false;
                    }
                    EditorFunction::RemoveLineBreaks => {
                        // println!("Remove line breaks selected"); // Remove before flight!!
                        self.is_dirty = true;
                        let mut text: String = self.content.text();
                        // let replaced: String = text.replace(['\n', '\r'], "");
                        text.retain(|c| c != '\n' && c != '\r');
                        self.content = text_editor::Content::with_text(&text);
                    }
                    EditorFunction::RemoveSpaces => {
                        // println!("Remove All spaces selected"); // Remove before flight!!
                        self.is_dirty = true;
                        let mut text: String = self.content.text();
                        text.retain(|c| !c.is_whitespace());
                        self.content = text_editor::Content::with_text(&text);
                        // If you just want to remove all single spaces: let despaced = full_text.replace(' ', "");
                        // If you only want to remove whitespace from the beginning and end: let trimmed = full_text.trim();
                        // If you want to collapse runs of whitespace into a single space: let normalized = full_text.split_whitespace().collect::<Vec<_>>().join(" ");
                        self.find_and_replace_visibility = false;
                    }
                }
                Task::none()
            }
        }
    }

    fn subscription(&self) -> Subscription<Message> {
        keyboard::listen().filter_map(|event| match event {
            keyboard::Event::KeyPressed { key, modifiers, .. } => match key {
                keyboard::Key::Character(s)
                    if s == SmolStr::new("s") && (modifiers.command() || modifiers.control()) =>
                {
                    Some(Message::Save)
                }
                keyboard::Key::Character(q)
                    if q == SmolStr::new("q") && (modifiers.command() || modifiers.control()) =>
                {
                    Some(Message::Exit)
                }
                keyboard::Key::Named(keyboard::key::Named::Enter)
                    if modifiers.command() || modifiers.control() =>
                {
                    Some(Message::Encrypt)
                }
                keyboard::Key::Named(keyboard::key::Named::Enter) if modifiers.alt() => {
                    Some(Message::Decrypt)
                }
                keyboard::Key::Named(keyboard::key::Named::Tab) if modifiers.command() => {
                    Some(Message::ShiftTabPressed)
                }
                keyboard::Key::Named(keyboard::key::Named::Tab) => Some(Message::TabPressed),
                keyboard::Key::Named(keyboard::key::Named::Escape) => Some(Message::ClearAll),
                keyboard::Key::Character(f)
                    if f == SmolStr::new("f") && (modifiers.command() || modifiers.control()) =>
                {
                    Some(Message::ToggleRow)
                }
                _ => None,
            },
            _ => None,
        })
    }

    fn view(&self) -> Element<'_, Message> {
        let controls_title_bar = {
            let controls_title = text("Controls").size(15);
            row![controls_title, space::horizontal()]
        }; // Space::new(Length::Fill, Length::Units(0))

        let controls_gen_pw_row = {
            let content = column![
                button("Generate password")
                    .style(button::subtle)
                    .on_press(Message::OpenDialog)
                    .padding(Padding::new(0.).top(6).right(10).bottom(7).left(10))
            ];
            let content_container: Element<'_, Message> = container(content).into();
            row![space::horizontal(), content_container]
        };

        let controls_primary_pw = {
            let prim_pw_label = text(format!("{}", "Password".to_string())).size(13);
            let prim_pw_input = row![
                password_input_field(
                    "First",
                    &self.first,
                    "input1",
                    !self.is_password_visible,
                    Message::FirstChanged
                ),
                button(eye_icon(self.is_password_visible))
                    .style(button::text)
                    // .padding(Padding::new(0.).top(6).right(10).bottom(7).left(10))
                    .on_press(Message::TogglePasswordVisibility)
            ]
            .align_y(Center);
            column![prim_pw_label, prim_pw_input].spacing(1)
        };

        let controls_secondary_pw = {
            let second_pw_label = text(format!("{}", "Confirm Password".to_string())).size(13);
            let second_pw_input = password_input_field(
                "Second",
                &self.second,
                "input2",
                !self.is_password_visible,
                Message::SecondChanged,
            );
            column![second_pw_label, second_pw_input].spacing(1)
        };

        let controls_encrypt_buttons = {
            let encrypt_button = row![
                button(text("Encrypt").center().size(18))
                    .on_press(Message::Encrypt)
                    .width(Length::Fill)
                    .padding(Padding::new(0.).top(8).right(10).bottom(9).left(10))
                    .style(button::primary)
            ];
            let decrypt_button = row![
                button(text("Decrypt").center().size(18))
                    .on_press(Message::Decrypt)
                    .width(Length::Fill)
                    .padding(Padding::new(0.).top(8).right(10).bottom(9).left(10))
                    .style(button::secondary)
            ];
            let clear_button = row![
                button(text("Clear").center().size(18))
                    .on_press(Message::ClearAll)
                    .width(Length::Fill)
                    .padding(Padding::new(0.).top(8).right(10).bottom(9).left(10))
                    .style(button::secondary)
            ];
            column![encrypt_button, decrypt_button, clear_button]
                .spacing(10)
                .padding([10, 0])
        };

        let controls_pw_check_response = {
            let (validation_text_pw_strength, validation_text_pw_match) = self.validation.clone();

            let shortcuts_content = row![
                // text("Shortcuts: ").size(9),
                text("⌘").size(16),
                text("Enter encrypt • ").size(9),
                text("⌥").size(16),
                text("Enter decrypt • ").size(9),
                text("⌘").size(16),
                text("S save • ").size(9),
                text("⌘").size(16),
                text("F find • Esc clear • ").size(9),
                text("⌘").size(16),
                text("Q exit").size(9)
            ]
            .align_y(iced::Alignment::Center);

            // let keyboard_shortcuts = tooltip(
            //     button(shortcuts_content)
            //     .style(button::text),
            //     text("[Ctrl+Enter] encrypt • [Alt+Enter] decrypt • [Ctrl+S] save • [Esc] clear • [Ctrl+Q] exit").size(9),
            //     tooltip::Position::Top,
            // )
            // .delay(Duration::from_millis(500)) // default is Duration::ZERO
            // .style(container::rounded_box)
            // .gap(3);
            let keyboard_shortcuts = tooltip(
                button(shortcuts_content).style(button::text),
                container(text("Shortcut: [Ctrl+Enter] encrypt • [Alt+Enter] decrypt • [Ctrl+S] save • [Ctrl+F] find • [Esc] clear • [Ctrl+Q] exit").size(16))
                    .padding(Padding::new(0.).top(2).right(3).bottom(3).left(3))
                    .style(container::rounded_box),
                tooltip::Position::FollowCursor,
            );

            column![
                text(validation_text_pw_strength),
                text(validation_text_pw_match),
                space::vertical(),
                keyboard_shortcuts
            ]
            .spacing(1)
        };

        let editor_controls = row![
            action(new_icon(), "New file".to_string(), Some(Message::New)),
            action(open_icon(), "Open file".to_string(), Some(Message::Open)),
            action(
                save_icon(),
                "Save file".to_string(),
                self.is_dirty.then_some(Message::Save)
            ),
            action(
                qrcode_open_icon(),
                "Open/scan QR code from a PNG file".to_string(),
                Some(Message::QRCodeOPEN)
            ),
            action(
                qrcode_save_icon(),
                "Create/Save QR code file".to_string(),
                Some(Message::QRCodeSave)
            ),
            action(paste_icon(), "Paste clipboard text".to_string(), Some(Message::Paste)),
            action(
                copy_icon(),
                "Copy to clipboard".to_string(),
                Some(Message::Copy)
            ),
            // action(
            //     lupe_icon(),
            //     "find and replace".to_string(),
            //     Some(Message::ToggleRow)
            // ),
            space::horizontal(),
            toggler(self.toggler_is_switched)
                .on_toggle(Message::ToggleTheme) //.label("toggle theme"))
            // button("toggle theme")
            //     .on_press(Message::ToggleTheme)
            //     .style(button::subtle)
        ]
        .spacing(10)
        .width(Length::FillPortion(3))
        .align_y(iced::Alignment::Center);

        // let lupe_row = container(
        //     row![lupe_icon(), text(format!("{}", &self.found)).size(18)]
        //         .spacing(8)
        //         .align_y(iced::Alignment::Center)
        // )
        // .padding([5, 10])
        // .style(|theme: &Theme| container::Style {
        //     background: Some(match theme {
        //         Theme::Dark => iced::Color::from_rgb8(0x32, 0x35, 0x39),
        //         _ => iced::Color::from_rgb(0.85, 0.92, 1.0),
        //     }.into()),
        //     // text_color: Some(iced::Color::from_rgb(1.0, 1.0, 1.0).into()),
        //     border: iced::border::rounded(16),
        //     ..container::Style::default()
        // });

        let lupe_row = container(
            if self.found == 0usize {
            row![lupe_icon()]
                .spacing(8)
                .align_y(iced::Alignment::Center)
            } else {
                row![lupe_icon(), text(format!("{}", self.found)).size(18)]
                    .spacing(8)
                    .align_y(iced::Alignment::Center)
            }
        )
        .padding([5, 10])
        .style(|theme: &Theme| container::Style {
            background: Some(match theme {
                Theme::Dark => iced::Color::from_rgb8(0x32, 0x35, 0x39),
                _ => iced::Color::from_rgb(0.85, 0.92, 1.0),
            }.into()),
            // text_color: Some(iced::Color::from_rgb(1.0, 1.0, 1.0).into()),
            border: iced::border::rounded(16),
            ..container::Style::default()
        });

        let function_picker = pick_list(
            EditorFunction::ALL,
            self.selected_function,
            Message::FunctionSelected,
        ).placeholder("choose");

        let find_and_replace_row: Element<_> = if self.find_and_replace_visibility {
            row![
                lupe_row,
                space::horizontal().width(5),
                TextInput::new("find...", &self.search).width(Length::Fill).on_input(Message::SearchChanged),
                TextInput::new("replace with...", &self.replace_with).width(Length::Fill).on_input(Message::ReplaceChanged),
                space::horizontal().width(5),
                button("Select").on_press(Message::FindSelect).style(button::subtle).padding([5, 10]),
                function_picker,
            ]
            .padding(Padding::new(0.).top(0).right(0).bottom(5).left(0))
            // .padding([5, 0])
            .spacing(5)
            .align_y(iced::Alignment::Center)
            .into()
        } else {
            iced::widget::Space::new().into() // or column![].into()
        };
        let editor_input = column![
            find_and_replace_row,
            text_editor(&self.content)
                .id(iced::widget::Id::new("input3"))
                .on_action(Message::Edit)
                .height(Length::Fill),
        ];

        let editor_status_bar = {
            // let status = if let Some(Error::IOFailed(error)) = self.error.as_ref() {
            //     text(error.to_string()).size(14)
            // } else {
            //     match self.path.as_deref().and_then(Path::to_str) {
            //         Some(path) => text(path).size(14),
            //         None => text("New file").size(14),
            //     }
            // };
            /* For better readability: */
            let status = match self.error.as_ref() {
                Some(Error::IOFailed(e)) => text(e.to_string()).size(14),
                _ => {
                    let label = self
                        .path
                        .as_deref()
                        .and_then(|p| p.to_str())
                        .unwrap_or("New file");
                    text(label).size(14)
                }
            };

            let position = {
                let cursor: text_editor::Cursor = self.content.cursor();
                let line: usize = cursor.position.line;
                let column: usize = cursor.position.column;

                text(format!("{}:{}", line + 1, column + 1))
            };

            row![status, space::horizontal(), position]
        };

        let left = container(
            column![
                controls_title_bar,
                controls_gen_pw_row,
                controls_primary_pw,
                controls_secondary_pw,
                controls_encrypt_buttons,
                controls_pw_check_response,
                // keyboard_shortcuts
            ]
            .spacing(10),
        )
        .width(Length::FillPortion(2))
        .padding(Padding::new(0.).top(20).right(0).bottom(0).left(20));

        // /***************Start Func */
        // let dropdown = pick_list(
        //     &[EditorFunction::RemoveLineBreaks, EditorFunction::RemoveSpaces][..],
        //     None,
        //     Message::FunctionSelected,
        // ).placeholder("Choose a function...");
        // /***************End Func */
        let right = container(
            column![editor_controls, editor_input, editor_status_bar]
                .spacing(10)
                .height(Length::Fill),
        )
        .width(Length::FillPortion(3));

        // container(row![left, right].spacing(35)).padding(10).into() // the original final line
        let base = container(row![left, right].spacing(35)).padding(10);


        /**** Popup Overlay Menu ****/

        // IMPORTANT: make the base fill the screen
        // The base is that thing which fills the screen, meaning the outer most box. That's what dialog widget uses to understand the screen dimensions.
        let gen_buttons_row = {
            let random_pass = button("Random password")
                .style(if self.passphrase_button {
                    button::primary
                } else {
                    button::subtle
                })
                .on_press(Message::PassBtnPressed)
                .padding(Padding::new(0.).top(6).right(10).bottom(7).left(10));

            let mnemonic = button("Mnemonic passphrase")
                .style(if self.mnemonic_button {
                    button::primary
                } else {
                    button::subtle
                })
                .on_press(Message::MnemonicBtnPressed)
                .padding(Padding::new(0.).top(6).right(10).bottom(7).left(10));
            
            let content = row![
                random_pass,
                space::horizontal().width(120),
                // iced::widget::Space::new().width(iced::Length::Fixed(100.0)), // works the same
                mnemonic,
            ];
            let pass_container: Element<'_, Message> = container(content).into();
            pass_container
        };

        let pass_slider = slider(12..=200, self.pass_slider_value, Message::PassSliderChanged)
            .step(1)
            .width(350)
            .height(30);
        let pass_slider_val: i32 = self.pass_slider_value.clone();
        let pass_slider_row = row![text("Password length:").size(14), pass_slider, text(format!("{}", pass_slider_val))]
            .spacing(20)
            .align_y(iced::Alignment::Center);

        let mnemonic_slider = slider(5..=30, self.mnemonic_slider_value, Message::MnemomicSliderChanged)
            .step(1)
            .width(350)
            .height(30);
        let mnemonic_slider_val: i32 = self.mnemonic_slider_value.clone();
        let mnemonic_slider_row = row![text("Mnemonic length:").size(14), mnemonic_slider, text(format!("{}", mnemonic_slider_val))]
            .spacing(20)
            .align_y(iced::Alignment::Center);

        let cb_a = checkbox(self.a).on_toggle(Message::A);
        let cb_a_label = text("Lowercase").size(14);
        let cb_b = checkbox(self.b).on_toggle(Message::B);
        let cb_b_label = text("Uppercase").size(14);
        let cb_c = checkbox(self.c).on_toggle(Message::C);
        let cb_c_label = text("Numbers").size(14);
        let cb_d = checkbox(self.d).on_toggle(Message::D);
        let cb_d_label = text("Symbols").size(14);

        let pass_checks = row![text("Password include:").size(14), cb_a, cb_a_label, cb_b, cb_b_label, cb_c, cb_c_label, cb_d, cb_d_label]
            .spacing(20)
            .align_y(iced::Alignment::Center);

        let content = container(column![
            text("Choose between a random password or a mnemonic passphrase.").size(14),
            gen_buttons_row,
            pass_slider_row,
            pass_checks,
            mnemonic_slider_row,
            TextInput::new("", &self.temp_passphrase)
                .width(Length::Fill)
                .padding(Padding::from(10))
                .line_height(text::LineHeight::Relative(1.75)),
            text("  Random password: characters, numbers, symbols – good for single-use secrets.\n  Mnemonic passphrase: a sequence of common words – easier to remember and type.").size(14),
        ].spacing(10));
        iced_dialog::dialog(self.is_open, base, content)
            .title("Generate password")
            .push_button(iced_dialog::button("Cancel", Message::Cancelled).style(button::subtle))
            .push_button(iced_dialog::button("Apply", Message::Applied).style(button::success))
            .width(860)
            .height(450)
            .on_press(Message::Cancelled)
            .into()
    }

    fn recompute_validation(&self) -> (String, String) {
        if self.first.len() < MIN_PASSWORD_LEN {
            (
                format!(
                    "Password must be at least {} chars and should include upper, lower, digit, and special character",
                    MIN_PASSWORD_LEN
                ),
                String::new(),
            )
        } else if is_mnemonic_passphrase(&self.first) {
            let strength: &str = "Mnemonic passphrase";
            let match_msg: &str = if self.first == self.second {
                "Passphrases match"
            } else {
                "Passphrases do not match"
            };
            (strength.to_string(), match_msg.to_string())
        } else {
            let strength: &str = if is_strong_passphrase(&self.first) {
                "Password strength: Good"
            } else {
                "Password strength: Weak"
            };

            let match_msg: &str = if self.first == self.second {
                "Passwords match"
            } else {
                "Passwords do not match"
            };

            (strength.to_string(), match_msg.to_string())
        }
    }
}

// fn first_input_field(_placeholder: &str, _value: &str) -> TextInput<'static, Message> {
//     TextInput::new(_placeholder, _value)
//         .width(Length::Fill)
//         .padding(Padding::from(10))
//         .line_height(text::LineHeight::Relative(1.75))
//         .on_input(Message::FirstChanged)
//         .password()
// }
// fn second_input_field(_placeholder: &str, _value: &str) -> TextInput<'static, Message> {
//     ...
// }

fn password_input_field<F>(
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

fn action(
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

fn eye_icon<'a>(visible: bool) -> Element<'a, Message> {
    if visible {
        icon('\u{E804}')
    } else {
        icon('\u{E805}')
    }
}

fn new_icon<'a>() -> Element<'a, Message> {
    icon('\u{E802}')
}

fn open_icon<'a>() -> Element<'a, Message> {
    icon('\u{F115}')
}

fn save_icon<'a>() -> Element<'a, Message> {
    icon('\u{E803}')
}

fn qrcode_open_icon<'a>() -> Element<'a, Message> {
    icon('\u{E800}')
}

fn qrcode_save_icon<'a>() -> Element<'a, Message> {
    icon('\u{E801}')
}

fn copy_icon<'a>() -> Element<'a, Message> {
    icon('\u{F0C5}')
}

fn paste_icon<'a>() -> Element<'a, Message> {
    icon('\u{F0EA}')
}

fn icon<'a, Message>(codepoint: char) -> Element<'a, Message> {
    const ICON_FONT: Font = Font::with_name("editor-icons");

    // text(codepoint).font(ICON_FONT).into() // 16 was default
    text(codepoint).font(ICON_FONT).size(18).into()
}

fn lupe_icon<'a>() -> Element<'a, Message> {
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

fn icon_b<'a, Message>(codepoint: char) -> Element<'a, Message> {
    const ICON_FONT: Font = Font::with_name("editor-icons");

    // text(codepoint).font(ICON_FONT).into() // 16 was default
    text(codepoint).font(ICON_FONT).size(16).into()
}

async fn pick_file(title_str: &str) -> Result<(PathBuf, Arc<String>), Error> {
    let handle = rfd::AsyncFileDialog::new()
        .set_title(title_str)
        .pick_file()
        .await
        .ok_or(Error::DialogClosed)?;

    load_file(handle.path().to_owned()).await
}

async fn load_file(path: PathBuf) -> Result<(PathBuf, Arc<String>), Error> {
    let contents = tokio::fs::read_to_string(&path)
        .await
        .map(Arc::new)
        .map_err(|error| error.kind())
        .map_err(Error::IOFailed)?;

    Ok((path, contents))
}

async fn save_file(path: Option<PathBuf>, text: String) -> Result<PathBuf, Error> {
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

async fn pick_qr_image(title_str: &str) -> Result<(PathBuf, Arc<String>), Error> {
    let handle = rfd::AsyncFileDialog::new()
        .set_title(title_str)
        .pick_file()
        .await
        .ok_or(Error::DialogClosed)?;

    load_qr_image(handle.path().to_owned()).await
}

async fn load_qr_image(path: PathBuf) -> Result<(PathBuf, Arc<String>), Error> {
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

async fn save_qr_image(
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

// Writes the given QrCode object to a PNG image with the specified scale and border width.
fn write_to_png_scaled(
    qr: &QrCode,
    border: i32,
    scale_factor: u32,
    file_path: &Path,
) -> Result<(), String> {
    // Validate inputs
    if border < 0 {
        return Err("Border must be non-negative".to_string());
    }
    if scale_factor < 1 {
        return Err("Scale factor must be positive".to_string());
    }

    // Calculate image size
    let size: i32 = qr.size();
    let img_size: u32 = (size + 2 * border) as u32;
    let mut img: ImageBuffer<Luma<u8>, Vec<u8>> =
        ImageBuffer::from_pixel(img_size, img_size, Luma([255u8]));

    // Draw QR code onto the image
    for y in 0..size {
        for x in 0..size {
            if qr.get_module(x, y) {
                img.put_pixel((x + border) as u32, (y + border) as u32, Luma([0u8]));
            }
        }
    }

    // Scale the image
    let scaled_img: ImageBuffer<Luma<u8>, Vec<u8>> = image::imageops::resize(
        &img,
        img_size * scale_factor,
        img_size * scale_factor,
        FilterType::Nearest,
    );

    // Save the scaled image as a PNG file
    scaled_img
        .save(file_path)
        .map_err(|e| format!("Failed to save PNG file: {}", e))
}

fn create_alphabet(include_lowercase: bool, include_uppercase: bool, include_numbers: bool, include_special: bool) -> String {
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
fn get_random_char(charset: &[u8]) -> char {
    let mut rng: OsRng = OsRng;
    let idx: usize = rng.next_u32() as usize % charset.len();
    charset[idx] as char
}
fn gen_random_pass(len: i32, charset: &[u8]) -> String {
    let pass: String = (0..len)
        .map(|_| get_random_char(&charset))
        .collect();

    pass
}

// Load embedded wordlist (one word per line, empty lines are ignored)
fn load_wordlist() -> Vec<&'static str> {
    let s: &'static str = include_str!("wordlist.txt");
    s.lines().map(str::trim).filter(|l| !l.is_empty()).collect()
}

// Generate a secure random mnemonic passphrase of length x.
fn generate_passphrase(wordlist: &[&str], n_words: usize) -> String {
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


fn find_in_editor_content(
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
                text_editor::Position { line: line_index, column: byte_pos },
                text_editor::Position { line: line_index, column: byte_pos + needle.len() },
            ));
        }
    }

    None
}


fn count_non_overlapping(haystack: &str, needle: &str) -> usize {
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


#[derive(Debug, Clone)]
enum Error {
    DialogClosed,
    IOFailed(io::ErrorKind),
    QrCodeGenerationFailed,
    PngWriteFailed,
}

/*
TODO:
[_] Light Roundcornered border around containers
[_] Round cornered generate password button
[_] Different Color styles
[_] https://deepwiki.com/iced-rs/iced/1.1-getting-started#common-widgets-and-macros
  Stack stack![...]	Overlays widgets on top of each other, vielleicht kann ich damit ja as generate_password window mit transparentem overlay machen oder so...oder einfach kompletter overlay
[_] Normale runde Schrift-Font als default, nur für den Texteditor halt eine gut lesbare schrift, wie aktuell. Das password input_text field zeigt ja eh Punkte.
[x] Option to toggle on/off the password text input visibility/dots
[x] Secure Text is not copy/paste-able anymore in 0.14.0, so i will have to display the generated password to the user in the generate password window itself and give warning message that the user
  has to secury the password before closing the generate window or the password will be lost.
[_] DropDown Menu for QRcode? import/export or at least a dropdown menu for the different texteditor functions like find and replace
[x] or do find and replace as a line below the texteditor which is normally hidden and visibility can be toggled by yet another button on the top line
[x] Error using find button in find and replace line. some characters like ** seem to irritate the counter for any following words and the wrong substring is highlighted! Correct the highlighting function!
[_] Lizenzen
[_] Clean clipboard after n seconds!
[_] Was mache ich mit den qrcode leveln? aktuell benutze ich automatisch medium aber ich könnte den user das auch wählen lassen. vielleicht doch durch ein dropdown oder so
[_] Optionally add encrypt text with gpg keys that are stored on the system, just like the notepad in kleopatra. basically turing it into a communication encryption tool using the extern gpg terminal tool via background process
[_] Die ganzen println lines müssen ja auch gelöscht werden, bevor ich das echt benutze
*/
