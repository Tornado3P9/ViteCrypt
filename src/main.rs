mod clipboard;
mod constants;
mod errors;
mod functions;

use constants::MIN_PASSWORD_LEN;

use errors::Error;

use std::path::PathBuf;
use std::sync::Arc;

use iced::Alignment::Center;
use iced::widget::{
    TextInput, button, checkbox, column, container, row, slider, space, text, text_editor, toggler,
    tooltip,
};
use iced::{Border, Color, Element, Length, Padding, Subscription, Task, Theme, exit, keyboard};
use smol_str::SmolStr;

use functions::{
    action, copy_icon, count_non_overlapping, create_alphabet, decrypt, encrypt, eye_icon,
    find_in_editor_content, gen_random_pass, generate_passphrase, is_mnemonic_passphrase,
    is_strong_passphrase, load_wordlist, lupe_icon, new_icon, open_icon, password_input_field,
    paste_icon, pick_file, pick_qr_image, qrcode_open_icon, qrcode_save_icon, save_file, save_icon,
    save_qr_image,
};

use qrcodegen::QrCodeEcc;

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

/// Holds the application's editor state, including the current document,
/// editing and search controls, validation data, and related UI state.
struct Editor {
    path: Option<PathBuf>,
    content: text_editor::Content,
    error: Option<Error>,
    theme: Theme,
    is_dirty: bool,

    // Variable for the theme toggle switch on the right side
    toggler_is_switched: bool,

    // Variables for the hidden search-and-replace controls for the text editor (Ctrl+F)
    search: String,
    replace_with: String,
    find_and_replace_visibility: bool,
    found: usize,
    selected_function: Option<EditorFunction>,

    // Variables for the Password Input buttons on the left side
    first: String,
    second: String,
    validation: (String, String),
    is_password_visible: bool,

    // Variables for the generate-password dialog overlay
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
}

#[derive(Debug, Clone)]
enum Message {
    // Button panel for the editor controls, positioned above the text editor content
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

    // Theme toggle switch on the right side
    ToggleTheme(bool),

    // Hidden search-and-replace controls for the text editor (Ctrl+F)
    SearchChanged(String),
    ReplaceChanged(String),
    FindSelect,
    ToggleRow,
    FunctionSelected(EditorFunction),

    // Functions for the buttons on the left side
    Encrypt,
    Decrypt,
    ClearAll,

    // Functions for the password input field on the left side
    FirstChanged(String),
    SecondChanged(String),
    TogglePasswordVisibility,

    // Additional keyboard shortcut functions
    Exit,
    TabPressed,
    ShiftTabPressed,

    // Elements for the generate-password dialog overlay
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
                if text.is_empty() {
                    println!("Set clipboard ok? false, nothing to copy!");
                    return Task::none();
                }

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
                    return Task::none();
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
                    return Task::none();
                }

                let encrypted_base58: String = self.content.text();
                let encrypted_blob: Vec<u8> = match bs58::decode(encrypted_base58).into_vec() {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Invalid Base58. Failed to decode: {e}");
                        return Task::none();
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
                self.content = text_editor::Content::new(); // text_editor::Content::with_text("");
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
                    self.temp_passphrase =
                        gen_random_pass(self.pass_slider_value, &new_alphabet.into_bytes());
                }

                Task::none()
            }
            Message::MnemonicBtnPressed => {
                if self.passphrase_button {
                    self.passphrase_button = false;
                    self.mnemonic_button = true;
                }

                let wordlist: Vec<&str> = load_wordlist();

                self.temp_passphrase =
                    generate_passphrase(&wordlist, self.mnemonic_slider_value as usize);

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
                            return Task::none(); // the program would crash if self.search is empty
                        }
                        self.is_dirty = true;
                        if let Some(pos) = full_text.find(&self.search) {
                            let mut replaced: String = full_text;
                            replaced
                                .replace_range(pos..pos + self.search.len(), &self.replace_with);

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

    // Global keyboard shortcuts using Iced's subscription API.
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

        // Simple Text Label element displaying the word "Controls"
        // ( because i don't know what else to write besides that this side of the program
        // contains the main controls elements )
        // in the left container
        let controls_title_bar = {
            let controls_title = text("v1.1").size(15); //text("Controls").size(15);
            row![controls_title, space::horizontal()]
        }; // Space::new(Length::Fill, Length::Units(0))

        // Inconspicuous region above the password input lines
        // containing a spacing element and the "Generate password" button
        // ( which, when pressed, will display an overlay window with multiple options
        // for creating a mnemonic passphrase or a random password )
        // in the left container
        let controls_gen_pw_row = {
            let content = column![
                button(text("Generate password").center().size(14)) //button("Generate password")
                    // .style(button::subtle)
                    .style(|theme, status| {
                        let mut style = iced::widget::button::subtle(theme, status);
                        style.border.radius = 15.0.into();
                        style
                    })
                    .on_press(Message::OpenDialog)
                    .padding(Padding::new(0.).top(6).right(11).bottom(7).left(11))
            ];
            let content_container: Element<'_, Message> = container(content).into();
            row![space::horizontal(), content_container]
        };

        // First password input line
        // in the left container
        let controls_primary_pw = {
            let prim_pw_label = container(text("Password").size(13)).padding(iced::padding::left(5)); //text(format!("{}", "Password".to_string())).size(13);
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

        // Second password input line
        // in the left container
        let controls_secondary_pw = {
            let second_pw_label = container(text("Confirm Password").size(13)).padding(iced::padding::left(5)); //text(format!("{}", "Confirm Password".to_string())).size(13);
            let second_pw_input = password_input_field(
                "Second",
                &self.second,
                "input2",
                !self.is_password_visible,
                Message::SecondChanged,
            );
            column![second_pw_label, second_pw_input].spacing(1)
        };

        // Main Buttons for en-/decrypting the text editor content
        // in the left container
        let controls_encrypt_buttons = {
            let encrypt_button = row![
                button(text("Encrypt").center().size(18))
                    .on_press(Message::Encrypt)
                    .width(Length::Fill)
                    .padding(Padding::new(0.).top(10).right(10).bottom(11).left(10))
                    // .style(button::primary)
                    .style(|theme, status| {
                        let mut style = iced::widget::button::primary(theme, status);
                        style.border.radius = 6.0.into();
                        style
                    })
            ];
            let decrypt_button = row![
                button(text("Decrypt").center().size(18))
                    .on_press(Message::Decrypt)
                    .width(Length::Fill)
                    // .padding(Padding::new(0.).top(8).right(10).bottom(9).left(10))
                    .padding(Padding::new(0.).top(9).right(10).bottom(10).left(10))
                    // .style(button::secondary)
                    .style(|theme, status| {
                        let mut style = iced::widget::button::secondary(theme, status);
                        style.border.radius = 6.0.into();
                        style
                    })
            ];
            let clear_button = row![
                button(text("Clear").center().size(18))
                    .on_press(Message::ClearAll)
                    .width(Length::Fill)
                    // .padding(Padding::new(0.).top(8).right(10).bottom(9).left(10))
                    .padding(Padding::new(0.).top(9).right(10).bottom(10).left(10))
                    // .style(button::secondary)
                    .style(|theme, status| {
                        let mut style = iced::widget::button::secondary(theme, status);
                        style.border.radius = 6.0.into();
                        style
                    })
            ];
            column![encrypt_button, decrypt_button, clear_button]
                .spacing(10)
                .padding([10, 0])
        };

        // This is just a column, containing text info lines and a spacing element
        // below the controls_encrypt_buttons
        // in the left container
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

        // This is the button row just above the text editor field
        // in the right container
        let editor_controls = container(row![
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
            action(
                paste_icon(),
                "Paste clipboard text".to_string(),
                Some(Message::Paste)
            ),
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
            toggler(self.toggler_is_switched).on_toggle(Message::ToggleTheme) //.label("toggle theme"))
                                                                              // button("toggle theme")
                                                                              //     .on_press(Message::ToggleTheme)
                                                                              //     .style(button::subtle)
        ]
        .spacing(10)
        .width(Length::FillPortion(3))
        .align_y(iced::Alignment::Center)
        ).padding(iced::Padding {
            top: 8.0,
            right: 15.0,
            bottom: 8.0,
            left: 5.0,
        })
        .style(|_theme| container::Style {
            border: Border {
                color: Color::from_rgb8(0x50, 0x54, 0x5d),
                width: 1.0,
                radius: 10.0.into(),
            },
            ..Default::default()
        });

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

        // "Lupe" is german for "Magnifying glass" because that's what the icon image looks like.
        // "lupe_row" is part of "find_and_replace_row"
        // in the right container
        let lupe_row = container(if self.found == 0usize {
            row![lupe_icon()]
                .spacing(8)
                .align_y(iced::Alignment::Center)
        } else {
            row![lupe_icon(), text(format!("{}", self.found)).size(18)]
                .spacing(8)
                .align_y(iced::Alignment::Center)
        })
        .padding([5, 10])
        .style(|theme: &Theme| container::Style {
            background: Some(
                match theme {
                    Theme::Dark => iced::Color::from_rgb8(0x32, 0x35, 0x39),
                    _ => iced::Color::from_rgb(0.85, 0.92, 1.0),
                }
                .into(),
            ),
            // text_color: Some(iced::Color::from_rgb(1.0, 1.0, 1.0).into()),
            border: iced::border::rounded(16),
            ..container::Style::default()
        });

        // The pick_list widget lets the user choose a function that will be applied to the text editor content.
        // "function_picker" is part of "find_and_replace_row".
        let function_picker = pick_list(
            EditorFunction::ALL,
            self.selected_function,
            Message::FunctionSelected,
        )
        .placeholder("choose");

        // The "find_and_replace_row" above the texte ditor field, which can be toggled via the shortcut "Ctrl+F".
        let find_and_replace_row: Element<_> = if self.find_and_replace_visibility {
            row![
                lupe_row,
                space::horizontal().width(5),
                TextInput::new("find...", &self.search)
                    .width(Length::Fill)
                    .on_input(Message::SearchChanged),
                TextInput::new("replace with...", &self.replace_with)
                    .width(Length::Fill)
                    .on_input(Message::ReplaceChanged),
                space::horizontal().width(5),
                button("Select")
                    .on_press(Message::FindSelect)
                    .style(button::subtle)
                    .padding([5, 10]),
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

        // The actual multi-line text editor field via the default text_editor widget
        // including the "find_and_replace_row" which can be toggled via the shortcut "Ctrl+F".
        // The editor has the id "input3", though even without it, iced allows jumping between
        // input fields using the "TAB-Key".
        let editor_input = column![
            find_and_replace_row,
            text_editor(&self.content)
                .id(iced::widget::Id::new("input3"))
                .on_action(Message::Edit)
                .height(Length::Fill)
                .style(|theme, status| {
                    let mut style = iced::widget::text_editor::default(theme, status);
                    style.border.radius = 10.0.into();
                    style
                })
                .padding(10),
        ];

        // An additional line just below the text editor field displaying the curser position and status/error messages
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
                Some(Error::IOFailed(e)) => text(e.to_string()).size(13),
                _ => {
                    let label = self
                        .path
                        .as_deref()
                        .and_then(|p| p.to_str())
                        .unwrap_or("New file");
                    text(label).size(13)
                }
            };

            let position = {
                let cursor: text_editor::Cursor = self.content.cursor();
                let line: usize = cursor.position.line;
                let column: usize = cursor.position.column;

                text(format!("{}:{}", line + 1, column + 1)).size(13)
            };

            row![status, space::horizontal(), position]
        };

        // The Application window is split into two sides, the left side holding the encryption part, the right side holding the text editor
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
        .padding(Padding::new(0.).top(20).right(20).bottom(0).left(20))
        .style(|_theme| container::Style {
            border: Border {
                color: Color::from_rgb8(0x50, 0x54, 0x5d),
                width: 1.0,
                radius: 10.0.into(),
            },
            ..Default::default()
        });

        // // Example for border style
        // container(
        //     column![text("Inside the bordered container")]
        // )
        // .padding(8)
        // .style(|_theme| container::Style {
        //     border: Border {
        //         color: Color::WHITE,
        //         width: 1.0,
        //         radius: 0.0.into(),
        //     },
        //     ..Default::default()
        // })
        // .into()
        //
        // let border = Border {
        //     color: color!("#50545d"),
        //     width: 1.0,
        //     radius: 0.0.into(),
        // };

        // // -- Start pick_list
        // let dropdown = pick_list(
        //     &[EditorFunction::RemoveLineBreaks, EditorFunction::RemoveSpaces][..],
        //     None,
        //     Message::FunctionSelected,
        // ).placeholder("Choose a function...");
        // // -- End pick_list

        // The Application window is split into two sides, the left side holding the encryption part, the right side holding the text editor
        let right = container(
            column![editor_controls, editor_input, editor_status_bar]
                .spacing(10)
                .height(Length::Fill),
        )
        .width(Length::FillPortion(3))
        .padding(Padding::new(0.).top(10).right(10).bottom(10).left(10))
        .style(|_theme| container::Style {
            border: Border {
                color: Color::from_rgb8(0x50, 0x54, 0x5d),
                width: 1.0,
                radius: 10.0.into(),
            },
            ..Default::default()
        });

        // // This is the previously final line before using the extern dialog overlay widget
        // container(row![left, right].spacing(35)).padding(10).into()

        // -- Begin of the Popup Overlay Menu
        // This is the base or root level of the program and the outer most container which holds everything else in it.
        // In order for me to use the "dialog widget" for the password generator overlay window with the transparent background,
        // I had to assign that outer most layer to it via the variable "base". That's what the dialog widget uses to understand the screen dimensions.
        // IMPORTANT: make the base fill the screen
        let base = container(row![left, right].spacing(35)).padding(10);

        // Creates the password and mnemonic-passphrase buttons for choosing a password-generation option,
        // highlighting the currently selected option.
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

        // Creates another row containing multiple options to refine the previous selections.
        let pass_slider = slider(12..=200, self.pass_slider_value, Message::PassSliderChanged)
            .step(1)
            .width(350)
            .height(30);
        let pass_slider_val: i32 = self.pass_slider_value.clone();
        let pass_slider_row = row![
            text("Password length:").size(14),
            pass_slider,
            text(format!("{}", pass_slider_val))
        ]
        .spacing(20)
        .align_y(iced::Alignment::Center);

        // Creates a row containing the mnemonic slider, which lets the user choose
        // the number of words in the passphrase.
        let mnemonic_slider = slider(
            5..=30,
            self.mnemonic_slider_value,
            Message::MnemomicSliderChanged,
        )
        .step(1)
        .width(350)
        .height(30);
        let mnemonic_slider_val: i32 = self.mnemonic_slider_value.clone();
        let mnemonic_slider_row = row![
            text("Mnemonic length:").size(14),
            mnemonic_slider,
            text(format!("{}", mnemonic_slider_val))
        ]
        .spacing(20)
        .align_y(iced::Alignment::Center);

        // Creates a row of controls for selecting which character types to include
        // when generating a password.
        let cb_a = checkbox(self.a).on_toggle(Message::A);
        let cb_a_label = text("Lowercase").size(14);
        let cb_b = checkbox(self.b).on_toggle(Message::B);
        let cb_b_label = text("Uppercase").size(14);
        let cb_c = checkbox(self.c).on_toggle(Message::C);
        let cb_c_label = text("Numbers").size(14);
        let cb_d = checkbox(self.d).on_toggle(Message::D);
        let cb_d_label = text("Symbols").size(14);

        let pass_checks = row![
            text("Password include:").size(14),
            cb_a,
            cb_a_label,
            cb_b,
            cb_b_label,
            cb_c,
            cb_c_label,
            cb_d,
            cb_d_label
        ]
        .spacing(20)
        .align_y(iced::Alignment::Center);

        // Creates the content row containing the option-refinement rows described above.
        // Also adds a read-only text input displaying the generated password or passphrase.
        // Below that a text description of each option, its pros and cons, and when to use it.
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

        // Putting the dialog together
        iced_dialog::dialog(self.is_open, base, content)
            .title("Generate password")
            .push_button(iced_dialog::button("Cancel", Message::Cancelled).style(button::subtle))
            .push_button(iced_dialog::button("Apply", Message::Applied).style(button::success))
            .width(860)
            .height(450)
            .on_press(Message::Cancelled)
            .into()
    }

    /// Recomputes the password strength and confirmation-match messages
    /// from the current input fields.
    ///
    /// Called as the user types so the UI can display updated validation
    /// feedback immediately.
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

/*********Start Texteditor Dropdown */
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
/*********End Texteditor Dropdown */

/*
TODO:
[_] Light Roundcornered border around containers
[_] Round cornered generate password button
[_] Different Color styles
[_] Normale runde Schrift-Font als default, nur für den Texteditor halt eine gut lesbare schrift, wie aktuell. Das password input_text field zeigt ja eh Punkte.
[x] Option to toggle on/off the password text input visibility/dots
[x] Secure Text is not copy/paste-able anymore in 0.14.0, so i will have to display the generated password to the user in the generate password window itself and give warning message that the user
  has to secury the password before closing the generate window or the password will be lost.
[x] DropDown Menu for QRcode? import/export or at least a dropdown menu for the different texteditor functions like find and replace
[x] or do find and replace as a line below the texteditor which is normally hidden and visibility can be toggled by yet another button on the top line
[x] Error using find button in find and replace line. some characters like ** seem to irritate the counter for any following words and the wrong substring is highlighted! Correct the highlighting function!
[_] Lizenzen
[_] Was mache ich mit den qrcode leveln? aktuell benutze ich automatisch medium aber ich könnte den user das auch wählen lassen. vielleicht doch durch ein dropdown oder so
[_] Optionally add encrypt text with gpg keys that are stored on the system, just like the notepad in kleopatra. basically turing it into a communication encryption tool using the extern gpg terminal tool via background process
*/
