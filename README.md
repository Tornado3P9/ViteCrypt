# ViteCrypt

Powered by 🦀 Rust and 🧊 iced v0.14.0

A local desktop application for encrypting text, saving it as a PNG QR code, and decrypting text from QR codes.
This project was built to test the iced-rs framework on Linux and is intended for experimentation rather than professional use.
While it’s available for anyone to use, it isn’t recommended for handling sensitive data or production use.

The clipboard operations are implemented using native operating-system APIs  
or commonly available command-line utilities:

- **Windows**: PowerShell and `System.Windows.Forms.Clipboard`
- **macOS**: `pbcopy` and `pbpaste`
- **Linux/Wayland**: `wl-copy` and `wl-paste`
- **Linux/X11**: `xclip` or `xsel`

Clipboard access may fail when the required utility is unavailable,
the desktop session is not accessible, or the operating system denies
access to the clipboard.

You must have [rust](https://rust-lang.org/) installed on your system if you want to compile the code manually:
```bash
# build release binary
cargo build --release

# build release cross-compiled Windows executable on linux
sudo apt install mingw-w64 binutils-mingw-w64-x86-64 gcc-mingw-w64-x86-64 # sudo dnf install mingw64-binutils mingw64-gcc
command -v x86_64-w64-mingw32-dlltool
rustup target list
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu

# build macos but only on a mac because you need their specific linker
rustup target list
rustup target add aarch64-apple-darwin
cargo build --release --target aarch64-apple-darwin
```
