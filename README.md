# ViteCrypt

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

# The clipboard operations are implemented using native operating-system APIs
# or commonly available command-line utilities:
#
# - Windows: PowerShell and `System.Windows.Forms.Clipboard`
# - macOS: `pbcopy` and `pbpaste`
# - Linux/Wayland: `wl-copy` and `wl-paste`
# - Linux/X11: `xclip` or `xsel`
#
# Clipboard access may fail when the required utility is unavailable,
# the desktop session is not accessible, or the operating system denies
# access to the clipboard.
```
