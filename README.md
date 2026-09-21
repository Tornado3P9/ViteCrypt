# ViteCrypt

# build release binary
cargo build --release

# build release cross-compiled Windows executable
sudo apt install mingw-w64 binutils-mingw-w64-x86-64 gcc-mingw-w64-x86-64 # sudo dnf install mingw64-binutils mingw64-gcc
command -v x86_64-w64-mingw32-dlltool
rustup target list
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu

# build macos but only on a mac because you need their specific linker
rustup target list
rustup target add aarch64-apple-darwin
cargo build --release --target aarch64-apple-darwin
