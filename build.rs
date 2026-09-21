use std::{fs, path::Path};

const MIN_WORDS: usize = 2_000;

fn main() {
    let wordlist_path = Path::new("src/wordlist.txt");

    // Re-run this build script whenever the wordlist changes.
    println!("cargo:rerun-if-changed={}", wordlist_path.display());

    let contents = fs::read_to_string(wordlist_path).unwrap_or_else(|error| {
        panic!(
            "failed to read {}: {error}",
            wordlist_path.display()
        )
    });

    let word_count = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .count();

    if word_count < MIN_WORDS {
        panic!(
            "{} must contain at least {} words, but contains {}",
            wordlist_path.display(),
            MIN_WORDS,
            word_count
        );
    }
}
