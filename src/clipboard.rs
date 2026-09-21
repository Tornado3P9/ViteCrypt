// src/clipboard.rs
use std::io;

fn is_empty_or_whitespace(s: &str) -> bool {
    s.trim().is_empty()
}

// Windows-only function
fn run_status(cmd: &mut std::process::Command) -> io::Result<()> {
    let status = cmd.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("command failed: {status}"),
        ))
    }
}

fn run_capture_stdout(cmd: &mut std::process::Command) -> io::Result<String> {
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("command failed: {:?}", out.status),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[cfg(target_os = "windows")]
pub fn get_clipboard_text() -> Option<String> {
    let ps = r#"
        try {
            Add-Type -AssemblyName System.Windows.Forms | Out-Null
            $t = [System.Windows.Forms.Clipboard]::GetText()
            if ($null -eq $t) { "" } else { $t }
        } catch { "" }
    "#;

    let mut cmd = std::process::Command::new("powershell");
    cmd.args(["-NoProfile", "-STA", "-Command", ps]);

    let s = run_capture_stdout(&mut cmd).ok()?;
    let s = s.trim_end_matches(&['\r', '\n'][..]).to_string();

    if is_empty_or_whitespace(&s) {
        None
    } else {
        Some(s)
    }
}

#[cfg(target_os = "windows")]
pub fn set_clipboard_text(text: &str) -> bool {
    let ps = r#"
        param([string]$t)
        try {
            Add-Type -AssemblyName System.Windows.Forms | Out-Null
            [System.Windows.Forms.Clipboard]::SetText($t)
            exit 0
        } catch { exit 1 }
    "#;

    let mut cmd = std::process::Command::new("powershell");
    cmd.args(["-NoProfile", "-STA", "-Command", ps, "--", text]);

    run_status(&mut cmd).is_ok()
}

#[cfg(target_os = "macos")]
pub fn get_clipboard_text() -> Option<String> {
    let mut cmd = std::process::Command::new("pbpaste");
    let s = run_capture_stdout(&mut cmd).ok()?;
    let s = s.trim_end_matches(&['\r', '\n'][..]).to_string();

    if is_empty_or_whitespace(&s) {
        None
    } else {
        Some(s)
    }
}

#[cfg(target_os = "macos")]
pub fn set_clipboard_text(text: &str) -> bool {
    let mut child = match std::process::Command::new("pbcopy")
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    if let Some(stdin) = child.stdin.as_mut() {
        use std::io::Write;
        if stdin.write_all(text.as_bytes()).is_err() {
            return false;
        }
    } else {
        return false;
    }

    child.wait().map(|s| s.success()).unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn program_exists(cmd: &str) -> bool {
    std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {} >/dev/null 2>&1", cmd))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn linux_is_wayland() -> bool {
    let session_type = std::env::var("XDG_SESSION_TYPE")
        .unwrap_or_default()
        .to_lowercase();
    session_type.contains("wayland") || std::env::var_os("WAYLAND_DISPLAY").is_some()
}

#[cfg(target_os = "linux")]
pub fn get_clipboard_text() -> Option<String> {
    let is_wayland: bool = linux_is_wayland();

    if is_wayland {
        if !program_exists("wl-paste") {
            return None;
        }

        let try_cmds: &[&[&str]] = &[
            &["wl-paste", "--type", "text", "--no-newline"],
            &["wl-paste", "--type", "text"],
            &["wl-paste", "--no-newline"],
            &["wl-paste"],
        ];

        for args in try_cmds {
            let mut cmd: std::process::Command = std::process::Command::new(args[0]);
            cmd.args(&args[1..]);

            if let Ok(s) = run_capture_stdout(&mut cmd) {
                let s: String = s.trim_end_matches(&['\r', '\n'][..]).to_string();
                if !is_empty_or_whitespace(&s) {
                    return Some(s);
                }
            }
        }
        None
    } else {
        if program_exists("xclip") {
            let try_cmds: &[&[&str]] = &[
                &["xclip", "-selection", "clipboard", "-o"],
                &["xclip", "-selection", "clipboard", "-out"],
            ];

            for args in try_cmds {
                let mut cmd: std::process::Command = std::process::Command::new(args[0]);
                cmd.args(&args[1..]);

                if let Ok(s) = run_capture_stdout(&mut cmd) {
                    let s: String = s.trim_end_matches(&['\r', '\n'][..]).to_string();
                    if !is_empty_or_whitespace(&s) {
                        return Some(s);
                    }
                }
            }
        }

        if program_exists("xsel") {
            let try_cmds: &[&[&str]] = &[
                &["xsel", "--clipboard", "--output"],
                &["xsel", "--clipboard", "--out"],
            ];

            for args in try_cmds {
                let mut cmd: std::process::Command = std::process::Command::new(args[0]);
                cmd.args(&args[1..]);

                if let Ok(s) = run_capture_stdout(&mut cmd) {
                    let s: String = s.trim_end_matches(&['\r', '\n'][..]).to_string();
                    if !is_empty_or_whitespace(&s) {
                        return Some(s);
                    }
                }
            }
        }

        None
    }
}

#[cfg(target_os = "linux")]
pub fn set_clipboard_text(text: &str) -> bool {
    // Wayland: wl-copy
    if linux_is_wayland() {
        if !program_exists("wl-copy") {
            return false;
        }

        let mut child: std::process::Child = match std::process::Command::new("wl-copy")
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        if let Some(stdin) = child.stdin.as_mut() {
            use std::io::Write;
            if stdin.write_all(text.as_bytes()).is_err() {
                return false;
            }
        } else {
            return false;
        }

        return child.wait().map(|s| s.success()).unwrap_or(false);
    }

    // X11: try xclip then xsel (best-effort fallback)
    if program_exists("xclip") {
        let res = (|| -> Result<bool, ()> {
            let mut child: std::process::Child = std::process::Command::new("xclip")
                .args(["-selection", "clipboard", "-i"])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .map_err(|_| ())?;

            {
                let stdin: &mut std::process::ChildStdin = child.stdin.as_mut().ok_or(())?;
                use std::io::Write;
                stdin.write_all(text.as_bytes()).map_err(|_| ())?;
            }

            let status: std::process::ExitStatus = child.wait().map_err(|_| ())?;
            Ok(status.success())
        })();

        if matches!(res, Ok(true)) {
            return true;
        }
        // otherwise fall through to xsel
    }

    if program_exists("xsel") {
        let res = (|| -> Result<bool, ()> {
            let mut child: std::process::Child = std::process::Command::new("xsel")
                .args(["--clipboard", "--input"])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .map_err(|_| ())?;

            {
                let stdin: &mut std::process::ChildStdin = child.stdin.as_mut().ok_or(())?;
                use std::io::Write;
                stdin.write_all(text.as_bytes()).map_err(|_| ())?;
            }

            let status: std::process::ExitStatus = child.wait().map_err(|_| ())?;
            Ok(status.success())
        })();

        return matches!(res, Ok(true));
    }

    false
}

// #[cfg(target_os = "linux")]
// pub fn set_clipboard_text(text: &str) -> bool {
//     let is_wayland = linux_is_wayland();

//     if is_wayland {
//         if !program_exists("wl-copy") {
//             return false;
//         }

//         let mut child = match std::process::Command::new("wl-copy")
//             .stdin(std::process::Stdio::piped())
//             .spawn()
//         {
//             Ok(c) => c,
//             Err(_) => return false,
//         };

//         if let Some(stdin) = child.stdin.as_mut() {
//             use std::io::Write;
//             if stdin.write_all(text.as_bytes()).is_err() {
//                 return false;
//             }
//         } else {
//             return false;
//         }

//         return child.wait().map(|s| s.success()).unwrap_or(false);
//     }

//     // X11: xclip then xsel
//     // if program_exists("xclip") {
//     //     let mut child = match std::process::Command::new("xclip")
//     //         .args(["-selection", "clipboard", "-i"])
//     //         .stdin(std::process::Stdio::piped())
//     //         .spawn()
//     //     {
//     //         Ok(c) => c,
//     //         Err(_) => return false,
//     //     };

//     //     if let Ok(mut child_ok) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| child)) {
//     //         if let Some(stdin) = child_ok.stdin.as_mut() {
//     //             use std::io::Write;
//     //             if stdin.write_all(text.as_bytes()).is_ok() {
//     //                 return child_ok.wait().map(|s| s.success()).unwrap_or(false);
//     //             }
//     //         }
//     //     }
//     // }
//     if program_exists("xclip") {
//         let mut child = match std::process::Command::new("xclip")
//             .args(["-selection", "clipboard", "-i"])
//             .stdin(std::process::Stdio::piped())
//             .spawn()
//         {
//             Ok(c) => c,
//             Err(_) => return false,
//         };

//         if let Some(stdin) = child.stdin.as_mut() {
//             use std::io::Write;
//             if stdin.write_all(text.as_bytes()).is_err() {
//                 return false;
//             }
//         } else {
//             return false;
//         }

//         return child.wait().map(|s| s.success()).unwrap_or(false);
//     }

//     //
//     if program_exists("xclip") {
//         let mut child = std::process::Command::new("xclip")
//             .args(["-selection", "clipboard", "-i"])
//             .stdin(std::process::Stdio::piped())
//             .spawn();

//         if let Ok(mut c) = child {
//             if let Some(stdin) = c.stdin.as_mut() {
//                 use std::io::Write;
//                 if stdin.write_all(text.as_bytes()).is_ok() {
//                     return c.wait().map(|s| s.success()).unwrap_or(false);
//                 }
//             }
//         }
//     }

//     // if program_exists("xsel") {
//     //     let mut child = std::process::Command::new("xsel")
//     //         .args(["--clipboard", "--input"])
//     //         .stdin(std::process::Stdio::piped())
//     //         .spawn();

//     //     if let Ok(mut c) = child {
//     //         if let Some(stdin) = c.stdin.as_mut() {
//     //             use std::io::Write;
//     //             if stdin.write_all(text.as_bytes()).is_ok() {
//     //                 return c.wait().map(|s| s.success()).unwrap_or(false);
//     //             }
//     //         }
//     //     }
//     // }
//     // //

//     if program_exists("xsel") {
//         let mut child = match std::process::Command::new("xsel")
//             .args(["--clipboard", "--input"])
//             .stdin(std::process::Stdio::piped())
//             .spawn()
//         {
//             Ok(c) => c,
//             Err(_) => return false,
//         };

//         if let Some(stdin) = child.stdin.as_mut() {
//             use std::io::Write;
//             if stdin.write_all(text.as_bytes()).is_err() {
//                 return false;
//             }
//         } else {
//             return false;
//         }

//         return child.wait().map(|s| s.success()).unwrap_or(false);
//     }

//     false
// }

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
pub fn get_clipboard_text() -> Option<String> {
    None
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
pub fn set_clipboard_text(_text: &str) -> bool {
    false
}
