#[cfg(not(target_os = "android"))]
pub fn copy_text_to_clipboard(text: &str) -> Result<(), String> {
    let mut cb = arboard::Clipboard::new().map_err(|e| format!("clipboard unavailable: {e}"))?;
    cb.set_text(text.to_string())
        .map_err(|e| format!("clipboard unavailable: {e}"))
}

#[cfg(not(target_os = "android"))]
pub fn read_text_from_clipboard() -> Result<String, String> {
    let mut cb = arboard::Clipboard::new().map_err(|e| format!("clipboard unavailable: {e}"))?;
    cb.get_text()
        .map_err(|e| format!("clipboard unavailable: {e}"))
}

#[cfg(target_os = "android")]
pub fn copy_text_to_clipboard(_text: &str) -> Result<(), String> {
    Err("clipboard text copy is unsupported on Android".into())
}

#[cfg(target_os = "android")]
pub fn read_text_from_clipboard() -> Result<String, String> {
    Err("clipboard text paste is unsupported on Android".into())
}
