/// The current Codex CLI version as embedded at compile time.
pub const CODEX_CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The version label shown in user-facing TUI banners/status surfaces.
pub const CODEX_DISPLAY_VERSION: &str = match option_env!("CODEX_DISPLAY_VERSION") {
    Some(version) => version,
    None => concat!("v", env!("CARGO_PKG_VERSION")),
};
