//! Unified error type crossing the Tauri boundary.
//!
//! Errors are strings for the webview: short "kind" + human message, so the UI
//! can style failures (hard crypto reject vs. IO hiccup) without ever seeing
//! error internals.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct AppError {
    /// Machine-readable category: "crypto" | "policy" | "io" | "input" | "internal"
    pub kind: &'static str,
    /// Human-readable explanation, safe to show to the user.
    pub message: String,
}

impl AppError {
    pub fn crypto(msg: impl Into<String>) -> Self {
        AppError { kind: "crypto", message: msg.into() }
    }
    pub fn policy(msg: impl Into<String>) -> Self {
        AppError { kind: "policy", message: msg.into() }
    }
    pub fn io(msg: impl Into<String>) -> Self {
        AppError { kind: "io", message: msg.into() }
    }
    pub fn input(msg: impl Into<String>) -> Self {
        AppError { kind: "input", message: msg.into() }
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        AppError { kind: "internal", message: msg.into() }
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::io(format!("file system error: {e}"))
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::io(format!("settings file error: {e}"))
    }
}

/// Convert an rPGP error into a user-facing message, keeping the most
/// interesting part of the underlying failure.
impl From<pgp::errors::Error> for AppError {
    fn from(e: pgp::errors::Error) -> Self {
        AppError::crypto(format!("OpenPGP operation failed: {e}"))
    }
}

pub type AppResult<T> = Result<T, AppError>;
