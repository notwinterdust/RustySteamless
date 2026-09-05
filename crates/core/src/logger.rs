//! Logging plumbing used by the unpacker variants.
//!
//! The original C# plugins emit messages through a `LoggingService`. The CLI
//! and the Tauri app surface these messages differently, so the core exposes a
//! minimal trait and each host supplies its own implementation.

/// Message severity, mirroring the C# `LogMessageType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Verbose diagnostic output ("Debug").
    Debug,
    /// Informational progress messages ("Information").
    Info,
    /// Successful step completion ("Success").
    Success,
    /// A failure message ("Error").
    Error,
}

/// Receives log messages emitted while a variant runs.
pub trait Logger {
    /// Handles a single log message.
    fn log(&self, level: Level, message: &str);
}

/// A `Logger` that discards everything. Useful when running headless.
pub struct NullLogger;

impl Logger for NullLogger {
    fn log(&self, _level: Level, _message: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Sink(std::sync::Mutex<Vec<String>>);

    impl Logger for Sink {
        fn log(&self, level: Level, message: &str) {
            self.0.lock().unwrap().push(format!("{level:?}: {message}"));
        }
    }

    #[test]
    fn logger_receives_messages() {
        let sink = Sink(std::sync::Mutex::new(Vec::new()));
        sink.log(Level::Info, "hello");
        let messages = sink.0.lock().unwrap();
        assert_eq!(messages[0], "Info: hello");
    }
}
