//! UART logger. Reproduces the C++ `log::*` line format
//! `[%8lu] INFO|WARN|ERR msg` so existing boot logs and the acceptance harness
//! keep working.

use core::fmt::Write as _;
use log::{Level, LevelFilter, Log, Metadata, Record};
use std::io::Write as _;

use crate::platform::time::now_ms;

struct UartLogger;

impl Log for UartLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let tag = match record.level() {
            Level::Warn => "WARN",
            Level::Error => "ERR ",
            _ => "INFO",
        };
        let mut line = String::with_capacity(96);
        let _ = writeln!(line, "[{:>8}] {} {}", now_ms(), tag, record.args());
        let mut out = std::io::stdout();
        let _ = out.write_all(line.as_bytes());
        let _ = out.flush();
    }

    fn flush(&self) {}
}

static LOGGER: UartLogger = UartLogger;

/// Installs the logger at INFO and above.
pub fn init() {
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(LevelFilter::Info);
}
