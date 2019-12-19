/*
 * Copyright (C) 2019 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use std::io;
use std::io::prelude::*;

pub struct Logger {
    pub level: log::Level,
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let log_level_string = match record.level() {
                log::Level::Error => "ERRO",
                log::Level::Warn  => "WARN",
                log::Level::Info  => "INFO",
                log::Level::Debug => "DEBG",
                log::Level::Trace => "TRCE",
            };
            let line    = format!("{:<4} {}\n", log_level_string, record.args());
            let _ignore = write!(io::stderr(), "{}", line);
        }
    }

    fn flush(&self) {
    }
}

pub fn parse_line(line: &str) -> (log::Level, &str) {
    match line.get(..5) {
        Some("ERRO ") => (log::Level::Error, line.get(5..).unwrap_or_else(|| unreachable!())),
        Some("WARN ") => (log::Level::Warn, line.get(5..).unwrap_or_else(|| unreachable!())),
        Some("INFO ") => (log::Level::Info, line.get(5..).unwrap_or_else(|| unreachable!())),
        Some("DEBG ") => (log::Level::Debug, line.get(5..).unwrap_or_else(|| unreachable!())),
        Some("TRCE ") => (log::Level::Trace, line.get(5..).unwrap_or_else(|| unreachable!())),
        _             => (log::Level::Info, &line[..]),
    }
}
