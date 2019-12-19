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
use std::net::{SocketAddr};
use std::sync::*;
use std::os::unix::prelude::*;
use std::path::{PathBuf};

use futures::prelude::*;
use kbuptlsd::prelude::*;
use log::{warn, debug, log};

#[derive(Clone)]
pub struct TlsClient {
    spawner: Arc<TlsClientProxySpawner>,
}

impl TlsClient {
    pub fn new(bin_path: PathBuf, args: TlsClientProxyArguments) -> Result<Self, failure::Error> {
        Ok(Self {
            spawner: Arc::new(TlsClientProxySpawner::new(bin_path, args)?),
        })
    }
    pub fn spawn(&self, stream: impl AsRawFd, address: SocketAddr) -> Result<TlsProxyStream, io::Error> {
        let child     = self.spawner.spawn(stream, address)?;
        let child_pid = child.pid();

        let (tls_stream, stderr_stream) = child.into_streams()?;

        let log_target = format!("kbuptlsd-{}", child_pid);
        let stderr_logger = stderr_stream.for_each(move |line: String| {
            let (log_level, line) = kbuptlsd::child::logger::parse_line(&line);
            log!(target: &log_target, log_level, "{} => {}", address, line);
            Ok(())
        });
        let stderr_logger = stderr_logger.then(move |result: Result<(), io::Error>| {
            match result {
                Ok(()) => {
                    debug!("{} => child process died", address);
                    Ok(())
                }
                Err(error) => {
                    warn!("{} => error reading from child stderr: {}", address, error);
                    Err(())
                }
            }
        });
        tokio::spawn(stderr_logger);

        Ok(tls_stream)
    }
}
