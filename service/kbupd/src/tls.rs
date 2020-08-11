//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::io;
use std::net::SocketAddr;
use std::os::unix::prelude::*;
use std::path::PathBuf;
use std::sync::*;

use futures::prelude::*;
use kbuptlsd::prelude::*;
use log::{debug, log, warn};

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
        let child = self.spawner.spawn(stream, address)?;
        let child_pid = child.pid();

        let (tls_stream, stderr_stream) = child.into_streams()?;

        let log_target = format!("kbuptlsd-{}", child_pid);
        let stderr_logger = stderr_stream.for_each(move |line: String| {
            let (log_level, line) = kbuptlsd::child::logger::parse_line(&line);
            log!(target: &log_target, log_level, "{} => {}", address, line);
            Ok(())
        });
        let stderr_logger = stderr_logger.then(move |result: Result<(), io::Error>| match result {
            Ok(()) => {
                debug!("{} => child process died", address);
                Ok(())
            }
            Err(error) => {
                warn!("{} => error reading from child stderr: {}", address, error);
                Err(())
            }
        });
        tokio::spawn(stderr_logger);

        Ok(tls_stream)
    }
}
