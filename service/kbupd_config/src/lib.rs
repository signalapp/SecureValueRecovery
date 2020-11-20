//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

pub mod frontend;
pub mod metrics;
pub mod replica;

pub use frontend::{FrontendConfig, FrontendConfigValidator};
pub use replica::{ReplicaConfig, ReplicaConfigValidator};

use std::net::ToSocketAddrs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use log::debug;

#[derive(Clone, Debug)]
pub struct ValidatorConfig {
    pub config_path:         PathBuf,
    pub check_dns_hostnames: bool,
}

pub trait KbupdConfigValidator {
    fn new(validator_config: &ValidatorConfig) -> Self;

    fn validate(&self) -> Result<()>;

    fn validate_hostports(host_ports: &[String]) -> Result<()> {
        let mut result = None;
        for host_port in host_ports.iter() {
            debug!("Looking up host_port: {}", host_port);
            let _ = match host_port.to_socket_addrs() {
                Ok(_) => {}
                Err(e) => {
                    // Collect multiple errors
                    let error = result.take().unwrap_or(Err(e.into()));
                    let new_error: Result<(), anyhow::Error> =
                        error.with_context(|| format!("DNS lookup failure for <host>:<port>: {}", host_port));
                    result.replace(new_error);
                }
            };
        }
        result.unwrap_or(Ok(()))
    }
}
