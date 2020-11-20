//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::fs;

use anyhow::{Context, Result};

use crate::replica::ReplicaConfig;
use crate::{KbupdConfigValidator, ValidatorConfig};

pub struct ReplicaConfigValidator {
    validator_config: ValidatorConfig,
}

impl KbupdConfigValidator for ReplicaConfigValidator {
    fn new(validator_config: &ValidatorConfig) -> Self {
        Self {
            validator_config: validator_config.clone(),
        }
    }

    fn validate(&self) -> Result<()> {
        let config_file = fs::File::open(&self.validator_config.config_path).with_context(|| {
            format!(
                "Failed to open replica config file: {}",
                self.validator_config.config_path.display()
            )
        })?;
        let config = serde_yaml::from_reader::<_, ReplicaConfig>(config_file).with_context(|| {
            format!(
                "Unable to parse replica config file: {}",
                self.validator_config.config_path.display()
            )
        })?;

        if self.validator_config.check_dns_hostnames {
            // Check replica peer hostnames
            let mut host_ports: Vec<String> = config.enclave.replicas.iter().map(|replica| replica.hostPort.clone()).collect();

            // Check replica source partition hostnames
            host_ports.append(
                &mut config
                    .enclave
                    .sourcePartition
                    .unwrap_or(Default::default())
                    .replicas
                    .iter()
                    .map(|replica| replica.hostPort.clone())
                    .collect(),
            );

            Self::validate_hostports(&host_ports)?;
        }
        Ok(())
    }
}
