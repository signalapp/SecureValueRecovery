//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::fs;

use anyhow::{Context, Result};

use crate::frontend::config::FrontendConfig;
use crate::{KbupdConfigValidator, ValidatorConfig};

pub struct FrontendConfigValidator {
    validator_config: ValidatorConfig,
}

impl KbupdConfigValidator for FrontendConfigValidator {
    fn new(validator_config: &ValidatorConfig) -> Self {
        Self {
            validator_config: validator_config.clone(),
        }
    }

    fn validate(&self) -> Result<()> {
        let config_file = fs::File::open(&self.validator_config.config_path).with_context(|| {
            format!(
                "Failed to open frontend config file: {}",
                self.validator_config.config_path.display()
            )
        })?;
        let config = serde_yaml::from_reader::<_, FrontendConfig>(config_file).with_context(|| {
            format!(
                "Unable to parse frontend config file: {}",
                self.validator_config.config_path.display()
            )
        })?;

        if self.validator_config.check_dns_hostnames {
            let host_ports: Vec<String> = config
                .enclaves
                .iter()
                .flat_map(|enclave| enclave.partitions.iter())
                .flat_map(|partition| partition.replicas.iter())
                .map(|replica| replica.hostPort.clone())
                .collect();

            Self::validate_hostports(&host_ports)?;
        }
        Ok(())
    }
}
