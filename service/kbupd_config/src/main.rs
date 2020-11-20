//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::path::Path;

use anyhow::{Context, Result};
use log::info;

use kbupd_config::*;

fn main() -> Result<()> {
    let arguments = parse_arguments();

    let log_level = if arguments.is_present("verbose") {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Warn
    };
    let mut logger = env_logger::Builder::from_default_env();
    logger.filter_level(log_level);
    logger.init();

    info!("Starting validation");

    let (subcommand_name, subcommand_arguments) = arguments.subcommand();
    let subcommand_arguments = subcommand_arguments.unwrap();

    match subcommand_name {
        "validate" => validate(&subcommand_arguments),
        _ => unreachable!(),
    }
}

fn validate(arguments: &clap::ArgMatches<'static>) -> Result<()> {
    let check_dns_hostnames = arguments.is_present("check_dns_hostnames");

    let (subcommand_name, subcommand_arguments) = arguments.subcommand();
    let subcommand_arguments = subcommand_arguments.unwrap();

    let mut result = Ok(());

    let config_file_paths = subcommand_arguments
        .values_of("config_file")
        .expect("no config_file")
        .map(Path::new);

    for config_file_path in config_file_paths {
        let validator_config = ValidatorConfig {
            config_path: config_file_path.to_owned(),
            check_dns_hostnames,
        };
        let validate_result = match subcommand_name {
            "frontend" => FrontendConfigValidator::new(&validator_config).validate(),
            "replica" => ReplicaConfigValidator::new(&validator_config).validate(),
            _ => unreachable!(),
        };

        match validate_result {
            Ok(()) => eprintln!("Validated config file {}", config_file_path.display()),
            Err(error) => result = Err(error).with_context(|| format!("Error validating config file {}", config_file_path.display())),
        }
    }
    result
}

fn parse_arguments() -> clap::ArgMatches<'static> {
    let debug_argument = clap::Arg::with_name("verbose")
        .short("v")
        .long("verbose")
        .help("Sets the level of verbosity");

    let config_file_argument = clap::Arg::with_name("config_file")
        .takes_value(true)
        .multiple(true)
        .index(1)
        .value_name("config_file_path")
        .help("Path to YAML config file");

    let validate_frontend_subcommand = clap::SubCommand::with_name("frontend")
        .arg(config_file_argument.clone())
        .about("validate kbupd frontend YAML config file");

    let validate_replica_subcommand = clap::SubCommand::with_name("replica")
        .arg(config_file_argument)
        .about("validate kbupd replica YAML config file");

    let check_dns_hostnames_argument = clap::Arg::with_name("check_dns_hostnames")
        .short("d")
        .long("check-dns-hostnames")
        .help("Check that the hostnames resolve with DNS");

    let config_validate_subcommand = clap::SubCommand::with_name("validate")
        .setting(clap::AppSettings::VersionlessSubcommands)
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .arg(check_dns_hostnames_argument)
        .subcommand(validate_frontend_subcommand)
        .subcommand(validate_replica_subcommand)
        .about("validate kbupd YAML config file");

    clap::App::new("kbupd-config")
        .version(clap::crate_version!())
        .about(format!("{} -- Config Utility", clap::crate_description!()).as_str())
        .author(clap::crate_authors!())
        .setting(clap::AppSettings::VersionlessSubcommands)
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .arg(debug_argument)
        .subcommand(config_validate_subcommand)
        .get_matches()
}

#[cfg(test)]
mod test {
    use super::*;
    use std::path::PathBuf;

    fn get_test_case_directory() -> PathBuf {
        let mut test_cases_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_cases_dir.push("test-cases");
        test_cases_dir
    }

    fn test_frontend(config_file: &str, expected_ok: bool) -> Result<()> {
        let mut frontend_hostnames_path = get_test_case_directory();
        frontend_hostnames_path.push(config_file);

        let validator_config = ValidatorConfig {
            config_path:         frontend_hostnames_path,
            check_dns_hostnames: true,
        };

        let validator = FrontendConfigValidator::new(&validator_config);

        let result = validator.validate();
        assert!(result.is_ok() == expected_ok);
        result
    }

    fn verify_io_not_found(error: anyhow::Error) {
        let io_error = error.downcast_ref::<std::io::Error>();
        assert!(io_error.is_some());
        let io_error = io_error.unwrap();
        assert!(io_error.kind() == std::io::ErrorKind::NotFound);
    }

    fn verify_yaml_parse_error(error: anyhow::Error) {
        let parse_error = error.downcast_ref::<serde_yaml::Error>();
        assert!(parse_error.is_some());
    }

    fn verify_dns_lookup_error(error: anyhow::Error) {
        let io_error = error.downcast_ref::<std::io::Error>();
        assert!(io_error.is_some());
        let io_error = io_error.unwrap();
        assert!(io_error.kind() == std::io::ErrorKind::Other);
    }

    #[test]
    fn test_frontend_does_not_exist() {
        let error = test_frontend("frontend.does-not-exist.yml", false).unwrap_err();
        verify_io_not_found(error);
    }

    #[test]
    fn test_frontend_does_not_parse() {
        let error = test_frontend("frontend.parse.bad.yml", false).unwrap_err();
        verify_yaml_parse_error(error);
    }

    #[test]
    fn test_frontend_hostnames_good() {
        let _ = test_frontend("frontend.hostnames.good.yml", true);
    }

    #[test]
    fn test_frontend_hostnames_bad() {
        let error = test_frontend("frontend.hostnames.bad.yml", false).unwrap_err();
        verify_dns_lookup_error(error);
    }

    fn test_replica(config_file: &str, expected_ok: bool) -> Result<()> {
        let mut replica_hostnames_path = get_test_case_directory();
        replica_hostnames_path.push(config_file);

        let validator_config = ValidatorConfig {
            config_path:         replica_hostnames_path,
            check_dns_hostnames: true,
        };

        let validator = ReplicaConfigValidator::new(&validator_config);

        let result = validator.validate();
        assert!(result.is_ok() == expected_ok);
        result
    }

    #[test]
    fn test_replica_does_not_exist() {
        let error = test_replica("replica.does-not-exist.yml", false).unwrap_err();
        verify_io_not_found(error);
    }

    #[test]
    fn test_replica_does_not_parse() {
        let error = test_replica("replica.parse.bad.yml", false).unwrap_err();
        verify_yaml_parse_error(error);
    }

    #[test]
    fn test_replica_hostnames_no_source_good() {
        let _ = test_replica("replica.hostnames-no-source.good.yml", true);
    }

    #[test]
    fn test_replica_hostnames_no_source_bad() {
        let error = test_replica("replica.hostnames-no-source.bad.yml", false).unwrap_err();
        verify_dns_lookup_error(error);
    }

    #[test]
    fn test_replica_hostnames_with_source_good() {
        let _ = test_replica("replica.hostnames-with-source.good.yml", true);
    }

    #[test]
    fn test_replica_hostnames_with_source_replica_bad() {
        let error = test_replica("replica.hostnames-with-source.replica-bad.yml", false).unwrap_err();
        verify_dns_lookup_error(error);
    }

    #[test]
    fn test_replica_hostnames_with_source_source_bad() {
        let error = test_replica("replica.hostnames-with-source.source-bad.yml", false).unwrap_err();
        verify_dns_lookup_error(error);
    }
}
