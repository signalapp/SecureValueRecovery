//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::fs;
use std::path::Path;

use kbupd_config::*;

fn main() {
    let arguments = parse_arguments();

    let (subcommand_name, subcommand_arguments) = arguments.subcommand();
    let subcommand_arguments = subcommand_arguments.unwrap();

    match subcommand_name {
        "validate" => match validate(&subcommand_arguments) {
            Ok(())  => (),
            Err(()) => std::process::exit(1),
        },
        _          => unreachable!(),
    }
}

fn validate(arguments: &clap::ArgMatches<'static>) -> Result<(), ()> {
    let (subcommand_name, subcommand_arguments) = arguments.subcommand();
    let subcommand_arguments = subcommand_arguments.unwrap();

    let mut result = Ok(());

    let config_file_paths = subcommand_arguments
        .values_of("config_file")
        .expect("no config_file")
        .map(Path::new);
    for config_file_path in config_file_paths {
        let config_file = match fs::File::open(&config_file_path) {
            Ok(config_file) => config_file,
            Err(error)      => {
                eprintln!("error opening config file {}: {}", config_file_path.display(), error);
                continue;
            }
        };

        let parse_result = match subcommand_name {
            "frontend" => serde_yaml::from_reader::<_, FrontendConfig>(config_file).map(drop),
            "replica"  => serde_yaml::from_reader::<_, ReplicaConfig>(config_file).map(drop),
            _          => unreachable!(),
        };

        match parse_result {
            Ok(())     => eprintln!("parsed config file {}", config_file_path.display()),
            Err(error) => {
                eprintln!("error parsing config file {}: {:?}", config_file_path.display(), error);
                result = Err(());
            }
        }
    }
    result
}

fn parse_arguments() -> clap::ArgMatches<'static> {
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

    let config_validate_subcommand = clap::SubCommand::with_name("validate")
        .setting(clap::AppSettings::VersionlessSubcommands)
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .subcommand(validate_frontend_subcommand)
        .subcommand(validate_replica_subcommand)
        .about("validate kbupd YAML config file");

    clap::App::new("kbupd-config")
        .version(clap::crate_version!())
        .about(format!("{} -- Config Utility", clap::crate_description!()).as_str())
        .author(clap::crate_authors!())
        .setting(clap::AppSettings::VersionlessSubcommands)
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .subcommand(config_validate_subcommand)
        .get_matches()
}
