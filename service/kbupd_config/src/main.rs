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

use std::fs;
use std::path::{Path};

use kbupd_config::*;

fn main() {
    let arguments = parse_arguments();

    let (subcommand_name, subcommand_arguments) = arguments.subcommand();
    let subcommand_arguments = subcommand_arguments.unwrap();

    match subcommand_name {
        "validate" => {
            match validate(&subcommand_arguments) {
                Ok(())  => (),
                Err(()) => std::process::exit(1),
            }
        }
        _ => unreachable!(),
    }
}

fn validate(arguments: &clap::ArgMatches<'static>) -> Result<(), ()> {
    let (subcommand_name, subcommand_arguments) = arguments.subcommand();
    let subcommand_arguments = subcommand_arguments.unwrap();

    let mut result = Ok(());

    let config_file_paths = subcommand_arguments.values_of("config_file").expect("no config_file").map(Path::new);
    for config_file_path in config_file_paths {
        let config_file = match fs::File::open(&config_file_path) {
            Ok(config_file) => config_file,
            Err(error) => {
                eprintln!("error opening config file {}: {}", config_file_path.display(), error);
                continue
            }
        };

        let parse_result = match subcommand_name {
            "frontend" => {
                serde_yaml::from_reader::<_, FrontendConfig>(config_file).map(drop)
            }
            "replica" => {
                serde_yaml::from_reader::<_, ReplicaConfig>(config_file).map(drop)
            }
            _ => unreachable!(),
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
    let config_file_argument =
        clap::Arg::with_name("config_file")
        .takes_value(true)
        .multiple(true)
        .index(1)
        .value_name("config_file_path")
        .help("Path to YAML config file");

    let validate_frontend_subcommand =
        clap::SubCommand::with_name("frontend")
        .arg(config_file_argument.clone())
        .about("validate kbupd frontend YAML config file");

    let validate_replica_subcommand =
        clap::SubCommand::with_name("replica")
        .arg(config_file_argument)
        .about("validate kbupd replica YAML config file");

    let config_validate_subcommand =
        clap::SubCommand::with_name("validate")
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
