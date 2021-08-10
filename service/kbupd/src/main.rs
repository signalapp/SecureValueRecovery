//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::fs;
use std::io;
use std::io::prelude::*;
use std::path::Path;

use failure::{bail, format_err, ResultExt};
use log::error;

use kbupd::*;
use kbupd_config::frontend::*;
use kbupd_config::replica::*;
use kbupd_util::hex;
use kbuptlsd::prelude::*;

fn main() {
    let arguments = parse_arguments();

    let log_level = if arguments.is_present("debug") {
        log::Level::Debug
    } else {
        log::Level::Info
    };

    let (logger, logger_guard) = logger::Logger::new_with_guard(log_level);
    log::set_boxed_logger(Box::new(logger)).expect("logger already set");
    log::set_max_level(log_level.to_level_filter());

    match run(arguments) {
        Ok(()) => (),
        Err(error) => {
            error!("initialization error: {:?}", error);
        }
    }

    drop(logger_guard);
    std::process::exit(1);
}

fn init_common_metrics() {
    kbupd::logger::init_metrics();
}

#[rustfmt::skip]
fn run(arguments: clap::ArgMatches<'static>) -> Result<(), failure::Error> {
    let (subcommand_name, subcommand_arguments) = arguments.subcommand();

    let subcommand_arguments = subcommand_arguments.expect("no subcommand arguments");
    let enclave_directory = Path::new(arguments.value_of("enclave_directory").expect("no enclave_directory"));
    let config_file_arg = Path::new(arguments.value_of("config_file").expect("no config_file"));
    let config_dir_arg = arguments.value_of("config_dir").map(Path::new);
    let full_hostname = arguments.value_of("full_hostname");
    let kbuptlsd_bin_path = Path::new(arguments.value_of("kbuptlsd_bin_file").expect("no kbuptlsd_bin_file"));
    let background = arguments.is_present("background");
    let pid_file = arguments.value_of("pid_file").map(open_pid_file).unwrap_or(Ok(None))?;

    let maybe_background_pipe = if background { Some(daemonize(pid_file)?) } else { None };

    let config_file_dir = config_file_arg.parent().unwrap_or(Path::new("."));
    let (config_directory, config_file_path) = match config_dir_arg {
        Some(config_directory) => (config_directory, config_directory.join(config_file_arg)),
        None                   => (config_file_dir, config_file_arg.to_owned()),
    };

    let config_file =
        fs::File::open(&config_file_path).with_context(|_| format_err!("error opening config file {}", config_file_path.display()))?;

    init_common_metrics();

    let service = match subcommand_name {
        "replica" => {
            let mut config: ReplicaConfig = serde_yaml::from_reader(config_file)
                .with_context(|_| format_err!("error reading config file {}", config_file_path.display()))?;

            set_argument(  &mut config.attestation.acceptGroupOutOfDate,    Some(arguments.is_present("ias_accept_group_out_of_date")).filter(|present| *present));
            set_argument(  &mut config.attestation.disabled,                Some(!arguments.is_present("ias_tls_config_file")).filter(|present| !*present));
            set_argument(  &mut config.attestation.host,                    arguments.value_of("ias_host"));
            parse_argument(&mut config.attestation.spid,                    arguments.value_of("ias_spid"), hex::parse_fixed).context("invalid --ias-spid")?;
            set_argument(  &mut config.control.listenHostPort,              arguments.value_of("control_listen_address"));
            set_argument(  &mut config.enclave.mrenclave,                   subcommand_arguments.value_of("enclave_filename"));
            parse_argument(&mut config.enclave.debug,                       subcommand_arguments.value_of("enclave_debug"), parse_yes_no).context("invalid --enclave-debug")?;
            parse_argument(&mut config.enclave.maxBackupDataLength,         subcommand_arguments.value_of("max_backup_data_length"), str::parse).context("invalid --max-backup-data-length")?;
            parse_argument(&mut config.enclave.electionTimeoutMs,           subcommand_arguments.value_of("election_timeout_ms"), str::parse).context("invalid --election-timeout-ms")?;
            parse_argument(&mut config.enclave.electionHeartbeats,          subcommand_arguments.value_of("election_heartbeats"), str::parse).context("invalid --election-heartbeats")?;
            parse_argument(&mut config.enclave.storageSize,                 subcommand_arguments.value_of("storage_size"), str::parse).context("invalid --storage-size")?;
            set_argument(  &mut config.enclave.listenHostPort,              subcommand_arguments.value_of("peer_listen_address"));

            if let Some(replicas) = subcommand_arguments.values_of("replicas") {
                config.enclave.replicas = replicas
                    .into_iter()
                    .map(|address: &str| ReplicaPeerConfig {
                        hostPort: address.to_string(),
                    })
                    .collect();
            }
            if let Some(source_replicas) = subcommand_arguments.values_of("source_replicas") {
                let replicas = source_replicas
                    .into_iter()
                    .map(|address: &str| ReplicaPeerConfig {
                        hostPort: address.to_string(),
                    })
                    .collect();
                config.enclave.sourcePartition = Some(ReplicaSourcePartitionConfig {
                    firstBackupId: hex::parse_fixed(subcommand_arguments.value_of("firstid").expect("no firstid"))
                        .context("invalid --firstid")?,
                    lastBackupId: hex::parse_fixed(subcommand_arguments.value_of("lastid").expect("no lastid"))
                        .context("invalid --lastid")?,
                    replicas,
                });
            }

            let cmdline_config = ReplicaCommandLineConfig {
                enclave_directory,
                config_directory,
                kbuptlsd_bin_path,
                full_hostname,
                exit_signals_enabled: subcommand_arguments.is_present("exit_signals"),
            };

            let peer_ca_file = Path::new(subcommand_arguments.value_of("peer_ca_file").expect("no peer_ca_file"));
            let peer_key_file = Path::new(subcommand_arguments.value_of("peer_key_file").expect("no peer_key_file"));

            let peer_tls_client_args = TlsClientProxyArguments::NoConfig {
                ca:       TlsClientProxyCaArgument::CustomPemFile(peer_ca_file.to_owned()),
                key_file: Some(peer_key_file.to_owned()),
                hostname: TlsClientProxyHostnameArgument::AllowInvalid,
            };

            let peer_tls_server_args = TlsProxyListenerArguments::NoConfig {
                ca_file:  peer_ca_file.to_owned(),
                key_file: peer_key_file.to_owned(),
            };

            Service::Replica(ReplicaService::start(
                config,
                cmdline_config,
                peer_tls_server_args,
                peer_tls_client_args,
            )?)
        }
        "frontend" => {
            let mut config: FrontendConfig = serde_yaml::from_reader(config_file)
                .with_context(|_| format_err!("error reading config file {}", config_file_path.display()))?;

            set_argument(  &mut config.api.listenHostPort,                      subcommand_arguments.value_of("api_listen_address"));
            parse_argument(&mut config.api.userAuthenticationTokenSharedSecret, subcommand_arguments.value_of("api_signal_user_token_secret"), hex::parse).context("invalid --api-signal-user-token-secret")?;
            set_argument(  &mut config.attestation.acceptGroupOutOfDate,        Some(arguments.is_present("ias_accept_group_out_of_date")).filter(|present| *present));
            set_argument(  &mut config.attestation.disabled,                    Some(!arguments.is_present("ias_tls_config_file")).filter(|present| !*present));
            set_argument(  &mut config.attestation.host,                        arguments.value_of("ias_host"));
            parse_argument(&mut config.attestation.spid,                        arguments.value_of("ias_spid"), hex::parse_fixed).context("invalid --ias-spid")?;

            set_argument(  &mut config.control.listenHostPort, arguments.value_of("control_listen_address"));

            if let Some(enclave_name) = subcommand_arguments.value_of("enclave_name") {
                let enclave_config = config
                    .enclaves
                    .iter_mut()
                    .find(|enclave_config: &&mut FrontendEnclaveConfig| enclave_config.name == enclave_name);
                let enclave_config = if let Some(enclave_config) = enclave_config {
                    enclave_config
                } else {
                    config.enclaves.push(FrontendEnclaveConfig {
                        name:              enclave_name.to_string(),
                        mrenclave:         Default::default(),
                        debug:             false,
                        partitions:        Default::default(),
                        electionTimeoutMs: 1000,

                        maxBackupDataLength: 0,
                        pendingRequestCount: 32768,
                        pendingRequestTtlMs: 0,
                    });
                    config.enclaves.last_mut().unwrap_or_else(|| unreachable!())
                };
                set_argument(  &mut enclave_config.mrenclave,           subcommand_arguments.value_of("enclave_filename"));
                parse_argument(&mut enclave_config.debug,               subcommand_arguments.value_of("enclave_debug"), parse_yes_no).context("invalid --enclave-debug")?;
                parse_argument(&mut enclave_config.partitions,          subcommand_arguments.values_of("partitions"), parse_partition_specs)?;
                parse_argument(&mut enclave_config.maxBackupDataLength, subcommand_arguments.value_of("max_backup_data_length"), str::parse).context("invalid --max-backup-data-length")?;
                parse_argument(&mut enclave_config.electionTimeoutMs,   subcommand_arguments.value_of("election_timeout_ms"), str::parse::<u64>).context("invalid --election-timeout-ms")?;
            }

            let peer_ca_file = Path::new(subcommand_arguments.value_of("peer_ca_file").expect("no peer_ca_file"));
            let peer_key_file = Path::new(subcommand_arguments.value_of("peer_key_file").expect("no peer_key_file"));

            let cmdline_config = FrontendCommandLineConfig {
                enclave_directory,
                config_directory,
                kbuptlsd_bin_path,
                full_hostname,
            };

            let peer_tls_args = TlsClientProxyArguments::NoConfig {
                ca:       TlsClientProxyCaArgument::CustomPemFile(peer_ca_file.to_owned()),
                key_file: Some(peer_key_file.to_owned()),
                hostname: TlsClientProxyHostnameArgument::AllowInvalid,
            };

            Service::Frontend(FrontendService::start(config, cmdline_config, peer_tls_args)?)
        }
        _ => unreachable!("no subcommand"),
    };

    if let Some(background_pipe) = maybe_background_pipe {
        let _ignore = background_pipe.ack(0);
    }

    service.join();
    Ok(())
}

enum Service {
    Frontend(FrontendService),
    Replica(ReplicaService),
}

impl Service {
    pub fn join(self) {
        match self {
            Service::Frontend(frontend) => frontend.join(),
            Service::Replica(replica) => replica.join(),
        }
    }
}

fn open_pid_file(path: &str) -> Result<Option<fs::File>, failure::Error> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|_| format_err!("error opening pid file {}", path))?;
    Ok(Some(file))
}

fn set_argument<T, U>(to_field: &mut U, maybe_argument: Option<T>)
where U: From<T> {
    if let Some(argument) = maybe_argument {
        *to_field = U::from(argument);
    }
}

fn parse_argument<T, U, E, F>(to_field: &mut U, maybe_argument: Option<T>, parse_fun: F) -> Result<(), E>
where F: Fn(T) -> Result<U, E> {
    if let Some(argument) = maybe_argument {
        *to_field = parse_fun(argument)?;
    }
    Ok(())
}

fn parse_yes_no(argument: &str) -> Result<bool, failure::Error> {
    match argument {
        "yes" | "" => Ok(true),
        "no" => Ok(false),
        _ => bail!("invalid yes/no value: {}", argument),
    }
}

fn parse_partition_specs<'a>(partition_specs: impl Iterator<Item = &'a str>) -> Result<Vec<FrontendPartitionConfig>, failure::Error> {
    let mut partitions: Vec<FrontendPartitionConfig> = Vec::new();
    for partition_specs in partition_specs {
        let mut partition_spec_split = partition_specs.splitn(2, '=');

        let key_range_spec = partition_spec_split.next().unwrap_or_default();

        let range = if key_range_spec.len() != 0 {
            let mut key_range_spec_split = key_range_spec.splitn(2, '-');
            Some(FrontendPartitionRangeConfig {
                firstBackupId: hex::parse_fixed(key_range_spec_split.next().unwrap_or_default()).context("invalid partition key range")?,
                lastBackupId:  hex::parse_fixed(key_range_spec_split.next().unwrap_or_default()).context("invalid partition key range")?,
            })
        } else {
            None
        };

        let replica_host_ports_spec = partition_spec_split.next().unwrap_or_default();

        let mut replicas: Vec<FrontendPartitionReplicaConfig> = Vec::new();
        for replica_host_port in replica_host_ports_spec.split(',') {
            replicas.push(FrontendPartitionReplicaConfig {
                hostPort: replica_host_port.to_string(),
            });
        }

        partitions.push(FrontendPartitionConfig { range, replicas });
    }
    Ok(partitions)
}

fn parse_arguments() -> clap::ArgMatches<'static> {
    let enclave_filename_argument = clap::Arg::with_name("enclave_filename")
        .takes_value(true)
        .long("enclave")
        .value_name("enclave_filename")
        .help("Filename of libkbupd_enclave.so");

    let enclave_debug_argument = clap::Arg::with_name("enclave_debug")
        .long("enclave-debug")
        .takes_value(true)
        .min_values(0)
        .possible_values(&["yes", "no"])
        .help("run enclave in SGX debug mode");

    let replicas_argument = clap::Arg::with_name("replicas")
        .multiple(true)
        .value_delimiter(",")
        .long("replicas")
        .value_name("node_spec")
        .help("Set of comma-separated node_specs of replicas, where node_spec is hex_node_id=hostname:port");

    let source_replicas_argument = clap::Arg::with_name("source_replicas")
        .requires("firstid")
        .requires("lastid")
        .multiple(true)
        .value_delimiter(",")
        .long("source-nodes")
        .value_name("node_spec")
        .help("Set of comma-separated node_specs of source replicas, where node_spec is hex_node_id=hostname:port");

    let firstid_argument = clap::Arg::with_name("firstid")
        .long("firstid")
        .value_name("backup_id")
        .help("First BackupId owned by this cluster");
    let lastid_argument = clap::Arg::with_name("lastid")
        .long("lastid")
        .value_name("backup_id")
        .help("Last BackupId owned by this cluster");

    let max_backup_data_length_argument = clap::Arg::with_name("max_backup_data_length")
        .long("max-backup-data-length")
        .value_name("max_backup_data_length")
        .help("Maximum allowable length of backed up data, in bytes");

    let election_timeout_ms_argument = clap::Arg::with_name("election_timeout_ms")
        .long("election-timeout-ms")
        .value_name("election_timeout_ms")
        .help("Raft group election timeout in milliseconds");

    let election_heartbeats_argument = clap::Arg::with_name("election_heartbeats")
        .long("election-heartbeats")
        .value_name("heartbeat_count")
        .help("Number of heartbeats per raft group election timeout period");

    let storage_size_argument = clap::Arg::with_name("storage_size")
        .takes_value(true)
        .long("storage-size")
        .value_name("backup_count")
        .help("Storage capacity for key backup entry data, in number of backups");

    let peer_key_file_argument = clap::Arg::with_name("peer_key_file")
        .takes_value(true)
        .required(true)
        .long("peer-key-file")
        .value_name("pkcs12_path")
        .help("Path to DER-encoded PKCS12 client certificate and private key used to authenticate with peers");

    let peer_ca_file_argument = clap::Arg::with_name("peer_ca_file")
        .takes_value(true)
        .required(true)
        .long("peer-ca-file")
        .value_name("certificate_path")
        .help("Path to PEM-encoded CA certificate used to authenticate peers");

    let peer_listen_argument = clap::Arg::with_name("peer_listen_address")
        .takes_value(true)
        .long("listen-peers")
        .value_name("listen_address")
        .help("ip[:port] address to listen for peers on");

    let exit_signals_argument = clap::Arg::with_name("exit_signals")
        .long("exit-signals")
        .help("Forcefully quit on SIGTERM/SIGQUIT/SIGINT signal");

    let replica_subcommand = clap::SubCommand::with_name("replica")
        .arg(peer_listen_argument)
        .arg(peer_ca_file_argument.clone())
        .arg(peer_key_file_argument.clone())
        .arg(replicas_argument)
        .arg(source_replicas_argument)
        .arg(firstid_argument)
        .arg(lastid_argument)
        .arg(max_backup_data_length_argument.clone())
        .arg(election_timeout_ms_argument.clone())
        .arg(election_heartbeats_argument)
        .arg(storage_size_argument)
        .arg(enclave_filename_argument.clone())
        .arg(enclave_debug_argument.clone())
        .arg(exit_signals_argument)
        .about("Starts a replica kbupd node");

    let api_listen_argument = clap::Arg::with_name("api_listen_address")
        .takes_value(true)
        .long("listen-api")
        .value_name("listen_address")
        .help("ip[:port] address to listen for HTTP API connections on");

    let api_signal_user_token_secret_argument = clap::Arg::with_name("api_signal_user_token_secret")
        .takes_value(true)
        .long("api-signal-user-token-secret")
        .value_name("shared_secret")
        .help("Secret shared with Signal Server to authenticate signal users, in hexadecimal");

    let partitions_argument = clap::Arg::with_name("partitions")
        .requires("enclave_name")
        .multiple(true)
        .value_delimiter(";")
        .long("partitions")
        .value_name("partition_spec")
        .help("Set of semicolon-separated partitions, where partition_spec is hex_lower_bound_key-hex_upper_bound_key=replica_host_port,... or =replica_host_port,...");

    let enclave_name_argument = clap::Arg::with_name("enclave_name")
        .requires("max_backup_data_length")
        .takes_value(true)
        .long("enclave-name")
        .value_name("enclave_name")
        .help("Name of enclave to use in client API (e.g. lowercase hexadecimal mrenclave value)");

    let frontend_subcommand = clap::SubCommand::with_name("frontend")
        .arg(api_listen_argument)
        .arg(api_signal_user_token_secret_argument)
        .arg(peer_ca_file_argument)
        .arg(peer_key_file_argument)
        .arg(partitions_argument)
        .arg(max_backup_data_length_argument.requires("enclave_name"))
        .arg(election_timeout_ms_argument.requires("enclave_name"))
        .arg(enclave_name_argument)
        .arg(enclave_filename_argument.requires("enclave_name"))
        .arg(enclave_debug_argument.requires("enclave_name"))
        .about("Starts a frontend kbupd node");

    let debug_argument = clap::Arg::with_name("debug").long("debug").help("emit debug logging");

    let background_argument = clap::Arg::with_name("background")
        .long("background")
        .help("run process in the background after initialization");

    let pid_file_argument = clap::Arg::with_name("pid_file")
        .takes_value(true)
        .long("pid-file")
        .value_name("pid_file")
        .help("file path to write pid to after initialization");

    let config_file_argument = clap::Arg::with_name("config_file")
        .takes_value(true)
        .required(true)
        .long("config-file")
        .value_name("config_file_path")
        .help("Path to YAML config file, relative to --config-dir if specified");

    let config_dir_argument = clap::Arg::with_name("config_dir")
        .takes_value(true)
        .long("config-dir")
        .value_name("config_dir_path")
        .help("Path to directory containing YAML config files, defaults to parent of --config-file");

    let full_hostname_argument = clap::Arg::with_name("full_hostname")
        .takes_value(true)
        .long("full-hostname")
        .value_name("fqdn")
        .help("Hostname FQDN to use when reporting metrics");

    let kbuptlsd_bin_file_argument = clap::Arg::with_name("kbuptlsd_bin_file")
        .takes_value(true)
        .required(true)
        .long("kbuptlsd-bin-file")
        .value_name("kbuptlsd_bin_path")
        .help("Path to kbuptlsd binary");

    let enclave_directory_argument = clap::Arg::with_name("enclave_directory")
        .takes_value(true)
        .required(true)
        .long("enclave-directory")
        .value_name("enclave_directory")
        .help("Path to directory containing enclaves");

    let ias_spid_argument = clap::Arg::with_name("ias_spid")
        .takes_value(true)
        .long("ias-spid")
        .value_name("spid_hex")
        .help("SGX SPID value in hexadecimal");

    let ias_host_argument = clap::Arg::with_name("ias_host")
        .takes_value(true)
        .long("ias-host")
        .value_name("url")
        .help("base URL, with scheme and port, used to access Intel Attestation Services");

    let ias_tls_config_file_argument = clap::Arg::with_name("ias_tls_config_file")
        .takes_value(true)
        .long("ias-tls-config-file")
        .value_name("ias_tls_config_file_path")
        .help("Path to kbuptlsd YAML config file used to access Intel Attestation Services");

    let ias_accept_group_out_of_date_argument = clap::Arg::with_name("ias_accept_group_out_of_date")
        .long("ias-accept-group-out-of-date")
        .help("allow serving Intel Attestation responses having a status of GROUP_OUT_OF_DATE instead of OK");

    let control_listen_argument = clap::Arg::with_name("control_listen_address")
        .takes_value(true)
        .long("listen-control")
        .value_name("listen_address")
        .help("ip[:port] address to listen for control connections on");

    clap::App::new(clap::crate_name!())
        .version(clap::crate_version!())
        .about(clap::crate_description!())
        .author(clap::crate_authors!())
        .setting(clap::AppSettings::VersionlessSubcommands)
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .arg(debug_argument)
        .arg(background_argument)
        .arg(pid_file_argument)
        .arg(config_file_argument)
        .arg(config_dir_argument)
        .arg(full_hostname_argument)
        .arg(kbuptlsd_bin_file_argument)
        .arg(enclave_directory_argument)
        .arg(ias_spid_argument)
        .arg(ias_host_argument)
        .arg(ias_tls_config_file_argument)
        .arg(ias_accept_group_out_of_date_argument)
        .arg(control_listen_argument)
        .subcommand(replica_subcommand)
        .subcommand(frontend_subcommand)
        .get_matches()
}

struct BackgroundPipe(i32);
impl BackgroundPipe {
    fn ack(self, exit_code: u8) -> Result<(), io::Error> {
        let buf: [u8; 1] = [exit_code; 1];
        loop {
            let written = unsafe { libc::write(self.0, buf.as_ptr() as *const libc::c_void, 1) };
            if written == 1 {
                break Ok(());
            } else if written == 0 {
                break Err(io::Error::from(io::ErrorKind::WriteZero));
            } else {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    break Err(error);
                }
            }
        }
    }
}
impl Drop for BackgroundPipe {
    fn drop(&mut self) {
        let _ignore = unsafe { libc::close(self.0) };
    }
}

fn daemonize(maybe_pid_file: Option<fs::File>) -> Result<BackgroundPipe, failure::Error> {
    let mut pipe: [i32; 2] = [0; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error().into());
    }

    if fork().context("error forking")? != 0 {
        let _ignore = unsafe { libc::close(pipe[1]) };

        let mut buf: [u8; 1] = [0; 1];
        let maybe_ack = loop {
            let read = unsafe { libc::read(pipe[0], buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if read == 1 {
                break Ok(buf[0]);
            } else if read == 0 {
                break Err(io::Error::from(io::ErrorKind::BrokenPipe));
            } else if read == -1 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    break Err(error);
                }
            }
        };
        if let Ok(ack) = maybe_ack {
            std::process::exit(ack as i32);
        } else {
            std::process::exit(1);
        }
    }
    let _ignore = unsafe { libc::close(pipe[0]) };
    let background_pipe = BackgroundPipe(pipe[1]);

    std::env::set_current_dir(&std::path::Path::new("/")).context("error setting current directory")?;

    if unsafe { libc::setsid() } == -1 {
        return Err(io::Error::last_os_error().into());
    }

    if fork().context("error double forking")? != 0 {
        std::process::exit(0);
    }

    if let Some(mut pid_file) = maybe_pid_file {
        let pid: u32 = std::process::id();
        write!(&mut pid_file, "{}\n", pid).context("error writing pid file")?;
        pid_file.flush().context("error writing pid file")?;
    }

    Ok(background_pipe)
}

fn fork() -> Result<i32, io::Error> {
    let pid = unsafe { libc::fork() };
    if pid < 0 { Err(io::Error::from_raw_os_error(pid)) } else { Ok(pid) }
}
