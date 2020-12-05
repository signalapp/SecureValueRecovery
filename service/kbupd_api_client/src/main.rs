//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::fmt::{Display, Write as _};
use std::io::{Cursor, Write as _};
use std::str::FromStr;
use std::sync::atomic;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::BufMut;
use failure::{format_err, ResultExt};
use futures::future;
use futures::prelude::*;
use http::Uri;
use kbupd_api::entities::*;
use kbupd_api_client::*;
use log::debug;
use rand::RngCore;
use tokio::prelude::future::Loop;

fn main() -> Result<(), failure::Error> {
    let arguments = parse_arguments();

    let (subcommand_name, subcommand_arguments) = arguments.subcommand();
    let subcommand_name = leak_argument(subcommand_name);
    let subcommand_arguments = subcommand_arguments.unwrap();

    let connect_uri = arguments
        .value_of("connect_uri")
        .unwrap_or_default()
        .parse::<Uri>()
        .context("invalid --connect uri")?;
    let insecure_ssl = arguments.is_present("insecure");
    let debug = arguments.is_present("debug");
    let username = arguments.value_of("username").map(str::to_string);
    let token_secret = parse_argument(arguments.value_of("token_secret"), parse_hex)
        .context("invalid --token-secret")?
        .unwrap_or_default();
    let password = arguments.value_of("password").map(str::to_string);

    let log_level = if debug { log::LevelFilter::Debug } else { log::LevelFilter::Info };
    let mut logger = env_logger::Builder::from_default_env();
    logger.filter_level(log_level);
    logger.default_format_timestamp_nanos(true);
    logger.init();

    let client = KeyBackupApiClient::new(connect_uri, insecure_ssl).context("error creating api client")?;

    let mut runtime = tokio::runtime::Runtime::new().context("error creating tokio runtime")?;

    match subcommand_name {
        "delete" => {
            let enclave_name = subcommand_arguments.value_of("enclave_name").unwrap_or_default().to_string();
            let service_id = subcommand_arguments
                .value_of("service_id")
                .map(parse_hex)
                .transpose()
                .context("invalid --service-id")?;
            let request_count =
                u64::from_str(arguments.value_of("request_count").unwrap_or_default()).context("invalid --request-count")?;
            let max_parallel = u64::from_str(arguments.value_of("max_parallel").unwrap_or("1")).context("invalid --max-parallel")?;
            let backup_id = subcommand_arguments
                .value_of("backup_id")
                .map(parse_hex_bytes::<[u8; 32]>)
                .transpose()
                .context("invalid --backup-id")?;
            let username = username.unwrap_or_else(rand_username);
            let credentials = calculate_credentials(username, password, &token_secret);

            let parallel_count = max_parallel.min(request_count);
            let requested = Arc::new(AtomicU64::new(0));

            let backup_id = match backup_id {
                Some(backup_id) => future::Either::A(Ok(backup_id).into_future()),
                None => {
                    let token_response = client
                        .get_token(&credentials, &enclave_name)
                        .map_err(|error| error.context("error during token request"));
                    let backup_id = token_response.map(|token_response: GetTokenResponse| token_response.backupId.into());
                    future::Either::B(backup_id)
                }
            };
            let backup_id = runtime.block_on(backup_id)?;
            let request_loop = move |()| {
                if requested.fetch_add(1, atomic::Ordering::SeqCst) + 1 > request_count {
                    return future::Either::A(Ok(future::Loop::Break(())).into_future());
                }
                let delete_request = kbupd_client::DeleteRequest {
                    service_id: service_id.clone(),
                    backup_id:  Some(backup_id.to_vec()),
                };
                debug!("sending request: {}", &delete_request);
                let request = kbupd_client::Request {
                    backup:  None,
                    restore: None,
                    delete:  Some(delete_request),
                };

                let response = client
                    .backup_request(&credentials, &enclave_name, request)
                    .map_err(|error| error.context("error during delete request").into());

                let continued = response.and_then(move |response: kbupd_client::Response| {
                    if let Some(delete_response) = response.delete {
                        debug!("server response: {}", &delete_response);
                        Ok(future::Loop::Continue(()))
                    } else {
                        Err(format_err!("server response was empty: {:?}", &response))
                    }
                });
                future::Either::B(continued)
            };
            let futures = (0..parallel_count).map(move |_| future::loop_fn((), request_loop.clone()));
            let responses = futures::stream::futures_unordered(futures).for_each(|_| Ok(()));

            runtime.block_on(responses)?;
        }
        "delete_all" => {
            let request_count =
                u64::from_str(arguments.value_of("request_count").unwrap_or_default()).context("invalid --request-count")?;
            let max_parallel = u64::from_str(arguments.value_of("max_parallel").unwrap_or("1")).context("invalid --max-parallel")?;
            let username = username.unwrap_or_else(rand_username);
            let credentials = calculate_credentials(username, password, &token_secret);

            let parallel_count = max_parallel.min(request_count);
            let requested = Arc::new(AtomicU64::new(0));

            let request_loop = move |()| {
                if requested.fetch_add(1, atomic::Ordering::SeqCst) + 1 > request_count {
                    return future::Either::A(Ok(future::Loop::Break(())).into_future());
                }

                let response = client
                    .delete_backups(&credentials)
                    .map_err(|error| error.context("error during delete request").into())
                    .and_then(|_| -> Result<Loop<_, ()>, failure::Error> {
                        debug!("server response: ok");
                        Ok(future::Loop::Continue(()))
                    });

                future::Either::B(response)
            };
            let futures = (0..parallel_count).map(move |_| future::loop_fn((), request_loop.clone()));
            let responses = futures::stream::futures_unordered(futures).for_each(|_response: ()| Ok(()));

            runtime.block_on(responses)?;
        }
        "backup" | "restore" => {
            let enclave_name = leak_argument(subcommand_arguments.value_of("enclave_name").unwrap_or_default());
            let service_id = leak_argument(
                &subcommand_arguments
                    .value_of("service_id")
                    .map(parse_hex)
                    .transpose()
                    .context("invalid --service-id")?,
            );
            let request_count =
                u64::from_str(arguments.value_of("request_count").unwrap_or_default()).context("invalid --request-count")?;
            let max_parallel = u64::from_str(arguments.value_of("max_parallel").unwrap_or("1")).context("invalid --max-parallel")?;
            let backup_data = parse_argument(subcommand_arguments.value_of("backup_data"), parse_hex_bytes::<[u8; 32]>)
                .context("invalid --backup-data")?;
            let backup_pin =
                parse_argument(subcommand_arguments.value_of("backup_pin"), parse_hex_bytes::<[u8; 32]>).context("invalid --backup-pin")?;
            let backup_tries =
                parse_argument(subcommand_arguments.value_of("backup_tries"), u32::from_str).context("invalid --backup-tries")?;
            let valid_from = parse_argument(subcommand_arguments.value_of("valid_from"), u64::from_str)?
                .unwrap_or_else(|| SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("system clock is not set")
                    .as_secs()
                    .saturating_sub(86400));

            let parallel_count = max_parallel.min(request_count);
            let requested = Arc::new(AtomicU64::new(0));

            struct RequestState {
                credentials: KeyBackupApiCredentials,
                backup_id:   Vec<u8>,
                token:       Vec<u8>,
            }
            #[derive(Default)]
            struct RequestLoopState {
                request_state: Option<RequestState>,
                responses:     Vec<Box<dyn Display + Send>>,
            }
            let request_loop = move |state: RequestLoopState| {
                let RequestLoopState {
                    request_state,
                    mut responses,
                } = state;

                if requested.fetch_add(1, atomic::Ordering::SeqCst) + 1 > request_count {
                    return future::Either::A(Ok(future::Loop::Break(responses)).into_future());
                }

                let request_state = if let Some(request_state) = request_state {
                    future::Either::A(Ok(request_state).into_future())
                } else {
                    let credentials =
                        calculate_credentials(username.clone().unwrap_or_else(rand_username), password.clone(), &token_secret);

                    debug!("fetching token for {}", &credentials.username);

                    let token_response = client
                        .get_token(&credentials, enclave_name)
                        .map_err(|error| error.context("error during token request").into());
                    let request_state = token_response.map(move |token_response: GetTokenResponse| RequestState {
                        credentials,
                        backup_id: token_response.backupId.to_vec(),
                        token: token_response.token.to_vec(),
                    });

                    future::Either::B(request_state)
                };
                let client = client.clone();
                let looped = request_state.and_then(move |request_state: RequestState| {
                    let RequestState {
                        credentials,
                        backup_id,
                        token,
                    } = request_state;
                    let request = match subcommand_name {
                        "backup" => {
                            let backup_request = kbupd_client::BackupRequest {
                                service_id: service_id.clone(),
                                backup_id:  Some(backup_id.clone()),
                                token:      Some(token),
                                valid_from: Some(valid_from),
                                data:       Some(backup_data.clone().unwrap_or_else(rand_bytes).to_vec()),
                                pin:        Some(backup_pin.clone().unwrap_or_else(rand_bytes).to_vec()),
                                tries:      Some(backup_tries.unwrap_or(10)),
                            };
                            debug!("sending request: {}", &backup_request);
                            kbupd_client::Request {
                                backup:  Some(backup_request),
                                restore: None,
                                delete:  None,
                            }
                        }
                        "restore" => {
                            let restore_request = kbupd_client::RestoreRequest {
                                service_id: service_id.clone(),
                                backup_id:  Some(backup_id.clone()),
                                token:      Some(token),
                                valid_from: Some(valid_from),
                                pin:        Some(backup_pin.clone().unwrap_or_else(rand_bytes).to_vec()),
                            };
                            debug!("sending request: {}", &restore_request);
                            kbupd_client::Request {
                                backup:  None,
                                restore: Some(restore_request),
                                delete:  None,
                            }
                        }
                        _ => unreachable!(),
                    };
                    let response = client
                        .backup_request(&credentials, enclave_name, request)
                        .map_err(|error| error.context("error during key backup request").into());
                    let looped = response.and_then(move |response: kbupd_client::Response| match subcommand_name {
                        "backup" => {
                            let backup_response = match response.backup {
                                Some(backup_response) => backup_response,
                                None => return Err(format_err!("server response was empty: {:?}", &response)),
                            };
                            debug!("server response: {}", &backup_response);
                            let token = match backup_response.token.clone() {
                                Some(token) => token,
                                None => return Err(format_err!("server backup response did not contain a token")),
                            };
                            responses.push(Box::new(backup_response));
                            let state = RequestLoopState {
                                request_state: Some(RequestState {
                                    credentials,
                                    backup_id,
                                    token,
                                }),
                                responses,
                            };
                            Ok(future::Loop::Continue(state))
                        }
                        "restore" => {
                            let restore_response = match response.restore {
                                Some(restore_response) => restore_response,
                                None => return Err(format_err!("server response was empty: {:?}", &response)),
                            };
                            debug!("server response: {}", &restore_response);
                            responses.push(Box::new(restore_response));
                            let state = RequestLoopState {
                                request_state: None,
                                responses,
                            };
                            Ok(future::Loop::Continue(state))
                        }
                        _ => unreachable!(),
                    });
                    looped
                });
                future::Either::B(looped)
            };
            let futures = (0..parallel_count).map(move |_| future::loop_fn(Default::default(), request_loop.clone()));
            let responses = futures::stream::futures_unordered(futures).collect();
            let responses = runtime.block_on(responses)?;

            let stdout = std::io::stdout();
            let mut stdout_lock = stdout.lock();
            for response in responses.iter().flatten() {
                write!(stdout_lock, "{}\n", response)?;
            }
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn parse_argument<T, U, E, F>(maybe_argument: Option<T>, parse_fun: F) -> Result<Option<U>, E>
where F: Fn(T) -> Result<U, E> {
    if let Some(argument) = maybe_argument {
        Ok(Some(parse_fun(argument)?))
    } else {
        Ok(None)
    }
}

fn parse_hex_bytes<T>(hex: &str) -> Result<T, failure::Error>
where T: AsRef<[u8]> + AsMut<[u8]> + Default {
    let mut buf = Cursor::new(T::default());
    if hex.len() == buf.remaining_mut().saturating_mul(2) {
        parse_hex_buf(hex, &mut buf)?;
        Ok(buf.into_inner())
    } else {
        Err(format_err!(
            "wrong size hexadecimal parameter {} != {}",
            hex.len(),
            buf.remaining_mut().saturating_mul(2)
        ))
    }
}

fn parse_hex(hex: &str) -> Result<Vec<u8>, failure::Error> {
    let mut bytes: Vec<u8> = Vec::with_capacity(hex.len() / 2);
    parse_hex_buf(hex, &mut bytes)?;
    Ok(bytes)
}

fn parse_hex_buf(mut hex: &str, bytes: &mut impl BufMut) -> Result<(), failure::Error> {
    while let Some(hex_byte_str) = hex.get(..2) {
        let hex_byte =
            u8::from_str_radix(hex_byte_str, 16).with_context(|_| format_err!("invalid hexadecimal byte '{}': {}", hex_byte_str, hex))?;
        bytes.put(hex_byte);
        hex = hex.get(2..).unwrap_or_default();
    }
    if hex.is_empty() {
        Ok(())
    } else {
        Err(format_err!("truncated hexademical: {}", hex))
    }
}

fn rand_bytes<T>() -> T
where T: AsMut<[u8]> + Default {
    let mut buf = T::default();
    rand::thread_rng().fill_bytes(buf.as_mut());
    buf
}

fn calculate_credentials(username: String, password: Option<String>, token_secret: &[u8]) -> KeyBackupApiCredentials {
    let password = password.unwrap_or_else(|| calculate_password(&username, token_secret));
    KeyBackupApiCredentials { username, password }
}

fn rand_username() -> String {
    let mut rand = rand::thread_rng();
    format!("test_{:016x}{:016x}", rand.next_u64(), rand.next_u64())
}

fn calculate_password(username: &str, token_secret: &[u8]) -> String {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock is not set")
        .as_secs();
    let sign_data = format!("{}:{}", username, timestamp);
    let sign_key = ring::hmac::SigningKey::new(&ring::digest::SHA256, token_secret);
    let signature = ring::hmac::sign(&sign_key, sign_data.as_bytes());
    let mut token = sign_data;
    token.push(':');
    for byte in &signature.as_ref()[..10] {
        write!(&mut token, "{:02x}", byte).unwrap_or_else(|_| unreachable!());
    }
    token
}

fn leak_argument<T, U>(argument: &T) -> &'static T
where
    T: ToOwned<Owned = U> + ?Sized,
    U: std::borrow::Borrow<T>,
    Box<T>: From<U>,
{
    Box::leak(argument.to_owned().into())
}

fn parse_arguments() -> clap::ArgMatches<'static> {
    let enclave_name_argument = clap::Arg::with_name("enclave_name")
        .takes_value(true)
        .required(true)
        .long("enclave-name")
        .value_name("enclave_name")
        .help("Name of enclave to query, in a frontend kbupd instance");

    let service_id_argument = clap::Arg::with_name("service_id")
        .takes_value(true)
        .long("service-id")
        .value_name("service_id_hex")
        .help("Service ID to use in client request, as a hexadecimal byte string");

    let backup_id_argument = clap::Arg::with_name("backup_id")
        .takes_value(true)
        .long("backup-id")
        .value_name("backup_id_hex")
        .help("Backup ID to use in client request, as a hexadecimal byte string.");

    let delete_subcommand = clap::SubCommand::with_name("delete")
        .arg(enclave_name_argument.clone())
        .arg(service_id_argument.clone())
        .arg(backup_id_argument.clone())
        .about("Key Backup Service HTTP API Client - Delete");

    let delete_all_subcommand = clap::SubCommand::with_name("delete_all")
        .about("Key Backup Service HTTP API Client - Delete all for user");

    let service_id_argument = clap::Arg::with_name("service_id")
        .takes_value(true)
        .long("service-id")
        .value_name("service_id_hex")
        .help("Service ID to use in client request, as a hexadecimal byte string");

    let backup_data_argument = clap::Arg::with_name("backup_data")
        .takes_value(true)
        .long("backup-data")
        .value_name("backup_data_hex")
        .help("Backup Key to use in client request, as a hexadecimal byte string. Randomly generated by default.");

    let backup_pin_argument = clap::Arg::with_name("backup_pin")
        .takes_value(true)
        .long("backup-pin")
        .value_name("backup_pin_hex")
        .help("Backup PIN to use in client request, as a hexadecimal byte string. Randomly generated by default.");

    let backup_tries_argument = clap::Arg::with_name("backup_tries")
        .takes_value(true)
        .default_value("10")
        .long("backup-tries")
        .value_name("backup_tries")
        .help("Backup try count to use in client request, in decimal");

    let valid_from_argument = clap::Arg::with_name("valid_from")
        .takes_value(true)
        .long("valid-from")
        .value_name("valid_from")
        .help("Backup validity timestamp in seconds since the UNIX epoch. 24 hours ago by default.");

    let backup_subcommand = clap::SubCommand::with_name("backup")
        .arg(enclave_name_argument.clone())
        .arg(service_id_argument.clone())
        .arg(backup_data_argument)
        .arg(backup_pin_argument.clone())
        .arg(backup_tries_argument)
        .arg(valid_from_argument.clone())
        .about("Key Backup Service HTTP API Client - Backup");

    let restore_subcommand = clap::SubCommand::with_name("restore")
        .arg(enclave_name_argument)
        .arg(service_id_argument)
        .arg(backup_pin_argument)
        .arg(valid_from_argument)
        .about("Key Backup Service HTTP API Client - Restore");

    let connect_argument = clap::Arg::with_name("connect_uri")
        .takes_value(true)
        .required(true)
        .long("connect")
        .value_name("connect_uri")
        .help("Base URI of HTTPS API to connect to (e.g. https://api.backup.signal.org/)");

    let insecure_argument = clap::Arg::with_name("insecure")
        .long("insecure")
        .help("Allow insecure server connections when using SSL");

    let username_argument = clap::Arg::with_name("username")
        .takes_value(true)
        .required_unless("token_secret")
        .long("username")
        .value_name("username")
        .help(
            "Username to authenticate with, as assigned by a Signal server. Randomly generated by default, if --token-secret is provided.",
        );

    let password_argument = clap::Arg::with_name("password")
        .takes_value(true)
        .long("password")
        .value_name("password")
        .help("Password to authenticate with, as assigned by a Signal server");

    let token_secret_argument = clap::Arg::with_name("token_secret")
        .takes_value(true)
        .long("token-secret")
        .value_name("hex_secret")
        .help("Secret used to generate auth tokens, as a hexadecimal byte string");

    let authentication_secret_group = clap::ArgGroup::with_name("auth_secret")
        .required(true)
        .arg("password")
        .arg("token_secret");

    let request_count_argument = clap::Arg::with_name("request_count")
        .takes_value(true)
        .default_value("1")
        .long("request-count")
        .value_name("request_count")
        .help("Number of requests to perform, in decimal. For request parameters randomized by default, different values will be generated for each request.");

    let max_parallel_argument = clap::Arg::with_name("max_parallel")
        .takes_value(true)
        .conflicts_with("username")
        .long("max-parallel")
        .value_name("max_parallel")
        .help("Maximum number of requests to perform in parallel, in decimal")
        .long_help("Parallel requests are only possible if no --username is provided.");

    let debug_argument = clap::Arg::with_name("debug").long("debug").help("emit debug logging");

    clap::App::new("kbupd_api_client")
        .version(clap::crate_version!())
        .about(format!("{} -- HTTP API Client", clap::crate_description!()).as_str())
        .author(clap::crate_authors!())
        .setting(clap::AppSettings::VersionlessSubcommands)
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .arg(connect_argument)
        .arg(insecure_argument)
        .arg(username_argument)
        .arg(password_argument)
        .arg(token_secret_argument)
        .group(authentication_secret_group)
        .arg(request_count_argument)
        .arg(max_parallel_argument)
        .arg(debug_argument)
        .subcommand(delete_subcommand)
        .subcommand(delete_all_subcommand)
        .subcommand(backup_subcommand)
        .subcommand(restore_subcommand)
        .get_matches()
}
