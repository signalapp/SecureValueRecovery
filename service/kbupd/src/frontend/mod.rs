//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

pub mod config;

use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use failure::{format_err, ResultExt};
use futures::future;
use futures::prelude::*;
use hyper::Uri;
use hyper::client::connect::HttpConnector;
use kbupd_config::metrics::*;
use kbupd_config::FrontendConfig;
use kbuptlsd::prelude::*;
use nix::sys::signal;
use nix::sys::signal::Signal::*;

use crate::api::auth::signal_user::SignalUserAuthenticator;
use crate::api::listener::ApiListener;
use crate::api::service::*;
use crate::backup::manager::*;
use crate::backup::request_manager::*;
use crate::enclave::attestation_manager::AttestationManager;
use crate::enclave::status_refresh::EnclaveStatusRefreshTask;
use crate::enclave::timer_tick::EnclaveTimerTickTask;
use crate::intel_client::*;
use crate::limits::rate_limiter::*;
use crate::metrics::{JsonReporter, PeriodicReporter, METRICS};
use crate::peer::discovery::*;
use crate::peer::manager::*;
use crate::protobufs::kbupd::*;
use crate::tls::*;
use crate::*;

const REPLICA_TIMEOUT_TICKS: u32 = 5;

const REQUEST_QUOTE_INTERVAL: Duration = Duration::from_secs(600);

const MIN_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(120);

const DEFAULT_METRICS_INTERVAL: Duration = Duration::from_secs(60);
const ENCLAVE_STATUS_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

const REQUEST_CACHE_TTL: Duration = Duration::from_secs(600);

const PENDING_REQUESTS_TABLE_ORDER: u8 = 15;

pub struct FrontendService {
    runtime:               tokio::runtime::Runtime,
    enclave_thread_joiner: Box<dyn Future<Item = Result<(), failure::Error>, Error = Box<dyn std::any::Any + Send + 'static>> + Send>,
}

#[derive(Clone)]
pub struct FrontendCommandLineConfig<'a> {
    pub enclave_directory: &'a Path,
    pub config_directory:  &'a Path,
    pub kbuptlsd_bin_path: &'a Path,
    pub full_hostname:     Option<&'a str>,
}

impl FrontendService {
    pub fn start(
        config: FrontendConfig,
        cmdline_config: FrontendCommandLineConfig,
        peer_tls_client_args: TlsClientProxyArguments,
    ) -> Result<Self, failure::Error>
    {
        let mut runtime = tokio::runtime::Builder::new().build().context("error starting tokio runtime")?;
        let mut executor = runtime.executor();

        let enclave_manager_channel = EnclaveManagerChannel::new();
        let enclave_manager_tx = enclave_manager_channel.sender().clone();

        let intel_client;
        let handshake_manager;
        if !config.attestation.disabled {
            let hostname = String::from(Uri::from_str(&config.attestation.host)
                .context("error parsing attestation hostname")?
                .host()
                .expect("attestation host does not contain a hostname"));

            let intel_client_proxy =
                TlsClientProxySpawner::new(cmdline_config.kbuptlsd_bin_path.to_owned(), TlsClientProxyArguments::NoConfig {
                    ca: TlsClientProxyCaArgument::System,
                    key_file: None,
                    hostname: TlsClientProxyHostnameArgument::Hostname(hostname)
                })
                .context("error creating intel attestation tls proxy client")?;

            let new_intel_client =
                new_ias_client(&config.attestation.host, &config.attestation.apiKey, intel_client_proxy).context("error creating intel attestation client")?;
            handshake_manager = Some(HandshakeManager::new(
                enclave_manager_tx.clone(),
                new_intel_client.clone(),
                config.attestation.acceptGroupOutOfDate,
            ));
            intel_client = Some(new_intel_client);
        } else {
            handshake_manager = None;
            intel_client = None;
        }

        let peer_tls_client =
            TlsClient::new(cmdline_config.kbuptlsd_bin_path.to_owned(), peer_tls_client_args).context("error creating peer tls client")?;

        let mut enclave_configs = Vec::new();
        for enclave_config in config.enclaves {
            let mut partition_discoveries = Vec::new();
            for partition_config in &enclave_config.partitions {
                let mut addresses = Vec::new();
                for replica in &partition_config.replicas {
                    addresses.push(replica.hostPort.clone());
                }

                let range = partition_config.range.as_ref().map(PartitionKeyRangePb::from);
                partition_discoveries.push(PartitionPeerDiscovery::new(range, addresses, &peer_tls_client).discover());
            }

            let partitions = runtime
                .block_on(future::join_all(partition_discoveries))
                .map_err(|()| failure::err_msg("error during partition discovery"))?;
            enclave_configs.push((enclave_config, partitions));
        }

        let (enclave_init_tx, enclave_init_rx) = std::sync::mpsc::channel::<()>();
        let (enclave_join_tx, enclave_join_rx) = futures::sync::oneshot::channel::<util::Never>();

        let enclave_spid = config.attestation.spid;
        let enclave_executor = runtime.executor();
        let enclave_directory = cmdline_config.enclave_directory.to_owned();
        let enclave_thread = thread::spawn(move || -> Result<(), failure::Error> {
            let mut enclaves = Vec::with_capacity(enclave_configs.len());
            for (enclave_config, partitions) in enclave_configs {
                let (peer_manager_tx, peer_manager_rx) = actor::channel();
                let (attestation_manager_tx, attestation_manager_rx) = actor::channel();

                let enclave_name = enclave_config.name.to_string();
                let enclave_filename = format!("{}.so", &enclave_config.mrenclave);
                let enclave_path = enclave_directory.join(&enclave_filename);

                let replica_timeout_ticks = REPLICA_TIMEOUT_TICKS;
                let replica_timeout = Duration::from_millis(enclave_config.electionTimeoutMs) * 4;
                let pending_request_ttl = Duration::from_millis(enclave_config.pendingRequestTtlMs);
                let timer_tick_interval = replica_timeout / replica_timeout_ticks;

                let enclave_frontend_config = EnclaveFrontendConfig {
                    replica_timeout_ticks,
                    request_quote_ticks: util::duration::as_ticks(REQUEST_QUOTE_INTERVAL, timer_tick_interval),
                    min_connect_timeout_ticks: util::duration::as_ticks(MIN_CONNECT_TIMEOUT, timer_tick_interval),
                    max_connect_timeout_ticks: util::duration::as_ticks(MAX_CONNECT_TIMEOUT, timer_tick_interval),
                    pending_request_ttl: util::duration::as_ticks(pending_request_ttl, timer_tick_interval),
                    pending_request_count: enclave_config.pendingRequestCount,
                    max_backup_data_length: enclave_config.maxBackupDataLength,
                    ias_version: 4
                };

                let mut partition_configs = Vec::new();
                for (partition_config, peer_discovery) in partitions {
                    partition_configs.push(partition_config);
                    enclave_executor.spawn(peer_discovery.finish(peer_manager_tx.clone()));
                }

                info!(
                    "starting enclave {} with mrenclave {} with timer tick interval {}ms and {:#?}",
                    &enclave_name,
                    &enclave_config.mrenclave,
                    timer_tick_interval.as_millis(),
                    &enclave_frontend_config
                );

                let start_frontend_request = StartFrontendRequest {
                    config:     enclave_frontend_config,
                    partitions: partition_configs,
                };

                let mut enclave = (Enclave::new(
                    enclave_name.clone(),
                    &enclave_path.to_string_lossy(),
                    enclave_config.debug,
                    enclave_spid,
                    peer_manager_tx.clone(),
                    attestation_manager_tx.clone(),
                )
                .with_context(|_| format_err!("error creating enclave {}", enclave_name)))?;
                let node_id = enclave
                    .start_frontend(start_frontend_request, PENDING_REQUESTS_TABLE_ORDER)
                    .with_context(|_| format_err!("error starting frontend in enclave {}", enclave_name))?;

                let peer_manager = PeerManager::new(
                    peer_manager_tx,
                    enclave_config.name.to_string(),
                    enclave_manager_channel.sender().clone(),
                    node_id,
                    peer_tls_client.clone(),
                );
                let timer_tick_task =
                    EnclaveTimerTickTask::new(timer_tick_interval, enclave_name, enclave_manager_channel.sender().clone());

                let attestation_manager = AttestationManager::new(enclave_manager_channel.sender().clone(), intel_client.clone());

                enclave_executor.spawn(peer_manager_rx.enter_loop(peer_manager));
                enclave_executor.spawn(attestation_manager_rx.enter_loop(attestation_manager));
                enclave_executor.spawn(timer_tick_task.into_future());

                enclaves.push(enclave);
            }

            enclave_init_tx.send(())?;

            let mut enclave_manager = EnclaveManager::new(enclave_manager_channel, enclaves);
            match enclave_manager.run() {
                Ok(()) => info!("enclave manager stopped upon user request"),
                Err(error) => {
                    error!("fatal enclave error: {}", error);
                    return Err(error.into());
                }
            }

            drop(enclave_join_tx);
            Ok(())
        });

        match enclave_init_rx.recv() {
            Ok(()) => (),
            Err(_) => {
                return Err(enclave_thread.join().unwrap().unwrap_err());
            }
        }

        let handshake_manager = if let Some(handshake_manager) = handshake_manager {
            Some(
                runtime
                    .block_on(handshake_manager.fetch_all())
                    .context("error fetching quotes from IAS")?,
            )
        } else {
            None
        };

        let signal_user_authenticator = Arc::new(SignalUserAuthenticator::new(&config.api.userAuthenticationTokenSharedSecret));

        let api_rate_limiters = SignalApiRateLimiters {
            token:       actor::spawn(RateLimiter::new("token", config.api.limits.token.into()), &mut executor)?,
            attestation: actor::spawn(RateLimiter::new("attestation", config.api.limits.attestation.into()), &mut executor)?,
            backup:      actor::spawn(RateLimiter::new("backup", config.api.limits.backup.into()), &mut executor)?,
        };

        let (backup_request_manager_tx, backup_request_manager_rx) = actor::channel();
        let backup_request_manager = BackupRequestManager::new(REQUEST_CACHE_TTL);

        let status_refresh_task = EnclaveStatusRefreshTask::new(ENCLAVE_STATUS_REFRESH_INTERVAL, enclave_manager_tx.clone());
        let backup_id_key = ring::hmac::SigningKey::new(&ring::digest::SHA256, &config.api.backupIdSecret);
        let backup_manager = SignalBackupManager::new(enclave_manager_tx.clone(), backup_id_key, backup_request_manager_tx);
        let api_service = SignalApiService::new(signal_user_authenticator, backup_manager, config.api.denyBackup, api_rate_limiters);
        let api_listener = ApiListener::new(&config.api.listenHostPort, api_service).context("error starting api listener")?;
        let control_listener =
            ControlListener::new(config.control.listenHostPort, enclave_manager_tx).context("error starting control listener")?;

        runtime.spawn(api_listener.into_future());
        runtime.spawn(control_listener.into_future());
        runtime.spawn(status_refresh_task.into_future());
        runtime.spawn(backup_request_manager.enter_loop(backup_request_manager_rx).map(drop));
        if let Some(handshake_manager) = handshake_manager {
            runtime.spawn(handshake_manager.into_future());
        }

        if let Some(metrics_config) = config.metrics {
            for reporter_config in metrics_config.reporters {
                let MetricsReporterConfig::Json(json_reporter_config) = reporter_config;

                let mut reporter_http_connector = HttpConnector::new(1);
                reporter_http_connector.enforce_http(false);

                let reporter_tls_proxy =
                    TlsClientProxySpawner::new(cmdline_config.kbuptlsd_bin_path.to_owned(), TlsClientProxyArguments::NoConfig {
                        ca:       TlsClientProxyCaArgument::System,
                        key_file: None,
                        hostname: TlsClientProxyHostnameArgument::Hostname(json_reporter_config.hostname.to_string()),
                    })
                    .context("error creating metrics json reporter tls proxy client")?;

                let reporter_tls_connector = TlsProxyConnector::new(Arc::new(reporter_tls_proxy), reporter_http_connector);

                let reporter_interval = json_reporter_config
                    .intervalSeconds
                    .map(Duration::from_secs)
                    .unwrap_or(DEFAULT_METRICS_INTERVAL);
                let json_reporter = JsonReporter::new(
                    &json_reporter_config.apiKey,
                    &json_reporter_config.hostname,
                    cmdline_config.full_hostname,
                    &json_reporter_config.environment,
                    &json_reporter_config.partition,
                    "frontend",
                    reporter_tls_connector,
                )
                .context("error creating metrics json reporter")?;
                let periodic_reporter = PeriodicReporter::new(json_reporter, METRICS.clone(), reporter_interval);

                periodic_reporter.start();
            }
        }

        unix_signal::ignore_signal(SIGPIPE).context("error setting sigaction")?;
        unix_signal::ignore_signal(SIGCHLD).context("error setting sigaction")?;

        let unix_signals = unix_signal::handle_signals(vec![SIGHUP, SIGUSR1, SIGUSR2]);
        let unix_signals = runtime.block_on(unix_signals)?;
        let handled_unix_signals = unix_signals.for_each(|signum: signal::Signal| {
            info!("received unix signal {}", signum);
            Ok(())
        });
        let unix_signal_task = handled_unix_signals.map_err(|error: std::io::Error| {
            error!("error in unix signal handler: {}", error);
        });
        runtime.spawn(unix_signal_task);

        let enclave_thread_joiner = Box::new(enclave_join_rx.then(move |_| enclave_thread.join()));
        Ok(Self {
            runtime,
            enclave_thread_joiner,
        })
    }

    pub fn join(mut self) {
        match self.runtime.block_on(self.enclave_thread_joiner) {
            Ok(Ok(())) => info!("enclave shutdown"),
            Ok(Err(enclave_error)) => error!("enclave error: {}", enclave_error),
            Err(_join_error) => error!("enclave thread died"),
        }
        drop(self.runtime);
    }
}
