//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use failure::ResultExt;
use futures::prelude::*;
use hyper::Uri;
use hyper::client::connect::HttpConnector;
use kbupd_config::metrics::*;
use kbupd_config::ReplicaConfig;
use kbuptlsd::prelude::*;
use nix::sys::signal;
use nix::sys::signal::Signal::*;

use crate::enclave::attestation_manager::AttestationManager;
use crate::enclave::revocation_list_refresh::RevocationListRefreshTask;
use crate::enclave::status_refresh::EnclaveStatusRefreshTask;
use crate::enclave::timer_tick::EnclaveTimerTickTask;
use crate::intel_client::*;
use crate::metrics::{JsonReporter, PeriodicReporter, METRICS};
use crate::peer::listener::*;
use crate::peer::manager::*;
use crate::protobufs::kbupd::*;
use crate::tls::*;
use crate::*;

const ELECTION_TIMEOUT_TICKS: u32 = 10;

const MIN_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(120);

const DEFAULT_METRICS_INTERVAL: Duration = Duration::from_secs(60);
const ENCLAVE_STATUS_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const REVOCATION_LIST_REFRESH_INTERVAL: Duration = Duration::from_secs(600);

const ENCLAVE_NAME: &str = "";

pub struct ReplicaService {
    runtime:               tokio::runtime::current_thread::Runtime,
    enclave_thread_joiner: Box<dyn Future<Item = Result<(), failure::Error>, Error = Box<dyn std::any::Any + Send + 'static>>>,
}

#[derive(Clone)]
pub struct ReplicaCommandLineConfig<'a> {
    pub enclave_directory:    &'a Path,
    pub config_directory:     &'a Path,
    pub kbuptlsd_bin_path:    &'a Path,
    pub full_hostname:        Option<&'a str>,
    pub exit_signals_enabled: bool,
}

impl ReplicaService {
    pub fn start(
        config: ReplicaConfig,
        cmdline_config: ReplicaCommandLineConfig<'_>,
        peer_tls_server_args: TlsProxyListenerArguments,
        peer_tls_client_args: TlsClientProxyArguments,
    ) -> Result<Self, failure::Error>
    {
        let mut runtime = tokio::runtime::current_thread::Builder::new()
            .build()
            .context("error starting tokio runtime")?;

        let (peer_manager_tx, peer_manager_rx) = actor::channel();
        let (attestation_manager_tx, attestation_manager_rx) = actor::channel();

        let enclave_manager_channel = EnclaveManagerChannel::new();
        let enclave_manager_tx = enclave_manager_channel.sender().clone();

        let maybe_intel_client = if !config.attestation.disabled {
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
                .context("error creating intel attestation tls client proxy")?;
            Some(new_ias_client(&config.attestation.host, &config.attestation.apiKey, intel_client_proxy).context("error creating intel attestation client")?)
        } else {
            None
        };

        let peer_tls_client =
            TlsClient::new(cmdline_config.kbuptlsd_bin_path.to_owned(), peer_tls_client_args).context("error creating peer tls client")?;

        let enclave_spid = config.attestation.spid;
        let peer_listen_address = config.enclave.listenHostPort;
        let tls_max_connections = config.enclave.maxConnections.max(128) as usize;
        let enclave_mrenclave = config.enclave.mrenclave;
        let enclave_debug = config.enclave.debug;
        let enclave_filename = format!("{}.so", &enclave_mrenclave);
        let enclave_path = cmdline_config.enclave_directory.join(&enclave_filename);

        let election_timeout_ticks = ELECTION_TIMEOUT_TICKS.max(config.enclave.electionHeartbeats);
        let election_timeout = Duration::from_millis(config.enclave.electionTimeoutMs);
        let timer_tick_interval = election_timeout / election_timeout_ticks;

        let enclave_replica_config = EnclaveReplicaConfig {
            election_timeout_ticks,
            heartbeat_timeout_ticks: election_timeout_ticks.checked_div(config.enclave.electionHeartbeats).unwrap_or(1),
            min_connect_timeout_ticks: util::duration::as_ticks(MIN_CONNECT_TIMEOUT, timer_tick_interval),
            max_connect_timeout_ticks: util::duration::as_ticks(MAX_CONNECT_TIMEOUT, timer_tick_interval),
            attestation_expiry_ticks: util::duration::as_ticks(
                Duration::from_millis(config.enclave.attestationExpiryCommitIntervalMs),
                timer_tick_interval,
            ),
            request_quote_ticks: util::duration::as_ticks(
                Duration::from_millis(config.enclave.attestationExpiryCommitIntervalMs),
                timer_tick_interval,
            ),
            replication_chunk_size: config.enclave.replicationChunkSize,
            transfer_chunk_size: config.enclave.transferChunkSize,
            storage_page_cache_size: Default::default(), // unused
            max_frontend_count: config.enclave.maxFrontendCount,
            raft_log_index_page_cache_size: 10,
        };

        info!(
            "starting enclave with mrenclave {} with timer tick interval {}ms and {:#?}",
            &enclave_mrenclave,
            timer_tick_interval.as_millis(),
            &enclave_replica_config
        );

        let start_replica_request = StartReplicaRequest {
            config: enclave_replica_config,
        };

        let (enclave_join_tx, enclave_join_rx) = futures::sync::oneshot::channel::<util::Never>();

        let (node_id_tx, node_id_rx) = std::sync::mpsc::channel();
        let enclave_peer_manager_tx = peer_manager_tx.clone();
        let enclave_thread = thread::spawn(move || -> Result<(), failure::Error> {
            let mut enclave = Enclave::new(
                ENCLAVE_NAME.to_string(),
                &enclave_path.to_string_lossy(),
                enclave_debug,
                enclave_spid,
                enclave_peer_manager_tx,
                attestation_manager_tx,
            )
            .context("error creating enclave")?;
            let node_id = enclave
                .start_replica(start_replica_request)
                .context("error starting replica in enclave")?;

            node_id_tx.send(node_id)?;

            let mut enclave_manager = EnclaveManager::new(enclave_manager_channel, vec![enclave]);
            while let Err(enclave_error) = enclave_manager.run() {
                error!("fatal enclave error, retrying in 1 second: {}", enclave_error);
                thread::sleep(Duration::from_secs(1));
            }

            drop(enclave_join_tx);
            Ok(())
        });

        let node_id = match node_id_rx.recv() {
            Ok(node_id) => node_id,
            Err(std::sync::mpsc::RecvError) => {
                return Err(enclave_thread.join().unwrap().unwrap_err());
            }
        };

        let peer_listener = PeerListener::new(
            peer_listen_address,
            cmdline_config.kbuptlsd_bin_path.to_owned(),
            tls_max_connections,
            peer_tls_server_args,
            peer_manager_tx.clone(),
        )
        .context("error starting peer listener")?;
        let peer_manager = PeerManager::new(
            peer_manager_tx.clone(),
            ENCLAVE_NAME.to_string(),
            enclave_manager_tx.clone(),
            node_id,
            peer_tls_client.clone(),
        );
        let attestation_manager = AttestationManager::new(enclave_manager_tx.clone(), maybe_intel_client.clone());
        let control_listener =
            ControlListener::new(config.control.listenHostPort, enclave_manager_tx.clone()).context("error starting control listener")?;
        let timer_tick_task = EnclaveTimerTickTask::new(timer_tick_interval, ENCLAVE_NAME.to_string(), enclave_manager_tx.clone());
        let status_refresh_task = EnclaveStatusRefreshTask::new(ENCLAVE_STATUS_REFRESH_INTERVAL, enclave_manager_tx.clone());
        let sig_rl_refresh_task = maybe_intel_client.map(|ias_client: KbupdIasClient| {
            RevocationListRefreshTask::new(REVOCATION_LIST_REFRESH_INTERVAL, ias_client, enclave_manager_tx.clone())
        });

        runtime.spawn(peer_listener.into_future());
        runtime.spawn(peer_manager_rx.enter_loop(peer_manager));
        runtime.spawn(attestation_manager_rx.enter_loop(attestation_manager));
        runtime.spawn(control_listener.into_future());
        runtime.spawn(timer_tick_task.into_future());
        runtime.spawn(status_refresh_task.into_future());
        if let Some(sig_rl_refresh_task) = sig_rl_refresh_task {
            runtime.spawn(sig_rl_refresh_task.into_future());
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
                    "replica",
                    reporter_tls_connector,
                )
                .context("error creating metrics json reporter")?;
                let periodic_reporter = PeriodicReporter::new(json_reporter, METRICS.clone(), reporter_interval);

                periodic_reporter.start();
            }
        }

        unix_signal::ignore_signal(SIGPIPE).context("error setting sigaction")?;
        unix_signal::ignore_signal(SIGCHLD).context("error setting sigaction")?;

        let unix_signals = unix_signal::handle_signals(vec![SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2]);
        let unix_signals = runtime.block_on(unix_signals)?;
        let enclave_manager_tx_2 = enclave_manager_tx.clone();
        let exit_signals_enabled = cmdline_config.exit_signals_enabled;
        let handled_unix_signals = unix_signals.for_each(move |signum: signal::Signal| {
            match signum {
                SIGINT | SIGQUIT | SIGTERM if exit_signals_enabled => {
                    warn!("shutting down due to unix signal {}", signum);
                    let _ignore = enclave_manager_tx_2.cast(|enclave_manager: &mut EnclaveManager| enclave_manager.stop());
                }
                _ => {
                    info!("received unix signal {}", signum);
                }
            }
            Ok(())
        });
        let unix_signal_task = handled_unix_signals.map_err(|error: std::io::Error| {
            error!("error in unix signal handler: {}", error);
        });
        runtime.spawn(unix_signal_task);

        let source_partition = if let Some(source_partition_config) = config.enclave.sourcePartition {
            let source_partition_range = PartitionKeyRangePb {
                first: BackupId {
                    id: source_partition_config.firstBackupId.to_vec(),
                },
                last:  BackupId {
                    id: source_partition_config.lastBackupId.to_vec(),
                },
            };

            let source_replica_addresses = source_partition_config.replicas.into_iter().map(|peer| peer.hostPort).collect();

            let peer_tls_client = peer_tls_client.clone();
            let source_node_ids = peer_manager_tx.call(move |peer_manager: &mut PeerManager, reply_tx| {
                peer_manager.discover_peers(source_replica_addresses, &peer_tls_client, reply_tx)
            });

            let peer_manager_tx = peer_manager_tx.clone();
            let source_partition = source_node_ids.map(move |source_node_ids: Vec<NodeId>| {
                let source_node_ids_2 = source_node_ids.clone();
                let _ignore =
                    peer_manager_tx.cast(move |peer_manager: &mut PeerManager| peer_manager.set_source_partition(source_node_ids_2));
                Some(SourcePartitionConfig {
                    node_ids: source_node_ids.into_iter().map(Vec::from).collect(),
                    range:    source_partition_range,
                })
            });
            let source_partition = source_partition.map_err(|error| {
                error!("error discovering source replicas: {}", error);
            });
            futures::future::Either::A(source_partition)
        } else {
            futures::future::Either::B(Ok(None).into_future())
        };

        let peer_replica_addresses = config.enclave.replicas.into_iter().map(|peer| peer.hostPort).collect();

        let peer_node_ids = peer_manager_tx.call(move |peer_manager: &mut PeerManager, reply_tx| {
            peer_manager.discover_peers(peer_replica_addresses, &peer_tls_client, reply_tx)
        });
        let peer_node_ids = peer_node_ids.map_err(|error| {
            error!("error discovering peer replicas: {}", error);
        });

        let replica_group_config = EnclaveReplicaGroupConfig {
            storage_size:           config.enclave.storageSize,
            raft_log_data_size:     config.enclave.raftLogSize,
            raft_log_index_size:    (config.enclave.raftLogSize / 128) as u32, // XXX correct ratio here
            max_backup_data_length: config.enclave.maxBackupDataLength,
        };

        let discovered_peers = source_partition.join(peer_node_ids);
        let replica_group_started = discovered_peers.map(
            move |(source_partition, peer_node_ids): (Option<SourcePartitionConfig>, Vec<NodeId>)| {
                if peer_node_ids.iter().all(|peer_node_id| peer_node_id < &node_id) {
                    let _ignore = enclave_manager_tx.cast(move |enclave_manager: &mut EnclaveManager| {
                        enclave_manager.start_replica_group(ENCLAVE_NAME, StartReplicaGroupRequest {
                            peer_node_ids: peer_node_ids.into_iter().map(Vec::from).collect(),
                            config: replica_group_config,
                            source_partition,
                        })
                    });
                }
            },
        );
        runtime.spawn(replica_group_started);

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
