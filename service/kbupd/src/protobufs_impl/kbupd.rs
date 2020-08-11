//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use crate::protobufs::kbupd::*;
use crate::util::{DisplayAsDebug, ListDisplay, OptionDisplay, ToHex};

impl std::fmt::Display for EnclaveStatus {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let EnclaveStatus {
            name,
            node_id,
            config,
            status,
        } = self;
        let mut debug = fmt.debug_struct("EnclaveStatus");
        debug.field("name", name);
        debug.field("node_id", &ToHex(node_id));

        match config {
            Some(enclave_status::Config::ReplicaConfig(replica_config)) => {
                debug.field("replica_config", replica_config);
            }
            Some(enclave_status::Config::FrontendConfig(frontend_config)) => {
                debug.field("frontend_config", frontend_config);
            }
            None => (),
        }

        match status {
            Some(enclave_status::Status::ReplicaStatus(replica_status)) => {
                debug.field("replica_status", &DisplayAsDebug(replica_status));
            }
            Some(enclave_status::Status::FrontendStatus(frontend_status)) => {
                debug.field("frontend_status", &DisplayAsDebug(frontend_status));
            }
            None => (),
        }

        debug.finish()
    }
}

impl std::fmt::Display for EnclaveMemoryStatus {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let EnclaveMemoryStatus {
            footprint_bytes,
            used_bytes,
            free_chunks,
        } = self;
        let mut debug = fmt.debug_struct("EnclaveFrontendStatus");
        debug.field("footprint_bytes", footprint_bytes);
        debug.field("used_bytes", used_bytes);
        debug.field("free_chunks", free_chunks);
        debug.finish()
    }
}

impl std::fmt::Display for EnclaveFrontendStatus {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let EnclaveFrontendStatus {
            memory_status,
            partitions,
            ranges,
        } = self;
        let mut debug = fmt.debug_struct("EnclaveFrontendStatus");
        if let Some(memory_status) = memory_status {
            debug.field("memory_status", &DisplayAsDebug(memory_status));
        }
        debug.field("partitions", &ListDisplay(partitions));
        debug.field("ranges", &ListDisplay(ranges));
        debug.finish()
    }
}

impl std::fmt::Display for EnclaveFrontendPartitionStatus {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let EnclaveFrontendPartitionStatus { group_id, nodes } = self;
        let mut debug = fmt.debug_struct("EnclaveFrontendPartitionStatus");
        debug.field("group_id", &ToHex(group_id));
        debug.field("nodes", &ListDisplay(nodes));
        debug.finish()
    }
}

impl std::fmt::Display for EnclaveFrontendRangeStatus {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let EnclaveFrontendRangeStatus { range, group_id } = self;
        write!(fmt, "{} => {}", range, &ToHex(group_id))
    }
}

impl std::fmt::Display for EnclaveReplicaStatus {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let EnclaveReplicaStatus { memory_status, partition } = self;

        let mut debug = fmt.debug_struct("EnclaveReplicaStatus");
        if let Some(memory_status) = memory_status {
            debug.field("memory_status", &DisplayAsDebug(memory_status));
        }
        if let Some(partition) = partition {
            debug.field("partition", &DisplayAsDebug(partition));
        }
        debug.finish()
    }
}

impl std::fmt::Display for EnclaveReplicaPartitionStatus {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let EnclaveReplicaPartitionStatus {
            group_id,
            service_id,
            range,
            peers,
            min_attestation,
            is_leader,
            current_term,
            prev_log_index,
            last_applied_index,
            commit_index,
            last_log_index,
            last_log_term,
            log_data_length,
            backup_count,
            xfer_status,
        } = self;
        let mut debug = fmt.debug_struct("EnclaveReplicaPartitionStatus");
        debug.field("group_id", &ToHex(group_id));
        debug.field("service_id", &OptionDisplay(service_id.as_ref().map(ToHex::new)));
        debug.field("range", &OptionDisplay(range.as_ref()));
        debug.field("peers", &ListDisplay(peers));
        debug.field("min_attestation", &DisplayAsDebug(min_attestation));
        debug.field("is_leader", is_leader);
        debug.field("current_term", current_term);
        debug.field("prev_log_index", prev_log_index);
        debug.field("last_applied_index", last_applied_index);
        debug.field("commit_index", commit_index);
        debug.field("last_log_index", last_log_index);
        debug.field("last_log_term", last_log_term);
        debug.field("log_data_length", log_data_length);
        debug.field("backup_count", backup_count);
        match xfer_status {
            Some(enclave_replica_partition_status::XferStatus::IncomingXferStatus(incoming_xfer_status)) => {
                debug.field("incoming_xfer_status", &DisplayAsDebug(incoming_xfer_status));
            }
            Some(enclave_replica_partition_status::XferStatus::OutgoingXferStatus(outgoing_xfer_status)) => {
                debug.field("outgoing_xfer_status", &DisplayAsDebug(outgoing_xfer_status));
            }
            None => (),
        }
        debug.finish()
    }
}

impl std::fmt::Display for EnclavePeerStatus {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let EnclavePeerStatus {
            node_id,
            attestation,
            replication_status,
            is_leader,
            inflight_requests,
            unsent_requests,
        } = self;
        let mut debug = fmt.debug_struct("EnclavePeerStatus");
        debug.field("node_id", &ToHex(node_id));
        debug.field("attestation", &OptionDisplay(attestation.as_ref()));
        if let Some(replication_status) = replication_status {
            debug.field("replication_status", &DisplayAsDebug(replication_status));
        }
        debug.field("is_leader", is_leader);
        debug.field("inflight_requests", inflight_requests);
        debug.field("unsent_requests", unsent_requests);

        debug.finish()
    }
}

impl std::fmt::Display for EnclavePeerReplicationStatus {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let EnclavePeerReplicationStatus {
            next_index,
            match_index,
            inflight_index,
            probing,
        } = self;
        let mut debug = fmt.debug_struct("EnclavePeerReplicationStatus");
        debug.field("next_index", next_index);
        debug.field("match_index", match_index);
        debug.field("inflight_index", &OptionDisplay(inflight_index.as_ref()));
        debug.field("probing", probing);
        debug.finish()
    }
}

impl std::fmt::Display for EnclaveIncomingXferStatus {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let EnclaveIncomingXferStatus { desired_range, nodes } = self;
        let mut debug = fmt.debug_struct("EnclaveIncomingXferStatus");
        debug.field("desired_range", &DisplayAsDebug(desired_range));
        debug.field("nodes", &ListDisplay(nodes));
        debug.finish()
    }
}

impl std::fmt::Display for EnclaveOutgoingXferStatus {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let EnclaveOutgoingXferStatus {
            group_id,
            full_xfer_range,
            current_chunk_range,
            paused,
            min_attestation,
            nodes,
        } = self;
        let mut debug = fmt.debug_struct("EnclaveOutgoingXferStatus");
        debug.field("group_id", &ToHex(group_id));
        debug.field("full_xfer_range", &DisplayAsDebug(full_xfer_range));
        debug.field("current_chunk_range", &OptionDisplay(current_chunk_range.as_ref()));
        debug.field("paused", paused);
        debug.field("min_attestation", &OptionDisplay(min_attestation.as_ref()));
        debug.field("nodes", &nodes.iter().map(DisplayAsDebug).collect::<Vec<_>>());
        debug.finish()
    }
}

impl std::fmt::Display for PartitionKeyRangePb {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{}-{}", ToHex(&self.first.id), ToHex(&self.last.id))
    }
}

impl std::fmt::Display for AttestationParameters {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let AttestationParameters { unix_timestamp_seconds } = self;
        let timestamp: chrono::DateTime<chrono::Utc> =
            chrono::DateTime::from(std::time::UNIX_EPOCH + std::time::Duration::from_secs(*unix_timestamp_seconds));
        write!(fmt, "{}", timestamp.to_rfc3339())
    }
}
