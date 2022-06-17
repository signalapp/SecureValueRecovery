//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

//
// shared types
//

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ServiceId {
    #[prost(bytes, required, tag = "1")]
    pub id: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BackupId {
    #[prost(bytes, required, tag = "1")]
    pub id: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PartitionKeyRangePb {
    #[prost(message, required, tag = "1")]
    pub first: BackupId,
    #[prost(message, required, tag = "2")]
    pub last:  BackupId,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IasReport {
    #[prost(bytes, required, tag = "2")]
    pub body:         std::vec::Vec<u8>,
    #[prost(bytes, required, tag = "3")]
    pub signature:    std::vec::Vec<u8>,
    #[prost(bytes, repeated, tag = "4")]
    pub certificates: ::std::vec::Vec<std::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AttestationParameters {
    #[prost(uint64, required, tag = "1")]
    pub unix_timestamp_seconds: u64,
}
//
// transaction requests
//

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateBackupRequest {
    #[prost(message, required, tag = "1")]
    pub backup_id: BackupId,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateBackupReply {
    #[prost(bytes, required, tag = "2")]
    pub token: std::vec::Vec<u8>,
    #[prost(uint32, optional, tag = "3")]
    pub tries: ::std::option::Option<u32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeleteBackupRequest {
    #[prost(message, required, tag = "1")]
    pub backup_id: BackupId,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeleteBackupReply {}
//
// untrusted messages
//

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UntrustedMessageBatch {
    #[prost(message, repeated, tag = "1")]
    pub messages: ::std::vec::Vec<UntrustedMessage>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UntrustedMessage {
    #[prost(oneof = "untrusted_message::Inner", tags = "1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16")]
    pub inner: ::std::option::Option<untrusted_message::Inner>,
}
pub mod untrusted_message {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Inner {
        #[prost(message, tag = "1")]
        StartFrontendRequest(super::StartFrontendRequest),
        #[prost(message, tag = "2")]
        StartReplicaRequest(super::StartReplicaRequest),
        #[prost(message, tag = "3")]
        StartReplicaGroupRequest(super::StartReplicaGroupRequest),
        #[prost(message, tag = "4")]
        UntrustedTransactionRequest(super::UntrustedTransactionRequest),
        #[prost(message, tag = "5")]
        UntrustedXferRequest(super::UntrustedXferRequest),
        #[prost(message, tag = "6")]
        GetEnclaveStatusRequest(super::GetEnclaveStatusRequest),
        #[prost(message, tag = "8")]
        GetQeInfoReply(super::GetQeInfoReply),
        #[prost(message, tag = "9")]
        GetQuoteReply(super::GetQuoteReply),
        #[prost(message, tag = "10")]
        GetAttestationReply(super::GetAttestationReply),
        #[prost(message, tag = "11")]
        NewMessageSignal(super::NewMessageSignal),
        #[prost(message, tag = "12")]
        TimerTickSignal(super::TimerTickSignal),
        #[prost(message, tag = "13")]
        SetFrontendConfigSignal(super::SetFrontendConfigSignal),
        #[prost(message, tag = "14")]
        SetReplicaConfigSignal(super::SetReplicaConfigSignal),
        #[prost(message, tag = "15")]
        ResetPeerSignal(super::ResetPeerSignal),
        #[prost(message, tag = "16")]
        SetVerboseLoggingSignal(super::SetVerboseLoggingSignal),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PartitionConfig {
    #[prost(bytes, required, tag = "1")]
    pub group_id: std::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub range:    ::std::option::Option<PartitionKeyRangePb>,
    #[prost(bytes, repeated, tag = "3")]
    pub node_ids: ::std::vec::Vec<std::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StartFrontendRequest {
    #[prost(message, repeated, tag = "1")]
    pub partitions: ::std::vec::Vec<PartitionConfig>,
    #[prost(message, required, tag = "2")]
    pub config:     EnclaveFrontendConfig,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveFrontendConfig {
    #[prost(uint32, required, tag = "1")]
    pub replica_timeout_ticks:     u32,
    #[prost(uint32, required, tag = "2")]
    pub request_quote_ticks:       u32,
    #[prost(uint32, required, tag = "3")]
    pub min_connect_timeout_ticks: u32,
    #[prost(uint32, required, tag = "4")]
    pub max_connect_timeout_ticks: u32,
    #[prost(uint32, required, tag = "5")]
    pub pending_request_count:     u32,
    #[prost(uint32, required, tag = "6")]
    pub pending_request_ttl:       u32,
    #[prost(uint32, required, tag = "7")]
    pub max_backup_data_length:    u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SourcePartitionConfig {
    #[prost(message, required, tag = "1")]
    pub range:    PartitionKeyRangePb,
    #[prost(bytes, repeated, tag = "2")]
    pub node_ids: ::std::vec::Vec<std::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StartReplicaRequest {
    #[prost(message, required, tag = "1")]
    pub config: EnclaveReplicaConfig,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveReplicaConfig {
    #[prost(uint32, required, tag = "1")]
    pub election_timeout_ticks:         u32,
    #[prost(uint32, required, tag = "2")]
    pub heartbeat_timeout_ticks:        u32,
    #[prost(uint32, required, tag = "3")]
    pub request_quote_ticks:            u32,
    #[prost(uint32, required, tag = "4")]
    pub min_connect_timeout_ticks:      u32,
    #[prost(uint32, required, tag = "5")]
    pub max_connect_timeout_ticks:      u32,
    #[prost(uint32, required, tag = "6")]
    pub attestation_expiry_ticks:       u32,
    #[prost(uint32, required, tag = "7")]
    pub replication_chunk_size:         u32,
    #[prost(uint32, required, tag = "8")]
    pub transfer_chunk_size:            u32,
    #[prost(uint32, required, tag = "10")]
    pub storage_page_cache_size:        u32,
    #[prost(uint32, required, tag = "13")]
    pub raft_log_index_page_cache_size: u32,
    #[prost(uint32, required, tag = "14")]
    pub max_frontend_count:             u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StartReplicaGroupRequest {
    #[prost(bytes, repeated, tag = "1")]
    pub peer_node_ids:    ::std::vec::Vec<std::vec::Vec<u8>>,
    #[prost(message, required, tag = "2")]
    pub config:           EnclaveReplicaGroupConfig,
    #[prost(message, optional, tag = "3")]
    pub source_partition: ::std::option::Option<SourcePartitionConfig>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveReplicaGroupConfig {
    #[prost(uint32, required, tag = "1")]
    pub storage_size:           u32,
    #[prost(uint64, required, tag = "2")]
    pub raft_log_data_size:     u64,
    #[prost(uint32, required, tag = "3")]
    pub raft_log_index_size:    u32,
    #[prost(uint32, required, tag = "4")]
    pub max_backup_data_length: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NewMessageSignal {
    #[prost(bytes, required, tag = "1")]
    pub node_id: std::vec::Vec<u8>,
    #[prost(bytes, required, tag = "2")]
    pub data:    std::vec::Vec<u8>,
    #[prost(bool, required, tag = "3")]
    pub syn:     bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TimerTickSignal {
    #[prost(fixed64, required, tag = "1")]
    pub now_secs: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetFrontendConfigSignal {
    #[prost(message, required, tag = "1")]
    pub config: EnclaveFrontendConfig,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetReplicaConfigSignal {
    #[prost(message, required, tag = "1")]
    pub config: EnclaveReplicaConfig,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ResetPeerSignal {
    #[prost(bytes, required, tag = "1")]
    pub peer_node_id: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetVerboseLoggingSignal {
    #[prost(bool, required, tag = "1")]
    pub verbose_logging: bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetQeInfoReply {
    #[prost(bytes, required, tag = "1")]
    pub mrenclave:   std::vec::Vec<u8>,
    #[prost(uint64, required, tag = "2")]
    pub flags:       u64,
    #[prost(uint64, required, tag = "3")]
    pub xfrm:        u64,
    #[prost(uint32, required, tag = "4")]
    pub misc_select: u32,
    #[prost(uint32, required, tag = "5")]
    pub config_svn:  u32,
    #[prost(bytes, required, tag = "6")]
    pub config_id:   std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetQuoteReply {
    #[prost(bytes, required, tag = "1")]
    pub request_id: std::vec::Vec<u8>,
    #[prost(bytes, required, tag = "2")]
    pub sgx_quote:  std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetAttestationReply {
    #[prost(bytes, required, tag = "1")]
    pub request_id: std::vec::Vec<u8>,
    #[prost(message, required, tag = "2")]
    pub ias_report: IasReport,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UntrustedTransactionRequest {
    #[prost(uint64, required, tag = "1")]
    pub request_id: u64,
    #[prost(oneof = "untrusted_transaction_request::Data", tags = "2, 3")]
    pub data:       ::std::option::Option<untrusted_transaction_request::Data>,
}
pub mod untrusted_transaction_request {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Data {
        #[prost(message, tag = "2")]
        CreateBackupRequest(super::CreateBackupRequest),
        #[prost(message, tag = "3")]
        DeleteBackupRequest(super::DeleteBackupRequest),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UntrustedXferRequest {
    #[prost(uint64, required, tag = "1")]
    pub request_id: u64,
    #[prost(oneof = "untrusted_xfer_request::Data", tags = "2")]
    pub data:       ::std::option::Option<untrusted_xfer_request::Data>,
}
pub mod untrusted_xfer_request {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Data {
        #[prost(enumeration = "super::XferControlCommand", tag = "2")]
        XferControlCommand(i32),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetEnclaveStatusRequest {
    #[prost(bool, required, tag = "1")]
    pub memory_status: bool,
}
//
// enclave messages
//

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveMessageBatch {
    #[prost(message, repeated, tag = "1")]
    pub messages: ::std::vec::Vec<EnclaveMessage>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveMessage {
    #[prost(oneof = "enclave_message::Inner", tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12")]
    pub inner: ::std::option::Option<enclave_message::Inner>,
}
pub mod enclave_message {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Inner {
        #[prost(message, tag = "1")]
        StartFrontendReply(super::StartFrontendReply),
        #[prost(message, tag = "2")]
        StartReplicaReply(super::StartReplicaReply),
        #[prost(message, tag = "3")]
        StartReplicaGroupReply(super::StartReplicaGroupReply),
        #[prost(message, tag = "4")]
        UntrustedTransactionReply(super::UntrustedTransactionReply),
        #[prost(message, tag = "5")]
        UntrustedXferReply(super::UntrustedXferReply),
        #[prost(message, tag = "6")]
        GetEnclaveStatusReply(super::GetEnclaveStatusReply),
        #[prost(message, tag = "7")]
        SendMessageRequest(super::SendMessageRequest),
        #[prost(message, tag = "8")]
        GetQeInfoRequest(super::GetQeInfoRequest),
        #[prost(message, tag = "9")]
        GetQuoteRequest(super::GetQuoteRequest),
        #[prost(message, tag = "10")]
        GetAttestationRequest(super::GetAttestationRequest),
        #[prost(message, tag = "11")]
        EnclaveLogSignal(super::EnclaveLogSignal),
        #[prost(message, tag = "12")]
        EnclaveTransactionSignal(super::EnclaveTransactionSignal),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StartFrontendReply {
    #[prost(bytes, required, tag = "1")]
    pub node_id: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StartReplicaReply {
    #[prost(bytes, required, tag = "1")]
    pub node_id: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StartReplicaGroupReply {
    #[prost(message, optional, tag = "1")]
    pub service_id: ::std::option::Option<ServiceId>,
    #[prost(bytes, optional, tag = "2")]
    pub group_id:   ::std::option::Option<std::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetEnclaveStatusReply {
    #[prost(oneof = "get_enclave_status_reply::Inner", tags = "1, 2")]
    pub inner: ::std::option::Option<get_enclave_status_reply::Inner>,
}
pub mod get_enclave_status_reply {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Inner {
        #[prost(message, tag = "1")]
        ReplicaStatus(super::EnclaveReplicaStatus),
        #[prost(message, tag = "2")]
        FrontendStatus(super::EnclaveFrontendStatus),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SendMessageRequest {
    #[prost(bytes, required, tag = "1")]
    pub node_id:   std::vec::Vec<u8>,
    #[prost(bytes, required, tag = "2")]
    pub data:      std::vec::Vec<u8>,
    #[prost(bool, required, tag = "3")]
    pub syn:       bool,
    #[prost(bytes, optional, tag = "4")]
    pub debug_msg: ::std::option::Option<std::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetQeInfoRequest {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetQuoteRequest {
    #[prost(bytes, required, tag = "1")]
    pub request_id: std::vec::Vec<u8>,
    #[prost(bytes, required, tag = "2")]
    pub sgx_report: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetAttestationRequest {
    #[prost(bytes, required, tag = "1")]
    pub request_id: std::vec::Vec<u8>,
    #[prost(bytes, required, tag = "2")]
    pub sgx_quote:  std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UntrustedTransactionReply {
    #[prost(uint64, required, tag = "1")]
    pub request_id: u64,
    #[prost(oneof = "untrusted_transaction_reply::Data", tags = "2, 3")]
    pub data:       ::std::option::Option<untrusted_transaction_reply::Data>,
}
pub mod untrusted_transaction_reply {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Data {
        #[prost(message, tag = "2")]
        CreateBackupReply(super::CreateBackupReply),
        #[prost(message, tag = "3")]
        DeleteBackupReply(super::DeleteBackupReply),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UntrustedXferReply {
    #[prost(uint64, required, tag = "1")]
    pub request_id: u64,
    #[prost(enumeration = "UntrustedXferReplyStatus", required, tag = "2")]
    pub status:     i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveLogSignal {
    #[prost(bytes, required, tag = "1")]
    pub message: std::vec::Vec<u8>,
    #[prost(bytes, required, tag = "2")]
    pub module:  std::vec::Vec<u8>,
    #[prost(bytes, required, tag = "3")]
    pub file:    std::vec::Vec<u8>,
    #[prost(uint32, required, tag = "4")]
    pub line:    u32,
    #[prost(enumeration = "EnclaveLogLevel", required, tag = "5")]
    pub level:   i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveTransactionSignal {
    #[prost(uint64, required, tag = "1")]
    pub log_index:   u64,
    #[prost(oneof = "enclave_transaction_signal::Transaction", tags = "2, 3, 4, 5, 6, 7, 8, 9, 10")]
    pub transaction: ::std::option::Option<enclave_transaction_signal::Transaction>,
}
pub mod enclave_transaction_signal {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Transaction {
        #[prost(message, tag = "2")]
        FrontendRequest(super::EnclaveFrontendRequestTransaction),
        #[prost(message, tag = "3")]
        StartXfer(super::EnclaveStartXferTransaction),
        #[prost(message, tag = "4")]
        SetSid(super::EnclaveSetSidTransaction),
        #[prost(message, tag = "5")]
        RemoveChunk(super::EnclaveRemoveChunkTransaction),
        #[prost(message, tag = "6")]
        ApplyChunk(super::EnclaveApplyChunkTransaction),
        #[prost(message, tag = "7")]
        PauseXfer(super::EnclavePauseXferTransaction),
        #[prost(message, tag = "8")]
        ResumeXfer(super::EnclaveResumeXferTransaction),
        #[prost(message, tag = "9")]
        FinishXfer(super::EnclaveFinishXferTransaction),
        #[prost(message, tag = "10")]
        SetTime(super::EnclaveSetTimeTransaction),
    }
}
//
// enclave transactions
//

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveFrontendRequestTransaction {
    #[prost(oneof = "enclave_frontend_request_transaction::Transaction", tags = "1, 2, 3, 4, 5, 6, 7, 8")]
    pub transaction: ::std::option::Option<enclave_frontend_request_transaction::Transaction>,
}
pub mod enclave_frontend_request_transaction {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Transaction {
        #[prost(message, tag = "1")]
        Create(super::EnclaveCreateBackupTransaction),
        #[prost(message, tag = "2")]
        Backup(super::EnclaveBackupTransaction),
        #[prost(message, tag = "3")]
        Restore(super::EnclaveRestoreTransaction),
        #[prost(message, tag = "4")]
        Delete(super::EnclaveDeleteBackupTransaction),
        #[prost(message, tag = "5")]
        XferInProgress(super::EnclaveTransactionErrorXferInProgress),
        #[prost(message, tag = "6")]
        WrongPartition(super::EnclaveTransactionErrorWrongPartition),
        #[prost(message, tag = "7")]
        InvalidRequest(super::EnclaveTransactionErrorInvalidRequest),
        #[prost(message, tag = "8")]
        InternalError(super::EnclaveTransactionErrorInternalError),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveCreateBackupTransaction {
    #[prost(message, required, tag = "1")]
    pub backup_id: BackupId,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveBackupTransaction {
    #[prost(message, required, tag = "1")]
    pub backup_id: BackupId,
    #[prost(enumeration = "super::kbupd_client::backup_response::Status", required, tag = "2")]
    pub status:    i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveRestoreTransaction {
    #[prost(message, required, tag = "1")]
    pub backup_id: BackupId,
    #[prost(enumeration = "super::kbupd_client::restore_response::Status", required, tag = "2")]
    pub status:    i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveDeleteBackupTransaction {
    #[prost(message, required, tag = "1")]
    pub backup_id: BackupId,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveTransactionErrorXferInProgress {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveTransactionErrorWrongPartition {
    #[prost(bool, required, tag = "1")]
    pub new_partition_unknown: bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveTransactionErrorInvalidRequest {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveTransactionErrorInternalError {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveStartXferTransaction {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveSetSidTransaction {
    #[prost(message, optional, tag = "1")]
    pub service_id: ::std::option::Option<ServiceId>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveRemoveChunkTransaction {
    #[prost(message, optional, tag = "1")]
    pub chunk_range: ::std::option::Option<PartitionKeyRangePb>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveApplyChunkTransaction {
    #[prost(message, optional, tag = "1")]
    pub chunk_range: ::std::option::Option<PartitionKeyRangePb>,
    #[prost(message, repeated, tag = "2")]
    pub chunk_ids:   ::std::vec::Vec<BackupId>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclavePauseXferTransaction {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveResumeXferTransaction {
    #[prost(message, optional, tag = "1")]
    pub chunk_range: ::std::option::Option<PartitionKeyRangePb>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveFinishXferTransaction {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveSetTimeTransaction {
    #[prost(uint64, optional, tag = "1")]
    pub now_secs: ::std::option::Option<u64>,
}
//
// enclave status
//

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveMemoryStatus {
    #[prost(uint32, required, tag = "1")]
    pub footprint_bytes: u32,
    #[prost(uint32, required, tag = "2")]
    pub used_bytes:      u32,
    #[prost(uint32, required, tag = "3")]
    pub free_chunks:     u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveReplicaStatus {
    #[prost(message, optional, tag = "1")]
    pub memory_status: ::std::option::Option<EnclaveMemoryStatus>,
    #[prost(message, optional, tag = "2")]
    pub partition:     ::std::option::Option<EnclaveReplicaPartitionStatus>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveReplicaPartitionStatus {
    #[prost(bytes, required, tag = "1")]
    pub group_id:           std::vec::Vec<u8>,
    #[prost(bytes, optional, tag = "2")]
    pub service_id:         ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(message, optional, tag = "3")]
    pub range:              ::std::option::Option<PartitionKeyRangePb>,
    #[prost(message, repeated, tag = "4")]
    pub peers:              ::std::vec::Vec<EnclavePeerStatus>,
    #[prost(message, required, tag = "5")]
    pub min_attestation:    AttestationParameters,
    #[prost(bool, required, tag = "6")]
    pub is_leader:          bool,
    #[prost(uint64, required, tag = "7")]
    pub current_term:       u64,
    #[prost(uint64, required, tag = "8")]
    pub prev_log_index:     u64,
    #[prost(uint64, required, tag = "9")]
    pub last_applied_index: u64,
    #[prost(uint64, required, tag = "10")]
    pub commit_index:       u64,
    #[prost(uint64, required, tag = "11")]
    pub last_log_index:     u64,
    #[prost(uint64, required, tag = "12")]
    pub last_log_term:      u64,
    #[prost(uint64, required, tag = "13")]
    pub log_data_length:    u64,
    #[prost(uint64, required, tag = "14")]
    pub backup_count:       u64,
    #[prost(oneof = "enclave_replica_partition_status::XferStatus", tags = "15, 16")]
    pub xfer_status:        ::std::option::Option<enclave_replica_partition_status::XferStatus>,
}
pub mod enclave_replica_partition_status {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum XferStatus {
        #[prost(message, tag = "15")]
        IncomingXferStatus(super::EnclaveIncomingXferStatus),
        #[prost(message, tag = "16")]
        OutgoingXferStatus(super::EnclaveOutgoingXferStatus),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclavePeerStatus {
    #[prost(bytes, required, tag = "1")]
    pub node_id:            std::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub attestation:        ::std::option::Option<AttestationParameters>,
    #[prost(message, optional, tag = "3")]
    pub replication_status: ::std::option::Option<EnclavePeerReplicationStatus>,
    #[prost(bool, required, tag = "4")]
    pub is_leader:          bool,
    #[prost(uint64, required, tag = "5")]
    pub inflight_requests:  u64,
    #[prost(uint64, required, tag = "6")]
    pub unsent_requests:    u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclavePeerReplicationStatus {
    #[prost(uint64, required, tag = "1")]
    pub next_index:     u64,
    #[prost(uint64, required, tag = "2")]
    pub match_index:    u64,
    #[prost(uint64, optional, tag = "3")]
    pub inflight_index: ::std::option::Option<u64>,
    #[prost(bool, required, tag = "4")]
    pub probing:        bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveIncomingXferStatus {
    #[prost(message, required, tag = "1")]
    pub desired_range: PartitionKeyRangePb,
    #[prost(message, repeated, tag = "2")]
    pub nodes:         ::std::vec::Vec<EnclavePeerStatus>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveOutgoingXferStatus {
    #[prost(bytes, required, tag = "1")]
    pub group_id:            std::vec::Vec<u8>,
    #[prost(message, required, tag = "2")]
    pub full_xfer_range:     PartitionKeyRangePb,
    #[prost(message, optional, tag = "3")]
    pub current_chunk_range: ::std::option::Option<PartitionKeyRangePb>,
    #[prost(bool, required, tag = "4")]
    pub paused:              bool,
    #[prost(message, optional, tag = "5")]
    pub min_attestation:     ::std::option::Option<AttestationParameters>,
    #[prost(message, repeated, tag = "6")]
    pub nodes:               ::std::vec::Vec<EnclavePeerStatus>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveFrontendStatus {
    #[prost(message, optional, tag = "1")]
    pub memory_status: ::std::option::Option<EnclaveMemoryStatus>,
    #[prost(message, repeated, tag = "2")]
    pub partitions:    ::std::vec::Vec<EnclaveFrontendPartitionStatus>,
    #[prost(message, repeated, tag = "3")]
    pub ranges:        ::std::vec::Vec<EnclaveFrontendRangeStatus>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveFrontendPartitionStatus {
    #[prost(bytes, required, tag = "1")]
    pub group_id: std::vec::Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    pub nodes:    ::std::vec::Vec<EnclavePeerStatus>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveFrontendRangeStatus {
    #[prost(message, required, tag = "1")]
    pub range:    PartitionKeyRangePb,
    #[prost(bytes, required, tag = "2")]
    pub group_id: std::vec::Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum XferControlCommand {
    Start  = 1,
    Finish = 2,
    Cancel = 3,
    Pause  = 4,
    Resume = 5,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum UntrustedXferReplyStatus {
    Unknown      = 0,
    Ok           = 1,
    NotLeader    = 2,
    InvalidState = 3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum EnclaveLogLevel {
    Error = 0,
    Warn  = 1,
    Info  = 2,
    Debug = 3,
}
