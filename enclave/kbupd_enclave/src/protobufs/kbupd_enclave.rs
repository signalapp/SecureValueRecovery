//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SecretBytes {
    #[prost(bytes, required, tag = "1")]
    pub data: std::vec::Vec<u8>,
}
//
// transactions
//

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionData {
    #[prost(oneof = "transaction_data::Inner", tags = "1, 2, 3, 4, 5, 6, 7, 8, 9")]
    pub inner: ::std::option::Option<transaction_data::Inner>,
}
pub mod transaction_data {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Inner {
        #[prost(message, tag = "1")]
        FrontendRequest(super::FrontendRequestTransaction),
        #[prost(message, tag = "2")]
        StartXfer(super::StartXferTransaction),
        #[prost(message, tag = "3")]
        SetSid(super::SetSidTransaction),
        #[prost(message, tag = "4")]
        RemoveChunk(super::RemoveChunkTransaction),
        #[prost(message, tag = "5")]
        ApplyChunk(super::ApplyChunkTransaction),
        #[prost(message, tag = "6")]
        PauseXfer(super::PauseXferTransaction),
        #[prost(message, tag = "7")]
        ResumeXfer(super::ResumeXferTransaction),
        #[prost(message, tag = "8")]
        FinishXfer(super::FinishXferTransaction),
        #[prost(message, tag = "9")]
        SetTime(super::SetTimeTransaction),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FrontendRequestTransaction {
    #[prost(bytes, required, tag = "1")]
    pub from_node_id: std::vec::Vec<u8>,
    #[prost(uint64, required, tag = "2")]
    pub request_id:   u64,
    #[prost(oneof = "frontend_request_transaction::Transaction", tags = "3, 4, 5, 6")]
    pub transaction:  ::std::option::Option<frontend_request_transaction::Transaction>,
}
pub mod frontend_request_transaction {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Transaction {
        #[prost(message, tag = "3")]
        Create(super::CreateBackupTransaction),
        #[prost(message, tag = "4")]
        Backup(super::BackupTransaction),
        #[prost(message, tag = "5")]
        Restore(super::RestoreTransaction),
        #[prost(message, tag = "6")]
        Delete(super::DeleteBackupTransaction),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateBackupTransaction {
    #[prost(message, required, tag = "1")]
    pub backup_id:          super::kbupd::BackupId,
    #[prost(bytes, required, tag = "2")]
    pub new_creation_nonce: std::vec::Vec<u8>,
    #[prost(bytes, required, tag = "3")]
    pub new_nonce:          std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BackupTransaction {
    #[prost(message, required, tag = "1")]
    pub backup_id:          super::kbupd::BackupId,
    #[prost(bytes, required, tag = "2")]
    pub old_nonce:          std::vec::Vec<u8>,
    #[prost(bytes, required, tag = "3")]
    pub new_creation_nonce: std::vec::Vec<u8>,
    #[prost(bytes, required, tag = "4")]
    pub new_nonce:          std::vec::Vec<u8>,
    #[prost(message, required, tag = "5")]
    pub data:               SecretBytes,
    #[prost(message, required, tag = "6")]
    pub pin:                SecretBytes,
    #[prost(uint32, required, tag = "7")]
    pub tries:              u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RestoreTransaction {
    #[prost(message, required, tag = "1")]
    pub backup_id:      super::kbupd::BackupId,
    #[prost(bytes, required, tag = "2")]
    pub creation_nonce: std::vec::Vec<u8>,
    #[prost(bytes, required, tag = "3")]
    pub old_nonce:      std::vec::Vec<u8>,
    #[prost(bytes, required, tag = "4")]
    pub new_nonce:      std::vec::Vec<u8>,
    #[prost(message, required, tag = "5")]
    pub pin:            SecretBytes,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeleteBackupTransaction {
    #[prost(message, required, tag = "1")]
    pub backup_id: super::kbupd::BackupId,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StartXferTransaction {
    #[prost(bytes, required, tag = "1")]
    pub from_node_id: std::vec::Vec<u8>,
    #[prost(message, required, tag = "2")]
    pub xfer_request: XferRequest,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetSidTransaction {
    #[prost(bytes, required, tag = "1")]
    pub from_node_id: std::vec::Vec<u8>,
    #[prost(message, required, tag = "2")]
    pub service_id:   super::kbupd::ServiceId,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RemoveChunkTransaction {
    #[prost(bytes, required, tag = "1")]
    pub from_node_id:     std::vec::Vec<u8>,
    #[prost(message, required, tag = "2")]
    pub xfer_chunk_reply: XferChunkReply,
    #[prost(message, required, tag = "3")]
    pub chunk_last:       super::kbupd::BackupId,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ApplyChunkTransaction {
    #[prost(bytes, required, tag = "1")]
    pub from_node_id:       std::vec::Vec<u8>,
    #[prost(message, required, tag = "2")]
    pub xfer_chunk_request: XferChunkRequest,
    #[prost(message, required, tag = "3")]
    pub xfer_chunk_reply:   XferChunkReply,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PauseXferTransaction {
    #[prost(uint64, required, tag = "1")]
    pub request_id: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ResumeXferTransaction {
    #[prost(uint64, required, tag = "1")]
    pub request_id: u64,
    #[prost(message, required, tag = "2")]
    pub chunk_last: super::kbupd::BackupId,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinishXferTransaction {
    #[prost(uint64, required, tag = "1")]
    pub request_id: u64,
    #[prost(bool, required, tag = "2")]
    pub force:      bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetTimeTransaction {
    #[prost(uint64, required, tag = "1")]
    pub now_secs: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PeerConnectRequest {
    #[prost(enumeration = "NodeType", required, tag = "1")]
    pub node_type:  i32,
    #[prost(message, optional, tag = "2")]
    pub ias_report: ::std::option::Option<super::kbupd::IasReport>,
    #[prost(bytes, required, tag = "3")]
    pub noise_data: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PeerConnectReply {
    #[prost(bytes, required, tag = "1")]
    pub sgx_quote:  std::vec::Vec<u8>,
    #[prost(bytes, required, tag = "2")]
    pub noise_data: std::vec::Vec<u8>,
}
//
// enclave-to-enclave requests
//

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveGetQuoteRequest {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnclaveGetQuoteReply {
    #[prost(bytes, required, tag = "1")]
    pub sgx_quote: std::vec::Vec<u8>,
}
//
// frontend to replica
//

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FrontendToReplicaMessage {
    #[prost(oneof = "frontend_to_replica_message::Inner", tags = "1, 2")]
    pub inner: ::std::option::Option<frontend_to_replica_message::Inner>,
}
pub mod frontend_to_replica_message {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Inner {
        #[prost(message, tag = "1")]
        TransactionRequest(super::TransactionRequest),
        #[prost(message, tag = "2")]
        EnclaveGetQuoteRequest(super::EnclaveGetQuoteRequest),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionRequest {
    #[prost(uint64, required, tag = "1")]
    pub request_id: u64,
    #[prost(oneof = "transaction_request::Data", tags = "2, 3, 4, 5")]
    pub data:       ::std::option::Option<transaction_request::Data>,
}
pub mod transaction_request {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Data {
        #[prost(message, tag = "2")]
        Create(super::super::kbupd::CreateBackupRequest),
        #[prost(message, tag = "3")]
        Backup(super::BackupTransactionRequest),
        #[prost(message, tag = "4")]
        Restore(super::RestoreTransactionRequest),
        #[prost(message, tag = "5")]
        Delete(super::DeleteTransactionRequest),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BackupTransactionRequest {
    #[prost(bytes, optional, tag = "1")]
    pub service_id: ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(message, required, tag = "2")]
    pub backup_id:  super::kbupd::BackupId,
    #[prost(bytes, required, tag = "3")]
    pub nonce:      std::vec::Vec<u8>,
    #[prost(uint64, required, tag = "4")]
    pub valid_from: u64,
    #[prost(message, required, tag = "5")]
    pub data:       SecretBytes,
    #[prost(message, required, tag = "6")]
    pub pin:        SecretBytes,
    #[prost(uint32, required, tag = "7")]
    pub tries:      u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RestoreTransactionRequest {
    #[prost(bytes, optional, tag = "1")]
    pub service_id: ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(message, required, tag = "2")]
    pub backup_id:  super::kbupd::BackupId,
    #[prost(bytes, required, tag = "3")]
    pub nonce:      std::vec::Vec<u8>,
    #[prost(uint64, required, tag = "4")]
    pub valid_from: u64,
    #[prost(message, required, tag = "5")]
    pub pin:        SecretBytes,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeleteTransactionRequest {
    #[prost(bytes, optional, tag = "1")]
    pub service_id: ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(message, required, tag = "2")]
    pub backup_id:  super::kbupd::BackupId,
}
//
// replica to frontend
//

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReplicaToFrontendMessage {
    #[prost(oneof = "replica_to_frontend_message::Inner", tags = "1, 2")]
    pub inner: ::std::option::Option<replica_to_frontend_message::Inner>,
}
pub mod replica_to_frontend_message {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Inner {
        #[prost(message, tag = "1")]
        TransactionReply(super::TransactionReply),
        #[prost(message, tag = "2")]
        EnclaveGetQuoteReply(super::EnclaveGetQuoteReply),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionReply {
    #[prost(uint64, required, tag = "1")]
    pub request_id: u64,
    #[prost(oneof = "transaction_reply::Data", tags = "2, 3, 4, 5, 6, 7, 8, 9, 10")]
    pub data:       ::std::option::Option<transaction_reply::Data>,
}
pub mod transaction_reply {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Data {
        #[prost(message, tag = "2")]
        ClientResponse(super::super::kbupd_client::Response),
        #[prost(message, tag = "3")]
        CreateBackupReply(super::super::kbupd::CreateBackupReply),
        #[prost(message, tag = "4")]
        DeleteBackupReply(super::super::kbupd::DeleteBackupReply),
        #[prost(message, tag = "5")]
        NotLeader(super::TransactionErrorNotLeader),
        #[prost(message, tag = "6")]
        WrongPartition(super::TransactionErrorWrongPartition),
        #[prost(message, tag = "7")]
        ServiceIdMismatch(super::TransactionErrorServiceIdMismatch),
        #[prost(message, tag = "8")]
        XferInProgress(super::TransactionErrorXferInProgress),
        #[prost(message, tag = "9")]
        InvalidRequest(super::TransactionErrorInvalidRequest),
        #[prost(message, tag = "10")]
        InternalError(super::TransactionErrorInternalError),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionErrorNotLeader {
    #[prost(bytes, optional, tag = "1")]
    pub leader_node_id: ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(message, required, tag = "2")]
    pub term:           super::raft::TermId,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionErrorWrongPartition {
    #[prost(message, optional, tag = "1")]
    pub range:         ::std::option::Option<super::kbupd::PartitionKeyRangePb>,
    #[prost(message, optional, tag = "2")]
    pub new_partition: ::std::option::Option<super::kbupd::PartitionConfig>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionErrorServiceIdMismatch {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionErrorXferInProgress {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionErrorInvalidRequest {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionErrorInternalError {}
//
// replica to replica
//

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReplicaToReplicaMessage {
    #[prost(oneof = "replica_to_replica_message::Inner", tags = "1, 2, 8, 9, 3, 4, 5, 6, 7")]
    pub inner: ::std::option::Option<replica_to_replica_message::Inner>,
}
pub mod replica_to_replica_message {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Inner {
        #[prost(message, tag = "1")]
        RaftMessage(super::super::raft::RaftMessage),
        #[prost(message, tag = "2")]
        CreateRaftGroupRequest(super::CreateRaftGroupRequest),
        #[prost(message, tag = "8")]
        EnclaveGetQuoteRequest(super::EnclaveGetQuoteRequest),
        #[prost(message, tag = "9")]
        EnclaveGetQuoteReply(super::EnclaveGetQuoteReply),
        #[prost(message, tag = "3")]
        XferRequest(super::XferRequest),
        #[prost(message, tag = "4")]
        XferReply(super::XferReply),
        #[prost(message, tag = "5")]
        XferChunkRequest(super::XferChunkRequest),
        #[prost(message, tag = "6")]
        XferChunkReply(super::XferChunkReply),
        #[prost(message, tag = "7")]
        XferErrorNotLeader(super::XferErrorNotLeader),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateRaftGroupRequest {
    #[prost(message, optional, tag = "1")]
    pub service_id:       ::std::option::Option<super::kbupd::ServiceId>,
    #[prost(message, required, tag = "2")]
    pub group_id:         super::raft::RaftGroupId,
    #[prost(bytes, repeated, tag = "3")]
    pub node_ids:         ::std::vec::Vec<std::vec::Vec<u8>>,
    #[prost(message, required, tag = "4")]
    pub config:           super::kbupd::EnclaveReplicaGroupConfig,
    #[prost(message, optional, tag = "5")]
    pub source_partition: ::std::option::Option<super::kbupd::SourcePartitionConfig>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct XferRequest {
    #[prost(uint32, required, tag = "1")]
    pub chunk_size: u32,
    #[prost(message, required, tag = "2")]
    pub full_range: super::kbupd::PartitionKeyRangePb,
    #[prost(bytes, repeated, tag = "3")]
    pub node_ids:   ::std::vec::Vec<std::vec::Vec<u8>>,
    #[prost(message, required, tag = "4")]
    pub group_id:   super::raft::RaftGroupId,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct XferReply {
    #[prost(message, required, tag = "1")]
    pub service: super::kbupd::ServiceId,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct XferChunkRequest {
    #[prost(message, required, tag = "1")]
    pub data:            SecretBytes,
    #[prost(message, required, tag = "2")]
    pub chunk_range:     super::kbupd::PartitionKeyRangePb,
    #[prost(message, required, tag = "3")]
    pub min_attestation: super::kbupd::AttestationParameters,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct XferChunkReply {
    #[prost(message, required, tag = "1")]
    pub new_last:   super::kbupd::BackupId,
    #[prost(uint32, required, tag = "2")]
    pub chunk_size: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct XferErrorNotLeader {
    #[prost(bytes, optional, tag = "1")]
    pub leader_node_id: ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(message, required, tag = "2")]
    pub term:           super::raft::TermId,
}
//
// remote enclave handshake
//

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum NodeType {
    None     = 0,
    Frontend = 1,
    Replica  = 2,
}
