//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RaftMessage {
    #[prost(message, required, tag = "1")]
    pub group: RaftGroupId,
    #[prost(message, required, tag = "2")]
    pub term:  TermId,
    #[prost(oneof = "raft_message::Inner", tags = "3, 4, 5, 6")]
    pub inner: ::std::option::Option<raft_message::Inner>,
}
pub mod raft_message {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Inner {
        #[prost(message, tag = "3")]
        VoteRequest(super::VoteRequest),
        #[prost(message, tag = "4")]
        VoteResponse(super::VoteResponse),
        #[prost(message, tag = "5")]
        AppendRequest(super::AppendRequest),
        #[prost(message, tag = "6")]
        AppendResponse(super::AppendResponse),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VoteRequest {
    #[prost(message, required, tag = "2")]
    pub last_log_idx:  LogIdx,
    #[prost(message, required, tag = "3")]
    pub last_log_term: TermId,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VoteResponse {
    #[prost(bool, required, tag = "2")]
    pub vote_granted: bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppendRequest {
    #[prost(message, required, tag = "1")]
    pub prev_log_idx:  LogIdx,
    #[prost(message, required, tag = "2")]
    pub prev_log_term: TermId,
    #[prost(message, required, tag = "3")]
    pub leader_commit: LogIdx,
    #[prost(message, repeated, tag = "4")]
    pub entries:       ::std::vec::Vec<LogEntry>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppendResponse {
    #[prost(bool, required, tag = "1")]
    pub success:      bool,
    #[prost(message, required, tag = "2")]
    pub match_idx:    LogIdx,
    #[prost(message, required, tag = "3")]
    pub last_log_idx: LogIdx,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LogEntry {
    #[prost(message, required, tag = "1")]
    pub term: TermId,
    #[prost(bytes, required, tag = "2")]
    pub data: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RaftGroupId {
    #[prost(bytes, required, tag = "1")]
    pub id: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TermId {
    #[prost(uint64, required, tag = "1")]
    pub id: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LogIdx {
    #[prost(uint64, required, tag = "1")]
    pub id: u64,
}
