//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Request {
    #[prost(message, optional, tag = "1")]
    pub backup:  ::std::option::Option<BackupRequest>,
    #[prost(message, optional, tag = "2")]
    pub restore: ::std::option::Option<RestoreRequest>,
    #[prost(message, optional, tag = "3")]
    pub delete:  ::std::option::Option<DeleteRequest>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Response {
    #[prost(message, optional, tag = "1")]
    pub backup:  ::std::option::Option<BackupResponse>,
    #[prost(message, optional, tag = "2")]
    pub restore: ::std::option::Option<RestoreResponse>,
    #[prost(message, optional, tag = "3")]
    pub delete:  ::std::option::Option<DeleteResponse>,
}
//
// backup
//

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BackupRequest {
    #[prost(bytes, optional, tag = "1")]
    pub service_id: ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(bytes, optional, tag = "2")]
    pub backup_id:  ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(bytes, optional, tag = "3")]
    pub nonce:      ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(uint64, optional, tag = "4")]
    pub valid_from: ::std::option::Option<u64>,
    #[prost(bytes, optional, tag = "5")]
    pub data:       ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(bytes, optional, tag = "6")]
    pub pin:        ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(uint32, optional, tag = "7")]
    pub tries:      ::std::option::Option<u32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BackupResponse {
    #[prost(enumeration = "backup_response::Status", optional, tag = "1")]
    pub status: ::std::option::Option<i32>,
    #[prost(bytes, optional, tag = "2")]
    pub nonce:  ::std::option::Option<std::vec::Vec<u8>>,
}
pub mod backup_response {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Status {
        Ok            = 1,
        AlreadyExists = 2,
        NotYetValid   = 3,
    }
}
//
// restore
//

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RestoreRequest {
    #[prost(bytes, optional, tag = "1")]
    pub service_id: ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(bytes, optional, tag = "2")]
    pub backup_id:  ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(bytes, optional, tag = "3")]
    pub nonce:      ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(uint64, optional, tag = "4")]
    pub valid_from: ::std::option::Option<u64>,
    #[prost(bytes, optional, tag = "5")]
    pub pin:        ::std::option::Option<std::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RestoreResponse {
    #[prost(enumeration = "restore_response::Status", optional, tag = "1")]
    pub status: ::std::option::Option<i32>,
    #[prost(bytes, optional, tag = "2")]
    pub nonce:  ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(bytes, optional, tag = "3")]
    pub data:   ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(uint32, optional, tag = "4")]
    pub tries:  ::std::option::Option<u32>,
}
pub mod restore_response {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Status {
        Ok            = 1,
        NonceMismatch = 2,
        NotYetValid   = 3,
        Missing       = 4,
        PinMismatch   = 5,
    }
}
//
// delete
//

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeleteRequest {
    #[prost(bytes, optional, tag = "1")]
    pub service_id: ::std::option::Option<std::vec::Vec<u8>>,
    #[prost(bytes, optional, tag = "2")]
    pub backup_id:  ::std::option::Option<std::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeleteResponse {}
