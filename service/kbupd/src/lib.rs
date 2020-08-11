//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![allow(unused_parens)]

use log::{debug, error, info, warn};

#[macro_use]
mod metrics;

mod actor;
mod api;
mod backup;
mod constants;
mod control;
mod enclave;
mod frontend;
mod intel_client;
mod limits;
#[cfg(test)]
mod mocks;
mod peer;
mod protobufs_impl;
mod replica;
mod tls;
mod unix_signal;
mod util;

pub mod logger;
pub mod protobufs;

pub use crate::control::{ControlCodec, ControlListener};
pub use crate::enclave::enclave::{Enclave, NodeId, SgxQuote};
pub use crate::enclave::enclave_manager::{EnclaveManager, EnclaveManagerChannel, EnclaveManagerSender};
pub use crate::enclave::error::*;
pub use crate::enclave::handshake_manager::HandshakeManager;
pub use crate::frontend::{FrontendCommandLineConfig, FrontendService};
pub use crate::replica::{ReplicaCommandLineConfig, ReplicaService};
