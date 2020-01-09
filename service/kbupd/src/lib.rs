/*
 * Copyright (C) 2019 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
