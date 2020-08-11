//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::cell::*;

use sgx_ffi::sgx::*;
use sgxsd_ffi::ecalls::*;

use crate::ffi::ecalls::*;
use crate::protobufs::kbupd::untrusted_message;
use crate::protobufs::kbupd::*;
use crate::service::frontend::*;
use crate::service::replica::*;

//
// public api
//

#[allow(variant_size_differences)]
pub enum ServiceState {
    NotStarted,
    Frontend(FrontendState),
    Replica(ReplicaState),
}

pub struct SgxsdState {}

#[cfg(not(any(test, feature = "test")))]
pub fn whereis<F, R>(fun: F) -> R
where F: FnOnce(&RefCell<ServiceState>) -> R {
    #[thread_local]
    static SERVICE: RefCell<ServiceState> = RefCell::new(ServiceState::NotStarted);

    fun(&SERVICE)
}

#[cfg(any(test, feature = "test"))]
pub fn whereis<F, R>(fun: F) -> R
where F: FnOnce(&RefCell<ServiceState>) -> R {
    thread_local! {
        static SERVICE: RefCell<ServiceState> = RefCell::new(ServiceState::NotStarted);
    }

    SERVICE.with(fun)
}

//
// ServiceState impls
//

impl KbupdService for ServiceState {
    fn untrusted_message(&mut self, msg: UntrustedMessage) {
        match msg.inner {
            Some(untrusted_message::Inner::StartFrontendRequest(start_frontend_req)) => {
                if let ServiceState::NotStarted = self {
                    *self = ServiceState::Frontend(FrontendState::init(start_frontend_req));
                } else {
                    warn!("node service already started");
                }
            }
            Some(untrusted_message::Inner::StartReplicaRequest(start_replica_req)) => {
                if let ServiceState::NotStarted = self {
                    *self = ServiceState::Replica(ReplicaState::init(start_replica_req));
                } else {
                    warn!("node service already started");
                }
            }
            Some(_) => match self {
                ServiceState::Replica(replica) => {
                    replica.untrusted_message(msg);
                }
                ServiceState::Frontend(frontend) => {
                    frontend.untrusted_message(msg);
                }
                ServiceState::NotStarted => {
                    warn!("node service not started");
                }
            },
            None => {}
        }
    }
}

impl SgxsdServer for SgxsdState {
    type HandleCallArgs = CallArgs;
    type InitArgs = StartArgs;
    type TerminateArgs = StopArgs;

    fn init(_args: Option<&Self::InitArgs>) -> Result<Self, SgxStatus> {
        Ok(Self {})
    }

    fn handle_call(
        &mut self,
        args: Option<&Self::HandleCallArgs>,
        request_data: &[u8],
        from: SgxsdMsgFrom,
    ) -> Result<(), (SgxStatus, SgxsdMsgFrom)>
    {
        let args = match args {
            Some(args) => args,
            None => return Err((SGX_ERROR_INVALID_PARAMETER, from)),
        };
        whereis(|service_ref| {
            let mut service = service_ref.borrow_mut();
            if let ServiceState::Frontend(frontend) = &mut *service {
                match frontend.decode_request(args.request_type, args.backup_id.to_vec(), request_data) {
                    Ok(request) => {
                        frontend.client_request(request, from);
                        Ok(())
                    }
                    Err(()) => Err((SGX_ERROR_INVALID_PARAMETER, from)),
                }
            } else {
                warn!("frontend service not started");
                Err((SGX_ERROR_INVALID_STATE, from))
            }
        })
    }

    fn terminate(self, _args: Option<&Self::TerminateArgs>) -> Result<(), SgxStatus> {
        Ok(())
    }
}
