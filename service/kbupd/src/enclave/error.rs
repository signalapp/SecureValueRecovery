//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::fmt;

use futures;
use sgx_sdk_ffi::*;

use super::ffi::sgxsd::*;

#[derive(Clone, failure::Fail)]
pub enum EnclaveError {
    #[fail(display = "enclave sgx error: {}", _0)]
    SgxsdError(#[cause] SgxsdError),
    #[fail(display = "enclave internal error: {}", _0)]
    InternalError(&'static str),
}

#[derive(Clone, failure::Fail)]
pub enum EnclaveTransactionError {
    #[fail(display = "enclave not found")]
    EnclaveNotFound,
    #[fail(display = "invalid request")]
    InvalidInput,
    #[fail(display = "request canceled by enclave")]
    RequestCanceled,
    #[fail(display = "internal error")]
    InternalError,
}

#[derive(Clone, failure::Fail)]
pub enum RemoteAttestationError {
    #[fail(display = "enclave not found")]
    EnclaveNotFound,
    #[fail(display = "invalid request")]
    InvalidInput,
    #[fail(display = "enclave error: {}", _0)]
    EnclaveError(#[cause] EnclaveError),
    #[fail(display = "request canceled by enclave")]
    RequestCanceled,
}

#[derive(Clone, failure::Fail)]
pub enum KeyBackupError {
    #[fail(display = "enclave not found")]
    EnclaveNotFound,
    #[fail(display = "invalid request")]
    InvalidInput,
    #[fail(display = "mac mismatch")]
    MacMismatch,
    #[fail(display = "pending request id not found")]
    PendingRequestIdNotFound,
    #[fail(display = "enclave error: {}", _0)]
    EnclaveError(#[cause] EnclaveError),
    #[fail(display = "request canceled by enclave")]
    RequestCanceled,
}

//
// EnclaveError impls
//

impl fmt::Debug for EnclaveError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

impl From<SgxsdError> for EnclaveError {
    fn from(from: SgxsdError) -> Self {
        EnclaveError::SgxsdError(from)
    }
}

//
// EnclaveTransactionError impls
//

impl fmt::Debug for EnclaveTransactionError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

impl From<futures::Canceled> for EnclaveTransactionError {
    fn from(_error: futures::Canceled) -> Self {
        EnclaveTransactionError::RequestCanceled
    }
}

//
// RemoteAttestationError impls
//

impl fmt::Debug for RemoteAttestationError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

impl From<futures::Canceled> for RemoteAttestationError {
    fn from(_error: futures::Canceled) -> Self {
        RemoteAttestationError::RequestCanceled
    }
}

impl From<SgxsdError> for RemoteAttestationError {
    fn from(error: SgxsdError) -> Self {
        match error.status.err() {
            Some(SgxError::InvalidParameter) => RemoteAttestationError::InvalidInput,
            _ => RemoteAttestationError::EnclaveError(EnclaveError::SgxsdError(error)),
        }
    }
}

impl From<EnclaveError> for RemoteAttestationError {
    fn from(error: EnclaveError) -> Self {
        match error {
            EnclaveError::SgxsdError(sgxsd_error) => Self::from(sgxsd_error),
            _ => RemoteAttestationError::EnclaveError(error),
        }
    }
}

//
// KeyBackupError impls
//

impl fmt::Debug for KeyBackupError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

impl From<futures::Canceled> for KeyBackupError {
    fn from(_error: futures::Canceled) -> Self {
        KeyBackupError::RequestCanceled
    }
}

impl From<SgxsdError> for KeyBackupError {
    fn from(error: SgxsdError) -> Self {
        match (error.kind, error.status.err()) {
            (SgxsdErrorKind::Returned, Some(SgxError::InvalidParameter)) => KeyBackupError::InvalidInput,
            (SgxsdErrorKind::Returned, Some(SgxError::MacMismatch)) => KeyBackupError::MacMismatch,
            (SgxsdErrorKind::Returned, Some(SgxError::SgxsdPendingRequestNotFound)) => KeyBackupError::PendingRequestIdNotFound,
            _ => KeyBackupError::EnclaveError(EnclaveError::SgxsdError(error)),
        }
    }
}

impl From<EnclaveError> for KeyBackupError {
    fn from(error: EnclaveError) -> Self {
        match error {
            EnclaveError::SgxsdError(sgxsd_error) => Self::from(sgxsd_error),
            _ => KeyBackupError::EnclaveError(error),
        }
    }
}
