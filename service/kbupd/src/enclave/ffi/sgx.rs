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

use std::convert::{TryInto};
use std::fmt;

use num_traits::{FromPrimitive};

use super::sgxsd::*;

use super::bindgen_wrapper::{
    sgx_calc_quote_size,
    sgx_create_enclave,
    sgx_get_quote,
    sgx_init_quote,
    sgx_target_info_t,
    sgx_report_t,
    sgx_spid_t,
    sgx_status_t,
    sgx_quote_t,
    SGX_SUCCESS,
    SGX_UNLINKABLE_SIGNATURE,
};

pub use super::bindgen_wrapper::{
    sgx_enclave_id_t as SgxEnclaveId,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SgxStatus {
    Success,
    Error(SgxError),
    Unknown(u32),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, num_derive::FromPrimitive)]
pub enum SgxError {
    Unexpected                  = 1,
    InvalidParameter            = 2,
    OutOfMemory                 = 3,
    EnclaveLost                 = 4,
    InvalidState                = 5,
    FeatureNotSupported         = 8,
    InvalidFunction             = 4097,
    OutOfTcs                    = 4099,
    EnclaveCrashed              = 4102,
    EcallNotAllowed             = 4103,
    OcallNotAllowed             = 4104,
    StackOverrun                = 4105,
    UndefinedSymbol             = 8192,
    InvalidEnclave              = 8193,
    InvalidEnclaveId            = 8194,
    InvalidSignature            = 8195,
    NdebugEnclave               = 8196,
    OutOfEpc                    = 8197,
    NoDevice                    = 8198,
    MemoryMapConflict           = 8199,
    InvalidMetadata             = 8201,
    DeviceBusy                  = 8204,
    InvalidVersion              = 8205,
    ModeIncompatible            = 8206,
    EnclaveFileAccess           = 8207,
    InvalidMisc                 = 8208,
    InvalidLaunchToken          = 8209,
    MacMismatch                 = 12289,
    InvalidAttribute            = 12290,
    InvalidCpusvn               = 12291,
    InvalidIsvsvn               = 12292,
    InvalidKeyname              = 12293,
    ServiceUnavailable          = 16385,
    ServiceTimeout              = 16386,
    AeInvalidEpidblob           = 16387,
    ServiceInvalidPrivilege     = 16388,
    EpidMemberRevoked           = 16389,
    UpdateNeeded                = 16390,
    NetworkFailure              = 16391,
    AeSessionInvalid            = 16392,
    Busy                        = 16394,
    McNotFound                  = 16396,
    McNoAccessRight             = 16397,
    McUsedUp                    = 16398,
    McOverQuota                 = 16399,
    KdfMismatch                 = 16401,
    UnrecognizedPlatform        = 16402,
    NoPrivilege                 = 20482,
    PclEncrypted                = 24577,
    PclNotEncrypted             = 24578,
    PclMacMismatch              = 24579,
    PclShaMismatch              = 24580,
    PclGuidMismatch             = 24581,
    FileBadStatus               = 28673,
    FileNoKeyId                 = 28674,
    FileNameMismatch            = 28675,
    FileNotSgxFile              = 28676,
    FileCantOpenRecoveryFile    = 28677,
    FileCantWriteRecoveryFile   = 28678,
    FileRecoveryNeeded          = 28679,
    FileFlushFailed             = 28680,
    FileCloseFailed             = 28681,
    UnsupportedAttKeyId         = 32769,
    AttKeyCertificationFailure  = 32770,
    AttKeyUninitialized         = 32771,
    InvalidAttKeyCertData       = 32772,
    EnclaveCreateInterrupted    = 61441,
    SgxsdPendingRequestNotFound = 65537,
}

//
// free functions
//

pub fn create_enclave(enclave_filename: &str, debug: bool) -> SgxsdResult<SgxEnclaveId> {
    let enclave_filename_cstr                  = std::ffi::CString::new(enclave_filename).unwrap();
    let mut launch_token:         [u8; 1024]   = [0; 1024];
    let mut launch_token_updated: i32          = Default::default();
    let mut enclave_id:           SgxEnclaveId = Default::default();
    sgxsd_res(|_| unsafe { sgx_create_enclave(
        enclave_filename_cstr.as_ptr(),
        debug as std::os::raw::c_int,
        &mut launch_token,
        &mut launch_token_updated,
        &mut enclave_id,
        std::ptr::null_mut()
    )}, "sgx_create_enclave")
        .map(|()| enclave_id)
}

pub fn get_gid() -> SgxsdResult<u32> {
    let mut qe_target_info: sgx_target_info_t = Default::default();
    let mut gid:            [u8; 4]           = Default::default();
    sgxsd_res(|_| unsafe { sgx_init_quote(&mut qe_target_info, &mut gid) }, "sgx_init_quote")?;
    Ok(u32::from_ne_bytes(gid))
}

pub fn get_qe_target_info() -> SgxsdResult<sgx_target_info_t> {
    let mut qe_target_info: sgx_target_info_t = Default::default();
    let mut gid:            [u8; 4]           = Default::default();
    sgxsd_res(|_| unsafe { sgx_init_quote(&mut qe_target_info, &mut gid) }, "sgx_init_quote")?;
    Ok(qe_target_info)
}

pub fn get_quote(report: &[u8], spid: &[u8], sig_rl: &[u8]) -> SgxsdResult<Vec<u8>> {
    let spid_struct = sgx_spid_t {
        id: spid.try_into().map_err(|_| SgxsdError { kind: SgxsdErrorKind::Sgx, status: SgxError::InvalidParameter.into(), name: "get_quote_spid" })?,
    };
    if report.len() == std::mem::size_of::<sgx_report_t>() {
        let report = unsafe { std::ptr::read_unaligned(report.as_ptr() as *const sgx_report_t) };

        let (p_sig_rl, sig_rl_len) = get_sig_rl_ptr(sig_rl);
        let mut quote_size: u32    = Default::default();
        sgxsd_res(|_| unsafe { sgx_calc_quote_size(p_sig_rl, sig_rl_len, &mut quote_size) }, "sgx_calc_quote_size")?;

        if (quote_size as usize) >= std::mem::size_of::<sgx_quote_t>() {
            let mut quote = vec![0; quote_size as usize];
            sgxsd_res(|_| unsafe {
                sgx_get_quote(&report, SGX_UNLINKABLE_SIGNATURE, &spid_struct,
                              std::ptr::null(),
                              p_sig_rl, sig_rl_len,
                              std::ptr::null_mut(),
                              quote.as_mut_ptr() as *mut sgx_quote_t, quote_size)
            }, "sgx_get_quote")?;
            Ok(quote)
        } else {
            Err(SgxsdError { kind: SgxsdErrorKind::Sgx, status: SgxError::Unexpected.into(), name: "bad_quote_size" })
        }
    } else {
        Err(SgxsdError { kind: SgxsdErrorKind::Sgx, status: SgxError::InvalidParameter.into(), name: "get_quote" })
    }
}

pub fn get_sig_rl_ptr(sig_rl: &[u8]) -> (*const u8, u32) {
    match sig_rl.len() {
        0 => (std::ptr::null(), 0),
        len if len < (u32::max_value() as usize) => (sig_rl.as_ptr(), len as u32),
        _ => (std::ptr::null(), 0)
    }
}

//
// SgxStatus impls
//

impl SgxStatus {
    pub fn err(&self) -> Option<&SgxError> {
        match self {
            SgxStatus::Error(error) => Some(error),
            _                       => None,
        }
    }
}

impl fmt::Display for SgxStatus {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, fmt)
    }
}

impl From<sgx_status_t> for SgxStatus {
    fn from(status: sgx_status_t) -> Self {
        if status == 0 {
            SgxStatus::Success
        } else if let Some(sgx_error_code) = SgxError::from_u32(status) {
            SgxStatus::Error(sgx_error_code)
        } else {
            SgxStatus::Unknown(status)
        }
    }
}

impl From<SgxError> for SgxStatus {
    fn from(sgx_error: SgxError) -> Self {
        SgxStatus::Error(sgx_error)
    }
}


impl From<SgxStatus> for sgx_status_t {
    fn from(sgx_status: SgxStatus) -> Self {
        match sgx_status {
            SgxStatus::Success             => SGX_SUCCESS,
            SgxStatus::Error(sgx_error)    => sgx_error.into(),
            SgxStatus::Unknown(sgx_status) => sgx_status,
        }
    }
}

//
// SgxError impls
//

impl fmt::Display for SgxError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, fmt)
    }
}

impl From<SgxError> for sgx_status_t {
    fn from(sgx_error: SgxError) -> Self {
        sgx_error as sgx_status_t
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sgx_quote_align() {
        assert_eq!(std::mem::align_of::<sgx_quote_t>(), 1);
    }
}
