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

#[allow(dead_code, non_snake_case, non_camel_case_types, non_upper_case_globals, improper_ctypes)]
mod bindgen_wrapper;

use std::fmt;
use std::mem;
use std::os::raw;
use std::ptr;

use num_traits::FromPrimitive;

use bindgen_wrapper::{
    sgx_calc_quote_size, sgx_create_enclave, sgx_create_enclave_from_buffer_ex, sgx_destroy_enclave, sgx_get_quote, sgx_init_quote,
    sgx_quote_t, sgx_spid_t, sgx_status_t, SGX_SUCCESS, SGX_UNLINKABLE_SIGNATURE,
};

pub use bindgen_wrapper::{
    sgx_enclave_id_t as SgxEnclaveId, sgx_quote_t as SgxQuote, sgx_report_t as SgxReport, sgx_target_info_t as SgxTargetInfo,
};

pub type SgxResult<T> = Result<T, SgxStatus>;

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

pub struct SgxEnclave {
    id:     SgxEnclaveId,
    buffer: Option<(*mut u8, usize, usize)>,
}

//
// SgxEnclave impls
//

impl SgxEnclave {
    pub fn new(mut buffer: Vec<u8>, debug: bool) -> SgxResult<SgxEnclave> {
        let buffer_ptr = buffer.as_mut_ptr();
        let buffer_len = buffer.len();
        let buffer_cap = buffer.capacity();
        mem::forget(buffer);

        let mut enclave_id: SgxEnclaveId = Default::default();
        SgxStatus::from(unsafe {
            sgx_create_enclave_from_buffer_ex(
                buffer_ptr,
                buffer_len,
                debug as raw::c_int,
                &mut enclave_id,
                ptr::null_mut(),
                0u32,
                ptr::null_mut(),
            )
        })
        .ok()?;
        Ok(SgxEnclave {
            id:     enclave_id,
            buffer: Some((buffer_ptr, buffer_len, buffer_cap)),
        })
    }

    pub fn id(&self) -> SgxEnclaveId {
        self.id
    }
}

impl Drop for SgxEnclave {
    fn drop(&mut self) {
        unsafe {
            if let Ok(()) = SgxStatus::from(sgx_destroy_enclave(self.id)).ok() {
                if let Some((buffer_ptr, buffer_len, buffer_cap)) = self.buffer {
                    drop(Vec::from_raw_parts(buffer_ptr, buffer_len, buffer_cap));
                }
            }
        }
    }
}

//
// free functions
//

pub fn create_enclave(enclave_filename: &str, debug: bool) -> SgxResult<SgxEnclaveId> {
    let enclave_filename_cstr = std::ffi::CString::new(enclave_filename).unwrap();
    let mut launch_token: [u8; 1024] = [0; 1024];
    let mut launch_token_updated: i32 = Default::default();
    let mut enclave_id: SgxEnclaveId = Default::default();
    SgxStatus::from(unsafe {
        sgx_create_enclave(
            enclave_filename_cstr.as_ptr(),
            debug as std::os::raw::c_int,
            &mut launch_token,
            &mut launch_token_updated,
            &mut enclave_id,
            std::ptr::null_mut(),
        )
    })
    .ok()?;
    Ok(enclave_id)
}

pub fn init_quote() -> SgxResult<(u32, SgxTargetInfo)> {
    // NB: sgx_init_quote expects qe_target_info to be zeroed (undocumented!)
    let mut qe_target_info: SgxTargetInfo = Default::default();
    let mut gid: [u8; 4] = Default::default();
    SgxStatus::from(unsafe { sgx_init_quote(&mut qe_target_info, &mut gid) }).ok()?;
    Ok((u32::from_ne_bytes(gid), qe_target_info))
}

pub fn get_gid() -> SgxResult<u32> {
    Ok(init_quote()?.0)
}

pub fn get_qe_target_info() -> SgxResult<SgxTargetInfo> {
    Ok(init_quote()?.1)
}

pub fn get_quote(report: SgxReport, spid: &[u8; 16], sig_rl: &[u8]) -> SgxResult<Vec<u8>> {
    let (p_sig_rl, sig_rl_len) = get_sig_rl_ptr(sig_rl);
    let mut quote_size: u32 = Default::default();
    SgxStatus::from(unsafe { sgx_calc_quote_size(p_sig_rl, sig_rl_len, &mut quote_size) }).ok()?;

    if (quote_size as usize) < mem::size_of::<sgx_quote_t>() {
        return Err(SgxError::Unexpected.into());
    }

    let mut quote: Vec<u8> = vec![0; quote_size as usize];
    let quote_size = quote.len() as u32;
    let spid_struct = sgx_spid_t { id: *spid };
    SgxStatus::from(unsafe {
        sgx_get_quote(
            &report,
            SGX_UNLINKABLE_SIGNATURE,
            &spid_struct,
            std::ptr::null(),
            p_sig_rl,
            sig_rl_len,
            std::ptr::null_mut(),
            quote.as_mut_ptr() as *mut sgx_quote_t,
            quote_size,
        )
    })
    .ok()?;

    Ok(quote)
}

fn get_sig_rl_ptr(sig_rl: &[u8]) -> (*const u8, u32) {
    match sig_rl.len() {
        0 => (std::ptr::null(), 0),
        len if len < (u32::max_value() as usize) => (sig_rl.as_ptr(), len as u32),
        _ => (std::ptr::null(), 0),
    }
}

//
// SgxReport impls
//

impl SgxReport {
    pub const SIZE: usize = mem::size_of::<Self>();

    pub fn new(data: &[u8]) -> Result<Self, ()> {
        if data.len() == Self::SIZE {
            Ok(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Self) })
        } else {
            Err(())
        }
    }
}

impl From<&[u8; Self::SIZE]> for SgxReport {
    fn from(from: &[u8; Self::SIZE]) -> Self {
        unsafe { std::ptr::read_unaligned(from.as_ptr() as *const Self) }
    }
}

//
// SgxStatus impls
//

impl SgxStatus {
    pub fn ok(self) -> SgxResult<()> {
        match self {
            SgxStatus::Success => Ok(()),
            status             => Err(status),
        }
    }

    pub fn err(&self) -> Option<&SgxError> {
        match self {
            SgxStatus::Error(error) => Some(error),
            _                       => None,
        }
    }
}

impl std::error::Error for SgxStatus {}

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

impl std::error::Error for SgxError {}

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
    use std::mem;

    use super::*;

    #[test]
    fn test_sgx_quote_align() {
        assert_eq!(mem::align_of::<sgx_quote_t>(), 1);
    }
}
