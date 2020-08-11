//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use crate::protobufs::kbupd_client;

#[derive(Default)]
struct ToHex<'a>(pub &'a [u8]);
impl<'a> ToHex<'a> {
    pub fn new<T: AsRef<[u8]>>(bytes: &'a T) -> Self {
        ToHex(bytes.as_ref())
    }
}
impl<'a> std::fmt::Display for ToHex<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

//
// BackupRequest impls
//

impl std::fmt::Display for kbupd_client::BackupRequest {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "service_id={} ", &self.service_id.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "backup_id={} ", &self.backup_id.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "token={} ", &self.token.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "data={} ", &self.data.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "pin={} ", &self.pin.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "tries={} ", &self.tries.unwrap_or(0))?;
        write!(fmt, "valid_from={}", &self.valid_from.unwrap_or(0))?;
        Ok(())
    }
}

//
// RestoreRequest impls
//

impl std::fmt::Display for kbupd_client::RestoreRequest {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "service_id={} ", &self.service_id.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "backup_id={} ", &self.backup_id.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "token={} ", &self.token.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "pin={} ", &self.pin.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "valid_from={}", &self.valid_from.unwrap_or(0))?;
        Ok(())
    }
}

//
// DeleteRequest impls
//

impl std::fmt::Display for kbupd_client::DeleteRequest {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "service_id={} ", &self.service_id.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "backup_id={}", &self.backup_id.as_ref().map(ToHex::new).unwrap_or_default())?;
        Ok(())
    }
}

//
// BackupResponse impls
//

impl std::fmt::Display for kbupd_client::BackupResponse {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Some(status) = kbupd_client::backup_response::Status::from_i32(self.status.unwrap_or(0)) {
            write!(fmt, "status={:?} ", &status)?;
        } else {
            write!(fmt, "status={:?} ", &self.status)?;
        }
        write!(fmt, "token={}", &self.token.as_ref().map(ToHex::new).unwrap_or_default())?;
        Ok(())
    }
}

//
// RestoreResponse impls
//

impl std::fmt::Display for kbupd_client::RestoreResponse {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Some(status) = kbupd_client::restore_response::Status::from_i32(self.status.unwrap_or(0)) {
            write!(fmt, "status={:?} ", &status)?;
        } else {
            write!(fmt, "status={:?} ", &self.status)?;
        }
        write!(fmt, "token={} ", &self.token.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "data={} ", &self.data.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "tries={}", &self.tries.unwrap_or(0))?;
        Ok(())
    }
}

//
// DeleteResponse impls
//

impl std::fmt::Display for kbupd_client::DeleteResponse {
    fn fmt(&self, _fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        Ok(())
    }
}
