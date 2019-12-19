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
        write!(fmt, "backup_id={} ",  &self.backup_id.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "token={} ",      &self.token.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "data={} ",       &self.data.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "pin={} ",        &self.pin.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "tries={} ",      &self.tries.unwrap_or(0))?;
        write!(fmt, "valid_from={}",  &self.valid_from.unwrap_or(0))?;
        Ok(())
    }
}

//
// RestoreRequest impls
//

impl std::fmt::Display for kbupd_client::RestoreRequest {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "service_id={} ", &self.service_id.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "backup_id={} ",   &self.backup_id.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "token={} ",      &self.token.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "pin={} ",        &self.pin.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "valid_from={}",  &self.valid_from.unwrap_or(0))?;
        Ok(())
    }
}

//
// DeleteRequest impls
//

impl std::fmt::Display for kbupd_client::DeleteRequest {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "service_id={} ", &self.service_id.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "backup_id={}",   &self.backup_id.as_ref().map(ToHex::new).unwrap_or_default())?;
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
        write!(fmt, "data={} ",  &self.data.as_ref().map(ToHex::new).unwrap_or_default())?;
        write!(fmt, "tries={}",  &self.tries.unwrap_or(0))?;
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
