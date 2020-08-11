//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use crate::prelude::*;

use num_traits::ToPrimitive;
use sgx_ffi::util::SecretValue;

use crate::protobufs::raft::LogEntry;
use crate::raft::*;
use crate::storage::storage_data::*;
use crate::util::*;

pub struct RaftLogData {
    storage: StorageData,

    head: usize,
    tail: usize,
}

#[derive(Clone, Copy)]
pub struct RaftLogDataEntry {
    pub nonce:  StorageDataNonce,
    pub offset: usize,
    pub length: u32,
}

impl RaftLogData {
    pub fn new(data_size: usize) -> Result<Self, ()> {
        Ok(Self {
            storage: StorageData::new(data_size)?,
            head:    Default::default(),
            tail:    Default::default(),
        })
    }

    pub fn len(&self) -> usize {
        if let Some(len) = self.head.checked_sub(self.tail) {
            len
        } else {
            self.storage.len().saturating_sub(self.tail).saturating_add(self.head)
        }
    }

    pub fn append(&mut self, log_entry: LogEntry) -> Result<RaftLogDataEntry, RaftLogAppendError> {
        let append_len = log_entry.data.len().saturating_add(StorageData::tag_len().into());
        let append_len = match append_len.to_u32() {
            Some(append_len) if append_len.to_usize() < self.storage.len() => append_len,
            Some(_) | None => {
                error!(
                    "transaction too large at {} bytes (have {} bytes of storage)",
                    log_entry.data.len(),
                    self.storage.len()
                );
                return Err(RaftLogAppendError::TooLarge { size: append_len });
            }
        };
        let mut offset = self.head;
        let mut new_head = offset.saturating_add(append_len.to_usize());
        if new_head >= self.storage.len() {
            if self.tail > 0 {
                offset = 0;
                new_head = append_len.to_usize();
            } else {
                return Err(RaftLogAppendError::OutOfSpace { log_entry });
            }
        }

        if offset < self.tail && new_head >= self.tail {
            Err(RaftLogAppendError::OutOfSpace { log_entry })
        } else {
            self.head = new_head;

            match self.storage.write(offset, log_entry.into_data()) {
                Ok(nonce) => Ok(RaftLogDataEntry {
                    nonce,
                    offset,
                    length: append_len,
                }),
                Err(()) => {
                    error!("wrote out of bounds to raft log at {} len {}", offset, append_len);
                    Err(RaftLogAppendError::InternalError)
                }
            }
        }
    }

    pub fn cancel(&mut self, cancelled_data_entries: Vec<RaftLogDataEntry>) -> Vec<SecretValue<Vec<u8>>> {
        if let Some(cancel_from_data_entry) = cancelled_data_entries.get(0) {
            self.head = cancel_from_data_entry.offset;
        }

        let mut cancelled_data = Vec::new();
        for cancelled_data_entry in cancelled_data_entries {
            if let Some(data) = self.read(&cancelled_data_entry) {
                cancelled_data.push(data);
            }
        }
        cancelled_data
    }

    pub fn pop_front_to(&mut self, popped_entry: &RaftLogDataEntry) {
        let tail = popped_entry.offset.saturating_add(popped_entry.length.to_usize());
        if tail < self.storage.len() {
            self.tail = tail;
        } else {
            self.tail = Default::default();
        }
    }

    pub fn read(&self, data_entry: &RaftLogDataEntry) -> Option<SecretValue<Vec<u8>>> {
        if let Ok(data) = self.storage.read(data_entry.offset, data_entry.length.to_usize(), data_entry.nonce) {
            Some(data)
        } else {
            error!(
                "error reading raft log entry at offset {} length {}",
                data_entry.offset, data_entry.length
            );
            None
        }
    }
}
