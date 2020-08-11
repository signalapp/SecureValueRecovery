//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

mod raft_log_data;
mod raft_log_index;

use sgx_ffi::util::SecretValue;

use crate::prelude::*;
use crate::protobufs::raft::*;
use crate::raft::*;
use crate::util::*;

use self::raft_log_data::*;
use self::raft_log_index::*;

pub struct RaftLogStorage {
    index:     RaftLogIndex,
    data:      RaftLogData,
    cancelled: Vec<SecretValue<Vec<u8>>>,
}

//
// RaftLog impls
//

impl RaftLogStorage {
    pub fn new(data_size: usize, index_size: u32, index_cache_size: usize) -> Result<Self, ()> {
        Ok(Self {
            index:     RaftLogIndex::new(index_size, index_cache_size)?,
            data:      RaftLogData::new(data_size)?,
            cancelled: Default::default(),
        })
    }

    pub fn take_cancelled(&mut self) -> Vec<SecretValue<Vec<u8>>> {
        std::mem::replace(&mut self.cancelled, Default::default())
    }

    pub fn data_len(&self) -> usize {
        self.data.len()
    }

    pub fn set_index_cache_size(&mut self, index_cache_size: usize) {
        self.index.set_cache_size(index_cache_size);
    }
}
impl RaftLog for RaftLogStorage {
    fn append(&mut self, log_entry: LogEntry) -> Result<(), RaftLogAppendError> {
        let term = log_entry.term;
        if !self.index.is_full() {
            let data_entry = if !log_entry.data.is_empty() {
                let data_entry = self.data.append(log_entry)?;
                Some(data_entry)
            } else {
                None
            };
            let index_entry = RaftLogIndexEntry { term, data: data_entry };
            if let Ok(()) = self.index.push_back(index_entry) {
                Ok(())
            } else {
                Err(RaftLogAppendError::InternalError)
            }
        } else {
            Err(RaftLogAppendError::OutOfSpace { log_entry })
        }
    }

    fn pop_front(&mut self, truncate_to: LogIdx) -> Result<(), ()> {
        if (!self.index.is_empty() && self.index.prev_log_idx() < truncate_to) {
            if let Some(popped_entry) = self.index.pop_front() {
                if let Some(popped_data_entry) = &popped_entry.data {
                    self.data.pop_front_to(popped_data_entry);
                }
            }
            Ok(())
        } else {
            Err(())
        }
    }

    fn cancel_from(&mut self, from_log_idx: LogIdx) -> Result<usize, ()> {
        let cancelled_data_entries = self.index.cancel_from(from_log_idx)?;
        self.cancelled = self.data.cancel(cancelled_data_entries);
        Ok(self.cancelled.len())
    }

    fn get(&mut self, log_idx: LogIdx) -> Option<LogEntry> {
        let index_entry = self.index.get(log_idx)?;
        let entry_data = if let Some(data_entry) = &index_entry.data {
            self.data.read(data_entry)?
        } else {
            SecretValue::new(Vec::new())
        };
        Some(LogEntry::new(index_entry.term, entry_data))
    }

    fn get_len(&mut self, log_idx: LogIdx) -> Option<usize> {
        let index_entry = self.index.get(log_idx)?;
        if let Some(data_entry) = &index_entry.data {
            Some(data_entry.length.to_usize())
        } else {
            Some(0)
        }
    }

    fn get_term(&mut self, log_idx: LogIdx) -> Option<TermId> {
        if log_idx == self.index.prev_log_idx() {
            self.index.prev_log_term()
        } else {
            self.index.get(log_idx).map(|entry| entry.term)
        }
    }

    fn prev_idx(&self) -> LogIdx {
        self.index.prev_log_idx()
    }

    fn last_idx(&self) -> LogIdx {
        self.index.last_log_idx()
    }

    fn last_term(&self) -> TermId {
        self.index.last_log_term()
    }
}
