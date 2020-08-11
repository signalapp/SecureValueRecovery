//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use crate::prelude::*;

use crate::protobufs::raft::*;
use crate::storage::*;
use crate::util::*;

use super::raft_log_data::*;

use std::num::*;

use bytes::*;
use num_traits::ToPrimitive;

pub struct RaftLogIndex {
    storage: StorageArray<RaftLogIndexEntry>,

    tail: u32,
    len:  u32,

    prev_log_idx:  LogIdx,
    prev_log_term: Option<TermId>,
    last_log_term: TermId,
}

#[derive(Clone)]
pub struct RaftLogIndexEntry {
    pub term: TermId,
    pub data: Option<RaftLogDataEntry>,
}

impl RaftLogIndex {
    pub fn new(index_size: u32, cache_size: usize) -> Result<Self, ()> {
        Ok(Self {
            storage:       StorageArray::new(index_size, cache_size)?,
            tail:          Default::default(),
            len:           Default::default(),
            prev_log_idx:  Default::default(),
            prev_log_term: Default::default(),
            last_log_term: Default::default(),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn is_full(&self) -> bool {
        self.len >= self.storage.len()
    }

    pub fn prev_log_idx(&self) -> LogIdx {
        self.prev_log_idx
    }

    pub fn prev_log_term(&self) -> Option<TermId> {
        self.prev_log_term
    }

    pub fn last_log_idx(&self) -> LogIdx {
        self.prev_log_idx + u64::from(self.len)
    }

    pub fn last_log_term(&self) -> TermId {
        self.last_log_term
    }

    pub fn set_cache_size(&mut self, cache_size: usize) {
        self.storage.set_cache_size(cache_size);
    }

    pub fn get(&mut self, log_idx: LogIdx) -> Option<&RaftLogIndexEntry> {
        let offset: u64 = log_idx.id.checked_sub((self.prev_log_idx + 1).id)?;
        if offset < u64::from(self.len) {
            let index = self.wrap_add(offset.to_u32().unwrap_or_else(|| unreachable!()));
            match self.storage.get(index).unwrap_or_else(|| panic!("overflow")) {
                Ok(slot) => slot,
                Err(storage_error) => {
                    error!(
                        "storage error reading from raft log index {} (current length {}): {}",
                        index, self.len, storage_error
                    );
                    None
                }
            }
        } else {
            None
        }
    }

    pub fn push_back(&mut self, entry: RaftLogIndexEntry) -> Result<(), ()> {
        if self.len < self.storage.len() {
            let index = self.wrap_add(self.len);
            match self.storage.get_mut(index).unwrap_or_else(|| panic!("overflow")) {
                Ok(slot) => {
                    self.len = self.len.checked_add(1).unwrap_or_else(|| unreachable!());
                    self.last_log_term = entry.term;
                    *slot = Some(entry);
                    Ok(())
                }
                Err(storage_error) => {
                    error!(
                        "storage error appending to raft log index {} (current length {}): {}",
                        index, self.len, storage_error
                    );
                    Err(())
                }
            }
        } else {
            Err(())
        }
    }

    pub fn pop_front(&mut self) -> Option<RaftLogIndexEntry> {
        if let Some(new_len) = self.len.checked_sub(1) {
            let entry = match self.storage.get(self.tail).unwrap_or_else(|| panic!("overflow")) {
                Ok(entry) => entry.cloned(),
                Err(storage_error) => {
                    error!(
                        "storage error popping from raft log index {} (current length {}): {}",
                        self.tail, self.len, storage_error
                    );
                    None
                }
            };
            self.prev_log_idx = self.prev_log_idx + 1;
            self.prev_log_term = entry.as_ref().map(|entry| entry.term);
            self.tail = self.wrap_add(1);
            self.len = new_len;
            entry
        } else {
            None
        }
    }

    pub fn cancel_from(&mut self, from_log_idx: LogIdx) -> Result<Vec<RaftLogDataEntry>, ()> {
        let mut cancelled = Vec::new();
        let from_offset: u64 = from_log_idx.id.checked_sub((self.prev_log_idx + 1).id).ok_or(())?;
        let from_offset: u32 = from_offset.to_u32().ok_or(())?;
        if let Some(cancel_len) = self.len.checked_sub(from_offset) {
            if let Some(cancel_len) = NonZeroU32::new(cancel_len) {
                let new_last_log_term = if from_offset != 0 {
                    if let Some(new_last_log_entry) = self.get(self.prev_log_idx + u64::from(from_offset)) {
                        new_last_log_entry.term
                    } else {
                        error!("error reading raft log index entry preceding {} to cancel", from_log_idx);
                        return Err(());
                    }
                } else {
                    if self.prev_log_idx == Default::default() {
                        Default::default()
                    } else if let Some(prev_log_term) = self.prev_log_term {
                        prev_log_term
                    } else {
                        error!("did not have prev raft log term preceding {} to cancel", from_log_idx);
                        return Err(());
                    }
                };

                for cancel_idx in 0..cancel_len.get() {
                    let cancel_log_idx = from_log_idx + u64::from(cancel_idx);
                    if let Some(cancel_entry) = self.get(cancel_log_idx) {
                        if let Some(cancel_data_entry) = cancel_entry.data {
                            cancelled.push(cancel_data_entry);
                        }
                    } else {
                        error!("error reading raft log index entry {} to cancel", cancel_log_idx);
                    }
                }
                self.len = from_offset;
                self.last_log_term = new_last_log_term;
            }
        } else {
            warn!(
                "tried to cancel non-existent raft log entries from {} (last is {})",
                from_log_idx,
                self.last_log_idx()
            );
        }
        Ok(cancelled)
    }

    #[allow(clippy::integer_arithmetic)]
    fn wrap_add(&self, addend: u32) -> u32 {
        let index_rem = self.storage.len() - self.tail;
        if addend < index_rem {
            self.tail + addend
        } else {
            if addend <= self.storage.len() {
                addend - index_rem
            } else {
                (addend - index_rem)
                    .checked_rem(self.storage.len())
                    .unwrap_or_else(|| unreachable!())
            }
        }
    }
}

impl StorageValue for RaftLogIndexEntry {
    fn encoded_len() -> u32 {
        8 + 8 + 8 + 4
    }

    fn encode<B: BufMut>(maybe_value: Option<&Self>, buf: &mut B) {
        if let Some(value) = maybe_value {
            buf.put_u64_le(value.term.id);
            if let Some(data) = &value.data {
                buf.put_u64_le(data.nonce.into());
                buf.put_u64_le(data.offset.to_u64());
                buf.put_u32_le(data.length);
            } else {
                buf.put_u64_le(0);
            }
        } else {
            buf.put_u64_le(0);
        }
    }

    fn decode<B: Buf>(buf: &mut B) -> Option<Self> {
        let term = buf.get_u64_le();
        if term != 0 {
            let term = TermId { id: term };
            if let Some(nonce) = NonZeroU64::new(buf.get_u64_le()) {
                let offset = buf.get_u64_le().to_usize();
                let length = buf.get_u32_le();

                Some(Self {
                    term,
                    data: Some(RaftLogDataEntry {
                        nonce: StorageDataNonce::new(nonce),
                        offset,
                        length,
                    }),
                })
            } else {
                Some(Self { term, data: None })
            }
        } else {
            None
        }
    }
}
