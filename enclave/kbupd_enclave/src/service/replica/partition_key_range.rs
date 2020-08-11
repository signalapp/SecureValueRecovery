//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::fmt;
use std::ops::*;

use crate::protobufs::kbupd::*;
use crate::util::*;

#[derive(Copy, Clone, Eq, PartialOrd, Ord)]
pub struct PartitionKey([u8; 32]);

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct PartitionKeyRange {
    first: PartitionKey,
    last:  PartitionKey,
}

//
// PartittionKeyRange impls
//

impl PartitionKeyRange {
    pub fn new(first: PartitionKey, last: PartitionKey) -> Result<Self, ()> {
        if first <= last { Ok(Self { first, last }) } else { Err(()) }
    }

    pub fn new_unbounded() -> Self {
        Self {
            first: PartitionKey::new([0x00; 32]),
            last:  PartitionKey::new([0xFF; 32]),
        }
    }

    pub fn try_from_pb(pb: &PartitionKeyRangePb) -> Result<Self, ()> {
        Self::from_ids(&pb.first, &pb.last)
    }

    fn from_ids(first: &BackupId, last: &BackupId) -> Result<Self, ()> {
        Self::new(PartitionKey::try_from_pb(first)?, PartitionKey::try_from_pb(last)?)
    }

    pub fn to_pb(&self) -> PartitionKeyRangePb {
        PartitionKeyRangePb {
            first: BackupId { id: self.first.to_vec() },
            last:  BackupId { id: self.last.to_vec() },
        }
    }

    pub fn first(&self) -> &PartitionKey {
        &self.first
    }

    pub fn last(&self) -> &PartitionKey {
        &self.last
    }

    pub fn contains(&self, key: &[u8; 32]) -> bool {
        (key >= &self.first && key <= &self.last)
    }

    pub fn contains_id(&self, key: &BackupId) -> bool {
        let mut id: [u8; 32] = Default::default();
        if key.id.len() == id.len() {
            id.copy_from_slice(&key.id);
            self.contains(&id)
        } else {
            false
        }
    }

    pub fn contains_range(&self, other: &Self) -> bool {
        self.contains(&other.first) && self.contains(&other.last)
    }

    pub fn overlaps_range(&self, other: &Self) -> bool {
        (self.contains(&other.first) || self.contains(&other.last) || other.contains(&self.first) || other.contains(&self.last))
    }

    pub fn split_off_inclusive(&mut self, new_last: &PartitionKey) -> Result<Option<Self>, ()> {
        if self.contains(new_last) {
            if let Some(other_first) = new_last.checked_add(1) {
                let other_last = std::mem::replace(&mut self.last, *new_last);
                Ok(Self::new(other_first, other_last).ok())
            } else {
                Ok(None)
            }
        } else {
            Err(())
        }
    }
}

impl RangeBounds<PartitionKey> for &PartitionKeyRange {
    fn start_bound(&self) -> Bound<&PartitionKey> {
        Bound::Included(&self.first)
    }

    fn end_bound(&self) -> Bound<&PartitionKey> {
        Bound::Included(&self.last)
    }
}

impl fmt::Debug for PartitionKeyRange {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt::Display::fmt(self, fmt)
    }
}
impl fmt::Display for PartitionKeyRange {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let Self { first, last } = self;
        write!(fmt, "{}-{}", first, last)
    }
}

//
// PartitionKey impls
//

impl PartitionKey {
    pub fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    pub fn try_from_pb(backup_id: &BackupId) -> Result<Self, ()> {
        let mut value = [0u8; 32];
        if backup_id.id.len() == value.len() {
            value.copy_from_slice(&backup_id.id);
            Ok(Self(value))
        } else {
            Err(())
        }
    }

    pub fn to_pb(&self) -> BackupId {
        BackupId { id: self.0.to_vec() }
    }

    #[allow(clippy::indexing_slicing, clippy::integer_arithmetic)]
    pub fn checked_sub(&self, rhs: u8) -> Option<Self> {
        let mut ret = [0x00; 32];
        let mut carry = rhs;
        for (i, b) in self.0.iter().rev().enumerate() {
            let new_b = b.overflowing_sub(carry);
            carry = if new_b.1 { 1 } else { 0 };
            ret[31 - i] = new_b.0;
        }
        if carry == 0 { Some(Self(ret)) } else { None }
    }

    #[allow(clippy::indexing_slicing, clippy::integer_arithmetic)]
    pub fn checked_add(&self, rhs: u8) -> Option<Self> {
        let mut ret = [0x00; 32];
        let mut carry = rhs;
        for (i, b) in self.0.iter().rev().enumerate() {
            let new_b = b.overflowing_add(carry);
            carry = if new_b.1 { 1 } else { 0 };
            ret[31 - i] = new_b.0;
        }
        if carry == 0 { Some(Self(ret)) } else { None }
    }
}

impl Deref for PartitionKey {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> PartialEq<T> for PartitionKey
where T: AsRef<[u8]>
{
    fn eq(&self, other: &T) -> bool {
        self.0 == other.as_ref()
    }
}

impl AsRef<[u8]> for PartitionKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PartitionKey {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt::Display::fmt(self, fmt)
    }
}

impl fmt::Display for PartitionKey {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let Self(key) = self;
        write!(fmt, "{}", ToHex(key))
    }
}

//
// tests
//

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_full_range() {
        PartitionKeyRange::try_from_pb(
            &PartitionKeyRange::from_ids(&BackupId { id: vec![0x00; 32] }, &BackupId { id: vec![0xFF; 32] })
                .unwrap()
                .to_pb(),
        )
        .unwrap();
    }
    #[test]
    fn valid_empty_range() {
        PartitionKeyRange::try_from_pb(
            &PartitionKeyRange::from_ids(&BackupId { id: vec![0x00; 32] }, &BackupId { id: vec![0x00; 32] })
                .unwrap()
                .to_pb(),
        )
        .unwrap();
    }

    #[test]
    fn invalid_inverted_range() {
        PartitionKeyRange::from_ids(&BackupId { id: vec![0xFF; 32] }, &BackupId { id: vec![0x00; 32] }).unwrap_err();
    }

    #[test]
    fn invalid_range_empty_first() {
        PartitionKeyRange::from_ids(&BackupId { id: vec![0x00; 0] }, &BackupId { id: vec![0xFF; 32] }).unwrap_err();
    }

    #[test]
    fn invalid_range_empty_last() {
        PartitionKeyRange::from_ids(&BackupId { id: vec![0x00; 32] }, &BackupId { id: vec![0xFF; 0] }).unwrap_err();
    }

    #[test]
    fn invalid_range_short_first() {
        PartitionKeyRange::from_ids(&BackupId { id: vec![0x00; 31] }, &BackupId { id: vec![0xFF; 32] }).unwrap_err();
    }

    #[test]
    fn invalid_range_short_last() {
        PartitionKeyRange::from_ids(&BackupId { id: vec![0x00; 31] }, &BackupId { id: vec![0xFF; 32] }).unwrap_err();
    }

    #[test]
    fn invalid_range_long_first() {
        PartitionKeyRange::from_ids(&BackupId { id: vec![0x00; 33] }, &BackupId { id: vec![0xFF; 32] }).unwrap_err();
    }

    #[test]
    fn invalid_range_long_last() {
        PartitionKeyRange::from_ids(&BackupId { id: vec![0x00; 32] }, &BackupId { id: vec![0xFF; 33] }).unwrap_err();
    }

    #[test]
    fn contains_id_valid() {
        let range = PartitionKeyRange::new_unbounded();
        assert!(range.contains_id(&BackupId { id: vec![0x00; 32] }));
        assert!(range.contains_id(&BackupId { id: vec![0xFF; 32] }));
        assert!(range.contains_id(&BackupId { id: vec![0x80; 32] }));

        let range = PartitionKeyRange::new(PartitionKey::new([0x00; 32]), PartitionKey::new([0x80; 32])).unwrap();
        assert!(range.contains_id(&BackupId { id: vec![0x00; 32] }));
        assert!(range.contains_id(&PartitionKey::new([0x80; 32]).checked_sub(1).unwrap().to_pb()));
        assert!(range.contains_id(&BackupId { id: vec![0x80; 32] }));
        assert!(!range.contains_id(&PartitionKey::new([0x80; 32]).checked_add(1).unwrap().to_pb()));
        assert!(!range.contains_id(&BackupId { id: vec![0xFF; 32] }));

        let range = PartitionKeyRange::new(PartitionKey::new([0xBE; 32]), PartitionKey::new([0xEF; 32])).unwrap();
        assert!(!range.contains_id(&BackupId { id: vec![0x00; 32] }));
        assert!(!range.contains_id(&PartitionKey::new([0xBE; 32]).checked_sub(1).unwrap().to_pb()));
        assert!(range.contains_id(&BackupId { id: vec![0xBE; 32] }));
        assert!(range.contains_id(&PartitionKey::new([0xBE; 32]).checked_add(1).unwrap().to_pb()));
        assert!(range.contains_id(&PartitionKey::new([0xEF; 32]).checked_sub(1).unwrap().to_pb()));
        assert!(range.contains_id(&BackupId { id: vec![0xEF; 32] }));
        assert!(!range.contains_id(&PartitionKey::new([0xEF; 32]).checked_add(1).unwrap().to_pb()));
        assert!(!range.contains_id(&BackupId { id: vec![0xFF; 32] }));
    }

    #[test]
    fn contains_id_invalid() {
        assert!(!PartitionKeyRange::new_unbounded().contains_id(&BackupId { id: vec![] }));
        assert!(!PartitionKeyRange::new_unbounded().contains_id(&BackupId { id: vec![0x00; 31] }));
        assert!(!PartitionKeyRange::new_unbounded().contains_id(&BackupId { id: vec![0x00; 33] }));
    }

    macro_rules! key {
        ([$value:expr] + $addend:expr) => {{
            PartitionKey::new([$value; 32])
                .checked_add($addend)
                .unwrap_or_else(|| panic!("test key overflow"))
        }};
        ([$value:expr] - $subtrahend:expr) => {{
            PartitionKey::new([$value; 32])
                .checked_sub($subtrahend)
                .unwrap_or_else(|| panic!("test key underflow"))
        }};
        ([$value:expr]) => {{ PartitionKey::new([$value; 32]) }};
    }

    macro_rules! range {
        ([$value:expr],                    $($second:tt)*) => (range!({key!([$value])},               $($second)*));
        ([$value:expr] + $addend:expr,     $($second:tt)*) => (range!({key!([$value] + $addend)},     $($second)*));
        ([$value:expr] - $subtrahend:expr, $($second:tt)*) => (range!({key!([$value] - $subtrahend)}, $($second)*));

        ($first:block, [$value:expr])                    => (range!($first, {key!([$value])}));
        ($first:block, [$value:expr] + $addend:expr)     => (range!($first, {key!([$value] + $addend)}));
        ($first:block, [$value:expr] - $subtrahend:expr) => (range!($first, {key!([$value] - $subtrahend)}));

        ($first:block, $last:block) => ({
            PartitionKeyRange::new($first, $last).unwrap_or_else(|()| panic!("invalid test range"))
        });
        () => ({
            PartitionKeyRange::new_unbounded()
        });
    }

    #[test]
    fn overlaps_range() {
        let range = range!();
        assert!(range.overlaps_range(&range!()));
        assert!(range.overlaps_range(&range!([0x00], [0x00])));
        assert!(range.overlaps_range(&range!([0x00], [0xBE])));
        assert!(range.overlaps_range(&range!([0xBE], [0xEF])));
        assert!(range.overlaps_range(&range!([0xEF], [0xFF])));
        assert!(range.overlaps_range(&range!([0xFF], [0xFF])));

        let range = range!([0x00], [0xBE]);
        assert!(range.overlaps_range(&range!()));
        assert!(range.overlaps_range(&range!([0x00], [0x00])));
        assert!(range.overlaps_range(&range!([0x00], [0xBE] - 1)));
        assert!(range.overlaps_range(&range!([0x00], [0xBE])));
        assert!(range.overlaps_range(&range!([0x00], [0xFF])));
        assert!(range.overlaps_range(&range!([0xBA], [0xBA])));
        assert!(range.overlaps_range(&range!([0xBA], [0xBE])));
        assert!(range.overlaps_range(&range!([0xBA], [0xBE] + 1)));
        assert!(range.overlaps_range(&range!([0xBE], [0xBE])));
        assert!(range.overlaps_range(&range!([0xBE], [0xBE] + 1)));
        assert!(!range.overlaps_range(&range!([0xBE] + 1, [0xEF])));
        assert!(!range.overlaps_range(&range!([0xEF], [0xFF])));
        assert!(!range.overlaps_range(&range!([0xFF], [0xFF])));

        let range = range!([0xBE], [0xEF]);
        assert!(range.overlaps_range(&range!()));
        assert!(!range.overlaps_range(&range!([0x00], [0x00])));
        assert!(!range.overlaps_range(&range!([0x00], [0xBE] - 1)));
        assert!(range.overlaps_range(&range!([0x00], [0xBE])));
        assert!(range.overlaps_range(&range!([0x00], [0xBF])));
        assert!(range.overlaps_range(&range!([0x00], [0xEF])));
        assert!(range.overlaps_range(&range!([0x00], [0xEF] + 1)));
        assert!(range.overlaps_range(&range!([0x00], [0xFF])));
        assert!(range.overlaps_range(&range!([0xBE], [0xEF])));
        assert!(range.overlaps_range(&range!([0xBE], [0xEF] + 1)));
        assert!(range.overlaps_range(&range!([0xBE] + 1, [0xEF] - 1)));
        assert!(range.overlaps_range(&range!([0xBE] + 1, [0xEF])));
        assert!(range.overlaps_range(&range!([0xBE] + 1, [0xEF] + 1)));
        assert!(range.overlaps_range(&range!([0xEF], [0xEF])));
        assert!(range.overlaps_range(&range!([0xEF], [0xEF] + 1)));
        assert!(!range.overlaps_range(&range!([0xEF] + 1, [0xEF] + 1)));
        assert!(!range.overlaps_range(&range!([0xEF] + 1, [0xFF])));

        let range = range!([0xEF], [0xFF]);
        assert!(!range.overlaps_range(&range!([0x00], [0x00])));
        assert!(!range.overlaps_range(&range!([0x00], [0xEF] - 1)));
        assert!(range.overlaps_range(&range!([0x00], [0xEF])));
        assert!(range.overlaps_range(&range!([0x00], [0xEF] + 1)));
        assert!(range.overlaps_range(&range!([0x00], [0xFF])));
        assert!(range.overlaps_range(&range!([0xEF], [0xEF])));
        assert!(range.overlaps_range(&range!([0xEF], [0xEF] + 1)));
        assert!(range.overlaps_range(&range!([0xEF], [0xFF])));
        assert!(range.overlaps_range(&range!([0xEF] + 1, [0xFF] - 1)));
        assert!(range.overlaps_range(&range!([0xEF] + 1, [0xFF])));
        assert!(range.overlaps_range(&range!([0xFF], [0xFF])));
    }

    #[test]
    fn split_off_first() {
        let mut range = PartitionKeyRange::new_unbounded();
        let split_off = range.split_off_inclusive(&PartitionKey::new([0x00; 32])).unwrap().unwrap();
        assert_eq!(range.first(), &[0x00; 32]);
        assert_eq!(range.last(), &[0x00; 32]);
        assert_eq!(split_off.first(), &range.last().checked_add(1).unwrap());
        assert_eq!(split_off.last(), &[0xff; 32]);

        let mut range = PartitionKeyRange::new(PartitionKey::new([0xbe; 32]), PartitionKey::new([0xef; 32])).unwrap();
        let split_off = range.split_off_inclusive(&PartitionKey::new([0xbe; 32])).unwrap().unwrap();
        assert_eq!(range.first(), &[0xbe; 32]);
        assert_eq!(range.last(), &[0xbe; 32]);
        assert_eq!(split_off.first(), &range.last().checked_add(1).unwrap());
        assert_eq!(split_off.last(), &[0xef; 32]);
    }

    #[test]
    fn split_off_mid() {
        let mut range = PartitionKeyRange::new_unbounded();
        let split_off = range.split_off_inclusive(&PartitionKey::new([0x80; 32])).unwrap().unwrap();
        assert_eq!(range.first(), &[0x00; 32]);
        assert_eq!(range.last(), &[0x80; 32]);
        assert_eq!(split_off.first(), &range.last().checked_add(1).unwrap());
        assert_eq!(split_off.last(), &[0xff; 32]);

        let mut range = PartitionKeyRange::new(PartitionKey::new([0xbe; 32]), PartitionKey::new([0xef; 32])).unwrap();
        let split_off = range.split_off_inclusive(&PartitionKey::new([0xdd; 32])).unwrap().unwrap();
        assert_eq!(range.first(), &[0xbe; 32]);
        assert_eq!(range.last(), &[0xdd; 32]);
        assert_eq!(split_off.first(), &range.last().checked_add(1).unwrap());
        assert_eq!(split_off.last(), &[0xef; 32]);
    }

    #[test]
    fn split_off_last() {
        let mut range = PartitionKeyRange::new_unbounded();
        let split_off = range.split_off_inclusive(&PartitionKey::new([0xff; 32])).unwrap();
        assert_eq!(range.first(), &[0x00; 32]);
        assert_eq!(range.last(), &[0xff; 32]);
        assert!(split_off.is_none());

        let mut range = PartitionKeyRange::new(PartitionKey::new([0xbe; 32]), PartitionKey::new([0xef; 32])).unwrap();
        let split_off = range.split_off_inclusive(&PartitionKey::new([0xef; 32])).unwrap();
        assert_eq!(range.first(), &[0xbe; 32]);
        assert_eq!(range.last(), &[0xef; 32]);
        assert!(split_off.is_none());
    }

    #[test]
    fn split_off_small() {
        let mut range = PartitionKeyRange::new(PartitionKey::new([0x00; 32]), PartitionKey::new([0x00; 32])).unwrap();
        let split_off = range.split_off_inclusive(&PartitionKey::new([0x00; 32])).unwrap();
        assert_eq!(range.first(), &[0x00; 32]);
        assert_eq!(range.last(), &[0x00; 32]);
        assert!(split_off.is_none());

        let mut range = PartitionKeyRange::new(PartitionKey::new([0xbe; 32]), PartitionKey::new([0xbe; 32])).unwrap();
        let split_off = range.split_off_inclusive(&PartitionKey::new([0xbe; 32])).unwrap();
        assert_eq!(range.first(), &[0xbe; 32]);
        assert_eq!(range.last(), &[0xbe; 32]);
        assert!(split_off.is_none());

        let mut range = PartitionKeyRange::new(PartitionKey::new([0xff; 32]), PartitionKey::new([0xff; 32])).unwrap();
        let split_off = range.split_off_inclusive(&PartitionKey::new([0xff; 32])).unwrap();
        assert_eq!(range.first(), &[0xff; 32]);
        assert_eq!(range.last(), &[0xff; 32]);
        assert!(split_off.is_none());
    }

    #[test]
    fn split_off_err() {
        let mut range = PartitionKeyRange::new(PartitionKey::new([0x00; 32]), PartitionKey::new([0x00; 32])).unwrap();
        range.split_off_inclusive(&range.last().checked_add(1).unwrap()).unwrap_err();
        range.split_off_inclusive(&PartitionKey::new([0xff; 32])).unwrap_err();

        let mut range = PartitionKeyRange::new(PartitionKey::new([0x00; 32]), PartitionKey::new([0xbe; 32])).unwrap();
        range.split_off_inclusive(&range.last().checked_add(1).unwrap()).unwrap_err();
        range.split_off_inclusive(&PartitionKey::new([0xbf; 32])).unwrap_err();
        range.split_off_inclusive(&PartitionKey::new([0xff; 32])).unwrap_err();

        let mut range = PartitionKeyRange::new(PartitionKey::new([0xbe; 32]), PartitionKey::new([0xbe; 32])).unwrap();
        range.split_off_inclusive(&PartitionKey::new([0x00; 32])).unwrap_err();
        range.split_off_inclusive(&PartitionKey::new([0xba; 32])).unwrap_err();
        range.split_off_inclusive(&range.first().checked_sub(1).unwrap()).unwrap_err();
        range.split_off_inclusive(&range.last().checked_add(1).unwrap()).unwrap_err();
        range.split_off_inclusive(&PartitionKey::new([0xef; 32])).unwrap_err();
        range.split_off_inclusive(&PartitionKey::new([0xff; 32])).unwrap_err();

        let mut range = PartitionKeyRange::new(PartitionKey::new([0xbf; 32]), PartitionKey::new([0xff; 32])).unwrap();
        range.split_off_inclusive(&PartitionKey::new([0x00; 32])).unwrap_err();
        range.split_off_inclusive(&PartitionKey::new([0xbe; 32])).unwrap_err();
        range.split_off_inclusive(&range.first().checked_sub(1).unwrap()).unwrap_err();

        let mut range = PartitionKeyRange::new(PartitionKey::new([0xff; 32]), PartitionKey::new([0xff; 32])).unwrap();
        range.split_off_inclusive(&PartitionKey::new([0x00; 32])).unwrap_err();
        range.split_off_inclusive(&PartitionKey::new([0xfe; 32])).unwrap_err();
    }

    #[test]
    fn checked_add() {
        for index in 0..32 {
            for index_value in 0x00..0xfe {
                let mut value = [0x00; 32];
                for byte in value[index + 1..32].iter_mut() {
                    *byte = 0xff;
                }
                value[index] = index_value;
                let mut addend = [0x00; 32];
                addend[index] = index_value + 1;
                assert_eq!(PartitionKey::new(value).checked_add(1).unwrap(), &addend);
            }
        }
    }

    #[test]
    fn checked_sub() {
        for index in 0..32 {
            for index_value in 0x01..0xff {
                let mut value = [0x00; 32];
                value[index] = index_value;
                let mut addend = [0x00; 32];
                addend[index] = index_value - 1;
                for byte in addend[index + 1..32].iter_mut() {
                    *byte = 0xff;
                }
                assert_eq!(PartitionKey::new(value).checked_sub(1).unwrap(), &addend);
            }
        }
    }

    #[test]
    fn checked_add_overflow() {
        assert_eq!(PartitionKey::new([0xff; 32]).checked_add(1), None);
    }

    #[test]
    fn checked_sub_overflow() {
        assert_eq!(PartitionKey::new([0x00; 32]).checked_sub(1), None);
    }
}
