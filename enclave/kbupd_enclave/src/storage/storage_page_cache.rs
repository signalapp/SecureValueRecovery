//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use crate::prelude::*;

use std::fmt;
use std::marker::*;
use std::rc::*;

use bytes::*;
use num_traits::ToPrimitive;

use crate::lru::*;
use crate::storage::storage_data::*;
use crate::util::*;

const PAGE_SIZE: u16 = 4096;

pub struct StoragePageCache<V> {
    cache_size: usize,

    pages:  Box<[StoragePage<V>]>,
    cached: Lru<StoragePageIndex>,
    data:   StorageData,
}

#[derive(Debug)]
pub enum StorageError {
    InternalError,
    ReadError,
}

pub trait StorageValue: Sized {
    fn encoded_len() -> u32;
    fn encode<B: BufMut>(value: Option<&Self>, buf: &mut B);
    fn decode<B: Buf>(buf: &mut B) -> Option<Self>;
    fn encode_to_vec(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(Self::encoded_len().to_usize());
        Self::encode(Some(self), &mut encoded);
        encoded
    }
    fn items_per_page() -> u32 {
        (u32::from(PAGE_SIZE) - u32::from(StorageData::tag_len())) / Self::encoded_len()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct StoragePageIndex(u32);

pub struct StorageItemIndex<V> {
    index: u32,
    _data: PhantomData<V>,
}

enum StoragePage<V> {
    Free,
    Poisoned,
    Uncached(UncachedStoragePage),
    Cached(Box<CachedStoragePage<V>>),
}

enum CachedStoragePageDirtyState {
    Dirty,
    Clean(StorageDataNonce),
}

struct CachedStoragePage<V> {
    dirty:     CachedStoragePageDirtyState,
    lru_entry: Weak<LruEntry<StoragePageIndex>>,
    items:     Box<[Option<V>]>,
}

struct UncachedStoragePage {
    nonce: StorageDataNonce,
}

impl<V> StoragePageCache<V>
where V: StorageValue
{
    pub fn with_page_count(page_count: u32, cache_size: usize) -> Result<Self, ()> {
        let data_size = page_count.to_usize().checked_mul(PAGE_SIZE.into()).ok_or(())?;
        Self::new(data_size, cache_size)
    }

    pub fn new(data_size: usize, cache_size: usize) -> Result<Self, ()> {
        let cache_size = cache_size.max(1);
        let data = StorageData::new(data_size)?;
        let max_page_count = StorageItemIndex::<V>::max_page_count().to_usize();
        let page_count = (data.len() / usize::from(PAGE_SIZE)).max(1).min(max_page_count);

        let mut pages: Vec<StoragePage<V>> = Vec::with_capacity(page_count);
        pages.extend(std::iter::repeat_with(Default::default).take(page_count));

        Ok(Self {
            cache_size,

            pages: pages.into(),
            cached: Default::default(),
            data,
        })
    }

    pub fn page_count(&self) -> u32 {
        self.pages.len().to_u32().unwrap_or(u32::max_value())
    }

    pub fn item_index(&self, index: u32) -> Option<StorageItemIndex<V>> {
        let entry = StorageItemIndex { index, _data: PhantomData };
        if u32::from(entry.page_index()) < self.page_count() {
            Some(entry)
        } else {
            None
        }
    }

    pub fn set_cache_size(&mut self, cache_size: usize) {
        self.cache_size = cache_size;
    }

    pub fn get_item(&mut self, entry: &StorageItemIndex<V>) -> Result<Option<&V>, StorageError> {
        let cached_page = self.read_page(entry.page_index())?;
        Ok(cached_page.get_item(entry))
    }

    pub fn get_item_mut(&mut self, entry: &StorageItemIndex<V>) -> Result<&mut Option<V>, StorageError> {
        let cached_page = self.read_page(entry.page_index())?;
        Ok(cached_page.get_item_mut(entry))
    }

    fn read_page(&mut self, page_index: StoragePageIndex) -> Result<&mut CachedStoragePage<V>, StorageError> {
        match self.pages.get(usize::from(page_index)) {
            Some(StoragePage::Free) | Some(StoragePage::Uncached(_)) => {
                while self.cached.len() >= self.cache_size {
                    if let Some(evict_lru_entry) = self.cached.pop_front() {
                        debug!("evicting storage page {}", evict_lru_entry.get());
                        self.write_page(*evict_lru_entry.get());
                    } else {
                        break;
                    }
                }
            }
            None | Some(StoragePage::Poisoned) | Some(StoragePage::Cached(_)) => {}
        }

        if let Some(page) = self.pages.get_mut(usize::from(page_index)) {
            let cached_page = match page.read(&self.data, &mut self.cached, page_index) {
                Ok(cached_page) => cached_page,
                Err(storage_error) => {
                    error!("fatal error reading page {}: {}", page_index, storage_error);
                    return Err(storage_error);
                }
            };

            self.cached.bump(&cached_page.lru_entry);

            Ok(cached_page)
        } else {
            error!("fetching out of bounds page {}!", page_index);
            Err(StorageError::InternalError)
        }
    }

    fn write_page(&mut self, page_index: StoragePageIndex) {
        if let Some(page) = self.pages.get_mut(usize::from(page_index)) {
            page.write(&mut self.data, page_index);
        } else {
            error!("evicting out of bounds page {}!", &page_index);
        }
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, fmt)
    }
}

impl fmt::Display for StoragePageIndex {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(index) = self;
        fmt::Display::fmt(index, fmt)
    }
}

impl From<StoragePageIndex> for u32 {
    fn from(from: StoragePageIndex) -> Self {
        from.0
    }
}

impl From<StoragePageIndex> for usize {
    fn from(from: StoragePageIndex) -> Self {
        from.0.to_usize()
    }
}

impl<V> StorageItemIndex<V>
where V: StorageValue
{
    fn page_index(&self) -> StoragePageIndex {
        StoragePageIndex(self.index / V::items_per_page())
    }

    fn item_index(&self) -> usize {
        (self.index % V::items_per_page()).to_usize()
    }

    fn max_page_count() -> u32 {
        u32::max_value() / V::items_per_page()
    }
}

impl<V> StoragePage<V>
where V: StorageValue
{
    fn read(
        &mut self,
        data: &StorageData,
        cached: &mut Lru<StoragePageIndex>,
        page_index: StoragePageIndex,
    ) -> Result<&mut CachedStoragePage<V>, StorageError>
    {
        match self {
            StoragePage::Cached(cached_page) => Ok(cached_page),
            StoragePage::Uncached(uncached_page) => {
                debug!("reading storage page {}", page_index);
                let lru_entry = cached.push_back(page_index);
                let mut cached_page = Box::new(CachedStoragePage::new(
                    CachedStoragePageDirtyState::Clean(uncached_page.nonce),
                    lru_entry,
                ));
                let offset = usize::from(page_index)
                    .checked_mul(PAGE_SIZE.into())
                    .ok_or(StorageError::InternalError)?;
                match data.read(offset, PAGE_SIZE.into(), uncached_page.nonce) {
                    Ok(decrypted) => {
                        let items_data = decrypted.get()[..].chunks(V::encoded_len().to_usize());
                        for (item, mut item_data) in cached_page.items.iter_mut().zip(items_data) {
                            *item = V::decode(&mut item_data);
                        }

                        *self = StoragePage::Cached(cached_page);
                        match self {
                            StoragePage::Cached(cached_page) => Ok(cached_page),
                            _ => static_unreachable!(),
                        }
                    }
                    Err(()) => {
                        *self = StoragePage::Poisoned;
                        Err(StorageError::ReadError)
                    }
                }
            }
            StoragePage::Poisoned => Err(StorageError::ReadError),
            StoragePage::Free => {
                let lru_entry = cached.push_back(page_index);
                *self = StoragePage::Cached(Box::new(CachedStoragePage::new(CachedStoragePageDirtyState::Dirty, lru_entry)));
                match self {
                    StoragePage::Cached(cached_page) => Ok(cached_page),
                    _ => static_unreachable!(),
                }
            }
        }
    }

    fn write(&mut self, data: &mut StorageData, page_index: StoragePageIndex) {
        let cached_page = match self {
            StoragePage::Cached(cached_page) => cached_page,
            _ => return,
        };

        *self = match cached_page.dirty {
            CachedStoragePageDirtyState::Clean(nonce) => StoragePage::Uncached(UncachedStoragePage { nonce }),
            CachedStoragePageDirtyState::Dirty if cached_page.is_empty() => StoragePage::Free,
            CachedStoragePageDirtyState::Dirty => {
                let mut secret_encoded_vec = SecretValue::new(Vec::with_capacity(PAGE_SIZE.into()));
                let encoded: &mut Vec<u8> = secret_encoded_vec.get_mut();
                for (item_index, item) in cached_page.items.iter().enumerate() {
                    encoded.resize(item_index.saturating_mul(V::encoded_len().to_usize()), 0);
                    V::encode(item.as_ref(), encoded);
                }
                encoded.resize(usize::from(PAGE_SIZE) - usize::from(StorageData::tag_len()), 0);

                let offset_res = usize::from(page_index).checked_mul(PAGE_SIZE.into()).ok_or(());
                match offset_res.and_then(|offset: usize| data.write(offset, secret_encoded_vec)) {
                    Ok(nonce) => StoragePage::Uncached(UncachedStoragePage { nonce }),
                    Err(()) => {
                        error!("wrote out of bounds page {}!", page_index);
                        return;
                    }
                }
            }
        };
    }
}

impl<V> Default for StoragePage<V> {
    fn default() -> Self {
        StoragePage::Free
    }
}

impl<V> CachedStoragePage<V>
where V: StorageValue
{
    fn new(dirty: CachedStoragePageDirtyState, lru_entry: Weak<LruEntry<StoragePageIndex>>) -> Self {
        let size = V::items_per_page();
        let mut items = Vec::with_capacity(size.to_usize());
        items.extend(std::iter::repeat_with(Default::default).take(size.to_usize()));
        Self {
            dirty,
            lru_entry,
            items: items.into(),
        }
    }

    fn get_item(&mut self, item_index: &StorageItemIndex<V>) -> Option<&V> {
        self.items
            .get(item_index.item_index())
            .unwrap_or_else(|| panic!("overflow"))
            .as_ref()
    }

    fn get_item_mut(&mut self, item_index: &StorageItemIndex<V>) -> &mut Option<V> {
        self.dirty = CachedStoragePageDirtyState::Dirty;
        self.items.get_mut(item_index.item_index()).unwrap_or_else(|| panic!("overflow"))
    }

    fn is_empty(&self) -> bool {
        for item_slot in self.items.iter() {
            if item_slot.is_some() {
                return false;
            }
        }
        true
    }
}
