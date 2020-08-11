//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use super::*;

pub struct StorageArray<V> {
    cache: StoragePageCache<V>,
}

//
// StorageArray impls
//

impl<V> StorageArray<V>
where V: StorageValue
{
    pub fn new(length: u32, cache_size: usize) -> Result<Self, ()> {
        let page_count = length
            .saturating_add(V::items_per_page() - 1)
            .checked_div(V::items_per_page())
            .unwrap_or_else(|| static_unreachable!());
        Ok(Self {
            cache: StoragePageCache::with_page_count(page_count, cache_size)?,
        })
    }

    pub fn len(&self) -> u32 {
        self.cache.page_count().saturating_mul(V::items_per_page())
    }

    pub fn set_cache_size(&mut self, cache_size: usize) {
        self.cache.set_cache_size(cache_size);
    }

    pub fn get(&mut self, index: u32) -> Option<Result<Option<&V>, StorageError>> {
        let item_index = self.cache.item_index(index)?;
        Some(self.cache.get_item(&item_index))
    }

    pub fn get_mut(&mut self, index: u32) -> Option<Result<&mut Option<V>, StorageError>> {
        let item_index = self.cache.item_index(index)?;
        Some(self.cache.get_item_mut(&item_index))
    }
}
