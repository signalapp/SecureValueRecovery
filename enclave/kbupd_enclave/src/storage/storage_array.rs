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

use super::*;

pub struct StorageArray<V> {
    cache: StoragePageCache<V>,
}

//
// StorageArray impls
//

impl<V> StorageArray<V>
where V: StorageValue,
{
    pub fn new(length: u32, cache_size: usize) -> Result<Self, ()> {
        let page_count = length.saturating_add(V::items_per_page() - 1)
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
