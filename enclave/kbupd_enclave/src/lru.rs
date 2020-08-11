//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use intrusive_collections::LinkedList;
use intrusive_collections::*;

use std::rc::*;

pub struct Lru<T> {
    list:   LinkedList<LruAdapter<T>>,
    token:  Rc<LruToken>,
    length: usize,
}

pub struct LruEntry<T> {
    item:  T,
    token: Weak<LruToken>,
    link:  LinkedListLink,
}

intrusive_adapter!(pub LruAdapter<T> = Rc<LruEntry<T>>: LruEntry<T> { link: LinkedListLink });

struct LruToken;

impl<T> Lru<T> {
    pub fn new() -> Self {
        Self {
            list:   LinkedList::new(LruAdapter::new()),
            token:  Rc::new(LruToken),
            length: Default::default(),
        }
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn push_back(&mut self, item: T) -> Weak<LruEntry<T>> {
        let lru_entry = Rc::new(LruEntry {
            item,
            token: Rc::downgrade(&self.token),
            link: Default::default(),
        });
        let lru_entry_weak = Rc::downgrade(&lru_entry);

        self.list.push_back(lru_entry);
        self.length = self.length.saturating_add(1);
        lru_entry_weak
    }

    pub fn bump(&mut self, lru_entry_weak: &Weak<LruEntry<T>>) -> bool {
        if let Some(lru_entry) = lru_entry_weak.upgrade() {
            // check that lru_entry is a member of self.list
            if let Some(lru_entry_token) = lru_entry.token.upgrade() {
                if !Rc::ptr_eq(&lru_entry_token, &self.token) {
                    return false;
                }
            } else {
                return false;
            }
            if !lru_entry.link.is_linked() {
                return false;
            }

            // safety: lru_entry must be a member of self.list
            let mut lru_cursor = unsafe { self.list.cursor_mut_from_ptr(lru_entry.as_ref()) };
            if let Some(lru_entry_rc) = lru_cursor.remove() {
                self.list.push_back(lru_entry_rc);
            } else {
                self.list.push_back(lru_entry);
            }
            true
        } else {
            false
        }
    }

    pub fn pop_front(&mut self) -> Option<Rc<LruEntry<T>>> {
        if let Some(lru_entry) = self.list.pop_front() {
            self.length = self.length.saturating_sub(1);
            Some(lru_entry)
        } else {
            None
        }
    }
}

impl<T> Default for Lru<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> LruEntry<T> {
    pub fn get(&self) -> &T {
        &self.item
    }
}

impl<'a, T> IntoIterator for &'a Lru<T> {
    type IntoIter = linked_list::Iter<'a, LruAdapter<T>>;
    type Item = &'a LruEntry<T>;

    fn into_iter(self) -> linked_list::Iter<'a, LruAdapter<T>> {
        self.list.iter()
    }
}
