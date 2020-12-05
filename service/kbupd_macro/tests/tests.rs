//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::sync::atomic::{AtomicUsize, Ordering};

use kbupd_macro::lazy_init;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

lazy_init! {
    pub fn init_values() {
        pub static ref VAL1: usize = COUNTER.fetch_add(1, Ordering::SeqCst);
        pub static ref VAL2: usize = COUNTER.fetch_add(1, Ordering::SeqCst);
        pub static ref VAL3: usize = COUNTER.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn check_init() {
    // The counter starts at 0.
    assert_eq!(0, COUNTER.load(Ordering::SeqCst));

    init_values();

    // Finding 3 in COUNTER, means that init_values() ran, and
    // intialized all 3 variables within the lazy_init block.
    assert_eq!(3, COUNTER.load(Ordering::SeqCst));

    assert_eq!(0, *VAL1);
    assert_eq!(1, *VAL2);
    assert_eq!(2, *VAL3);
}
