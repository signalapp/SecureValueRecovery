//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn verbose_logging_enabled() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

pub fn set_verbose_logging_enabled(enabled: bool) {
    VERBOSE.store(enabled, Ordering::SeqCst)
}
